// Gate: deterministic detect-then-kill.
// - kprobe on binder_transaction entry: current uid is blocked AND target
//   handle != 0 (the first handle != 0 transaction of a new process is
//   attachApplication) -> mark the tgid pending.
// - kretprobe on binder_transaction exit: marked -> push ringbuf event.
// - A gate thread drains the ring buffer and queues each pid to a single
//   killer thread. The killer waits for the pid's oom_score_adj to become 0
//   (attach handshake done -> the process is foreground) and only then sends
//   SIGKILL from userspace: no black screen, no fixed delay. A 300ms timeout
//   catches background launches that never reach foreground.

use std::collections::HashMap as StdHashMap;
use std::convert::TryInto;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use aya::maps::{HashMap, MapData, RingBuf};
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Ebpf, EbpfLoader};

use crate::config::log;

/// Read a pid's oom_score_adj (None when the pid already exited). A value of
/// 0 means the process is the foreground app (FOREGROUND_APP_ADJ). Verified on
/// device: at the attach boundary the value is still -1000 (inherited from
/// zygote), and it flips to 0 a few ms later once the attach handshake is
/// complete -- so 0 is a real, later, deterministic "safe to kill" signal.
fn read_oom_score_adj(pid: u32) -> Option<i32> {
    std::fs::read_to_string(format!("/proc/{pid}/oom_score_adj"))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
}

pub struct Gate {
    /// Holds the BPF object so kprobe links stay attached while the daemon lives.
    _bpf: Ebpf,
    /// Block map: uid -> 1. The engine adds/removes uids through it.
    pub blocked: HashMap<MapData, u32, u8>,
    /// Write end of the wake pipe: writing a byte unblocks the stats thread.
    wake_fd: RawFd,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Gate {
    pub fn start(
        kill_count: Arc<Mutex<StdHashMap<u32, u64>>>,
    ) -> anyhow::Result<Self> {
        let mut bpf = EbpfLoader::new().load(include_bytes_aligned!("../bpf/gate.bpf.o"))?;

        let entry_prog: &mut KProbe = bpf
            .program_mut("gate_binder_entry")
            .ok_or_else(|| anyhow::anyhow!("BPF program 'gate_binder_entry' not found"))?
            .try_into()?;
        entry_prog.load()?;
        entry_prog.attach("binder_transaction", 0)?;
        log("[gate] kprobe attached to binder_transaction (entry)");

        let exit_prog: &mut KProbe = bpf
            .program_mut("gate_binder_exit")
            .ok_or_else(|| anyhow::anyhow!("BPF program 'gate_binder_exit' not found"))?
            .try_into()?;
        exit_prog.load()?;
        exit_prog.attach("binder_transaction", 0)?;
        log("[gate] kretprobe attached to binder_transaction (exit)");

        let blocked: HashMap<MapData, u32, u8> = bpf
            .take_map("blocked_uids")
            .ok_or_else(|| anyhow::anyhow!("map 'blocked_uids' not found"))?
            .try_into()?;
        let mut events: RingBuf<_> = bpf
            .take_map("events")
            .ok_or_else(|| anyhow::anyhow!("map 'events' not found"))?
            .try_into()?;

        // Wake pipe: drop writes a byte so the stats thread unblocks and exits.
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            anyhow::bail!("pipe failed");
        }
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let ring_fd = events.as_raw_fd();

        let counters = Arc::clone(&kill_count);

        // Single killer thread: pids are killed the moment their oom_score_adj
        // hits 0 (attach handshake done -> foreground), never on a fixed delay.
        // The timeout only catches background launches that never reach
        // foreground. Polling runs only while a pid is pending, so idle cost
        // is zero.
        const POLL_MS: u64 = 5;
        const TIMEOUT_MS: u64 = 300;
        let (kill_tx, kill_rx) = std::sync::mpsc::channel::<(u32, u32)>();
        let killer = std::thread::spawn(move || {
            // Pending (pid, uid, queued_at). Polled round-robin so a slow
            // background launch never delays a foreground one.
            let mut pending: Vec<(u32, u32, std::time::Instant)> = Vec::new();
            loop {
                // One bounded receive, then drain anything already queued.
                match kill_rx.recv_timeout(std::time::Duration::from_millis(POLL_MS)) {
                    Ok((pid, uid)) => {
                        pending.push((pid, uid, std::time::Instant::now()));
                        while let Ok((pid, uid)) = kill_rx.try_recv() {
                            pending.push((pid, uid, std::time::Instant::now()));
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        // Gate thread dropped the sender: finish pending kills
                        // so shutdown never leaves a blocked app running.
                        for (pid, uid, _) in pending.drain(..) {
                            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                            if let Ok(mut c) = counters.lock() {
                                *c.entry(uid).or_insert(0) += 1;
                            }
                        }
                        break;
                    }
                }
                let mut i = 0;
                while i < pending.len() {
                    let (pid, uid, started) = pending[i];
                    match read_oom_score_adj(pid) {
                        Some(0) => {
                            // Foreground and attach-complete: kill now, before
                            // the first frame is drawn.
                            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                            log(&format!("[gate] kill pid={pid} uid={uid} (foreground)"));
                            if let Ok(mut c) = counters.lock() {
                                *c.entry(uid).or_insert(0) += 1;
                            }
                            pending.swap_remove(i);
                        }
                        None => {
                            // Already exited before we could kill it.
                            pending.swap_remove(i);
                        }
                        Some(_) if started.elapsed()
                            >= std::time::Duration::from_millis(TIMEOUT_MS) =>
                        {
                            // Background launch: never became foreground, kill it.
                            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                            log(&format!("[gate] kill pid={pid} uid={uid} (timeout)"));
                            if let Ok(mut c) = counters.lock() {
                                *c.entry(uid).or_insert(0) += 1;
                            }
                            pending.swap_remove(i);
                        }
                        Some(_) => {
                            i += 1;
                        }
                    }
                }
            }
        });

        let handle = std::thread::spawn(move || {
            // One spawn may emit several events while dying; kill and count once.
            let mut recent: StdHashMap<u32, std::time::Instant> = StdHashMap::new();
            let mut pfds = [
                libc::pollfd { fd: ring_fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: read_fd, events: libc::POLLIN, revents: 0 },
            ];
            loop {
                let r = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
                if r <= 0 {
                    continue; // EINTR or error, retry
                }
                if (pfds[1].revents & libc::POLLIN) != 0 {
                    break; // wake pipe: shutdown
                }
                if (pfds[0].revents & libc::POLLIN) != 0 {
                    // Drain immediately and queue each pid; the killer waits
                    // for the oom_score_adj==0 trigger, so the drain itself
                    // never sleeps and the ring buffer is never blocked.
                    while let Some(item) = events.next() {
                        if item.len() < 8 {
                            continue;
                        }
                        let pid = u32::from_ne_bytes(item[0..4].try_into().unwrap());
                        let uid = u32::from_ne_bytes(item[4..8].try_into().unwrap());
                        if let Some(t) = recent.get(&pid) {
                            if t.elapsed().as_secs() < 5 {
                                continue;
                            }
                        }
                        log(&format!("[gate] blocked spawn pid={pid} uid={uid}"));
                        kill_tx.send((pid, uid)).ok();
                        recent.insert(pid, std::time::Instant::now());
                        if recent.len() > 64 {
                            recent.retain(|_, t| t.elapsed().as_secs() < 10);
                        }
                    }
                }
            }
            // Drop the sender so the killer observes the disconnect, then join it.
            drop(kill_tx);
            let _ = killer.join();
            unsafe { libc::close(read_fd) };
        });

        Ok(Self {
            _bpf: bpf,
            blocked,
            wake_fd: write_fd,
            handle: Some(handle),
        })
    }

    pub fn set_blocked(&mut self, uid: u32, blocked: bool) -> anyhow::Result<()> {
        if blocked {
            self.blocked.insert(uid, 1, 0)?;
        } else {
            self.blocked.remove(&uid)?;
        }
        Ok(())
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        // Wake the stats thread so it exits, then join.
        let one = [1u8; 1];
        unsafe { libc::write(self.wake_fd, one.as_ptr() as *const _, 1) };
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        unsafe { libc::close(self.wake_fd) };
    }
}

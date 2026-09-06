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

/// Open a pidfd for a pid, or None when the process already exited (or pidfd
/// is unavailable). The fd pins the exact process so it can be signalled
/// safely even after the pid number is recycled. pidfd needs Linux 5.3+,
/// always present on the 5.10/6.1 GKI kernels this module targets. libc for
/// musl does not export pidfd_open, so go through the raw syscall.
fn pidfd_open(pid: u32) -> Option<i32> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as usize, 0usize) };
    if fd >= 0 { Some(fd as i32) } else { None }
}

/// Send SIGKILL through a pidfd, then close it. Targets the exact process the
/// fd refers to; a recycled pid number cannot redirect this.
fn pidfd_kill(pidfd: i32) {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd as usize,
            libc::SIGKILL as usize,
            0usize, // siginfo_t* NULL
            0usize, // flags
        );
        libc::close(pidfd);
    }
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
        //
        // Every pending pid is pinned with a pidfd: SIGKILL is sent through
        // pidfd_send_signal, so a recycled pid number can never redirect the
        // kill onto an innocent process. poll(pidfd) detects the original
        // process exiting, which also stops us from reading a recycled pid's
        // oom_score_adj.
        const POLL_MS: u64 = 5;
        const TIMEOUT_MS: u64 = 300;
        let (kill_tx, kill_rx) = std::sync::mpsc::channel::<(u32, u32)>();
        let killer = std::thread::spawn(move || {
            // Pending (pidfd, pid, uid, queued_at). Polled round-robin so a
            // slow background launch never delays a foreground one.
            let mut pending: Vec<(i32, u32, u32, std::time::Instant)> = Vec::new();
            loop {
                // Receive: block when idle (zero wakeups while nothing is
                // pending), bounded poll while a kill is being waited on.
                let recv_result = if pending.is_empty() {
                    kill_rx.recv().map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected)
                } else {
                    kill_rx.recv_timeout(std::time::Duration::from_millis(POLL_MS))
                };
                match recv_result {
                    Ok((pid, uid)) => {
                        if let Some(pidfd) = pidfd_open(pid) {
                            pending.push((pidfd, pid, uid, std::time::Instant::now()));
                        }
                        while let Ok((pid, uid)) = kill_rx.try_recv() {
                            if let Some(pidfd) = pidfd_open(pid) {
                                pending.push((pidfd, pid, uid, std::time::Instant::now()));
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        // Sender dropped. Finish any pending kills right away
                        // (shutdown must not leave a blocked app running), then
                        // exit.
                        for (pidfd, _, uid, _) in pending.drain(..) {
                            pidfd_kill(pidfd);
                            if let Ok(mut c) = counters.lock() {
                                *c.entry(uid).or_insert(0) += 1;
                            }
                        }
                        break;
                    }
                }
                let mut i = 0;
                while i < pending.len() {
                    let (pidfd, pid, uid, started) = pending[i];
                    // The pidfd becomes readable when the original process
                    // exits: drop it (never kill a recycled pid).
                    let mut pfd = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
                    let pr = unsafe { libc::poll(&mut pfd, 1, 0) };
                    if pr > 0 && (pfd.revents & libc::POLLIN) != 0 {
                        unsafe { libc::close(pidfd) };
                        pending.swap_remove(i);
                        continue;
                    }
                    match read_oom_score_adj(pid) {
                        Some(0) => {
                            // Foreground and attach-complete: kill now, before
                            // the first frame is drawn.
                            pidfd_kill(pidfd);
                            log(&format!("[gate] kill pid={pid} uid={uid} (foreground)"));
                            if let Ok(mut c) = counters.lock() {
                                *c.entry(uid).or_insert(0) += 1;
                            }
                            pending.swap_remove(i);
                        }
                        None => {
                            // Already exited before we could kill it.
                            unsafe { libc::close(pidfd) };
                            pending.swap_remove(i);
                        }
                        Some(_) if started.elapsed()
                            >= std::time::Duration::from_millis(TIMEOUT_MS) =>
                        {
                            // Background launch: never became foreground, kill it.
                            pidfd_kill(pidfd);
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

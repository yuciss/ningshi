// Gate: deterministic detect-then-kill.
// - kprobe on binder_transaction entry: current uid is blocked AND target
//   handle != 0 (the first handle != 0 transaction of a new process is
//   attachApplication) -> mark the tgid pending.
// - kretprobe on binder_transaction exit: marked -> push ringbuf event.
// - A gate thread drains the ring buffer and queues each kill to a single
//   killer thread. Every kill gets its own ~10ms deadline so system_server can
//   finish the attach reply before the death notification (no black screen),
//   without ever blocking the drain.

use std::collections::HashMap as StdHashMap;
use std::convert::TryInto;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use aya::maps::{HashMap, MapData, RingBuf};
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Ebpf, EbpfLoader};

use crate::config::log;

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

        // Single killer thread: kill jobs are queued and executed one at a time,
        // each with its own deadline. The drain loop never sleeps, so the ring
        // buffer is never blocked; SIGKILL is fast enough that one worker keeps
        // up with any burst.
        const KILL_DELAY_MS: u64 = 10;
        let (kill_tx, kill_rx) = std::sync::mpsc::channel::<(std::time::Instant, u32, u32)>();
        let killer = std::thread::spawn(move || {
            // Sleep until the deadline (system_server has time to finish the
            // attach), then kill from userspace: no black screen. Exits once
            // the gate thread drops the sender on shutdown.
            while let Ok((deadline, pid, uid)) = kill_rx.recv() {
                let now = std::time::Instant::now();
                if deadline > now {
                    std::thread::sleep(deadline.duration_since(now));
                }
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                if let Ok(mut c) = counters.lock() {
                    *c.entry(uid).or_insert(0) += 1;
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
                    // Drain immediately and queue each kill with its own ~10ms
                    // deadline: system_server gets the attach reply in, and the
                    // drain is never blocked by a sleep.
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
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_millis(KILL_DELAY_MS);
                        kill_tx.send((deadline, pid, uid)).ok();
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

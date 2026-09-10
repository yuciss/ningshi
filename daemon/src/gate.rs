// Gate: deterministic detect-then-kill.
//
// Two kernel anchors, either of which is enough to catch a blocked app before
// its code runs (see bpf/gate.bpf.c):
//   * kprobe/kretprobe on binder_transaction (first non-zero-handle transaction
//     of a new process = attachApplication);
//   * kretprobe on __arm64_sys_setresuid (a process just swapped to a blocked
//     uid, which zygote's child does before any app code runs).
// The module keeps working when only one of them can be attached, and reports
// which ones are live through `status.gate` instead of failing silently.
//
// Events are drained and each pid is queued to a single killer thread, which
// waits for the pid's oom_score_adj to become 0 (attach handshake done -> the
// process is foreground) and only then sends SIGKILL from userspace: no black
// screen, no fixed delay. A 300ms timeout catches background launches that
// never reach foreground. Every kill goes through a pidfd and re-checks the
// block list first.

use std::collections::HashMap as StdHashMap;
use std::convert::TryInto;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aya::maps::{HashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Ebpf, EbpfLoader};

use crate::config::log;
use crate::proc;

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

/// Which anchors are attached plus the counters the BPF program keeps. Reported
/// as `status.gate`: a degrading gate must never be invisible.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct GateHealth {
    pub binder_entry: bool,
    pub binder_exit: bool,
    pub uid_switch: bool,
    /// blocked transactions marked at entry
    pub marks: u64,
    /// events emitted by the binder anchor
    pub events: u64,
    /// ring buffer full: binder events lost
    pub ringbuf_full: u64,
    /// events emitted by the uid-switch anchor
    pub uid_switch_events: u64,
    /// ring buffer full: uid-switch events lost
    pub uid_switch_ringbuf_full: u64,
    /// target handle could not be read
    pub probe_read_failures: u64,
    /// queued kills dropped because the uid was no longer blocked
    pub kill_skipped: u64,
}

pub struct Gate {
    /// Holds the BPF object so kprobe links stay attached while the daemon lives.
    _bpf: Ebpf,
    /// Block map: uid -> 1. The engine adds/removes uids through it.
    pub blocked: HashMap<MapData, u32, u8>,
    /// Per-CPU counters kept by the BPF programs.
    stats: PerCpuArray<MapData, u64>,
    /// Mirror of the block map for the killer thread: a pid queued by the gate
    /// must still be blocked when the kill is actually sent (a stale mark can
    /// otherwise redirect a kill onto a recycled pid).
    blocked_set: Arc<Mutex<StdHashMap<u32, u8>>>,
    /// Attach state + counter for kills refused by the userspace re-check.
    attached: GateHealth,
    kill_skipped: Arc<AtomicU64>,
    /// Write end of the wake pipe: writing a byte unblocks the stats thread.
    wake_fd: RawFd,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// Load and attach one program, tolerating a kernel that does not know the
/// symbol: the caller decides whether enough anchors are left.
fn attach_probe(bpf: &mut Ebpf, program: &str, symbol: &str) -> anyhow::Result<()> {
    let prog: &mut KProbe = bpf
        .program_mut(program)
        .ok_or_else(|| anyhow::anyhow!("BPF program '{program}' not found"))?
        .try_into()?;
    prog.load()?;
    prog.attach(symbol, 0)?;
    Ok(())
}

impl Gate {
    pub fn start(kill_count: Arc<Mutex<StdHashMap<u32, u64>>>) -> anyhow::Result<Self> {
        let mut bpf = EbpfLoader::new().load(include_bytes_aligned!("../bpf/gate.bpf.o"))?;

        let mut attached = GateHealth::default();
        match attach_probe(&mut bpf, "gate_binder_entry", "binder_transaction") {
            Ok(()) => {
                attached.binder_entry = true;
                log("[gate] kprobe attached to binder_transaction (entry)");
            }
            Err(e) => log(&format!("[gate] binder entry anchor unavailable: {e}")),
        }
        match attach_probe(&mut bpf, "gate_binder_exit", "binder_transaction") {
            Ok(()) => {
                attached.binder_exit = true;
                log("[gate] kretprobe attached to binder_transaction (exit)");
            }
            Err(e) => log(&format!("[gate] binder exit anchor unavailable: {e}")),
        }
        match attach_probe(&mut bpf, "gate_uid_switch", "__arm64_sys_setresuid") {
            Ok(()) => {
                attached.uid_switch = true;
                log("[gate] kretprobe attached to __arm64_sys_setresuid");
            }
            Err(e) => log(&format!("[gate] uid-switch anchor unavailable: {e}")),
        }
        if !attached.binder_entry && !attached.uid_switch {
            anyhow::bail!(
                "no usable kernel anchor: neither binder_transaction nor \
                 __arm64_sys_setresuid could be attached"
            );
        }

        let blocked: HashMap<MapData, u32, u8> = bpf
            .take_map("blocked_uids")
            .ok_or_else(|| anyhow::anyhow!("map 'blocked_uids' not found"))?
            .try_into()?;
        let stats: PerCpuArray<MapData, u64> = bpf
            .take_map("stats")
            .ok_or_else(|| anyhow::anyhow!("map 'stats' not found"))?
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
        let blocked_set: Arc<Mutex<StdHashMap<u32, u8>>> =
            Arc::new(Mutex::new(StdHashMap::new()));
        let killer_blocked = Arc::clone(&blocked_set);
        let kill_skipped = Arc::new(AtomicU64::new(0));
        let killer_skipped = Arc::clone(&kill_skipped);

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
                        if let Some(pidfd) = proc::pidfd_open(pid) {
                            pending.push((pidfd, pid, uid, std::time::Instant::now()));
                        }
                        while let Ok((pid, uid)) = kill_rx.try_recv() {
                            if let Some(pidfd) = proc::pidfd_open(pid) {
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
                            proc::pidfd_kill(pidfd);
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
                        proc::close(pidfd);
                        pending.swap_remove(i);
                        continue;
                    }
                    match read_oom_score_adj(pid) {
                        Some(0) => {
                            // Foreground and attach-complete: kill now, before
                            // the first frame is drawn.
                            if kill_if_blocked(
                                &killer_blocked,
                                &killer_skipped,
                                pidfd,
                                pid,
                                uid,
                            ) {
                                log(&format!("[gate] kill pid={pid} uid={uid} (foreground)"));
                                if let Ok(mut c) = counters.lock() {
                                    *c.entry(uid).or_insert(0) += 1;
                                }
                            }
                            pending.swap_remove(i);
                        }
                        None => {
                            // Already exited before we could kill it.
                            proc::close(pidfd);
                            pending.swap_remove(i);
                        }
                        Some(_) if started.elapsed()
                            >= std::time::Duration::from_millis(TIMEOUT_MS) =>
                        {
                            // Background launch: never became foreground, kill it.
                            if kill_if_blocked(
                                &killer_blocked,
                                &killer_skipped,
                                pidfd,
                                pid,
                                uid,
                            ) {
                                log(&format!("[gate] kill pid={pid} uid={uid} (timeout)"));
                                if let Ok(mut c) = counters.lock() {
                                    *c.entry(uid).or_insert(0) += 1;
                                }
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
            proc::close(read_fd);
        });

        Ok(Self {
            _bpf: bpf,
            blocked,
            stats,
            blocked_set,
            attached,
            kill_skipped,
            wake_fd: write_fd,
            handle: Some(handle),
        })
    }

    pub fn set_blocked(&mut self, uid: u32, blocked: bool) -> anyhow::Result<()> {
        if blocked {
            self.blocked.insert(uid, 1, 0)?;
            if let Ok(mut s) = self.blocked_set.lock() {
                s.insert(uid, 1);
            }
        } else {
            self.blocked.remove(&uid)?;
            if let Ok(mut s) = self.blocked_set.lock() {
                s.remove(&uid);
            }
        }
        Ok(())
    }

    /// Attach state plus the kernel counters, for `status.gate`.
    pub fn health(&self) -> GateHealth {
        let mut h = self.attached;
        h.kill_skipped = self.kill_skipped.load(Ordering::Relaxed);
        let read = |idx: u32| -> u64 {
            match self.stats.get(&idx, 0) {
                Ok(values) => values.iter().copied().sum(),
                Err(_) => 0,
            }
        };
        h.marks = read(0);
        h.events = read(1);
        h.ringbuf_full = read(2);
        h.uid_switch_events = read(3);
        h.uid_switch_ringbuf_full = read(4);
        h.probe_read_failures = read(5);
        h
    }
}

/// Kill only if the uid is still on the block list, and always close the pidfd.
/// The gate's kernel-side mark can outlive the rule (the process may be killed
/// by a sweep or a transition before its kretprobe runs), so the userspace side
/// re-checks: a kill must never land on an app the user did not block.
fn kill_if_blocked(
    set: &Arc<Mutex<StdHashMap<u32, u8>>>,
    skipped: &Arc<AtomicU64>,
    pidfd: i32,
    pid: u32,
    uid: u32,
) -> bool {
    if proc::uid_in(set, uid) {
        proc::pidfd_kill(pidfd);
        true
    } else {
        skipped.fetch_add(1, Ordering::Relaxed);
        proc::close(pidfd);
        log(&format!("[gate] skip pid={pid} uid={uid} (no longer blocked)"));
        false
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
        proc::close(self.wake_fd);
    }
}

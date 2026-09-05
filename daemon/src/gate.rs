// Gate: deterministic detect-then-kill, no delay hacks.
// - kprobe on binder_transaction entry: current uid is blocked AND target
//   handle != 0 (the first handle != 0 transaction of a new process is
//   attachApplication) -> mark the tgid pending.
// - kretprobe on binder_transaction exit: marked -> push ringbuf event,
//   background thread sends SIGKILL.
// Attach has completed at that point, so system_server gets the death
// notification instantly: no black screen.

use std::collections::HashMap as StdHashMap;
use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, Ordering};
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
    stop: Arc<AtomicBool>,
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

        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let counters = Arc::clone(&kill_count);
        let handle = std::thread::spawn(move || {
            // One spawn can emit several events while dying; kill and count it once.
            let mut recent: StdHashMap<u32, std::time::Instant> = StdHashMap::new();
            while !stop2.load(Ordering::Relaxed) {
                match events.next() {
                    Some(item) => {
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
                        log(&format!("[gate] block spawn pid={pid} uid={uid}"));
                        // Attach already completed (event fires at the kretprobe),
                        // so killing now lets system_server clean up instantly.
                        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                        if let Ok(mut c) = counters.lock() {
                            *c.entry(uid).or_insert(0) += 1;
                        }
                        recent.insert(pid, std::time::Instant::now());
                        if recent.len() > 64 {
                            recent.retain(|_, t| t.elapsed().as_secs() < 10);
                        }
                    }
                    None => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
        });

        Ok(Self {
            _bpf: bpf,
            blocked,
            stop,
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
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// Cleanup: kill every process of one or more uids.
//
// Two things matter here:
//  * one /proc pass for the whole sweep, not one per blocked uid (the cgroup v2
//    fast path only exists on some kernels, and the fallback used to re-read
//    every process status once per uid);
//  * every signal goes through a pidfd after re-checking the pid's uid, so a
//    recycled pid number can never send SIGKILL to an unrelated process.

use std::collections::{BTreeSet, HashMap};
use std::fs;

use crate::config::{log, CGROUP_ROOT};
use crate::proc;

/// Pids of one uid from the cgroup fast path, when the kernel has that layout.
/// `Some(empty)` means the cgroup exists and the uid has no processes at all,
/// so the /proc fallback is not needed for it.
fn cgroup_pids(uid: u32) -> Option<Vec<i32>> {
    let content = fs::read_to_string(format!("{CGROUP_ROOT}/apps/uid_{uid}/cgroup.procs")).ok()?;
    let pids: Vec<i32> = content
        .split_whitespace()
        .filter_map(|s| s.parse::<i32>().ok())
        .filter(|p| *p > 1)
        .collect();
    Some(pids)
}

/// Kill all processes of the given uids, returns the number of signals sent.
pub fn kill_uids(uids: &BTreeSet<u32>) -> usize {
    if uids.is_empty() {
        return 0;
    }
    // pid -> expected uid, so the final signal can be re-validated.
    let mut targets: HashMap<i32, u32> = HashMap::new();
    let mut missing: BTreeSet<u32> = BTreeSet::new();

    for &uid in uids {
        match cgroup_pids(uid) {
            Some(pids) => {
                if !pids.is_empty() {
                    log(&format!("[clear] cgroup listed {} procs (uid={uid})", pids.len()));
                }
                for pid in pids {
                    targets.insert(pid, uid);
                }
            }
            None => {
                missing.insert(uid);
            }
        }
    }

    // Single pass for every uid the cgroup path did not cover.
    if !missing.is_empty() {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Ok(pid) = name.parse::<i32>() else { continue };
                if pid <= 1 {
                    continue;
                }
                if let Some(uid) = proc::pid_uid(pid) {
                    if missing.contains(&uid) {
                        targets.insert(pid, uid);
                    }
                }
            }
        }
    }

    let mut killed = 0;
    for (pid, uid) in targets {
        if proc::kill_pid_if_uid(pid, uid) {
            killed += 1;
        }
    }
    if killed > 0 {
        log(&format!("[clear] killed {killed} procs ({} uids)", uids.len()));
    }
    killed
}

/// Kill all processes of a single uid (rule transition path).
pub fn kill_uid(uid: u32) -> usize {
    let mut set = BTreeSet::new();
    set.insert(uid);
    kill_uids(&set)
}

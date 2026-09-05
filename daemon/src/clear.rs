// Cleanup: kill all processes of a uid.
// Prefer the cgroup path (fast and accurate), fall back to a /proc scan.

use std::fs;

use crate::config::{log, CGROUP_ROOT};

/// Kill all processes of a uid, returns the number killed.
pub fn kill_uid(uid: u32) -> usize {
    let mut killed = 0;

    // Preferred: standard AOSP cgroup v2 layout is apps/uid_<n>/.
    let procs_path = format!("{CGROUP_ROOT}/apps/uid_{uid}/cgroup.procs");
    if let Ok(content) = fs::read_to_string(&procs_path) {
        let pids: Vec<i32> = content
            .split_whitespace()
            .filter_map(|s| s.parse::<i32>().ok())
            .filter(|p| *p > 1)
            .collect();
        if !pids.is_empty() {
            for pid in &pids {
                unsafe { libc::kill(*pid, libc::SIGKILL) };
            }
            killed += pids.len();
            log(&format!("[clear] cgroup killed {} procs (uid={uid})", pids.len()));
            return killed;
        }
    }

    // Fallback: scan /proc for processes with this real uid.
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Ok(pid) = name.parse::<i32>() else { continue };
            if pid <= 1 {
                continue;
            }
            if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
                if let Some(line) = status.lines().find(|l| l.starts_with("Uid:")) {
                    let real_uid: u32 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    if real_uid == uid {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                        killed += 1;
                    }
                }
            }
        }
    }

    if killed > 0 {
        log(&format!("[clear] /proc killed {killed} procs (uid={uid})"));
    }
    killed
}

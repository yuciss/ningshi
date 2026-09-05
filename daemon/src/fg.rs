// Foreground and screen state detection, kernel level only (no binder).

use std::collections::HashSet;

/// Candidate top-app cpuset files. Android keeps the v1 cpuset at /dev/cpuset;
/// fall back to the cgroup v2 mount and to tasks for other layouts.
const TOP_APP_CANDIDATES: &[&str] = &[
    "/dev/cpuset/top-app/cgroup.procs",
    "/sys/fs/cgroup/cpuset/top-app/cgroup.procs",
    "/dev/cpuset/top-app/tasks",
];

/// Pids currently in the top-app cpuset (empty when unavailable).
pub fn top_app_pids() -> HashSet<i32> {
    for path in TOP_APP_CANDIDATES {
        if let Ok(content) = std::fs::read_to_string(path) {
            let mut set = HashSet::new();
            for tok in content.split_whitespace() {
                if let Ok(pid) = tok.parse::<i32>() {
                    if pid > 1 {
                        set.insert(pid);
                    }
                }
            }
            // An empty file means this layout is unused on this device; keep
            // trying the next candidate instead of silently returning nothing
            // (which would break foreground accounting).
            if !set.is_empty() {
                return set;
            }
        }
    }
    HashSet::new()
}

/// Resolve the real uid of a single pid (None if it exited).
fn pid_uid(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u32>().ok())
}

/// Foreground uids for the given top-app pids, and (when need_live is set)
/// live uids from one full /proc pass. When every duration rule counts
/// "foreground" only, need_live is false and we read just the few top-app
/// pids instead of walking all of /proc every tick.
pub fn uids_snapshot(top_pids: &HashSet<i32>, need_live: bool) -> (HashSet<u32>, HashSet<u32>) {
    let mut live = HashSet::new();
    let mut fg = HashSet::new();

    if !need_live {
        for &pid in top_pids {
            if let Some(uid) = pid_uid(pid) {
                fg.insert(uid);
            }
        }
        return (live, fg);
    }

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return (live, fg);
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(pid) = name.parse::<i32>() else { continue };
        if pid <= 1 {
            continue;
        }
        if let Some(uid) = pid_uid(pid) {
            live.insert(uid);
            if top_pids.contains(&pid) {
                fg.insert(uid);
            }
        }
    }
    (live, fg)
}

/// Whether the physical display is off (locked). Scans DRM connector dpms
/// files; virtual displays always report On and are ignored. Returns false
/// (screen assumed on) when no connector is found, so this can never
/// wrongly block anything.
pub fn screen_off() -> bool {
    let Ok(entries) = std::fs::read_dir("/sys/class/drm") else {
        return false;
    };
    let mut found = false;
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if !name.contains('-') || name.contains("Virtual") {
            continue;
        }
        if let Ok(s) = std::fs::read_to_string(format!("/sys/class/drm/{name}/dpms")) {
            found = true;
            if s.trim() == "On" {
                return false;
            }
        }
    }
    found
}

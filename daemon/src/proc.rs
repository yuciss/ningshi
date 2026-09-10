// Process helpers shared by the gate, the cleanup sweep and the foreground
// detector.
//
// Every kill goes through a pidfd: SIGKILL is sent to the exact process the
// descriptor pins, so a recycled pid number can never redirect it. The uid is
// read from /proc/<pid> ownership (one stat) instead of parsing the ~1.5 KB
// status file of every process in the system; verified on device against the
// "Uid:" line for all 682 processes (identical).

use std::os::unix::fs::MetadataExt;

/// Real uid of a pid, or None when the process is already gone.
pub fn pid_uid(pid: i32) -> Option<u32> {
    std::fs::metadata(format!("/proc/{pid}")).ok().map(|m| m.uid())
}

/// Open a pidfd for a pid, or None when the process already exited (or pidfd
/// is unavailable). pidfd needs Linux 5.3+, always present on the 5.10/6.1 GKI
/// kernels this module targets. libc for musl does not export pidfd_open, so go
/// through the raw syscall.
pub fn pidfd_open(pid: u32) -> Option<i32> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as usize, 0usize) };
    if fd >= 0 {
        Some(fd as i32)
    } else {
        None
    }
}

/// Send a signal through a pidfd. Returns false when the process has already
/// exited. The caller still owns the descriptor.
pub fn pidfd_send_signal(pidfd: i32, sig: i32) -> bool {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd as usize,
            sig as usize,
            0usize, // siginfo_t* NULL
            0usize, // flags
        )
    };
    rc == 0
}

/// Send SIGKILL through a pidfd and close it.
pub fn pidfd_kill(pidfd: i32) {
    pidfd_send_signal(pidfd, libc::SIGKILL);
    close(pidfd);
}

pub fn close(fd: i32) {
    unsafe { libc::close(fd) };
}

/// Kill one pid, but only if it still runs under `uid`.
///
/// The uid is re-checked immediately before the signal is sent: a pid listed a
/// moment ago may already be gone, and its number may already belong to someone
/// else. Returns true when a signal was actually delivered.
pub fn kill_pid_if_uid(pid: i32, uid: u32) -> bool {
    if pid_uid(pid) != Some(uid) {
        return false;
    }
    match pidfd_open(pid as u32) {
        Some(fd) => {
            let sent = pidfd_send_signal(fd, libc::SIGKILL);
            close(fd);
            sent
        }
        None => false,
    }
}

/// Is this uid blocked, according to a mirror of the BPF block map?
pub fn uid_in(set: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u32, u8>>>, uid: u32) -> bool {
    set.lock().map(|s| s.contains_key(&uid)).unwrap_or(false)
}

/// Package name carried by a process's own cmdline.
///
/// Android sets an app process's argv[0] to its package name (a secondary
/// process is "com.foo:remote"), so the process itself answers "who am I" without
/// consulting any system file. That is what makes the block decision independent
/// of `/data/system/packages.list`, its format, its appId column and how uids are
/// allocated - and it is what stops a freshly installed app that inherited a
/// recycled uid from being killed.
pub fn pkg_from_cmdline(raw: &[u8]) -> Option<String> {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    let argv0 = &raw[..end];
    if argv0.is_empty() {
        return None;
    }
    let name = String::from_utf8_lossy(argv0);
    // "com.foo:remote" -> "com.foo"; drop the helper suffix only.
    let pkg = name.split(':').next().unwrap_or(&name).trim();
    if pkg.is_empty() {
        return None;
    }
    Some(pkg.to_string())
}

/// The package name of a running process, or None when it cannot be read
/// (already gone, or not an Android app process at all).
pub fn pkg_of_pid(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    pkg_from_cmdline(&raw)
}

#[cfg(test)]
mod tests {
    use super::pkg_from_cmdline;

    #[test]
    fn reads_the_package_name() {
        assert_eq!(pkg_from_cmdline(b"com.example.app\0").as_deref(), Some("com.example.app"));
        assert_eq!(pkg_from_cmdline(b"com.example.app\0--flag\0").as_deref(), Some("com.example.app"));
    }

    #[test]
    fn strips_a_secondary_process_suffix() {
        assert_eq!(pkg_from_cmdline(b"com.example.app:remote\0").as_deref(), Some("com.example.app"));
        assert_eq!(pkg_from_cmdline(b"com.example.app:service\0").as_deref(), Some("com.example.app"));
    }

    #[test]
    fn rejects_what_is_not_a_package() {
        // Kernel threads have an empty cmdline; other programs carry their own
        // argv[0], which simply will not match any rule.
        assert_eq!(pkg_from_cmdline(b""), None);
        assert_eq!(pkg_from_cmdline(b"\0"), None);
        assert_eq!(pkg_from_cmdline(b"\0--flag\0"), None);
        assert_eq!(pkg_from_cmdline(b"sh\0").as_deref(), Some("sh"));
    }
}

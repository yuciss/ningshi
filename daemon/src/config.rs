// Paths and shared helpers.

use std::os::unix::fs::PermissionsExt;

/// Module directory: scripts, binary, socket and log live here. Its contents
/// are replaced on module update, so user data must NOT live here.
pub const MODULE_DIR: &str = "/data/adb/modules/ningshi";
/// Persistent data directory: survives module updates/reinstalls.
pub const DATA_DIR: &str = "/data/adb/ningshi";
/// cgroup v2 mount point (standard Android path).
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Path inside the module directory.
pub fn module_file(name: &str) -> String {
    format!("{MODULE_DIR}/{name}")
}

/// Path inside the persistent data directory.
pub fn data_file(name: &str) -> String {
    format!("{DATA_DIR}/{name}")
}

/// Create the persistent data directory (idempotent) and keep it root-only.
pub fn ensure_data_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(DATA_DIR)?;
    let _ = std::fs::set_permissions(DATA_DIR, std::fs::Permissions::from_mode(0o700));
    Ok(())
}

pub fn rules_path() -> String {
    data_file("rules.json")
}

/// Last known good rule set: refreshed after every successful parse and used
/// when the live file becomes unreadable, so a corrupt write can never silently
/// disarm the module.
pub fn rules_backup_path() -> String {
    data_file("rules.json.ok")
}

/// Held with flock() by the running daemon. Two instances would attach two sets
/// of probes with two conflicting block maps, so the second one exits.
pub fn lock_path() -> String {
    data_file("daemon.lock")
}

pub fn state_path() -> String {
    data_file("state.json")
}

pub fn socket_path() -> String {
    module_file("ningshi.sock")
}

pub fn log_path() -> String {
    module_file("ningshi.log")
}

/// Clear the log file. service.sh holds it with O_APPEND, so truncate is safe.
pub fn clear_log() -> anyhow::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(log_path())?;
    Ok(())
}

/// Log to stderr; service.sh redirects it to the log file.
pub fn log(msg: &str) {
    eprintln!("{msg}");
}

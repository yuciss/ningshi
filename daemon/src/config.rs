// Paths and shared helpers.

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

/// Create the persistent data directory (idempotent).
pub fn ensure_data_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(DATA_DIR)
}

pub fn rules_path() -> String {
    data_file("rules.json")
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

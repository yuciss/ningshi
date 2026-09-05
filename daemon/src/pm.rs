// Package manager: resolve uids from /data/system/packages.list (multi user).
// Reading the file directly as root avoids pm/binder.

use std::collections::HashMap;

/// Package list file: rewritten on install/uninstall, app uids change or get recycled.
pub const PACKAGES_LIST: &str = "/data/system/packages.list";

/// Build the full "user:pkg" -> uid map.
/// Line format: <pkg> <uid> <dataPath> <seinfo> [gids...]; user = uid / 100000.
pub fn resolve_uids() -> anyhow::Result<HashMap<String, u32>> {
    let content = std::fs::read_to_string(PACKAGES_LIST)?;
    let mut map = HashMap::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let (Some(pkg), Some(uid_str)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(uid) = uid_str.parse::<u32>() else { continue };
        let user = uid / 100000;
        map.insert(format!("{user}:{pkg}"), uid);
    }
    Ok(map)
}

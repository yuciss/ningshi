// Package manager: resolve uids from /data/system/packages.list (multi user).
// Reading the file directly as root avoids pm/binder.
//
// Ownership model (the one KernelSU's App Profile doc describes): an app is
// identified by an appId, and its uid is `userId * 100000 + appId`. The package
// list carries the appId per package, so the map is built for every user that
// exists on the device - which is what makes a rule key like "10:com.foo"
// resolve to the work profile's uid instead of quietly matching nothing.

use std::collections::HashMap;

/// Package list file: rewritten on install/uninstall, app uids change or get recycled.
pub const PACKAGES_LIST: &str = "/data/system/packages.list";

/// One directory per Android user (0, 10, ...).
pub const USERS_DIR: &str = "/data/system/users";

/// The (key, uid) pairs a package gets for one raw column value.
///
/// A value below 100000 is an appId, so it gets one key per existing user.
/// Anything larger already carries its user: should a future Android write full
/// uids into this file, the mapping still resolves instead of matching nothing.
pub fn keys_for(raw: u32, pkg: &str, users: &[u32]) -> Vec<(String, u32)> {
    if raw >= 100_000 {
        let user = raw / 100_000;
        return vec![(format!("{user}:{pkg}"), raw)];
    }
    users
        .iter()
        .map(|&user| (format!("{user}:{pkg}"), user * 100_000 + raw))
        .collect()
}

/// Android users that exist on this device; user 0 is always included.
pub fn users() -> Vec<u32> {
    let mut users = vec![0u32];
    if let Ok(entries) = std::fs::read_dir(USERS_DIR) {
        for entry in entries.flatten() {
            if let Ok(user) = entry.file_name().to_string_lossy().parse::<u32>() {
                if !users.contains(&user) {
                    users.push(user);
                }
            }
        }
    }
    users.sort_unstable();
    users
}

/// Build the full "user:pkg" -> uid map.
/// Line format: <pkg> <appId> <dataPath> <seinfo> [gids...].
pub fn resolve_uids() -> anyhow::Result<HashMap<String, u32>> {
    let content = std::fs::read_to_string(PACKAGES_LIST)?;
    let users = users();
    let mut map = HashMap::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let (Some(pkg), Some(raw)) = (parts.next(), parts.next()) else { continue };
        let Ok(raw) = raw.parse::<u32>() else { continue };
        for (key, uid) in keys_for(raw, pkg, &users) {
            map.insert(key, uid);
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::keys_for;

    #[test]
    fn main_user_uid_is_the_app_id() {
        assert_eq!(keys_for(10235, "com.foo", &[0]), vec![("0:com.foo".to_string(), 10235)]);
    }

    #[test]
    fn every_user_gets_its_own_uid() {
        let keys = keys_for(10235, "com.foo", &[0, 10]);
        assert_eq!(keys[0], ("0:com.foo".to_string(), 10235));
        assert_eq!(keys[1], ("10:com.foo".to_string(), 1010235));
    }

    #[test]
    fn a_full_uid_column_still_resolves() {
        // Defensive: if the file ever carries a full uid, take the user from it
        // instead of producing "0:..." entries that match no process.
        let keys = keys_for(1010235, "com.foo", &[0, 10]);
        assert_eq!(keys, vec![("10:com.foo".to_string(), 1010235)]);
    }
}

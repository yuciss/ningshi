// Rule engine: evaluates rules, updates the block map, triggers cleanup and notifications.
// Priority: extension > always_on > lock_block (screen off) > cooldown > duration over > time windows.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use chrono::{NaiveDate, Timelike};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::clear;
use crate::config::{log, rules_path, state_path};
use crate::fg;
use crate::gate::Gate;
use crate::pm;
use crate::rules::{DurationRule, GroupRule, RuleSet, Rules, TimeWindow};

const MAX_TICK_SECS: u64 = 60;
const STATE_SAVE_SECS: u64 = 60;
const SWEEP_SECS: u64 = 60;

/// Runtime state persisted across daemon restarts so that a reboot does not
/// defeat daily limits. Active extensions are intentionally NOT saved:
/// restarting the module revokes them (by design).
#[derive(Debug, Default, Serialize, Deserialize)]
struct StateFile {
    day: String,
    usage_seconds: HashMap<u32, u64>,
    usage_fg: HashMap<u32, u64>,
    cooldown_until: HashMap<u32, u64>,
    group_cooldown_until: HashMap<String, u64>,
    ext_granted_today: HashMap<u32, u32>,
    group_ext_granted_today: HashMap<String, u32>,
    kill_count: HashMap<u32, u64>,
}

/// Packages (uid >= 10000) that must never be blocked: killing them would
/// freeze the system. uid < 10000 is already rejected separately.
const PROTECTED_PACKAGES: &[&str] = &["me.weishu.kernelsu", "com.android.systemui"];

/// "user:pkg" -> pkg part, used by is_protected_key.
fn is_protected_key(key: &str) -> bool {
    let pkg = key.split_once(':').map(|(_, p)| p).unwrap_or(key);
    PROTECTED_PACKAGES.contains(&pkg)
}

pub struct Engine {
    gate: Gate,
    rules: Rules,
    /// "user:pkg" -> uid
    uid_of: HashMap<String, u32>,
    /// currently blocked uids
    blocked: BTreeSet<u32>,
    /// rules.json mtime, detects rule changes
    last_mtime: Option<SystemTime>,
    /// packages.list mtime, detects install/uninstall (uid change/recycle)
    last_pkg_mtime: Option<SystemTime>,
    /// uid -> extension deadline (epoch seconds), reset daily
    extension_until: HashMap<u32, u64>,
    /// group id -> shared-pool extension deadline (epoch seconds), reset daily
    group_extension_until: HashMap<String, u64>,
    /// uid -> extension minutes granted today (daily cap 120)
    ext_granted_today: HashMap<u32, u32>,
    /// group id -> extension minutes granted today (shared pool)
    group_ext_granted_today: HashMap<String, u32>,
    /// uid -> cooldown deadline (epoch seconds), duration rules with a cooldown
    cooldown_until: HashMap<u32, u64>,
    /// group id -> cooldown deadline (shared pool)
    group_cooldown_until: HashMap<String, u64>,
    /// uid -> usage in seconds, any scope (running at all)
    usage_seconds: HashMap<u32, u64>,
    /// uid -> foreground usage in seconds (cpuset top-app)
    usage_fg: HashMap<u32, u64>,
    /// per-uid block counts today (gate kills and transition kills)
    kill_count: Arc<Mutex<HashMap<u32, u64>>>,
    /// last tick epoch seconds
    last_tick: Option<u64>,
    /// last tick date, detects day rollover
    last_day: Option<NaiveDate>,
    /// configured timezone offset east in seconds (None = device local time)
    tz_secs: Option<i32>,
    /// last state save epoch seconds
    last_save: u64,
    /// last blocked-uid sweep epoch seconds
    last_sweep: u64,
    /// cached device-local offset for tz "auto" (seconds east)
    auto_offset: AtomicI32,
    /// epoch when auto_offset was last refreshed
    auto_offset_at: AtomicU64,
}

impl Engine {
    pub fn new(
        gate: Gate,
        rules: Rules,
        kill_count: Arc<Mutex<HashMap<u32, u64>>>,
    ) -> anyhow::Result<Self> {
        let mut eng = Self {
            gate,
            rules,
            uid_of: HashMap::new(),
            blocked: BTreeSet::new(),
            last_mtime: None,
            last_pkg_mtime: None,
            extension_until: HashMap::new(),
            group_extension_until: HashMap::new(),
            ext_granted_today: HashMap::new(),
            group_ext_granted_today: HashMap::new(),
            cooldown_until: HashMap::new(),
            group_cooldown_until: HashMap::new(),
            usage_seconds: HashMap::new(),
            usage_fg: HashMap::new(),
            kill_count,
            last_tick: None,
            last_day: None,
            tz_secs: None,
            last_save: 0,
            last_sweep: 0,
            auto_offset: AtomicI32::new(0),
            auto_offset_at: AtomicU64::new(0),
        };
        eng.reload()?;
        eng.load_state();
        Ok(eng)
    }

    /// Restore today's usage/cooldown/budget state (survives daemon restarts).
    fn load_state(&mut self) {
        let path = state_path();
        let Ok(data) = std::fs::read_to_string(&path) else {
            return;
        };
        let Ok(st) = serde_json::from_str::<StateFile>(&data) else {
            return;
        };
        let today = self.now_parts().2;
        if st.day != today.format("%Y-%m-%d").to_string() {
            return;
        }
        // Restored state belongs to today: keep the first tick's daily reset
        // from immediately wiping it (last_day starts as None).
        self.last_day = Some(today);
        self.usage_seconds = st.usage_seconds;
        self.usage_fg = st.usage_fg;
        self.cooldown_until = st.cooldown_until;
        self.group_cooldown_until = st.group_cooldown_until;
        self.ext_granted_today = st.ext_granted_today;
        self.group_ext_granted_today = st.group_ext_granted_today;
        if let Ok(mut c) = self.kill_count.lock() {
            *c = st.kill_count;
        }
        log("[engine] state restored");
    }

    /// Persist runtime state (every minute). Active extensions are not saved.
    fn save_state(&mut self) {
        let (now_epoch, _, date) = self.now_parts();
        let st = StateFile {
            day: date.format("%Y-%m-%d").to_string(),
            usage_seconds: self.usage_seconds.clone(),
            usage_fg: self.usage_fg.clone(),
            cooldown_until: self.cooldown_until.clone(),
            group_cooldown_until: self.group_cooldown_until.clone(),
            ext_granted_today: self.ext_granted_today.clone(),
            group_ext_granted_today: self.group_ext_granted_today.clone(),
            kill_count: self.kill_count.lock().map(|c| c.clone()).unwrap_or_default(),
        };
        if let Ok(json) = serde_json::to_string(&st) {
            let path = state_path();
            // Atomic replace: write a temp file then rename, so a crash
            // mid-write cannot leave a truncated state.json.
            let tmp = format!("{path}.tmp");
            if std::fs::write(&tmp, json).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
                let _ = std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
            }
        }
        self.last_save = now_epoch;
    }

    /// Force reload rules.json and rebuild the uid map.
    pub fn reload(&mut self) -> anyhow::Result<()> {
        // Snapshot old shared_pool flags to detect timing-mode toggles.
        let old_shared: HashMap<String, bool> = self
            .rules
            .groups
            .iter()
            .map(|(gid, g)| (gid.clone(), g.shared_pool))
            .collect();
        if let Ok(rules) = Rules::load(std::path::Path::new(&rules_path())) {
            self.rules = rules;
        }
        self.tz_secs = parse_tz(&self.rules.settings.timezone);
        self.uid_of = pm::resolve_uids()?;
        if let Ok(meta) = std::fs::metadata(rules_path()) {
            if let Ok(mtime) = meta.modified() {
                self.last_mtime = Some(mtime);
            }
        }
        // Toggling shared_pool changes how usage/cooldown are aggregated.
        // Clear any cooldown started under the old mode so it cannot linger
        // and wrongly block/unblock members. Per-uid usage is kept either way.
        for (gid, old) in old_shared {
            let new = self.rules.groups.get(&gid).map(|g| g.shared_pool).unwrap_or(old);
            if new != old {
                self.group_cooldown_until.remove(&gid);
                if let Some(g) = self.rules.groups.get(&gid) {
                    for m in &g.members {
                        if let Some(&uid) = self.uid_of.get(m) {
                            self.cooldown_until.remove(&uid);
                        }
                    }
                }
                log(&format!("[engine] shared_pool toggled for {gid}, cooldown reset"));
            }
        }
        log("[engine] rules reloaded");
        Ok(())
    }

    /// Periodic work: detect rule/package changes, accumulate usage, re-evaluate.
    pub fn tick(&mut self) -> anyhow::Result<()> {
        self.reload_if_changed()?;
        self.sync_packages()?;

        let (now_epoch, now_min, today) = self.now_parts();

        // Daily reset in the configured timezone.
        if self.last_day != Some(today) {
            self.last_day = Some(today);
            self.usage_seconds.clear();
            self.usage_fg.clear();
            self.extension_until.clear();
            self.group_extension_until.clear();
            self.ext_granted_today.clear();
            self.group_ext_granted_today.clear();
            self.cooldown_until.clear();
            self.group_cooldown_until.clear();
            if let Ok(mut c) = self.kill_count.lock() {
                c.clear();
            }
            log("[engine] new day: usage and extensions reset");
        }

        // Accumulate usage by real elapsed time.
        let elapsed = self
            .last_tick
            .map_or(0, |t| now_epoch.saturating_sub(t))
            .min(MAX_TICK_SECS);
        self.last_tick = Some(now_epoch);
        // Usage accounting is only needed while some duration rule exists;
        // skip the whole /proc scan otherwise (idle overhead).
        let need_usage = self
            .rules
            .apps
            .values()
            .any(|a| a.enabled && a.rules.duration.limit_minutes > 0)
            || self
                .rules
                .groups
                .values()
                .any(|g| g.enabled && g.rules.duration.limit_minutes > 0);
        if elapsed > 0 && need_usage {
            let top_pids = fg::top_app_pids();
            // The full live-uid /proc scan is only needed when some rule
            // counts "any" or "background"; foreground-only rules cost just
            // a few pid reads per tick.
            let need_live = self
                .rules
                .apps
                .values()
                .any(|a| a.enabled && a.rules.duration.limit_minutes > 0 && a.rules.duration.scope != "foreground")
                || self
                    .rules
                    .groups
                    .values()
                    .any(|g| g.enabled && g.rules.duration.limit_minutes > 0 && g.rules.duration.scope != "foreground");
            let (live, fg_uids) = fg::uids_snapshot(&top_pids, need_live);
            // Dedup: several packages may share one uid (sharedUserId).
            let uids: BTreeSet<u32> = self.uid_of.values().copied().collect();
            for &uid in &uids {
                if live.contains(&uid) {
                    *self.usage_seconds.entry(uid).or_insert(0) += elapsed;
                }
                if fg_uids.contains(&uid) {
                    *self.usage_fg.entry(uid).or_insert(0) += elapsed;
                }
            }
        }

        // Cooldown maintenance for duration rules that have a cooldown period.
        let mut cooldown_jobs: Vec<(u32, DurationRule)> = Vec::new();
        let mut group_jobs: Vec<(String, GroupRule)> = Vec::new();
        for (key, app) in &self.rules.apps {
            let Some(&uid) = self.uid_of.get(key) else { continue };
            if app.enabled
                && app.rules.duration.limit_minutes > 0
                && app.rules.duration.freeze_minutes > 0
            {
                cooldown_jobs.push((uid, app.rules.duration.clone()));
            }
        }
        for (gid, g) in &self.rules.groups {
            if !g.enabled
                || g.rules.duration.limit_minutes == 0
                || g.rules.duration.freeze_minutes == 0
            {
                continue;
            }
            if g.shared_pool {
                group_jobs.push((gid.clone(), g.clone()));
            } else {
                for member in &g.members {
                    let Some(&uid) = self.uid_of.get(member) else { continue };
                    cooldown_jobs.push((uid, g.rules.duration.clone()));
                }
            }
        }
        for (uid, d) in cooldown_jobs {
            self.maintain_uid_cooldown(uid, &d, now_epoch);
        }
        for (gid, g) in group_jobs {
            self.maintain_group_cooldown(&gid, &g, now_epoch);
        }

        // Only poll the screen state when some enabled rule uses lock_block.
        let need_screen = self.rules.apps.values().any(|a| a.enabled && a.rules.lock_block)
            || self.rules.groups.values().any(|g| g.enabled && g.rules.lock_block);
        let screen_off = need_screen && fg::screen_off();

        // Compute the wanted state per uid.
        let mut want: HashMap<u32, bool> = HashMap::new();
        for (key, app) in &self.rules.apps {
            let Some(&uid) = self.uid_of.get(key) else { continue };
            if uid < 10000 || is_protected_key(key) {
                continue;
            }
            let ext = self.extension_until.get(&uid).is_some_and(|&t| now_epoch < t);
            let over = self.over_duration(&app.rules.duration, uid, None);
            let cool = self.cooldown_until.get(&uid).is_some_and(|&t| now_epoch < t);
            want.insert(uid, app.enabled && eval(&app.rules, now_min, ext, over, cool, screen_off));
        }
        for (gid, g) in &self.rules.groups {
            for member in &g.members {
                let Some(&uid) = self.uid_of.get(member) else { continue };
                if uid < 10000 || is_protected_key(member) {
                    continue;
                }
                // Extension is always per-group: the +5/+20 button exempts the
                // whole group; shared_pool only affects usage/cooldown pooling.
                let ext = self
                    .group_extension_until
                    .get(gid)
                    .is_some_and(|&t| now_epoch < t);
                let over = self.over_duration(&g.rules.duration, uid, Some(g));
                let cool = if g.shared_pool {
                    self.group_cooldown_until.get(gid).is_some_and(|&t| now_epoch < t)
                } else {
                    self.cooldown_until.get(&uid).is_some_and(|&t| now_epoch < t)
                };
                want.insert(uid, g.enabled && eval(&g.rules, now_min, ext, over, cool, screen_off));
            }
        }

        // Apply transitions: allowed -> blocked triggers cleanup + notification.
        for (&uid, &should_block) in want.iter() {
            let was = self.blocked.contains(&uid);
            if should_block && !was {
                let n = clear::kill_uid(uid);
                log(&format!("[engine] block uid={uid} (clear {n})"));
                if let Ok(mut c) = self.kill_count.lock() {
                    *c.entry(uid).or_insert(0) += 1;
                }
            }
            if should_block != was {
                self.gate.set_blocked(uid, should_block)?;
                if should_block {
                    self.blocked.insert(uid);
                } else {
                    self.blocked.remove(&uid);
                }
            }
        }
        // Uids no longer referenced by any rule: unblock.
        let current: Vec<u32> = self.blocked.iter().copied().collect();
        for uid in current {
            if !want.contains_key(&uid) {
                self.gate.set_blocked(uid, false)?;
                self.blocked.remove(&uid);
                log(&format!("[engine] unblock uid={uid} (rule removed)"));
            }
        }

        // Safety net: periodically sweep blocked uids for any process that
        // slipped past the gate (e.g. one that only did ServiceManager
        // lookups and never attached). Not counted as a user-visible block.
        if now_epoch.saturating_sub(self.last_sweep) >= SWEEP_SECS {
            self.last_sweep = now_epoch;
            for uid in self.blocked.iter().copied() {
                let n = clear::kill_uid(uid);
                if n > 0 {
                    log(&format!("[engine] sweep killed {n} procs uid={uid}"));
                }
            }
        }

        if now_epoch.saturating_sub(self.last_save) >= STATE_SAVE_SECS {
            self.save_state();
        }

        Ok(())
    }

    /// App install/uninstall rewrites packages.list (uid change/recycle).
    /// On change, rebuild the uid map, migrate per-uid state, and let the
    /// next want computation block the new uid / release the old one.
    pub fn sync_packages(&mut self) -> anyhow::Result<()> {
        let Ok(meta) = std::fs::metadata(pm::PACKAGES_LIST) else {
            return Ok(());
        };
        let Ok(mtime) = meta.modified() else {
            return Ok(());
        };
        if self.last_pkg_mtime == Some(mtime) {
            return Ok(());
        }

        let new_uids = pm::resolve_uids()?; // on failure keep old mtime, retry next tick
        self.last_pkg_mtime = Some(mtime);

        for (key, &new_uid) in &new_uids {
            let Some(&old_uid) = self.uid_of.get(key) else { continue };
            if old_uid == new_uid {
                continue;
            }
            for map in [&mut self.usage_seconds, &mut self.usage_fg] {
                if let Some(v) = map.remove(&old_uid) {
                    map.insert(new_uid, v);
                }
            }
            if let Some(v) = self.extension_until.remove(&old_uid) {
                self.extension_until.insert(new_uid, v);
            }
            log(&format!("[engine] uid changed {key}: {old_uid} -> {new_uid}"));
        }
        self.uid_of = new_uids;

        // Drop state of uninstalled apps (their uid may be recycled by another app).
        let live: HashSet<u32> = self.uid_of.values().copied().collect();
        self.usage_seconds.retain(|uid, _| live.contains(uid));
        self.usage_fg.retain(|uid, _| live.contains(uid));
        self.extension_until.retain(|uid, _| live.contains(uid));
        self.ext_granted_today.retain(|uid, _| live.contains(uid));
        self.cooldown_until.retain(|uid, _| live.contains(uid));
        if let Ok(mut c) = self.kill_count.lock() {
            c.retain(|uid, _| live.contains(uid));
        }
        log("[engine] packages.list changed, uid map re-synced");
        Ok(())
    }

    fn reload_if_changed(&mut self) -> anyhow::Result<()> {
        let Ok(meta) = std::fs::metadata(rules_path()) else { return Ok(()) };
        let Ok(mtime) = meta.modified() else { return Ok(()) };
        if self.last_mtime == Some(mtime) {
            return Ok(());
        }
        self.reload()
    }

    fn over_duration(&self, d: &DurationRule, uid: u32, group: Option<&GroupRule>) -> bool {
        if d.limit_minutes == 0 {
            return false;
        }
        let limit = (d.limit_minutes as u64) * 60;
        let secs = match group {
            Some(g) if g.shared_pool => g
                .members
                .iter()
                .filter_map(|m| self.uid_of.get(m))
                .map(|&u| self.scoped_usage(u, &d.scope))
                .sum(),
            _ => self.scoped_usage(uid, &d.scope),
        };
        secs >= limit
    }

    /// Usage under the given counting scope.
    fn scoped_usage(&self, uid: u32, scope: &str) -> u64 {
        let any = self.usage_seconds.get(&uid).copied().unwrap_or(0);
        let fg = self.usage_fg.get(&uid).copied().unwrap_or(0);
        match scope {
            "background" => any.saturating_sub(fg),
            "any" => any,
            _ => fg, // "foreground" default
        }
    }

    /// Per-uid cooldown: start when the period is used up, reset usage when it ends.
    fn maintain_uid_cooldown(&mut self, uid: u32, d: &DurationRule, now: u64) {
        if let Some(until) = self.cooldown_until.get(&uid).copied() {
            if now < until {
                return; // still cooling down
            }
            self.cooldown_until.remove(&uid);
            self.usage_seconds.insert(uid, 0);
            self.usage_fg.insert(uid, 0);
        }
        let used = self.scoped_usage(uid, &d.scope);
        let limit = (d.limit_minutes as u64) * 60;
        if used >= limit {
            self.cooldown_until.insert(uid, now + (d.freeze_minutes as u64) * 60);
            log(&format!("[engine] cooldown start uid={uid}"));
        }
    }

    /// Shared-pool cooldown: same cycle, pooled across all members.
    fn maintain_group_cooldown(&mut self, gid: &str, g: &GroupRule, now: u64) {
        if let Some(until) = self.group_cooldown_until.get(gid).copied() {
            if now < until {
                return;
            }
            self.group_cooldown_until.remove(gid);
            for m in &g.members {
                if let Some(&uid) = self.uid_of.get(m) {
                    self.usage_seconds.insert(uid, 0);
                    self.usage_fg.insert(uid, 0);
                }
            }
        }
        let used: u64 = g
            .members
            .iter()
            .filter_map(|m| self.uid_of.get(m))
            .map(|&u| self.scoped_usage(u, &g.rules.duration.scope))
            .sum();
        let limit = (g.rules.duration.limit_minutes as u64) * 60;
        if used >= limit {
            self.group_cooldown_until
                .insert(gid.to_string(), now + (g.rules.duration.freeze_minutes as u64) * 60);
            log(&format!("[engine] group cooldown start {gid}"));
        }
    }

    /// Current epoch seconds, minute of day and date in the configured timezone.
    /// The daemon is a static musl binary without Android's TZ handling, so
    /// "auto" resolves the device offset via `date +%z` (cached 60s) instead
    /// of chrono::Local, which would silently stay on UTC.
    fn now_parts(&self) -> (u64, u32, NaiveDate) {
        let utc = chrono::Utc::now();
        let epoch = utc.timestamp() as u64;
        let secs = match self.tz_secs {
            Some(s) => s,
            None => self.resolve_auto_offset(epoch),
        };
        let off = chrono::FixedOffset::east_opt(secs)
            .unwrap_or_else(|| chrono::FixedOffset::east_opt(0).unwrap());
        let dt = utc.with_timezone(&off);
        (epoch, dt.hour() * 60 + dt.minute(), dt.date_naive())
    }

    /// Device-local UTC offset in seconds, refreshed at most once per minute.
    fn resolve_auto_offset(&self, now: u64) -> i32 {
        let cached_at = self.auto_offset_at.load(Ordering::Relaxed);
        if cached_at != 0 && now.saturating_sub(cached_at) < 60 {
            return self.auto_offset.load(Ordering::Relaxed);
        }
        let off = match std::process::Command::new("date").arg("+%z").output() {
            Ok(o) => parse_tz_offset(String::from_utf8_lossy(&o.stdout).trim()),
            Err(_) => 0,
        };
        self.auto_offset.store(off, Ordering::Relaxed);
        self.auto_offset_at.store(now, Ordering::Relaxed);
        off
    }

    /// Status snapshot for the WebUI.
    pub fn status(&self) -> serde_json::Value {
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "blocked_uids": self.blocked.iter().copied().collect::<Vec<u32>>(),
            "app_count": self.rules.apps.len(),
            "group_count": self.rules.groups.len(),
            "extensions": self.extension_until.iter()
                .map(|(uid, until)| (uid.to_string(), *until))
                .collect::<HashMap<String, u64>>(),
            "group_extensions": self.group_extension_until.clone(),
            "usage_seconds": self.usage_seconds.iter()
                .map(|(uid, s)| (uid.to_string(), *s))
                .collect::<HashMap<String, u64>>(),
            "usage_fg_seconds": self.usage_fg.iter()
                .map(|(uid, s)| (uid.to_string(), *s))
                .collect::<HashMap<String, u64>>(),
            "kill_counts": self.kill_count.lock()
                .map(|c| c.iter().map(|(uid, n)| (uid.to_string(), *n)).collect::<HashMap<String, u64>>())
                .unwrap_or_default(),
            "screen_off": fg::screen_off(),
        })
    }

    /// Add extension minutes. key = "user:pkg" or a group id.
    /// Runtime state only: lost on module restart, reset daily, capped at 120 min/day.
    /// Returns the minutes actually added.
    pub fn add_extension(&mut self, key: &str, minutes: u32) -> anyhow::Result<u32> {
        let (now_epoch, ..) = self.now_parts();
        if let Some(&uid) = self.uid_of.get(key) {
            let used = self.ext_granted_today.get(&uid).copied().unwrap_or(0);
            if used >= 120 {
                anyhow::bail!("daily extension limit (120 min) reached");
            }
            let add = minutes.min(120 - used);
            self.ext_granted_today.insert(uid, used + add);
            let base = self
                .extension_until
                .get(&uid)
                .copied()
                .unwrap_or(0)
                .max(now_epoch);
            let until = base + (add as u64) * 60;
            self.extension_until.insert(uid, until);
            log(&format!("[engine] extension {key} (uid={uid}) +{add}min"));
            return Ok(add);
        }
        if self.rules.groups.get(key).is_some() {
            let used = self.group_ext_granted_today.get(key).copied().unwrap_or(0);
            if used >= 120 {
                anyhow::bail!("daily extension limit (120 min) reached");
            }
            let add = minutes.min(120 - used);
            self.group_ext_granted_today.insert(key.to_string(), used + add);
            let base = self
                .group_extension_until
                .get(key)
                .copied()
                .unwrap_or(0)
                .max(now_epoch);
            let until = base + (add as u64) * 60;
            self.group_extension_until.insert(key.to_string(), until);
            log(&format!("[engine] extension group {key} +{add}min"));
            return Ok(add);
        }
        anyhow::bail!("unknown app or group key: {key}")
    }

}

// Priority:
// 1. extension active -> allow (temporary exemption, even over always_on)
// 2. always_on -> block
// 3. lock_block and screen off -> block
// 4. cooldown active -> block
// 5. duration exceeded -> block
// 6. time windows: block mode -> block inside; allow mode -> block outside
// otherwise -> allow
fn eval(
    rules: &RuleSet,
    now_min: u32,
    ext_active: bool,
    over_duration: bool,
    cooldown: bool,
    screen_off: bool,
) -> bool {
    if ext_active {
        return false;
    }
    if rules.always_on {
        return true;
    }
    if rules.lock_block && screen_off {
        return true;
    }
    if cooldown {
        return true;
    }
    if over_duration {
        return true;
    }
    let tw = &rules.time_windows;
    if !tw.windows.is_empty() {
        let in_any = tw.windows.iter().any(|w| in_window(w, now_min));
        match tw.mode.as_str() {
            "allow" => {
                if !in_any {
                    return true;
                }
            }
            _ => {
                if in_any {
                    return true;
                }
            }
        }
    }
    false
}

fn in_window(w: &TimeWindow, now_min: u32) -> bool {
    let start = parse_hhmm(&w.start);
    let end = parse_hhmm(&w.end);
    if start == end {
        return false;
    }
    if start < end {
        start <= now_min && now_min < end
    } else {
        // window crosses midnight
        now_min >= start || now_min < end
    }
}

fn parse_hhmm(s: &str) -> u32 {
    let Some((h, m)) = s.split_once(':') else {
        return 0;
    };
    let h: u32 = h.parse().unwrap_or(0);
    let m: u32 = m.parse().unwrap_or(0);
    h * 60 + m
}

/// Parse timezone setting: "auto" or "" = device local, "UTC+N"/"UTC-N" = fixed offset.
fn parse_tz(value: &str) -> Option<i32> {
    let v = value.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("auto") {
        return None;
    }
    let n: i32 = v.strip_prefix("UTC")?.parse().ok()?;
    Some(n * 3600)
}

/// Parse `date +%z` output like "+0800" into seconds east of UTC.
fn parse_tz_offset(s: &str) -> i32 {
    let b = s.trim().as_bytes();
    if b.len() != 5 || (b[0] != b'+' && b[0] != b'-') {
        return 0;
    }
    let hh = (b[1] as i32 - b'0' as i32) * 10 + (b[2] as i32 - b'0' as i32);
    let mm = (b[3] as i32 - b'0' as i32) * 10 + (b[4] as i32 - b'0' as i32);
    let secs = hh * 3600 + mm * 60;
    if b[0] == b'-' {
        -secs
    } else {
        secs
    }
}

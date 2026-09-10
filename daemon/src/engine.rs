// Rule engine: evaluates rules, updates the block map, triggers cleanup and notifications.
// Priority: extension > always_on > lock_block (screen off) > cooldown > duration over > time windows.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use chrono::{Datelike, NaiveDate, Timelike};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::clear;
use crate::config::{log, rules_backup_path, rules_path, state_path};
use crate::fg;
use crate::gate::Gate;
use crate::pm;
use crate::rules::{DurationRule, GroupRule, RuleSet, Rules, TimeWindow, RULES_VERSION_MAX};

const MAX_TICK_SECS: u64 = 60;
const STATE_SAVE_SECS: u64 = 60;
const SWEEP_SECS: u64 = 60;

/// Wake cadences, in seconds. The scheduler in `next_wake_secs` picks the
/// shortest one that keeps the configured features correct.
/// Blocking a launch never depends on these: that happens in the kernel gate.
const ACTIVE_TICK_SECS: u64 = 15;
const SWEEP_TICK_SECS: u64 = SWEEP_SECS;
const IDLE_TICK_SECS: u64 = 300;

/// Where the rule set in memory came from. `Default` means the module is
/// running with no rules at all, which must never be invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RulesSource {
    File,
    Backup,
    Default,
}

impl RulesSource {
    fn as_str(self) -> &'static str {
        match self {
            RulesSource::File => "file",
            RulesSource::Backup => "backup",
            RulesSource::Default => "default",
        }
    }
}

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
/// freeze the system. uid < 10000 is already rejected separately. Settings is
/// on the list because it is the user's way back out of any rule.
const PROTECTED_PACKAGES: &[&str] = &[
    "me.weishu.kernelsu",
    "com.android.systemui",
    "com.android.settings",
];

/// Static list plus the device's own launcher and input method: blocking the
/// IME leaves the user unable to type, blocking the launcher leaves an empty
/// home screen. Both are read once per rules reload (never on the hot path).
fn resolve_protected() -> HashSet<String> {
    let mut set: HashSet<String> = PROTECTED_PACKAGES.iter().map(|s| (*s).to_string()).collect();
    if let Some(line) = cmd_line(
        "/system/bin/settings",
        &["get", "secure", "default_input_method"],
        false,
    ) {
        // "com.android.inputmethod.latin/.LatinIME"
        if let Some((pkg, _)) = line.split_once('/') {
            set.insert(pkg.to_string());
        }
    }
    if let Some(line) = cmd_line(
        "/system/bin/cmd",
        &[
            "package",
            "resolve-activity",
            "--brief",
            // Without an action the resolver answers "No activity found".
            "-a",
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.HOME",
        ],
        true,
    ) {
        if let Some((pkg, _)) = line.split_once('/') {
            set.insert(pkg.to_string());
        }
    }
    set
}

/// Run a helper binary and return one line of its output (first or last).
/// Used only on the slow path; a wedged system_server would block this call,
/// which is acceptable because it happens at startup and on rule changes.
fn cmd_line(program: &str, args: &[&str], last: bool) -> Option<String> {
    let out = std::process::Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = if last {
        text.lines().rev().find(|l| !l.trim().is_empty())
    } else {
        text.lines().find(|l| !l.trim().is_empty())
    }?;
    Some(line.trim().to_string())
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
    /// configured timezone offset east in seconds (None = UTC fallback)
    tz_secs: Option<i32>,
    /// packages that may never be blocked (static list + IME + launcher)
    protected: HashSet<String>,
    /// screen state from the last tick; None until a lock_block rule asks for it
    /// (status must not probe DRM on its own)
    screen_off: Option<bool>,
    /// where the active rule set came from (file / backup / built-in default)
    rules_source: RulesSource,
    /// interval the loop will sleep with next, for `status`
    last_interval: u64,
    /// daemon start (epoch seconds), for `status.uptime`
    started: u64,
    /// last state save epoch seconds
    last_save: u64,
    /// last blocked-uid sweep epoch seconds
    last_sweep: u64,
}

impl Engine {
    pub fn new(gate: Gate, kill_count: Arc<Mutex<HashMap<u32, u64>>>) -> anyhow::Result<Self> {
        let mut eng = Self {
            gate,
            rules: Rules::default(),
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
            protected: HashSet::new(),
            screen_off: None,
            rules_source: RulesSource::Default,
            last_interval: ACTIVE_TICK_SECS,
            started: 0,
            last_save: 0,
            last_sweep: 0,
        };
        eng.started = eng.now_parts().0;
        eng.load_rules();
        eng.load_state();
        Ok(eng)
    }

    /// Pick the rule set: the live file, else the last known good copy, else the
    /// built-in default. A parse failure must never silently disarm the module.
    fn load_rules(&mut self) {
        match Rules::load(std::path::Path::new(&rules_path())) {
            Ok(rules) => {
                self.rules = rules;
                self.rules_source = RulesSource::File;
                self.refresh_backup();
                log("[engine] rules loaded from rules.json");
            }
            Err(e) => {
                log(&format!("[engine] rules.json unusable: {e}"));
                let backup = rules_backup_path();
                match Rules::load(std::path::Path::new(&backup)) {
                    Ok(rules) => {
                        self.rules = rules;
                        self.rules_source = RulesSource::Backup;
                        log("[engine] using the last known good rules (rules.json.ok)");
                    }
                    Err(e2) => {
                        self.rules = Rules::default();
                        self.rules_source = RulesSource::Default;
                        log(&format!("[engine] no usable rules: NOTHING IS BLOCKED ({e2})"));
                    }
                }
            }
        }
    }

    /// Keep a copy of the file that just parsed successfully.
    fn refresh_backup(&self) {
        if let Err(e) = std::fs::copy(rules_path(), rules_backup_path()) {
            log(&format!("[engine] could not refresh rules.json.ok: {e}"));
        }
    }

    /// Validate a candidate rules file and only then make it the live one. The
    /// WebUI writes a temp file and calls this: a bad payload is rejected here
    /// while the running configuration stays untouched.
    pub fn apply_rules_file(&mut self, src: &str) -> anyhow::Result<usize> {
        let data = std::fs::read_to_string(src)
            .map_err(|e| anyhow::anyhow!("cannot read {src}: {e}"))?;
        let mut rules: Rules =
            serde_json::from_str(&data).map_err(|e| anyhow::anyhow!("invalid rules: {e}"))?;
        if rules.version > RULES_VERSION_MAX {
            anyhow::bail!(
                "rules version {} is newer than this module supports ({RULES_VERSION_MAX})",
                rules.version
            );
        }
        rules.sanitize();
        let canonical = serde_json::to_string_pretty(&rules)?;
        let target = rules_path();
        let tmp = format!("{target}.new");
        std::fs::write(&tmp, &canonical)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, &target)?;
        self.reload()?;
        if self.rules_source != RulesSource::File {
            anyhow::bail!("rules were replaced but could not be read back");
        }
        log(&format!(
            "[engine] applied rules from {src} ({} apps, {} groups)",
            self.rules.apps.len(),
            self.rules.groups.len()
        ));
        Ok(self.rules.apps.len())
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
        let (now_epoch, _, date, _) = self.now_parts();
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
            self.rules_source = RulesSource::File;
            self.refresh_backup();
        } else if self.rules_source != RulesSource::File {
            // Already running on a fallback set: pick up a repaired file (or a
            // repaired backup) instead of staying on stale rules.
            self.load_rules();
        }
        self.tz_secs = parse_tz(&self.rules.settings.timezone);
        self.protected = resolve_protected();
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

        let (now_epoch, now_min, today, weekday) = self.now_parts();

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
        // Usage accounting is only needed while some duration rule exists, and
        // only for the uids that actually carry a limit.
        if elapsed > 0 && self.needs_usage() {
            let targets = self.duration_targets();
            let top_pids = fg::top_app_pids();
            // The live-uid pass over /proc is only needed when some rule counts
            // "any" or "background"; foreground-only rules cost just a few stats
            // of the top-app pids.
            let need_live = self.needs_live_scan();
            let (live, fg_uids) = fg::uids_snapshot(&top_pids, need_live, &targets);
            for &uid in &targets {
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
        // The result is cached for `status`, which must stay side-effect free.
        let screen_off = if self.needs_screen() {
            let off = fg::screen_off();
            self.screen_off = Some(off);
            off
        } else {
            false
        };

        // Compute the wanted state per uid, and record which package names are
        // blocked for each uid: the killer confirms a process's identity from its
        // own cmdline before signalling, so a recycled uid cannot hit a new app.
        let mut want: HashMap<u32, bool> = HashMap::new();
        let mut blocked_names: HashMap<u32, Vec<String>> = HashMap::new();
        for (key, app) in &self.rules.apps {
            let Some(&uid) = self.uid_of.get(key) else { continue };
            if uid < 10000 || self.is_protected(key) {
                continue;
            }
            let ext = self.extension_until.get(&uid).is_some_and(|&t| now_epoch < t);
            let over = self.over_duration(&app.rules.duration, uid, None);
            let cool = self.cooldown_until.get(&uid).is_some_and(|&t| now_epoch < t);
            let block =
                app.enabled && eval(&app.rules, now_min, weekday, ext, over, cool, screen_off);
            want.insert(uid, block);
            if block {
                if let Some(pkg) = package_of(key) {
                    blocked_names.entry(uid).or_default().push(pkg);
                }
            }
        }
        for (gid, g) in &self.rules.groups {
            for member in &g.members {
                let Some(&uid) = self.uid_of.get(member) else { continue };
                if uid < 10000 || self.is_protected(member) {
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
                let block =
                    g.enabled && eval(&g.rules, now_min, weekday, ext, over, cool, screen_off);
                want.insert(uid, block);
                if block {
                    if let Some(pkg) = package_of(member) {
                        blocked_names.entry(uid).or_default().push(pkg);
                    }
                }
            }
        }
        for names in blocked_names.values_mut() {
            names.sort();
            names.dedup();
        }
        self.gate.set_block_index(blocked_names);

        // Apply transitions: allowed -> blocked triggers cleanup + notification.
        for (&uid, &should_block) in want.iter() {
            let was = self.blocked.contains(&uid);
            if should_block && !was {
                let n = clear::kill_uid(uid);
                log(&format!("[engine] block uid={uid} (clear {n})"));
                // Count only real interceptions: a transition onto the block
                // list with nothing running is not a kill.
                if n > 0 {
                    if let Ok(mut c) = self.kill_count.lock() {
                        *c.entry(uid).or_insert(0) += 1;
                    }
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

        // Safety net: periodically sweep every blocked uid for processes that
        // slipped past the gate (e.g. a cached process that never made an
        // outgoing binder call). One pass over /proc for all of them.
        if now_epoch.saturating_sub(self.last_sweep) >= SWEEP_SECS {
            self.last_sweep = now_epoch;
            if !self.blocked.is_empty() {
                let n = clear::kill_uids(&self.blocked);
                if n > 0 {
                    log(&format!("[engine] sweep killed {n} procs"));
                }
            }
        }

        if now_epoch.saturating_sub(self.last_save) >= STATE_SAVE_SECS {
            self.save_state();
        }

        // Everything else `status` needs is read on demand: the gate counters
        // come straight from the kernel maps (a cheap read, not a tick), so a
        // diagnostic can never be an interval out of date.
        self.last_interval = self.tick_interval_secs();

        Ok(())
    }

    /// Is any enabled rule limiting usage? (drives the usage accounting pass)
    fn needs_usage(&self) -> bool {
        self.enabled_sets().any(|s| s.duration.limit_minutes > 0)
    }

    /// Does any enabled rule count something other than foreground time?
    fn needs_live_scan(&self) -> bool {
        self.enabled_sets()
            .any(|s| s.duration.limit_minutes > 0 && s.duration.scope != "foreground")
    }

    /// Does any enabled rule care about the physical screen state?
    fn needs_screen(&self) -> bool {
        self.enabled_sets().any(|s| s.lock_block)
    }

    /// Every enabled rule set: app rules and group rules.
    fn enabled_sets(&self) -> impl Iterator<Item = &RuleSet> {
        self.rules
            .apps
            .values()
            .filter(|a| a.enabled)
            .map(|a| &a.rules)
            .chain(self.rules.groups.values().filter(|g| g.enabled).map(|g| &g.rules))
    }

    /// Uids that have a duration limit configured. Only these need to be looked
    /// up in /proc at all.
    fn duration_targets(&self) -> HashSet<u32> {
        let mut out = HashSet::new();
        for (key, app) in &self.rules.apps {
            if app.enabled && app.rules.duration.limit_minutes > 0 {
                if let Some(&uid) = self.uid_of.get(key) {
                    out.insert(uid);
                }
            }
        }
        for g in self.rules.groups.values() {
            if !g.enabled || g.rules.duration.limit_minutes == 0 {
                continue;
            }
            for m in &g.members {
                if let Some(&uid) = self.uid_of.get(m) {
                    out.insert(uid);
                }
            }
        }
        out
    }

    /// How long the main loop may sleep before the next tick is needed.
    ///
    /// Blocking a launched app never depends on this: the gate runs in the
    /// kernel. Userspace ticks exist for bookkeeping (usage accounting), for
    /// the periodic sweep over blocked uids, and to apply time-based
    /// transitions on time.
    pub fn tick_interval_secs(&self) -> u64 {
        let (now_epoch, now_min, _, weekday) = self.now_parts();
        let mut expiries = Vec::with_capacity(
            self.extension_until.len()
                + self.group_extension_until.len()
                + self.cooldown_until.len()
                + self.group_cooldown_until.len(),
        );
        expiries.extend(self.extension_until.values().copied());
        expiries.extend(self.group_extension_until.values().copied());
        expiries.extend(self.cooldown_until.values().copied());
        expiries.extend(self.group_cooldown_until.values().copied());
        next_wake_secs(&WakeInputs {
            rules: &self.rules,
            any_blocked: !self.blocked.is_empty(),
            expiries,
            now_epoch,
            now_min,
            weekday,
            sec_in_min: now_epoch % 60,
        })
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

    /// Current epoch seconds, minute of day, date and ISO weekday (1 = Monday)
    /// in the configured timezone.
    fn now_parts(&self) -> (u64, u32, NaiveDate, u8) {
        let utc = chrono::Utc::now();
        let epoch = utc.timestamp() as u64;
        let secs = self.tz_secs.unwrap_or(0);
        let off = chrono::FixedOffset::east_opt(secs)
            .unwrap_or_else(|| chrono::FixedOffset::east_opt(0).unwrap());
        let dt = utc.with_timezone(&off);
        (
            epoch,
            dt.hour() * 60 + dt.minute(),
            dt.date_naive(),
            dt.weekday().number_from_monday() as u8,
        )
    }

    /// Status snapshot for the WebUI. Reads in-memory state only: a status
    /// query must never tick the engine (that could kill processes as a side
    /// effect of opening the WebUI).
    pub fn status(&self) -> serde_json::Value {
        let mut protected: Vec<&String> = self.protected.iter().collect();
        protected.sort();
        let now = self.now_parts().0;
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "rules_ok": self.rules_source == RulesSource::File,
            "rules_source": self.rules_source.as_str(),
            "interval": self.last_interval,
            "last_tick_age": now.saturating_sub(self.last_tick.unwrap_or(now)),
            "uptime": now.saturating_sub(self.started),
            "gate": self.gate.health(),
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
            "screen_off": self.screen_off,
            "protected": protected,
        })
    }

    /// Add extension minutes. key = "user:pkg" or a group id.
    /// Runtime state only: lost on module restart, reset daily, capped at 120 min/day.
    /// Returns the minutes actually added.
    pub fn add_extension(&mut self, key: &str, minutes: u32) -> anyhow::Result<u32> {
        let (now_epoch, ..) = self.now_parts();
        // An app that lives in a group is governed by the group's extension
        // pool, so a per-uid extension would be stored and then never read.
        // Extending a whole group from an app key would be a much bigger
        // surprise than an error, so refuse and point at the group.
        if !self.rules.apps.contains_key(key) {
            if let Some(gid) = self.group_of_member(key) {
                anyhow::bail!("{key} is managed by group '{gid}'; extend that group instead");
            }
        }
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

    /// The group that owns this "user:pkg" key, if any.
    fn group_of_member(&self, key: &str) -> Option<String> {
        self.rules
            .groups
            .iter()
            .find(|(_, g)| g.members.iter().any(|m| m == key))
            .map(|(gid, _)| gid.clone())
    }

    /// "user:pkg" -> is this package on the never-block list?
    fn is_protected(&self, key: &str) -> bool {
        let pkg = key.split_once(':').map(|(_, p)| p).unwrap_or(key);
        self.protected.contains(pkg)
    }

}

// Priority:
// 1. extension active -> allow (temporary exemption, even over always_on)
// 2. always_on -> block
// 3. lock_block and screen off -> block
// 4. cooldown active -> block
// 5. duration exceeded -> block
// 6. time windows: allow mode (the default) -> block outside; block mode -> block inside
// otherwise -> allow
fn eval(
    rules: &RuleSet,
    now_min: u32,
    weekday: u8,
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
        let in_any = tw.windows.iter().any(|w| in_window(w, now_min, weekday));
        // Only an explicit "block" blocks inside a window; the default and any
        // unknown value mean "only usable inside".
        if tw.mode == "block" {
            if in_any {
                return true;
            }
        } else if !in_any {
            return true;
        }
    }
    false
}

/// Is this window active right now on this weekday?
/// Weekdays are ISO (1 = Monday .. 7 = Sunday); an empty day set = every day.
fn in_window(w: &TimeWindow, now_min: u32, weekday: u8) -> bool {
    let start = parse_hhmm(&w.start);
    let end = parse_hhmm(&w.end);
    if start == end {
        return false;
    }
    if start < end {
        day_allowed(w, weekday) && start <= now_min && now_min < end
    } else if now_min >= start {
        // Crosses midnight, still inside the first part: the window belongs to
        // the day it started on.
        day_allowed(w, weekday)
    } else if now_min < end {
        // Crosses midnight, we are in the tail: it started the day before.
        day_allowed(w, prev_weekday(weekday))
    } else {
        false
    }
}

fn day_allowed(w: &TimeWindow, weekday: u8) -> bool {
    days_allow(&w.days, weekday)
}

fn days_allow(days: &[u8], weekday: u8) -> bool {
    days.is_empty() || days.contains(&weekday)
}

fn prev_weekday(weekday: u8) -> u8 {
    if weekday <= 1 {
        7
    } else {
        weekday - 1
    }
}

/// Everything the wake scheduler needs. Kept as a plain struct so the schedule
/// can be unit tested without a gate, a BPF object or a wall clock.
struct WakeInputs<'a> {
    rules: &'a Rules,
    any_blocked: bool,
    /// expiry deadlines (epoch seconds) of extensions and cooldowns
    expiries: Vec<u64>,
    now_epoch: u64,
    now_min: u32,
    weekday: u8,
    /// seconds already elapsed inside the current minute
    sec_in_min: u64,
}

/// The sleep schedule: the shortest interval that still applies every
/// configured feature on time, and a long idle sleep when nothing is
/// time-dependent. Ticks are bookkeeping only, so a long sleep never weakens
/// blocking (the kernel gate catches launches).
fn next_wake_secs(i: &WakeInputs) -> u64 {
    let mut secs = IDLE_TICK_SECS;

    // Blocked uids need the periodic sweep for anything that slipped past the
    // gate and never made an outgoing binder call.
    if i.any_blocked {
        secs = secs.min(SWEEP_TICK_SECS);
    }

    let app_sets = i.rules.apps.values().filter(|a| a.enabled).map(|a| &a.rules);
    let group_sets = i.rules.groups.values().filter(|g| g.enabled).map(|g| &g.rules);
    let mut edge: Option<u64> = None;
    for set in app_sets.chain(group_sets) {
        // Usage accounting needs a steady cadence while a limit is configured.
        if set.duration.limit_minutes > 0 {
            secs = secs.min(ACTIVE_TICK_SECS);
        }
        // The screen can turn off at any moment while lock_block is on.
        if set.lock_block {
            secs = secs.min(ACTIVE_TICK_SECS);
        }
        // Time windows switch on minute boundaries: wake exactly at the edge.
        for w in &set.time_windows.windows {
            if let Some(s) = window_edge_secs(w, i.now_min, i.weekday, i.sec_in_min) {
                edge = Some(edge.map_or(s, |b: u64| b.min(s)));
            }
        }
    }
    if let Some(s) = edge {
        secs = secs.min(s);
    }

    // Extensions and cooldowns must take effect the moment they expire.
    for &t in &i.expiries {
        if t > i.now_epoch {
            secs = secs.min(t - i.now_epoch);
        }
    }

    // Daily counters reset at local midnight.
    let to_midnight = ((1440 - i.now_min as u64) * 60).saturating_sub(i.sec_in_min);
    secs.min(to_midnight.max(1)).max(1)
}

/// Seconds until this window's answer flips. Walks minute by minute with the
/// same predicate the engine decides with, so the schedule can never disagree
/// with the decision. None for a degenerate window (start == end).
fn window_edge_secs(w: &TimeWindow, now_min: u32, weekday: u8, sec_in_min: u64) -> Option<u64> {
    let start = parse_hhmm(&w.start);
    let end = parse_hhmm(&w.end);
    if start == end {
        return None;
    }
    let inside = in_window(w, now_min, weekday);
    // Any non-degenerate window flips within its own cycle (< 2 days).
    for step in 1..=(2 * 1440u32) {
        let abs = now_min + step;
        let m = abs % 1440;
        let d = ((weekday as u32 - 1 + abs / 1440) % 7) as u8 + 1;
        let now_inside = if start < end {
            days_allow(&w.days, d) && start <= m && m < end
        } else if m >= start {
            days_allow(&w.days, d)
        } else if m < end {
            days_allow(&w.days, prev_weekday(d))
        } else {
            false
        };
        if now_inside != inside {
            return Some(((step as u64) * 60).saturating_sub(sec_in_min).max(1));
        }
    }
    None
}

/// "user:pkg" -> "pkg". This is the identity the killer confirms against the
/// process's own cmdline.
fn package_of(key: &str) -> Option<String> {
    key.split_once(':')
        .map(|(_, pkg)| pkg.to_string())
        .filter(|pkg| !pkg.is_empty())
}

fn parse_hhmm(s: &str) -> u32 {    let Some((h, m)) = s.split_once(':') else {
        return 0;
    };
    let h: u32 = h.parse().unwrap_or(0);
    let m: u32 = m.parse().unwrap_or(0);
    h * 60 + m
}

/// Parse the timezone setting. Only fixed "UTC" / "UTC+N" / "UTC-N" offsets
/// are supported (no device-local "auto", no DST); any other value falls back
/// to UTC. The installer bakes the detected offset in at install time.
fn parse_tz(value: &str) -> Option<i32> {
    let v = value.trim();
    if v == "UTC" {
        return Some(0);
    }
    let n: i32 = v.strip_prefix("UTC")?.parse().ok()?;
    Some(n * 3600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::TimeWindows;

    const MON: u8 = 1;
    const TUE: u8 = 2;

    fn win(start: &str, end: &str, days: &[u8]) -> TimeWindow {
        TimeWindow { start: start.into(), end: end.into(), days: days.to_vec() }
    }

    fn set(mode: &str, windows: Vec<TimeWindow>) -> RuleSet {
        RuleSet {
            always_on: false,
            lock_block: false,
            time_windows: TimeWindows { mode: mode.into(), windows },
            duration: DurationRule::default(),
        }
    }

    fn decide(s: &RuleSet, now_min: u32, weekday: u8) -> bool {
        eval(s, now_min, weekday, false, false, false, false)
    }

    #[test]
    fn plain_window_matches_minutes_and_days() {
        let w = win("09:00", "10:00", &[]);
        assert!(in_window(&w, 9 * 60, MON));
        assert!(in_window(&w, 9 * 60 + 59, MON));
        assert!(!in_window(&w, 10 * 60, MON)); // end is exclusive
        assert!(!in_window(&w, 9 * 60 - 1, MON));

        let weekend = win("09:00", "10:00", &[6, 7]);
        assert!(!in_window(&weekend, 9 * 60, MON));
        assert!(in_window(&weekend, 9 * 60, 7));
    }

    #[test]
    fn cross_midnight_uses_the_starting_day() {
        // Monday 22:00 -> Tuesday 07:00
        let w = win("22:00", "07:00", &[MON]);
        assert!(in_window(&w, 22 * 60, MON));
        assert!(in_window(&w, 23 * 60 + 59, MON));
        assert!(in_window(&w, 0, TUE)); // the tail belongs to Monday's window
        assert!(in_window(&w, 6 * 60 + 59, TUE));
        assert!(!in_window(&w, 7 * 60, TUE));
        assert!(!in_window(&w, 21 * 60, TUE));
        // Monday 00:00 would belong to a Sunday window, which is not selected.
        assert!(!in_window(&w, 0, MON));
    }

    #[test]
    fn multi_day_cross_midnight_window() {
        // Friday + Saturday 23:00-06:00
        let w = win("23:00", "06:00", &[5, 6]);
        assert!(in_window(&w, 2 * 60, 6)); // Sat 02:00, started Friday
        assert!(in_window(&w, 2 * 60, 7)); // Sun 02:00, started Saturday
        assert!(!in_window(&w, 2 * 60, MON)); // Mon 02:00, started Sunday
        assert!(in_window(&w, 23 * 60 + 30, 6)); // Sat 23:30
        assert!(!in_window(&w, 23 * 60 + 30, 7)); // Sun 23:30
    }

    #[test]
    fn allow_mode_blocks_everything_outside_windows() {
        let s = set("allow", vec![win("09:00", "10:00", &[])]);
        assert!(!decide(&s, 9 * 60 + 30, MON)); // inside -> allowed
        assert!(decide(&s, 11 * 60, MON)); // outside -> blocked
        assert!(decide(&s, 0, MON));
    }

    #[test]
    fn block_mode_blocks_inside_windows() {
        let s = set("block", vec![win("09:00", "10:00", &[])]);
        assert!(decide(&s, 9 * 60 + 30, MON));
        assert!(!decide(&s, 11 * 60, MON));
    }

    #[test]
    fn unknown_mode_fails_open() {
        let s = set("", vec![win("09:00", "10:00", &[])]);
        assert!(!decide(&s, 9 * 60 + 30, MON));
        assert!(decide(&s, 11 * 60, MON));
    }

    #[test]
    fn no_windows_never_restrict() {
        let s = set("allow", vec![]);
        assert!(!decide(&s, 0, MON));
        let s = set("block", vec![]);
        assert!(!decide(&s, 0, MON));
    }

    #[test]
    fn window_on_selected_day_only() {
        let s = set("allow", vec![win("09:00", "10:00", &[6, 7])]);
        assert!(!decide(&s, 9 * 60 + 30, 7)); // Sunday inside -> allowed
        assert!(decide(&s, 9 * 60 + 30, MON)); // Monday -> blocked
    }

    #[test]
    fn extension_and_always_on_take_priority() {
        let mut s = set("allow", vec![]);
        s.always_on = true;
        assert!(decide(&s, 0, MON));
        assert!(!eval(&s, 0, MON, true, false, false, false)); // extension wins
        assert!(eval(&set("allow", vec![]), 0, MON, false, true, false, false)); // over duration
        assert!(eval(&set("allow", vec![]), 0, MON, false, false, true, false)); // cooldown
    }

    #[test]
    fn prev_weekday_wraps_around() {
        assert_eq!(prev_weekday(1), 7);
        assert_eq!(prev_weekday(2), 1);
        assert_eq!(prev_weekday(7), 6);
    }

    // ---------- wake scheduler ----------

    const NO_RULES: &str = r#"{"version":1,"apps":{},"groups":{}}"#;

    fn wake_inputs<'a>(
        rules: &'a Rules,
        any_blocked: bool,
        expiries: Vec<u64>,
        now_min: u32,
        sec_in_min: u64,
        weekday: u8,
    ) -> WakeInputs<'a> {
        WakeInputs {
            rules,
            any_blocked,
            expiries,
            now_epoch: 1_000_000,
            now_min,
            weekday,
            sec_in_min,
        }
    }

    fn wake_at(rules_json: &str, any_blocked: bool, expiries: Vec<u64>, now_min: u32, sec_in_min: u64) -> u64 {
        let rules: Rules = serde_json::from_str(rules_json).unwrap();
        next_wake_secs(&wake_inputs(&rules, any_blocked, expiries, now_min, sec_in_min, MON))
    }

    #[test]
    fn idle_sleep_when_nothing_is_configured() {
        // No rules, nothing blocked: nothing can change by itself.
        assert_eq!(wake_at(NO_RULES, false, vec![], 8 * 60, 0), IDLE_TICK_SECS);
    }

    #[test]
    fn blocked_uids_keep_the_sweep_cadence() {
        assert_eq!(wake_at(NO_RULES, true, vec![], 8 * 60, 0), SWEEP_TICK_SECS);
    }

    #[test]
    fn duration_and_lock_block_need_the_active_cadence() {
        let duration = r#"{"version":1,"apps":{"0:com.a":{"enabled":true,
            "duration":{"limit_minutes":30}}},"groups":{}}"#;
        assert_eq!(wake_at(duration, false, vec![], 8 * 60, 0), ACTIVE_TICK_SECS);

        let lock = r#"{"version":1,"apps":{"0:com.a":{"enabled":true,"lock_block":true}},"groups":{}}"#;
        assert_eq!(wake_at(lock, false, vec![], 8 * 60, 0), ACTIVE_TICK_SECS);
    }

    #[test]
    fn disabled_rules_do_not_shorten_the_sleep() {
        let disabled = r#"{"version":1,"apps":{"0:com.a":{"enabled":false,"lock_block":true,
            "duration":{"limit_minutes":30}}},"groups":{}}"#;
        assert_eq!(wake_at(disabled, false, vec![], 8 * 60, 0), IDLE_TICK_SECS);
        // A window list with no entries restricts nothing.
        let empty_windows = r#"{"version":1,"apps":{"0:com.a":{"enabled":true,
            "time_windows":{"mode":"allow","windows":[]}}},"groups":{}}"#;
        assert_eq!(wake_at(empty_windows, false, vec![], 8 * 60, 0), IDLE_TICK_SECS);
    }

    #[test]
    fn window_edge_is_used_as_the_wakeup() {
        // 08:57 now, the window opens at 09:00 -> 180s, shorter than idle.
        let w = r#"{"version":1,"apps":{"0:com.a":{"enabled":true,
            "time_windows":{"mode":"allow","windows":[{"start":"09:00","end":"10:00"}]}}},"groups":{}}"#;
        assert_eq!(wake_at(w, false, vec![], 8 * 60 + 57, 0), 180);
        // 50s into the minute before the edge: wake 10s from now.
        assert_eq!(wake_at(w, false, vec![], 8 * 60 + 59, 50), 10);
        // Inside a window that ends at 06:02: the closing edge is next.
        let closing = r#"{"version":1,"apps":{"0:com.a":{"enabled":true,
            "time_windows":{"mode":"allow","windows":[{"start":"22:00","end":"06:02"}]}}},"groups":{}}"#;
        assert_eq!(wake_at(closing, false, vec![], 6 * 60, 0), 120);
    }

    #[test]
    fn window_edges_respect_weekday_sets() {
        // Monday-only window: opens in 180s on Monday, a week away on Tuesday.
        let rules: Rules = serde_json::from_str(
            r#"{"version":1,"apps":{"0:com.a":{"enabled":true,
            "time_windows":{"mode":"allow","windows":[{"start":"09:00","end":"10:00","days":[1]}]}}},"groups":{}}"#,
        )
        .unwrap();
        let monday = next_wake_secs(&wake_inputs(&rules, false, vec![], 8 * 60 + 57, 0, 1));
        assert_eq!(monday, 180);
        let tuesday = next_wake_secs(&wake_inputs(&rules, false, vec![], 8 * 60 + 57, 0, 2));
        assert_eq!(tuesday, IDLE_TICK_SECS);
    }

    #[test]
    fn expiries_and_midnight_cap_the_sleep() {
        // An extension ending in 45s must be noticed then.
        assert_eq!(wake_at(NO_RULES, false, vec![1_000_045], 8 * 60, 0), 45);
        // Already expired deadlines do not hold the loop back.
        assert_eq!(wake_at(NO_RULES, false, vec![999_000], 8 * 60, 0), IDLE_TICK_SECS);
        // 23:59:30 -> daily counters reset in 30s.
        assert_eq!(wake_at(NO_RULES, false, vec![], 1439, 30), 30);
    }

    #[test]
    fn sleep_is_never_zero() {
        assert!(wake_at(NO_RULES, false, vec![], 0, 0) >= 1);
    }

    #[test]
    fn package_identity_comes_from_the_key() {
        assert_eq!(package_of("0:com.example.app").as_deref(), Some("com.example.app"));
        assert_eq!(package_of("10:com.example.app").as_deref(), Some("com.example.app"));
        assert_eq!(package_of("nodots"), None);
        assert_eq!(package_of("0:"), None);
    }
}

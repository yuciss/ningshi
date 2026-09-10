// serde types for rules.json (contract shared by daemon and WebUI).
//
// App keys and group members use "<user_id>:<package>",
// e.g. "0:com.foo" (main user), "10:com.foo" (work profile).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Highest rules.json schema this build understands. A file that claims a newer
/// version is refused instead of being misread with today's fields.
pub const RULES_VERSION_MAX: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct Rules {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub apps: BTreeMap<String, AppRule>,
    #[serde(default)]
    pub groups: BTreeMap<String, GroupRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Settings {
    /// Fixed UTC offset: "UTC" or "UTC+N"/"UTC-N". No "auto"/DST.
    #[serde(default = "d_timezone")]
    pub timezone: String,
    /// UI language: "zh" or "en".
    #[serde(default = "d_language")]
    pub language: String,
    /// Truncate the log when the module (re)starts.
    #[serde(default)]
    pub clear_log_on_boot: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            timezone: "UTC".into(),
            language: "en".into(),
            clear_log_on_boot: false,
        }
    }
}

fn d_timezone() -> String {
    "UTC".into()
}
fn d_language() -> String {
    "en".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AppRule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(flatten)]
    pub rules: RuleSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GroupRule {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    /// Shared usage/extension pool across members.
    #[serde(default)]
    pub shared_pool: bool,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(flatten)]
    pub rules: RuleSet,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct RuleSet {
    #[serde(default)]
    pub always_on: bool,
    /// Block immediately while the screen is off (locked).
    #[serde(default)]
    pub lock_block: bool,
    #[serde(default)]
    pub time_windows: TimeWindows,
    #[serde(default)]
    pub duration: DurationRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TimeWindows {
    /// "allow" = only usable inside the windows (default); "block" = not allowed inside.
    /// Only the literal "block" selects block mode: anything missing or unknown
    /// stays allow, so the module fails open like every other detection.
    #[serde(default = "d_window_mode")]
    pub mode: String,
    #[serde(default)]
    pub windows: Vec<TimeWindow>,
}

impl Default for TimeWindows {
    fn default() -> Self {
        Self { mode: d_window_mode(), windows: Vec::new() }
    }
}

/// Default is "allow" (only usable inside the windows): a window is something
/// the user grants, so an unset/missing mode must not silently mean "blocked".
fn d_window_mode() -> String {
    "allow".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TimeWindow {
    /// "HH:MM"; end <= start means the window crosses midnight.
    /// Defaulted so one malformed window cannot fail the whole rules.json
    /// parse and drop every rule on daemon restart.
    #[serde(default)]
    pub start: String,
    #[serde(default)]
    pub end: String,
    /// Weekdays this window applies to, ISO numbering: 1 = Monday .. 7 = Sunday.
    /// Empty (the default, and what a hand-written file gets) = every day.
    /// For a window that crosses midnight the set refers to the day the window
    /// *starts* on, so days=[1] + 22:00-07:00 covers Monday 22:00 to Tuesday 07:00.
    #[serde(default)]
    pub days: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct DurationRule {
    #[serde(default)]
    pub limit_minutes: u32,
    /// Cooldown period in minutes (0 = plain daily limit, reset at midnight).
    #[serde(default)]
    pub freeze_minutes: u32,
    /// Counting scope: "foreground" | "background" | "any".
    #[serde(default = "d_scope")]
    pub scope: String,
}

fn d_scope() -> String {
    "foreground".into()
}

impl Rules {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let mut rules: Self = serde_json::from_str(&data)?;
        rules.sanitize();
        Ok(rules)
    }

    /// Drop values that would otherwise be "never matches": an invalid weekday
    /// left in `days` would make an allow-window block the app forever.
    pub fn sanitize(&mut self) {
        let sets = self
            .apps
            .values_mut()
            .map(|a| &mut a.rules)
            .chain(self.groups.values_mut().map(|g| &mut g.rules));
        for set in sets {
            for w in &mut set.time_windows.windows {
                w.days.retain(|d| (1..=7).contains(d));
                w.days.sort_unstable();
                w.days.dedup();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_with(json_windows: &str) -> Rules {
        let text = format!(
            r#"{{"version":1,"apps":{{"0:com.foo":{{"enabled":true,"time_windows":{{"windows":[{json_windows}]}}}}}}}}"#
        );
        let mut r: Rules = serde_json::from_str(&text).unwrap();
        r.sanitize(); // Rules::load does this for real; the tests mirror it
        r
    }

    #[test]
    fn window_mode_defaults_to_allow() {
        let r = rules_with(r#"{"start":"09:00","end":"10:00"}"#);
        assert_eq!(r.apps["0:com.foo"].rules.time_windows.mode, "allow");
        assert_eq!(TimeWindows::default().mode, "allow");
        // No "days" in the file = every day.
        assert!(r.apps["0:com.foo"].rules.time_windows.windows[0].days.is_empty());
    }

    #[test]
    fn days_default_empty_and_sanitized() {
        let r = rules_with(r#"{"start":"09:00","end":"10:00","days":[3,9,0,3,1]}"#);
        let w = &r.apps["0:com.foo"].rules.time_windows.windows[0];
        assert_eq!(w.days, vec![1, 3]);
    }

    #[test]
    fn sanitize_runs_on_load() {
        let dir = std::env::temp_dir().join("ningshi-rules-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.json");
        std::fs::write(
            &path,
            r#"{"apps":{"0:com.foo":{"enabled":true,"time_windows":{"windows":[{"start":"09:00","end":"10:00","days":[0,7,8]}]}}}}"#,
        )
        .unwrap();
        let r = Rules::load(&path).unwrap();
        assert_eq!(r.apps["0:com.foo"].rules.time_windows.windows[0].days, vec![7]);
    }

    /// A file shaped exactly like the one the WebUI writes: allow-mode windows
    /// with weekday sets, a parked (disabled) app rule, and a backslash in a
    /// group name (which is what used to corrupt rules.json).
    #[test]
    fn webui_payload_parses() {
        let text = r#"{
          "version": 1,
          "settings": {"timezone": "UTC+8", "language": "zh", "clear_log_on_boot": false},
          "apps": {
            "0:com.example.game": {
              "enabled": false,
              "always_on": false,
              "time_windows": {"mode": "allow", "windows": []},
              "duration": {"limit_minutes": 30, "freeze_minutes": 10, "scope": "foreground"}
            }
          },
          "groups": {
            "g1": {
              "name": "工作\\c组",
              "enabled": true,
              "shared_pool": true,
              "members": ["0:com.example.a"],
              "time_windows": {
                "mode": "allow",
                "windows": [{"start": "09:00", "end": "12:00", "days": [1, 3, 5]}]
              },
              "duration": {"limit_minutes": 0, "freeze_minutes": 0, "scope": "foreground"}
            }
          }
        }"#;
        let r: Rules = serde_json::from_str(text).expect("WebUI payload must parse");
        let g = &r.groups["g1"];
        assert_eq!(g.members.len(), 1);
        assert_eq!(g.rules.time_windows.windows[0].days, vec![1, 3, 5]);
        assert!(g.rules.time_windows.mode == "allow");
        assert!(g.name.contains("工作"));
        assert!(!r.apps["0:com.example.game"].enabled);
        assert_eq!(r.apps["0:com.example.game"].rules.duration.limit_minutes, 30);
    }
}

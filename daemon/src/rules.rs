// serde types for rules.json (contract shared by daemon and WebUI).
//
// App keys and group members use "<user_id>:<package>",
// e.g. "0:com.foo" (main user), "10:com.foo" (work profile).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

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
    /// "auto" (device) or "UTC+N"/"UTC-N" fixed offset.
    #[serde(default = "d_timezone")]
    pub timezone: String,
    /// "auto" (system), "zh", "en".
    #[serde(default = "d_language")]
    pub language: String,
    /// Truncate the log when the module (re)starts.
    #[serde(default)]
    pub clear_log_on_boot: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            timezone: "auto".into(),
            language: "auto".into(),
            clear_log_on_boot: false,
        }
    }
}

fn d_timezone() -> String {
    "auto".into()
}
fn d_language() -> String {
    "auto".into()
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct TimeWindows {
    /// "block" = not allowed inside; "allow" = only allowed inside.
    #[serde(default = "d_window_mode")]
    pub mode: String,
    #[serde(default)]
    pub windows: Vec<TimeWindow>,
}

fn d_window_mode() -> String {
    "block".into()
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
        Ok(serde_json::from_str(&data)?)
    }
}

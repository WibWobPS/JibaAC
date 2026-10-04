use anticheat_model::EnforcementMode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeThresholds {
    pub suspicious: u8,
    pub high_risk: u8,
    pub critical: u8,
    pub confirmed: u8,
}

impl Default for ModeThresholds {
    fn default() -> Self {
        Self {
            suspicious: 20,
            high_risk: 40,
            critical: 60,
            confirmed: 80,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitBucket {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

impl Default for RateLimitBucket {
    fn default() -> Self {
        Self {
            capacity: 30.0,
            refill_per_sec: 5.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub per_account: RateLimitBucket,
    pub per_session: RateLimitBucket,
    pub per_endpoint: RateLimitBucket,
    pub per_ip: RateLimitBucket,
    pub per_operation: HashMap<String, RateLimitBucket>,
    pub global_per_sec: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let mut per_operation = HashMap::new();
        per_operation.insert(
            String::from("login"),
            RateLimitBucket {
                capacity: 10.0,
                refill_per_sec: 1.0,
            },
        );
        per_operation.insert(
            String::from("gacha"),
            RateLimitBucket {
                capacity: 8.0,
                refill_per_sec: 0.5,
            },
        );
        per_operation.insert(
            String::from("reward_claim"),
            RateLimitBucket {
                capacity: 12.0,
                refill_per_sec: 1.0,
            },
        );
        per_operation.insert(
            String::from("stage_end"),
            RateLimitBucket {
                capacity: 15.0,
                refill_per_sec: 1.5,
            },
        );
        Self {
            per_account: RateLimitBucket {
                capacity: 120.0,
                refill_per_sec: 20.0,
            },
            per_session: RateLimitBucket {
                capacity: 90.0,
                refill_per_sec: 15.0,
            },
            per_endpoint: RateLimitBucket {
                capacity: 40.0,
                refill_per_sec: 8.0,
            },
            per_ip: RateLimitBucket {
                capacity: 300.0,
                refill_per_sec: 50.0,
            },
            per_operation,
            global_per_sec: 2000.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleToggles {
    pub replay_detection: bool,
    pub impossible_progression: bool,
    pub economy: bool,
    pub inventory: bool,
    pub stage_machine: bool,
    pub reward_provenance: bool,
    pub gacha_authority: bool,
    pub time_validation: bool,
    pub session_binding: bool,
    pub rate_limit: bool,
    pub bot_detection: bool,
    pub ownership: bool,
    pub admin_guard: bool,
    pub request_shape: bool,
}

impl RuleToggles {
    pub fn all_enabled() -> Self {
        Self {
            replay_detection: true,
            impossible_progression: true,
            economy: true,
            inventory: true,
            stage_machine: true,
            reward_provenance: true,
            gacha_authority: true,
            time_validation: true,
            session_binding: true,
            rate_limit: true,
            bot_detection: true,
            ownership: true,
            admin_guard: true,
            request_shape: true,
        }
    }
    pub fn all_disabled() -> Self {
        Self {
            replay_detection: false,
            impossible_progression: false,
            economy: false,
            inventory: false,
            stage_machine: false,
            reward_provenance: false,
            gacha_authority: false,
            time_validation: false,
            session_binding: false,
            rate_limit: false,
            bot_detection: false,
            ownership: false,
            admin_guard: false,
            request_shape: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnticheatConfig {
    pub enabled: bool,
    pub mode: EnforcementMode,
    pub default_deny: bool,
    pub risk_decay_per_minute: f64,
    pub thresholds: ModeThresholds,
    pub rules: RuleToggles,
    pub rate_limit: RateLimitConfig,
    pub clock_skew_ms: i64,
    pub max_future_ms: i64,
    pub max_past_ms: i64,
    pub replay_window_ms: i64,
    pub min_stage_ms: i64,
    pub max_score_per_second: i64,
    pub trusted_proxies: Vec<String>,
}

impl Default for AnticheatConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: EnforcementMode::Enforce,
            default_deny: true,
            risk_decay_per_minute: 1.5,
            thresholds: ModeThresholds::default(),
            rules: RuleToggles::all_enabled(),
            rate_limit: RateLimitConfig::default(),
            clock_skew_ms: 5000,
            max_future_ms: 30000,
            max_past_ms: 300000,
            replay_window_ms: 3600000,
            min_stage_ms: 15000,
            max_score_per_second: 1000000,
            trusted_proxies: Vec::new(),
        }
    }
}

impl AnticheatConfig {
    pub fn shadow() -> Self {
        Self {
            mode: EnforcementMode::Shadow,
            ..Self::default()
        }
    }
    pub fn log_only() -> Self {
        Self {
            mode: EnforcementMode::LogOnly,
            ..Self::default()
        }
    }
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            mode: EnforcementMode::Off,
            rules: RuleToggles::all_disabled(),
            ..Self::default()
        }
    }
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

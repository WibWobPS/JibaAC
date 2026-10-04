use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperationId(pub String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl SessionId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl RequestId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl OperationId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn value(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementMode {
    Off,
    LogOnly,
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionAction {
    Allow,
    AllowAndLog,
    Throttle,
    Deny,
    Rollback,
    InvalidateSession,
    FreezeAccount,
    RequireReauth,
    FlagForReview,
    Ban,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Normal,
    Suspicious,
    HighRisk,
    Critical,
    Confirmed,
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        if score >= 80 {
            Self::Confirmed
        } else if score >= 60 {
            Self::Critical
        } else if score >= 40 {
            Self::HighRisk
        } else if score >= 20 {
            Self::Suspicious
        } else {
            Self::Normal
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn default_score(&self) -> u8 {
        match self {
            Self::Low => 8,
            Self::Medium => 18,
            Self::High => 32,
            Self::Critical => 55,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Login,
    SessionCreate,
    NormalRequest,
    ExpensiveRequest,
    StageStart,
    StageEnd,
    Gacha,
    RewardClaim,
    InventoryWrite,
    AccountMutation,
    DataDownload,
    AdminOperation,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub account_id: AccountId,
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub sequence: u64,
    pub nonce: String,
    pub timestamp_ms: i64,
    pub received_ms: i64,
    pub endpoint: String,
    pub operation: OperationKind,
    pub ip: Option<String>,
    pub device_fingerprint: Option<String>,
    pub udkey: Option<String>,
    pub gdkey: Option<String>,
    pub is_admin: bool,
    pub payload: serde_json::Value,
    pub payload_bytes: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerState {
    pub previous_balances: HashMap<String, i64>,
    pub claimed_deltas: HashMap<String, i64>,
    pub stage_state: Option<StageState>,
    pub owned_items: Vec<String>,
    pub owned_yokai: Vec<String>,
    pub reward_cause: Option<String>,
    pub session_known_sequence: Option<u64>,
    pub account_risk_score: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StageState {
    NotStarted,
    Started,
    Completed,
    RewardGranted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: f32,
    pub score_delta: u8,
    pub message: String,
    pub endpoint: String,
    pub request_fingerprint: String,
    pub action_fingerprint: String,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        confidence: f32,
        score_delta: u8,
        message: impl Into<String>,
        endpoint: impl Into<String>,
        request_fingerprint: impl Into<String>,
        action_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            confidence,
            score_delta,
            message: message.into(),
            endpoint: endpoint.into(),
            request_fingerprint: request_fingerprint.into(),
            action_fingerprint: action_fingerprint.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub allowed: bool,
    pub action: DecisionAction,
    pub risk_score: u8,
    pub risk_level: RiskLevel,
    pub findings: Vec<Finding>,
    pub request_fingerprint: String,
    pub action_fingerprint: String,
    pub audit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub account_id: AccountId,
    pub currency: String,
    pub source: String,
    pub destination: String,
    pub amount: i64,
    pub previous_balance: i64,
    pub new_balance: i64,
    pub operation_id: String,
    pub request_id: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_id: String,
    pub timestamp: DateTime<Utc>,
    pub account_id: String,
    pub session_id: String,
    pub request_id: String,
    pub operation_id: Option<String>,
    pub endpoint: String,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: f32,
    pub risk_score: u8,
    pub action: DecisionAction,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskState {
    pub account_id: String,
    pub score: u8,
    pub updated_ms: i64,
    pub events: u64,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ModelError {
    #[error("invalid field {field}: {reason}")]
    InvalidField { field: String, reason: String },
    #[error("missing field {0}")]
    MissingField(String),
    #[error("type mismatch for field {0}")]
    TypeMismatch(String),
}

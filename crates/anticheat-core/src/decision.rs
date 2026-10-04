#![allow(clippy::too_many_arguments)]
use anticheat_model::{CheckResult, DecisionAction, EnforcementMode, Finding, RiskLevel};
use anticheat_protocol::{action_fingerprint, request_fingerprint};
use anticheat_storage::InMemoryStores;
use uuid::Uuid;

use crate::{AnticheatConfig, RiskEngine};

#[derive(Debug, Clone)]
pub struct PipelineOutput {
    pub result: CheckResult,
    pub decayed_before: f64,
}

pub struct DecisionPipeline {
    pub config: AnticheatConfig,
    pub stores: InMemoryStores,
    pub risk: RiskEngine,
}

impl DecisionPipeline {
    pub fn new(config: AnticheatConfig, stores: InMemoryStores) -> Self {
        let decay = config.risk_decay_per_minute;
        Self {
            config,
            stores,
            risk: RiskEngine::new(decay),
        }
    }

    pub fn decide(
        &self,
        account_id: &str,
        session_id: &str,
        request_id: &str,
        sequence: u64,
        nonce: &str,
        endpoint: &str,
        operation: &anticheat_model::OperationKind,
        payload: &serde_json::Value,
        mut findings: Vec<Finding>,
        now_ms: i64,
    ) -> CheckResult {
        let req_fp = request_fingerprint(
            account_id, session_id, request_id, sequence, nonce, endpoint,
        );
        let act_fp = action_fingerprint(endpoint, operation, payload);
        for finding in findings.iter_mut() {
            if finding.request_fingerprint.is_empty() {
                finding.request_fingerprint = req_fp.clone();
            }
            if finding.action_fingerprint.is_empty() {
                finding.action_fingerprint = act_fp.clone();
            }
        }
        let deltas: Vec<u8> = findings.iter().map(|item| item.score_delta).collect();
        let risk_score = self
            .risk
            .apply_findings(&self.stores, account_id, &deltas, now_ms);
        let risk_level = RiskLevel::from_score(risk_score);
        let critical_block = findings.iter().any(|item| {
            item.rule_id == "crypto.integrity"
                || item.rule_id == "session.hijack"
                || item.rule_id == "admin.escalation"
        });
        let action = self.action_for(findings.is_empty(), critical_block, risk_level);
        let effective = self.apply_mode(action);
        let allowed_effective = matches!(
            effective,
            DecisionAction::Allow | DecisionAction::AllowAndLog
        );
        let audit_id = Uuid::new_v4().to_string();
        self.emit_audit(
            &audit_id, account_id, session_id, request_id, endpoint, &findings, risk_score,
            effective, now_ms,
        );
        self.update_metrics(&findings, effective);
        CheckResult {
            allowed: allowed_effective,
            action: effective,
            risk_score,
            risk_level,
            findings,
            request_fingerprint: req_fp,
            action_fingerprint: act_fp,
            audit_id,
        }
    }

    fn action_for(&self, clean: bool, critical_block: bool, level: RiskLevel) -> DecisionAction {
        if clean {
            return DecisionAction::Allow;
        }
        if critical_block {
            return DecisionAction::Deny;
        }
        match level {
            RiskLevel::Normal => DecisionAction::AllowAndLog,
            RiskLevel::Suspicious => DecisionAction::Throttle,
            RiskLevel::HighRisk => DecisionAction::Deny,
            RiskLevel::Critical => DecisionAction::InvalidateSession,
            RiskLevel::Confirmed => DecisionAction::FreezeAccount,
        }
    }

    fn apply_mode(&self, action: DecisionAction) -> DecisionAction {
        if !self.config.enabled {
            return DecisionAction::Allow;
        }
        match self.config.mode {
            EnforcementMode::Off => DecisionAction::Allow,
            EnforcementMode::LogOnly => DecisionAction::AllowAndLog,
            EnforcementMode::Shadow => match action {
                DecisionAction::Allow => DecisionAction::Allow,
                _ => DecisionAction::AllowAndLog,
            },
            EnforcementMode::Enforce => action,
        }
    }

    fn emit_audit(
        &self,
        audit_id: &str,
        account_id: &str,
        session_id: &str,
        request_id: &str,
        endpoint: &str,
        findings: &[Finding],
        risk_score: u8,
        action: DecisionAction,
        now_ms: i64,
    ) {
        use chrono::{DateTime, Utc};
        let timestamp = DateTime::from_timestamp_millis(now_ms).unwrap_or_else(Utc::now);
        if findings.is_empty() {
            self.stores.append_audit(anticheat_model::AuditEvent {
                audit_id: audit_id.to_string(),
                timestamp,
                account_id: account_id.to_string(),
                session_id: session_id.to_string(),
                request_id: request_id.to_string(),
                operation_id: None,
                endpoint: endpoint.to_string(),
                rule_id: String::from("pipeline.clean"),
                severity: anticheat_model::Severity::Low,
                confidence: 1.0,
                risk_score,
                action,
                detail: String::from("no findings"),
            });
            return;
        }
        for finding in findings {
            self.stores.append_audit(anticheat_model::AuditEvent {
                audit_id: audit_id.to_string(),
                timestamp,
                account_id: account_id.to_string(),
                session_id: session_id.to_string(),
                request_id: request_id.to_string(),
                operation_id: None,
                endpoint: endpoint.to_string(),
                rule_id: finding.rule_id.clone(),
                severity: finding.severity,
                confidence: finding.confidence,
                risk_score,
                action,
                detail: finding.message.clone(),
            });
        }
    }

    fn update_metrics(&self, findings: &[Finding], action: DecisionAction) {
        self.stores.incr_metric("requests_checked");
        if findings.is_empty() {
            return;
        }
        self.stores.incr_metric("requests_flagged");
        for finding in findings {
            let key = format!("rule.{}", finding.rule_id);
            self.stores.incr_metric(&key);
        }
        match action {
            DecisionAction::Deny | DecisionAction::Rollback => {
                self.stores.incr_metric("requests_rejected")
            }
            DecisionAction::Throttle => self.stores.incr_metric("rate_limits_triggered"),
            DecisionAction::InvalidateSession => self.stores.incr_metric("sessions_invalidated"),
            DecisionAction::FreezeAccount | DecisionAction::Ban => {
                self.stores.incr_metric("accounts_frozen")
            }
            DecisionAction::FlagForReview => self.stores.incr_metric("flagged_for_review"),
            _ => {}
        }
    }
}

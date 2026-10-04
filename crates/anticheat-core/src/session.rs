use anticheat_model::{RequestContext, Severity};
use anticheat_storage::{InMemoryStores, SessionRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionVerdict {
    Ok,
    FirstSeen,
    StaleSequence,
    ReusedSequence,
    FingerprintChanged,
    Invalidated,
    Expired,
    IdentityChanged,
}

pub struct SessionValidator {
    pub expiry_ms: i64,
}

impl Default for SessionValidator {
    fn default() -> Self {
        Self {
            expiry_ms: 86400000,
        }
    }
}

impl SessionValidator {
    pub fn validate(
        &self,
        stores: &InMemoryStores,
        ctx: &RequestContext,
        now_ms: i64,
    ) -> (SessionVerdict, Severity, String) {
        let session_id = ctx.session_id.value();
        match stores.get_session(session_id) {
            None => {
                stores.upsert_session(SessionRecord {
                    session_id: session_id.to_string(),
                    account_id: ctx.account_id.value().to_string(),
                    created_ms: now_ms,
                    last_seen_ms: now_ms,
                    last_sequence: ctx.sequence,
                    fingerprint: ctx.device_fingerprint.clone().unwrap_or_default(),
                    ip: ctx.ip.clone(),
                    valid: true,
                    reconnects: 1,
                });
                (
                    SessionVerdict::FirstSeen,
                    Severity::Low,
                    String::from("first observation for session"),
                )
            }
            Some(mut record) => {
                if !record.valid {
                    return (
                        SessionVerdict::Invalidated,
                        Severity::Critical,
                        String::from("request on invalidated session"),
                    );
                }
                if now_ms.saturating_sub(record.created_ms) > self.expiry_ms {
                    stores.invalidate_session(session_id);
                    return (
                        SessionVerdict::Expired,
                        Severity::High,
                        String::from("session exceeded expiry"),
                    );
                }
                if record.account_id != ctx.account_id.value() {
                    return (
                        SessionVerdict::IdentityChanged,
                        Severity::Critical,
                        String::from("session changed account identity"),
                    );
                }
                let current_fp = ctx.device_fingerprint.clone().unwrap_or_default();
                if !record.fingerprint.is_empty()
                    && !current_fp.is_empty()
                    && record.fingerprint != current_fp
                {
                    record.reconnects = record.reconnects.saturating_add(1);
                    record.fingerprint = current_fp;
                    record.last_seen_ms = now_ms;
                    record.last_sequence = ctx.sequence;
                    stores.upsert_session(record);
                    return (
                        SessionVerdict::FingerprintChanged,
                        Severity::High,
                        String::from("session fingerprint changed"),
                    );
                }
                if ctx.sequence < record.last_sequence {
                    return (
                        SessionVerdict::StaleSequence,
                        Severity::High,
                        String::from("sequence moved backwards"),
                    );
                }
                if ctx.sequence == record.last_sequence {
                    return (
                        SessionVerdict::ReusedSequence,
                        Severity::High,
                        String::from("sequence reused"),
                    );
                }
                record.last_seen_ms = now_ms;
                record.last_sequence = ctx.sequence;
                if let Some(ip) = ctx.ip.clone() {
                    record.ip = Some(ip);
                }
                stores.upsert_session(record);
                (
                    SessionVerdict::Ok,
                    Severity::Low,
                    String::from("session sequence advanced"),
                )
            }
        }
    }
}

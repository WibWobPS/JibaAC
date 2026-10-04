use anticheat_model::{AuditEvent, LedgerEntry, RiskState};
use dashmap::DashMap;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct ReplayRecord {
    pub fingerprint: String,
    pub first_seen_ms: i64,
    pub endpoint: String,
}

#[derive(Debug, Clone, Default)]
pub struct SessionRecord {
    pub session_id: String,
    pub account_id: String,
    pub created_ms: i64,
    pub last_seen_ms: i64,
    pub last_sequence: u64,
    pub fingerprint: String,
    pub ip: Option<String>,
    pub valid: bool,
    pub reconnects: u32,
}

#[derive(Debug, Clone)]
pub struct Bucket {
    pub tokens: f64,
    pub last_ms: i64,
}

#[derive(Debug, Clone)]
pub struct InMemoryStores {
    replay: Arc<DashMap<String, ReplayRecord>>,
    sessions: Arc<DashMap<String, SessionRecord>>,
    risks: Arc<DashMap<String, RiskState>>,
    buckets: Arc<DashMap<String, Bucket>>,
    ledger: Arc<Mutex<Vec<LedgerEntry>>>,
    audit: Arc<Mutex<Vec<AuditEvent>>>,
    stage: Arc<DashMap<String, String>>,
    events: Arc<DashMap<String, VecDeque<i64>>>,
    metrics: Arc<DashMap<String, u64>>,
}

impl Default for InMemoryStores {
    fn default() -> Self {
        Self {
            replay: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            risks: Arc::new(DashMap::new()),
            buckets: Arc::new(DashMap::new()),
            ledger: Arc::new(Mutex::new(Vec::new())),
            audit: Arc::new(Mutex::new(Vec::new())),
            stage: Arc::new(DashMap::new()),
            events: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
        }
    }
}

impl InMemoryStores {
    pub fn insert_replay(&self, key: String, record: ReplayRecord) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.replay.entry(key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(slot) => {
                slot.insert(record);
                true
            }
        }
    }

    pub fn has_replay(&self, key: &str) -> bool {
        self.replay.contains_key(key)
    }

    pub fn replay_len(&self) -> usize {
        self.replay.len()
    }

    pub fn prune_replay(&self, older_than_ms: i64) {
        let stale: Vec<String> = self
            .replay
            .iter()
            .filter(|entry| entry.value().first_seen_ms < older_than_ms)
            .map(|entry| entry.key().clone())
            .collect();
        for key in stale {
            self.replay.remove(&key);
        }
    }

    pub fn get_session(&self, session_id: &str) -> Option<SessionRecord> {
        self.sessions
            .get(session_id)
            .map(|entry| entry.value().clone())
    }

    pub fn upsert_session(&self, record: SessionRecord) {
        self.sessions.insert(record.session_id.clone(), record);
    }

    pub fn invalidate_session(&self, session_id: &str) {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            entry.value_mut().valid = false;
        }
    }

    pub fn get_risk(&self, account_id: &str) -> Option<RiskState> {
        self.risks
            .get(account_id)
            .map(|entry| entry.value().clone())
    }

    pub fn set_risk(&self, state: RiskState) {
        self.risks.insert(state.account_id.clone(), state);
    }

    pub fn take_bucket(&self, key: &str) -> Option<Bucket> {
        self.buckets.get(key).map(|entry| entry.value().clone())
    }

    pub fn put_bucket(&self, key: String, bucket: Bucket) {
        self.buckets.insert(key, bucket);
    }

    pub fn append_ledger(&self, entry: LedgerEntry) {
        if let Ok(mut guard) = self.ledger.lock() {
            guard.push(entry);
        }
    }

    pub fn ledger_for(&self, account_id: &str) -> Vec<LedgerEntry> {
        if let Ok(guard) = self.ledger.lock() {
            return guard
                .iter()
                .filter(|entry| entry.account_id.value() == account_id)
                .cloned()
                .collect();
        }
        Vec::new()
    }

    pub fn append_audit(&self, event: AuditEvent) {
        if let Ok(mut guard) = self.audit.lock() {
            guard.push(event);
        }
    }

    pub fn audit_len(&self) -> usize {
        if let Ok(guard) = self.audit.lock() {
            return guard.len();
        }
        0
    }

    pub fn recent_audit(&self, limit: usize) -> Vec<AuditEvent> {
        if let Ok(guard) = self.audit.lock() {
            let total = guard.len();
            let start = total.saturating_sub(limit);
            return guard[start..].to_vec();
        }
        Vec::new()
    }

    pub fn get_stage(&self, account_id: &str) -> Option<String> {
        self.stage
            .get(account_id)
            .map(|entry| entry.value().clone())
    }

    pub fn set_stage(&self, account_id: String, stage: String) {
        self.stage.insert(account_id, stage);
    }

    pub fn push_event_time(&self, key: String, timestamp_ms: i64, window_ms: i64) -> Vec<i64> {
        let mut entry = self.events.entry(key).or_default();
        entry.push_back(timestamp_ms);
        while let Some(front) = entry.front().copied() {
            if timestamp_ms.saturating_sub(front) > window_ms {
                entry.pop_front();
            } else {
                break;
            }
        }
        entry.iter().copied().collect()
    }

    pub fn incr_metric(&self, name: &str) {
        let mut entry = self.metrics.entry(name.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    pub fn metrics_snapshot(&self) -> HashMap<String, u64> {
        self.metrics
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect()
    }
}

use anticheat_model::{RiskLevel, RiskState};
use anticheat_storage::InMemoryStores;

#[derive(Debug, Clone)]
pub struct RiskEngine {
    pub decay_per_minute: f64,
}

impl RiskEngine {
    pub fn new(decay_per_minute: f64) -> Self {
        Self { decay_per_minute }
    }

    pub fn decayed_score(&self, stored: &RiskState, now_ms: i64) -> f64 {
        let elapsed_ms = now_ms.saturating_sub(stored.updated_ms).max(0) as f64;
        let minutes = elapsed_ms / 60000.0;
        let decay = minutes * self.decay_per_minute;
        (stored.score as f64 - decay).clamp(0.0, 100.0)
    }

    pub fn apply_findings(
        &self,
        stores: &InMemoryStores,
        account_id: &str,
        deltas: &[u8],
        now_ms: i64,
    ) -> u8 {
        let base = stores
            .get_risk(account_id)
            .map(|stored| self.decayed_score(&stored, now_ms))
            .unwrap_or(0.0);
        let added: u32 = deltas.iter().map(|value| *value as u32).sum();
        let next = (base + added as f64).clamp(0.0, 100.0) as u8;
        let previous_events = stores
            .get_risk(account_id)
            .map(|state| state.events)
            .unwrap_or(0);
        stores.set_risk(RiskState {
            account_id: account_id.to_string(),
            score: next,
            updated_ms: now_ms,
            events: previous_events.saturating_add(1),
        });
        next
    }

    pub fn level_for(score: u8) -> RiskLevel {
        RiskLevel::from_score(score)
    }
}

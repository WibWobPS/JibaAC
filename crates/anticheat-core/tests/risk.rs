use anticheat_core::{AnticheatConfig, RiskEngine};
use anticheat_model::RiskState;
use anticheat_storage::InMemoryStores;

#[test]
fn risk_decays_over_time() {
    let stores = InMemoryStores::default();
    stores.set_risk(RiskState {
        account_id: String::from("acc"),
        score: 60,
        updated_ms: 0,
        events: 1,
    });
    let engine = RiskEngine::new(1.5);
    let stored = stores.get_risk("acc").expect("risk");
    let decayed = engine.decayed_score(&stored, 3_600_000);
    assert!(decayed < 60.0);
}

#[test]
fn disabled_config_allows_all() {
    let config = AnticheatConfig::disabled();
    assert!(!config.enabled);
}

use anticheat_core::AnticheatConfig;
use anticheat_model::{
    AccountId, OperationKind, RequestContext, RequestId, ServerState, SessionId, StageState,
};
use anticheat_rules::Engine;
use serde_json::json;
use std::collections::HashMap;

fn ctx_for(
    endpoint: &str,
    payload: serde_json::Value,
    sequence: u64,
    request_id: &str,
) -> RequestContext {
    let bytes = serde_json::to_string(&payload)
        .map(|text| text.len())
        .unwrap_or(0);
    RequestContext {
        account_id: AccountId::new("acc-1"),
        session_id: SessionId::new("sess-1"),
        request_id: RequestId::new(request_id),
        sequence,
        nonce: format!("nonce-{sequence}"),
        timestamp_ms: 1_700_000_000_000,
        received_ms: 1_700_000_000_000,
        endpoint: endpoint.to_string(),
        operation: OperationKind::Unknown,
        ip: Some(String::from("127.0.0.1")),
        device_fingerprint: Some(String::from("device-1")),
        udkey: Some(String::from("ud-1")),
        gdkey: Some(String::from("gd-1")),
        is_admin: false,
        payload,
        payload_bytes: bytes,
    }
}

fn engine() -> Engine {
    Engine::new(AnticheatConfig::default())
}

#[test]
fn clean_login_allows() {
    let engine = engine();
    let ctx = ctx_for("/login.nhn", json!({"gdkey": "gd-1"}), 1, "req-1");
    let result = engine.evaluate(&ctx, &ServerState::default(), 1_700_000_000_000);
    assert!(result.allowed);
}

#[test]
fn duplicate_request_rejected_as_replay() {
    let engine = engine();
    let payload = json!({"gdkey": "gd-1", "cause": "login", "elapsed_ms": 60000});
    let ctx = ctx_for("/gameEnd.nhn", payload.clone(), 1, "same-req");
    let mut state = ServerState::default();
    state.stage_state = Some(StageState::Started);
    state.reward_cause = Some(String::from("stage completion"));
    let first = engine.evaluate(&ctx, &state, 1_700_000_000_000);
    assert!(first.allowed);
    let second = engine.evaluate(&ctx, &state, 1_700_000_000_100);
    assert!(!second.allowed);
    assert!(second
        .findings
        .iter()
        .any(|finding| finding.rule_id == "replay.duplicate"));
}

#[test]
fn negative_currency_denied() {
    let engine = engine();
    let ctx = ctx_for(
        "/missionReward.nhn",
        json!({"source": "mission", "coins": -5}),
        2,
        "req-neg",
    );
    let mut state = ServerState::default();
    state.claimed_deltas.insert(String::from("coins"), -10);
    state.previous_balances.insert(String::from("coins"), 5);
    state.reward_cause = Some(String::from("mission completion"));
    let result = engine.evaluate(&ctx, &state, 1_700_000_000_000);
    assert!(!result.allowed);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id.contains("economy")));
}

#[test]
fn currency_mint_without_source_flagged() {
    let engine = engine();
    let ctx = ctx_for("/missionReward.nhn", json!({}), 3, "req-mint");
    let mut state = ServerState::default();
    state.claimed_deltas.insert(String::from("coins"), 500);
    let result = engine.evaluate(&ctx, &state, 1_700_000_000_000);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "economy.missing_source"));
}

#[test]
fn stage_skip_rejected() {
    let engine = engine();
    let ctx = ctx_for("/gameEnd.nhn", json!({"elapsed_ms": 60000}), 4, "req-stage");
    let state = ServerState::default();
    let result = engine.evaluate(&ctx, &state, 1_700_000_000_000);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "stage.skipped"));
}

#[test]
fn too_fast_completion_flagged() {
    let engine = engine();
    let ctx = ctx_for("/gameEnd.nhn", json!({"elapsed_ms": 1000}), 5, "req-fast");
    let mut state = ServerState::default();
    state.stage_state = Some(StageState::Started);
    let result = engine.evaluate(&ctx, &state, 1_700_000_000_000);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "stage.too_fast"));
}

#[test]
fn gacha_client_result_rejected() {
    let engine = engine();
    let ctx = ctx_for(
        "/executeGacha.nhn",
        json!({"rarity": 8, "itemId": 123}),
        6,
        "req-gacha",
    );
    let result = engine.evaluate(&ctx, &ServerState::default(), 1_700_000_000_000);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "gacha.client_result"));
}

#[test]
fn forbidden_flag_rejected() {
    let engine = engine();
    let ctx = ctx_for("/login.nhn", json!({"admin": true}), 7, "req-flag");
    let result = engine.evaluate(&ctx, &ServerState::default(), 1_700_000_000_000);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "protocol.forbidden_flag"));
}

#[test]
fn future_timestamp_flagged() {
    let engine = engine();
    let mut ctx = ctx_for("/login.nhn", json!({}), 8, "req-time");
    ctx.timestamp_ms = 1_700_000_000_000 + 600_000;
    let result = engine.evaluate(&ctx, &ServerState::default(), 1_700_000_000_000);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id.starts_with("time.")));
}

#[test]
fn sequence_reuse_flagged() {
    let engine = engine();
    let first = ctx_for("/login.nhn", json!({}), 10, "req-a");
    let second = ctx_for("/login.nhn", json!({}), 10, "req-b");
    let now = 1_700_000_000_000;
    let first_result = engine.evaluate(&first, &ServerState::default(), now);
    assert!(first_result.allowed);
    let second_result = engine.evaluate(&second, &ServerState::default(), now + 100);
    assert!(second_result
        .findings
        .iter()
        .any(|finding| finding.rule_id.contains("session")));
}

#[test]
fn shadow_mode_never_denies() {
    let mut config = AnticheatConfig::default();
    config.mode = anticheat_model::EnforcementMode::Shadow;
    let engine = Engine::new(config);
    let ctx = ctx_for("/executeGacha.nhn", json!({"rarity": 8}), 20, "req-shadow");
    let result = engine.evaluate(&ctx, &ServerState::default(), 1_700_000_000_000);
    assert!(result.allowed);
    assert!(!result.findings.is_empty());
}

#[test]
fn risk_accumulates_across_violations() {
    let engine = engine();
    let now = 1_700_000_000_000;
    for index in 0..4 {
        let ctx = ctx_for(
            "/executeGacha.nhn",
            json!({"rarity": 8}),
            (30 + index) as u64,
            &format!("req-risk-{index}"),
        );
        let result = engine.evaluate(&ctx, &ServerState::default(), now + (index as i64) * 1000);
        if index >= 2 {
            assert!(result.risk_score > 0);
        }
    }
}

#[test]
fn economy_overflow_flagged() {
    let engine = engine();
    let ctx = ctx_for(
        "/missionReward.nhn",
        json!({"source": "event"}),
        40,
        "req-overflow",
    );
    let mut state = ServerState::default();
    state
        .claimed_deltas
        .insert(String::from("coins"), 10_000_000_000);
    state.previous_balances.insert(String::from("coins"), 100);
    state.reward_cause = Some(String::from("event reward"));
    let result = engine.evaluate(&ctx, &state, 1_700_000_000_000);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "economy.overflow"));
}

#[test]
fn concurrent_same_request_only_one_wins() {
    let engine = Engine::new(AnticheatConfig::default());
    let payload = json!({"source": "stage", "elapsed_ms": 60000});
    let mut handles = Vec::new();
    let engine_ref = std::sync::Arc::new(engine);
    for index in 0..8 {
        let engine_clone = engine_ref.clone();
        let payload_clone = payload.clone();
        handles.push(std::thread::spawn(move || {
            let ctx = ctx_for("/gameEnd.nhn", payload_clone, 100, "shared-req");
            let mut state = ServerState::default();
            state.stage_state = Some(StageState::Started);
            state.reward_cause = Some(String::from("stage completion"));
            let _ = index;
            engine_clone.evaluate(&ctx, &state, 1_700_000_000_000)
        }));
    }
    let mut denied = 0;
    for handle in handles {
        let result = handle.join().expect("thread");
        if result
            .findings
            .iter()
            .any(|finding| finding.rule_id == "replay.duplicate")
        {
            denied += 1;
        }
    }
    assert!(denied >= 7);
}

#[test]
fn malformed_huge_payload_flagged() {
    let engine = engine();
    let mut ctx = ctx_for("/login.nhn", json!({"a": "x"}), 50, "req-huge");
    ctx.payload_bytes = 10_000_000;
    let result = engine.evaluate(&ctx, &ServerState::default(), 1_700_000_000_000);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "request.oversize"));
}

#[test]
fn invalid_account_id_mismatch() {
    let engine = engine();
    let ctx = ctx_for(
        "/missionReward.nhn",
        json!({"account_id": "other"}),
        51,
        "req-acct",
    );
    let result = engine.evaluate(&ctx, &ServerState::default(), 1_700_000_000_000);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "ownership.account_mismatch"));
}

#[test]
fn empty_state_allows_legitimate_reward() {
    let engine = engine();
    let ctx = ctx_for("/login.nhn", json!({"gdkey": "gd-1"}), 60, "req-legit");
    let state = ServerState {
        previous_balances: HashMap::new(),
        claimed_deltas: HashMap::new(),
        stage_state: None,
        owned_items: Vec::new(),
        owned_yokai: Vec::new(),
        reward_cause: None,
        session_known_sequence: None,
        account_risk_score: 0,
    };
    let result = engine.evaluate(&ctx, &state, 1_700_000_000_000);
    assert!(result.allowed);
}

use anticheat_core::AnticheatConfig;
use anticheat_model::{AccountId, RequestContext, RequestId, ServerState, SessionId};
use anticheat_rules::Engine;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(data) {
        let bytes = data.len();
        if bytes > 300000 {
            return;
        }
        let ctx = RequestContext {
            account_id: AccountId::new("fuzz"),
            session_id: SessionId::new("fuzz"),
            request_id: RequestId::new("fuzz"),
            sequence: 1,
            nonce: String::from("fuzz"),
            timestamp_ms: 1700000000000,
            received_ms: 1700000000000,
            endpoint: String::from("/gameEnd.nhn"),
            operation: anticheat_model::OperationKind::Unknown,
            ip: None,
            device_fingerprint: None,
            udkey: None,
            gdkey: None,
            is_admin: false,
            payload,
            payload_bytes: bytes,
        };
        let engine = Engine::new(AnticheatConfig::default());
        let _ = engine.evaluate(&ctx, &ServerState::default(), 1700000000000);
    }
});

use anticheat_core::AnticheatConfig;
use anticheat_model::{AccountId, RequestContext, RequestId, ServerState, SessionId};
use anticheat_rules::Engine;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::OnceLock;

#[allow(clippy::missing_safety_doc)]
static ENGINE: OnceLock<Engine> = OnceLock::new();

fn engine() -> &'static Engine {
    ENGINE.get_or_init(|| Engine::new(AnticheatConfig::default()))
}

#[derive(serde::Deserialize)]
struct FfiInput {
    account_id: String,
    session_id: String,
    request_id: String,
    sequence: u64,
    nonce: String,
    timestamp_ms: i64,
    endpoint: String,
    ip: Option<String>,
    device_fingerprint: Option<String>,
    udkey: Option<String>,
    gdkey: Option<String>,
    is_admin: Option<bool>,
    payload: serde_json::Value,
    state: Option<ServerState>,
    now_ms: Option<i64>,
}

fn build_context(input: &FfiInput, now_ms: i64) -> RequestContext {
    let payload_bytes = serde_json::to_string(&input.payload)
        .map(|text| text.len())
        .unwrap_or(0);
    RequestContext {
        account_id: AccountId::new(input.account_id.clone()),
        session_id: SessionId::new(input.session_id.clone()),
        request_id: RequestId::new(input.request_id.clone()),
        sequence: input.sequence,
        nonce: input.nonce.clone(),
        timestamp_ms: input.timestamp_ms,
        received_ms: now_ms,
        endpoint: input.endpoint.clone(),
        operation: anticheat_model::OperationKind::Unknown,
        ip: input.ip.clone(),
        device_fingerprint: input.device_fingerprint.clone(),
        udkey: input.udkey.clone(),
        gdkey: input.gdkey.clone(),
        is_admin: input.is_admin.unwrap_or(false),
        payload: input.payload.clone(),
        payload_bytes,
    }
}

fn check_json_inner(text: &str) -> String {
    let parsed: Result<FfiInput, _> = serde_json::from_str(text);
    let input = match parsed {
        Ok(value) => value,
        Err(err) => {
            let error = serde_json::json!({
                "allowed": false,
                "action": "DENY",
                "risk_score": 100,
                "error": err.to_string(),
            });
            return error.to_string();
        }
    };
    let now_ms = input
        .now_ms
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
    let ctx = build_context(&input, now_ms);
    let state = input.state.clone().unwrap_or_default();
    let result = engine().evaluate(&ctx, &state, now_ms);
    serde_json::to_string(&result).unwrap_or_else(|_| String::from("{\"allowed\":false}"))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn anticheat_check_json(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }
    let text = unsafe { CStr::from_ptr(input).to_string_lossy().into_owned() };
    let output = check_json_inner(&text);
    match CString::new(output) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn anticheat_free_string(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(value);
    }
}

#[no_mangle]
pub extern "C" fn anticheat_version() -> *const c_char {
    c"anticheat-ffi 0.1.0".as_ptr() as *const c_char
}

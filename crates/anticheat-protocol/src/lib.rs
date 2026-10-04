use anticheat_model::OperationKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointClass {
    Login,
    SessionCreation,
    Normal,
    Expensive,
    Stage,
    Gacha,
    Rewards,
    Inventory,
    AccountMutation,
    DataDownload,
    Suspicious,
    Admin,
}

pub fn classify_endpoint(endpoint: &str) -> EndpointClass {
    let lower = endpoint.to_lowercase();
    if lower.contains("login") {
        return EndpointClass::Login;
    }
    if lower.contains("createuser") || lower.contains("create_gdkey") || lower.contains("active") {
        return EndpointClass::SessionCreation;
    }
    if lower.contains("gacha") || lower.contains("crank") {
        return EndpointClass::Gacha;
    }
    if lower.contains("gameend")
        || lower.contains("game_end")
        || lower.contains("gamestart")
        || lower.contains("game_start")
    {
        return EndpointClass::Stage;
    }
    if lower.contains("missionreward")
        || lower.contains("mission_reward")
        || lower.contains("presentbox")
        || lower.contains("present_box")
        || lower.contains("loginstamp")
        || lower.contains("login_stamp")
    {
        return EndpointClass::Rewards;
    }
    if lower.contains("buyitem")
        || lower.contains("buy_item")
        || lower.contains("useitem")
        || lower.contains("use_item")
        || lower.contains("conflate")
        || lower.contains("evolve")
        || lower.contains("release")
    {
        return EndpointClass::Inventory;
    }
    if lower.contains("rename")
        || lower.contains("updateprofile")
        || lower.contains("update_profile")
        || lower.contains("deleteuser")
        || lower.contains("delete_user")
    {
        return EndpointClass::AccountMutation;
    }
    if lower.contains("getmaster")
        || lower.contains("get_master")
        || lower.contains("datadownload")
        || lower.contains("data_download")
    {
        return EndpointClass::DataDownload;
    }
    if lower.contains("admin") || lower.contains("grant") || lower.contains("ban") {
        return EndpointClass::Admin;
    }
    if lower.contains("shop")
        || lower.contains("hitodama")
        || lower.contains("mapunlock")
        || lower.contains("map_unlock")
        || lower.contains("mapwarp")
        || lower.contains("map_warp")
    {
        return EndpointClass::Expensive;
    }
    EndpointClass::Normal
}

pub fn operation_for_class(class: EndpointClass) -> OperationKind {
    match class {
        EndpointClass::Login => OperationKind::Login,
        EndpointClass::SessionCreation => OperationKind::SessionCreate,
        EndpointClass::Expensive => OperationKind::ExpensiveRequest,
        EndpointClass::Stage => OperationKind::StageEnd,
        EndpointClass::Gacha => OperationKind::Gacha,
        EndpointClass::Rewards => OperationKind::RewardClaim,
        EndpointClass::Inventory => OperationKind::InventoryWrite,
        EndpointClass::AccountMutation => OperationKind::AccountMutation,
        EndpointClass::DataDownload => OperationKind::DataDownload,
        EndpointClass::Admin => OperationKind::AdminOperation,
        EndpointClass::Suspicious => OperationKind::Unknown,
        EndpointClass::Normal => OperationKind::NormalRequest,
    }
}

pub fn normalize_endpoint(raw: &str) -> String {
    let mut out = raw.trim().to_lowercase();
    while out.ends_with('/') && out.len() > 1 {
        out.pop();
    }
    if out.contains(".nhn/") {
        if let Some(pos) = out.find(".nhn/") {
            out.truncate(pos + 4);
        }
    }
    if !out.starts_with('/') {
        out = ["/", out.as_str()].concat();
    }
    out
}

pub fn request_fingerprint(
    account: &str,
    session: &str,
    request_id: &str,
    sequence: u64,
    nonce: &str,
    endpoint: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(account.as_bytes());
    hasher.update([0u8]);
    hasher.update(session.as_bytes());
    hasher.update([0u8]);
    hasher.update(request_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(sequence.to_le_bytes());
    hasher.update([0u8]);
    hasher.update(nonce.as_bytes());
    hasher.update([0u8]);
    hasher.update(endpoint.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn action_fingerprint(
    endpoint: &str,
    operation: &OperationKind,
    payload: &serde_json::Value,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(endpoint.as_bytes());
    hasher.update([0u8]);
    let op = serde_json::to_string(operation).unwrap_or_else(|_| String::from("unknown"));
    hasher.update(op.as_bytes());
    hasher.update([0u8]);
    let canonical = canonical_json(payload);
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn operation_hash(account: &str, endpoint: &str, payload: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(account.as_bytes());
    hasher.update([0u8]);
    hasher.update(endpoint.as_bytes());
    hasher.update([0u8]);
    hasher.update(canonical_json(payload).as_bytes());
    hex::encode(hasher.finalize())
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let encoded_key = serde_json::to_string(key).unwrap_or_default();
                let encoded_value = canonical_json(&map[key]);
                parts.push(format!("{encoded_key}:{encoded_value}"));
            }
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(items) => {
            let encoded: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", encoded.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

pub fn is_sensitive_mutation(endpoint: &str) -> bool {
    matches!(
        classify_endpoint(endpoint),
        EndpointClass::Stage
            | EndpointClass::Gacha
            | EndpointClass::Rewards
            | EndpointClass::Inventory
            | EndpointClass::AccountMutation
            | EndpointClass::Expensive
            | EndpointClass::Admin
    )
}

#[derive(Debug, Clone)]
pub struct ShapeLimits {
    pub max_bytes: usize,
    pub max_fields: usize,
    pub max_array_items: usize,
    pub max_depth: usize,
    pub max_string_len: usize,
}

impl Default for ShapeLimits {
    fn default() -> Self {
        Self {
            max_bytes: 262144,
            max_fields: 256,
            max_array_items: 2048,
            max_depth: 12,
            max_string_len: 8192,
        }
    }
}

pub fn payload_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => {
            let mut deepest = 0usize;
            for child in map.values() {
                let child_depth = payload_depth(child);
                if child_depth > deepest {
                    deepest = child_depth;
                }
            }
            deepest.saturating_add(1)
        }
        serde_json::Value::Array(items) => {
            let mut deepest = 0usize;
            for child in items {
                let child_depth = payload_depth(child);
                if child_depth > deepest {
                    deepest = child_depth;
                }
            }
            deepest.saturating_add(1)
        }
        _ => 0,
    }
}

pub fn count_fields(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => {
            let mut total = map.len();
            for child in map.values() {
                total = total.saturating_add(count_fields(child));
            }
            total
        }
        serde_json::Value::Array(items) => {
            let mut total = items.len();
            for child in items {
                total = total.saturating_add(count_fields(child));
            }
            total
        }
        _ => 0,
    }
}

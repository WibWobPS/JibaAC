use anticheat_protocol::{
    classify_endpoint, is_sensitive_mutation, normalize_endpoint, operation_hash,
};
use serde_json::json;

#[test]
fn endpoint_classification_covers_nhn() {
    assert_eq!(format!("{:?}", classify_endpoint("/gameEnd.nhn")), "Stage");
    assert_eq!(
        format!("{:?}", classify_endpoint("/executeGacha.nhn")),
        "Gacha"
    );
    assert_eq!(
        format!("{:?}", classify_endpoint("/missionReward.nhn")),
        "Rewards"
    );
    assert!(is_sensitive_mutation("/gameEnd.nhn"));
    assert!(!is_sensitive_mutation("/getMaster.nhn"));
}

#[test]
fn normalization_strips_trailing_slash() {
    assert_eq!(normalize_endpoint("/gameEnd.nhn/"), "/gameend.nhn");
}

#[test]
fn operation_hash_stable() {
    let first = operation_hash("acc", "/gameend.nhn", &json!({"b": 1, "a": 2}));
    let second = operation_hash("acc", "/gameend.nhn", &json!({"a": 2, "b": 1}));
    assert_eq!(first, second);
}

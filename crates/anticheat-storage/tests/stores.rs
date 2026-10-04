use anticheat_storage::InMemoryStores;
use anticheat_storage::ReplayRecord;

#[test]
fn replay_insert_is_idempotent() {
    let stores = InMemoryStores::default();
    let first = stores.insert_replay(
        String::from("key"),
        ReplayRecord {
            fingerprint: String::from("fp"),
            first_seen_ms: 10,
            endpoint: String::from("ep"),
        },
    );
    let second = stores.insert_replay(
        String::from("key"),
        ReplayRecord {
            fingerprint: String::from("fp"),
            first_seen_ms: 11,
            endpoint: String::from("ep"),
        },
    );
    assert!(first);
    assert!(!second);
}

#[test]
fn metrics_snapshot_counts() {
    let stores = InMemoryStores::default();
    stores.incr_metric("requests_checked");
    stores.incr_metric("requests_checked");
    let snapshot = stores.metrics_snapshot();
    assert_eq!(snapshot.get("requests_checked"), Some(&2));
}

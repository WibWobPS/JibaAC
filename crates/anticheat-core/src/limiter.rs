use anticheat_storage::{Bucket, InMemoryStores};

#[derive(Debug, Clone)]
pub struct RateLimiter;

impl RateLimiter {
    pub fn check(
        stores: &InMemoryStores,
        key: &str,
        capacity: f64,
        refill_per_sec: f64,
        now_ms: i64,
        cost: f64,
    ) -> bool {
        let mut bucket = stores.take_bucket(key).unwrap_or(Bucket {
            tokens: capacity,
            last_ms: now_ms,
        });
        let elapsed_sec = (now_ms.saturating_sub(bucket.last_ms).max(0) as f64) / 1000.0;
        bucket.tokens = (bucket.tokens + elapsed_sec * refill_per_sec).min(capacity);
        bucket.last_ms = now_ms;
        let allowed = bucket.tokens >= cost;
        if allowed {
            bucket.tokens -= cost;
        }
        stores.put_bucket(key.to_string(), bucket);
        allowed
    }

    pub fn key_for(parts: &[&str]) -> String {
        parts.join("|")
    }
}

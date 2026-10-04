use anticheat_protocol::normalize_endpoint;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let normalized = normalize_endpoint(text);
        let _ = anticheat_protocol::classify_endpoint(&normalized);
    }
});

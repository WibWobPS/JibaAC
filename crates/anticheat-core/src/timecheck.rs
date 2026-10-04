#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeVerdict {
    Ok,
    Future,
    TooOld,
    ImpossibleInterval,
}

pub struct TimeValidator {
    pub max_future_ms: i64,
    pub max_past_ms: i64,
    pub clock_skew_ms: i64,
}

impl TimeValidator {
    pub fn new(max_future_ms: i64, max_past_ms: i64, clock_skew_ms: i64) -> Self {
        Self {
            max_future_ms,
            max_past_ms,
            clock_skew_ms,
        }
    }

    pub fn validate(&self, claimed_ms: i64, server_ms: i64) -> TimeVerdict {
        let delta = claimed_ms.saturating_sub(server_ms);
        if delta > self.max_future_ms + self.clock_skew_ms {
            return TimeVerdict::Future;
        }
        if delta < 0 && delta.abs() > self.max_past_ms + self.clock_skew_ms {
            return TimeVerdict::TooOld;
        }
        TimeVerdict::Ok
    }

    pub fn stage_duration_ok(&self, started_ms: Option<i64>, ended_ms: i64, min_ms: i64) -> bool {
        match started_ms {
            None => false,
            Some(started) => ended_ms.saturating_sub(started) >= min_ms,
        }
    }
}

#![allow(clippy::too_many_arguments)]
#![allow(clippy::manual_range_contains)]
use anticheat_core::{
    AnticheatConfig, DecisionPipeline, RateLimiter, SessionValidator, TimeValidator,
};
use anticheat_model::{CheckResult, Finding, RequestContext, ServerState, Severity, StageState};
use anticheat_protocol::{
    action_fingerprint, classify_endpoint, count_fields, is_sensitive_mutation, normalize_endpoint,
    operation_for_class, operation_hash, payload_depth, request_fingerprint, ShapeLimits,
};
use anticheat_storage::{InMemoryStores, ReplayRecord, SessionRecord};

pub struct Engine {
    pub config: AnticheatConfig,
    pub stores: InMemoryStores,
    pub pipeline: DecisionPipeline,
    pub sessions: SessionValidator,
    pub time: TimeValidator,
    pub limits: ShapeLimits,
}

impl Engine {
    pub fn new(config: AnticheatConfig) -> Self {
        let stores = InMemoryStores::default();
        Self::with_stores(config, stores)
    }

    pub fn with_stores(config: AnticheatConfig, stores: InMemoryStores) -> Self {
        let pipeline = DecisionPipeline::new(config.clone(), stores.clone());
        let sessions = SessionValidator::default();
        let time = TimeValidator::new(
            config.max_future_ms,
            config.max_past_ms,
            config.clock_skew_ms,
        );
        Self {
            config,
            stores,
            pipeline,
            sessions,
            time,
            limits: ShapeLimits::default(),
        }
    }

    pub fn evaluate(&self, ctx: &RequestContext, state: &ServerState, now_ms: i64) -> CheckResult {
        let endpoint = normalize_endpoint(&ctx.endpoint);
        let class = classify_endpoint(&endpoint);
        let operation = operation_for_class(class);
        let req_fp = request_fingerprint(
            ctx.account_id.value(),
            ctx.session_id.value(),
            ctx.request_id.value(),
            ctx.sequence,
            &ctx.nonce,
            &endpoint,
        );
        let act_fp = action_fingerprint(&endpoint, &operation, &ctx.payload);
        let mut findings: Vec<Finding> = Vec::new();
        if self.config.rules.request_shape {
            if let Some(finding) = self.check_shape(ctx, &endpoint, &req_fp, &act_fp) {
                findings.push(finding);
            }
            if let Some(finding) = self.check_forbidden_flags(ctx, &endpoint, &req_fp, &act_fp) {
                findings.push(finding);
            }
        }
        if self.config.rules.session_binding {
            for finding in self.check_session(ctx, &endpoint, &req_fp, &act_fp, now_ms) {
                findings.push(finding);
            }
        }
        if self.config.rules.time_validation {
            if let Some(finding) = self.check_time(ctx, &endpoint, &req_fp, &act_fp, now_ms) {
                findings.push(finding);
            }
        }
        if self.config.rules.replay_detection {
            if let Some(finding) = self.check_replay(ctx, &endpoint, &req_fp, &act_fp, now_ms) {
                findings.push(finding);
            }
        }
        if self.config.rules.rate_limit {
            for finding in self.check_rates(ctx, &endpoint, &class, &req_fp, &act_fp, now_ms) {
                findings.push(finding);
            }
        }
        if self.config.rules.ownership {
            if let Some(finding) = self.check_ownership(ctx, &endpoint, &req_fp, &act_fp) {
                findings.push(finding);
            }
        }
        if self.config.rules.admin_guard {
            if let Some(finding) = self.check_admin(ctx, &endpoint, &req_fp, &act_fp) {
                findings.push(finding);
            }
        }
        if is_sensitive_mutation(&endpoint) {
            if self.config.rules.economy {
                for finding in self.check_economy(ctx, state, &endpoint, &req_fp, &act_fp) {
                    findings.push(finding);
                }
            }
            if self.config.rules.inventory {
                if let Some(finding) = self.check_inventory(ctx, state, &endpoint, &req_fp, &act_fp)
                {
                    findings.push(finding);
                }
            }
            if self.config.rules.stage_machine {
                if let Some(finding) =
                    self.check_stage(ctx, state, &endpoint, &req_fp, &act_fp, now_ms)
                {
                    findings.push(finding);
                }
            }
            if self.config.rules.reward_provenance {
                if let Some(finding) = self.check_reward(ctx, state, &endpoint, &req_fp, &act_fp) {
                    findings.push(finding);
                }
            }
            if self.config.rules.gacha_authority {
                if let Some(finding) = self.check_gacha(ctx, &endpoint, &req_fp, &act_fp) {
                    findings.push(finding);
                }
            }
            if self.config.rules.impossible_progression {
                if let Some(finding) = self.check_progression(ctx, &endpoint, &req_fp, &act_fp) {
                    findings.push(finding);
                }
            }
        }
        if self.config.rules.bot_detection {
            if let Some(finding) = self.check_bot(ctx, &endpoint, &req_fp, &act_fp, now_ms) {
                findings.push(finding);
            }
        }
        self.pipeline.decide(
            ctx.account_id.value(),
            ctx.session_id.value(),
            ctx.request_id.value(),
            ctx.sequence,
            &ctx.nonce,
            &endpoint,
            &operation,
            &ctx.payload,
            findings,
            now_ms,
        )
    }

    fn fail(
        rule: &str,
        severity: Severity,
        confidence: f32,
        delta: u8,
        message: String,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Finding {
        Finding::new(
            rule, severity, confidence, delta, message, endpoint, req_fp, act_fp,
        )
    }

    fn check_shape(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Option<Finding> {
        if ctx.payload_bytes > self.limits.max_bytes {
            return Some(Self::fail(
                "request.oversize",
                Severity::High,
                0.95,
                30,
                format!(
                    "payload bytes {} exceed limit {}",
                    ctx.payload_bytes, self.limits.max_bytes
                ),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        let fields = count_fields(&ctx.payload);
        if fields > self.limits.max_fields {
            return Some(Self::fail(
                "request.too_many_fields",
                Severity::High,
                0.9,
                28,
                format!("field count {fields} exceed limit"),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        let depth = payload_depth(&ctx.payload);
        if depth > self.limits.max_depth {
            return Some(Self::fail(
                "request.too_deep",
                Severity::High,
                0.9,
                28,
                format!("nesting depth {depth} exceed limit"),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        if let Some(obj) = ctx.payload.as_object() {
            for (key, value) in obj {
                if let Some(text) = value.as_str() {
                    if text.len() > self.limits.max_string_len {
                        return Some(Self::fail(
                            "request.string_too_long",
                            Severity::Medium,
                            0.8,
                            16,
                            format!("field {key} string too long"),
                            endpoint,
                            req_fp,
                            act_fp,
                        ));
                    }
                }
                if let Some(items) = value.as_array() {
                    if items.len() > self.limits.max_array_items {
                        return Some(Self::fail(
                            "request.array_too_large",
                            Severity::High,
                            0.9,
                            28,
                            format!("field {key} array too large"),
                            endpoint,
                            req_fp,
                            act_fp,
                        ));
                    }
                }
            }
        }
        None
    }

    fn check_forbidden_flags(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Option<Finding> {
        let forbidden = [
            "anti_cheat",
            "anticheat",
            "debug",
            "admin",
            "trusted",
            "bypass",
            "godmode",
        ];
        if let Some(obj) = ctx.payload.as_object() {
            for key in obj.keys() {
                let lower = key.to_lowercase();
                for flag in forbidden {
                    if lower.contains(flag) {
                        let is_true_bool = obj[key].as_bool().unwrap_or(false);
                        let is_true_str = obj[key]
                            .as_str()
                            .map(|text| text.to_lowercase() == "true")
                            .unwrap_or(false);
                        if is_true_bool || is_true_str {
                            return Some(Self::fail(
                                "protocol.forbidden_flag",
                                Severity::Critical,
                                0.9,
                                45,
                                format!("client sent forbidden flag {key}"),
                                endpoint,
                                req_fp,
                                act_fp,
                            ));
                        }
                    }
                }
            }
        }
        None
    }

    fn check_session(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
        now_ms: i64,
    ) -> Vec<Finding> {
        let mut out = Vec::new();
        let session_id = ctx.session_id.value();
        match self.stores.get_session(session_id) {
            None => {
                self.stores.upsert_session(SessionRecord {
                    session_id: session_id.to_string(),
                    account_id: ctx.account_id.value().to_string(),
                    created_ms: now_ms,
                    last_seen_ms: now_ms,
                    last_sequence: ctx.sequence,
                    fingerprint: ctx.device_fingerprint.clone().unwrap_or_default(),
                    ip: ctx.ip.clone(),
                    valid: true,
                    reconnects: 1,
                });
            }
            Some(record) => {
                if !record.valid {
                    out.push(Self::fail(
                        "session.invalidated",
                        Severity::Critical,
                        0.95,
                        50,
                        String::from("request on invalidated session"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                    return out;
                }
                if now_ms.saturating_sub(record.created_ms) > self.sessions.expiry_ms {
                    self.stores.invalidate_session(session_id);
                    out.push(Self::fail(
                        "session.expired",
                        Severity::High,
                        0.9,
                        30,
                        String::from("session exceeded expiry"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                    return out;
                }
                if record.account_id != ctx.account_id.value() {
                    out.push(Self::fail(
                        "session.hijack",
                        Severity::Critical,
                        0.9,
                        55,
                        String::from("session changed account identity"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                    return out;
                }
                let current_fp = ctx.device_fingerprint.clone().unwrap_or_default();
                if !record.fingerprint.is_empty()
                    && !current_fp.is_empty()
                    && record.fingerprint != current_fp
                {
                    let mut updated = record.clone();
                    updated.reconnects = updated.reconnects.saturating_add(1);
                    updated.fingerprint = current_fp;
                    updated.last_seen_ms = now_ms;
                    updated.last_sequence = ctx.sequence;
                    self.stores.upsert_session(updated);
                    out.push(Self::fail(
                        "session.fingerprint",
                        Severity::High,
                        0.75,
                        26,
                        String::from("session fingerprint changed"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                    return out;
                }
                if ctx.sequence < record.last_sequence {
                    out.push(Self::fail(
                        "session.stale_sequence",
                        Severity::High,
                        0.85,
                        30,
                        String::from("sequence moved backwards"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                    return out;
                }
                if ctx.sequence == record.last_sequence && record.last_sequence != 0 {
                    out.push(Self::fail(
                        "session.reused_sequence",
                        Severity::High,
                        0.85,
                        30,
                        String::from("sequence reused"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                    return out;
                }
                let mut updated = record.clone();
                updated.last_seen_ms = now_ms;
                updated.last_sequence = ctx.sequence;
                if let Some(ip) = ctx.ip.clone() {
                    updated.ip = Some(ip);
                }
                self.stores.upsert_session(updated);
            }
        }
        out
    }

    fn check_time(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
        now_ms: i64,
    ) -> Option<Finding> {
        let claimed = ctx.timestamp_ms;
        if claimed == 0 {
            return None;
        }
        match self.time.validate(claimed, now_ms) {
            anticheat_core::TimeVerdict::Ok => None,
            anticheat_core::TimeVerdict::Future => Some(Self::fail(
                "time.future",
                Severity::High,
                0.85,
                28,
                format!("client timestamp {claimed} is in the future"),
                endpoint,
                req_fp,
                act_fp,
            )),
            anticheat_core::TimeVerdict::TooOld => Some(Self::fail(
                "time.too_old",
                Severity::Medium,
                0.8,
                18,
                format!("client timestamp {claimed} is too old"),
                endpoint,
                req_fp,
                act_fp,
            )),
            anticheat_core::TimeVerdict::ImpossibleInterval => Some(Self::fail(
                "time.impossible",
                Severity::High,
                0.85,
                28,
                String::from("impossible time interval"),
                endpoint,
                req_fp,
                act_fp,
            )),
        }
    }

    fn check_replay(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
        now_ms: i64,
    ) -> Option<Finding> {
        let op_hash = operation_hash(ctx.account_id.value(), endpoint, &ctx.payload);
        let key = format!(
            "{}|{}|{op_hash}",
            ctx.session_id.value(),
            ctx.request_id.value()
        );
        let inserted = self.stores.insert_replay(
            key,
            ReplayRecord {
                fingerprint: req_fp.to_string(),
                first_seen_ms: now_ms,
                endpoint: endpoint.to_string(),
            },
        );
        if !inserted {
            return Some(Self::fail(
                "replay.duplicate",
                Severity::High,
                0.92,
                34,
                String::from("duplicate request id with same operation hash"),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        self.stores
            .prune_replay(now_ms.saturating_sub(self.config.replay_window_ms));
        None
    }

    fn check_rates(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        class: &anticheat_protocol::EndpointClass,
        req_fp: &str,
        act_fp: &str,
        now_ms: i64,
    ) -> Vec<Finding> {
        let mut out = Vec::new();
        let account_key = RateLimiter::key_for(&["account", ctx.account_id.value()]);
        if !RateLimiter::check(
            &self.stores,
            &account_key,
            self.config.rate_limit.per_account.capacity,
            self.config.rate_limit.per_account.refill_per_sec,
            now_ms,
            1.0,
        ) {
            out.push(Self::fail(
                "rate.account",
                Severity::Medium,
                0.8,
                20,
                String::from("account rate exceeded"),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        let session_key = RateLimiter::key_for(&["session", ctx.session_id.value()]);
        if !RateLimiter::check(
            &self.stores,
            &session_key,
            self.config.rate_limit.per_session.capacity,
            self.config.rate_limit.per_session.refill_per_sec,
            now_ms,
            1.0,
        ) {
            out.push(Self::fail(
                "rate.session",
                Severity::Medium,
                0.8,
                18,
                String::from("session rate exceeded"),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        let endpoint_key = RateLimiter::key_for(&["endpoint", endpoint]);
        if !RateLimiter::check(
            &self.stores,
            &endpoint_key,
            self.config.rate_limit.per_endpoint.capacity,
            self.config.rate_limit.per_endpoint.refill_per_sec,
            now_ms,
            1.0,
        ) {
            out.push(Self::fail(
                "rate.endpoint",
                Severity::Medium,
                0.75,
                16,
                String::from("endpoint rate exceeded"),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        if let Some(ip) = ctx.ip.as_deref() {
            let ip_key = RateLimiter::key_for(&["ip", ip]);
            if !RateLimiter::check(
                &self.stores,
                &ip_key,
                self.config.rate_limit.per_ip.capacity,
                self.config.rate_limit.per_ip.refill_per_sec,
                now_ms,
                1.0,
            ) {
                out.push(Self::fail(
                    "rate.ip",
                    Severity::Medium,
                    0.7,
                    14,
                    String::from("ip rate exceeded"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
        }
        let op_name = format!("{class:?}").to_lowercase();
        let bucket = self
            .config
            .rate_limit
            .per_operation
            .get(&op_name)
            .cloned()
            .unwrap_or(anticheat_core::RateLimitBucket {
                capacity: 20.0,
                refill_per_sec: 4.0,
            });
        let op_key = RateLimiter::key_for(&["op", ctx.account_id.value(), &op_name]);
        if !RateLimiter::check(
            &self.stores,
            &op_key,
            bucket.capacity,
            bucket.refill_per_sec,
            now_ms,
            1.0,
        ) {
            out.push(Self::fail(
                "rate.operation",
                Severity::Medium,
                0.8,
                20,
                format!("operation {op_name} rate exceeded"),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        out
    }

    fn check_ownership(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Option<Finding> {
        let claimed_account = ctx
            .payload
            .get("account_id")
            .and_then(|value| value.as_str());
        if let Some(claimed) = claimed_account {
            if claimed != ctx.account_id.value() {
                return Some(Self::fail(
                    "ownership.account_mismatch",
                    Severity::Critical,
                    0.9,
                    45,
                    String::from("payload account does not match session account"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
        }
        if ctx.gdkey.is_none() && is_sensitive_mutation(endpoint) {
            return Some(Self::fail(
                "ownership.missing_gdkey",
                Severity::High,
                0.8,
                26,
                String::from("sensitive mutation without account key"),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        if let (Some(udkey), Some(gdkey)) = (ctx.udkey.as_deref(), ctx.gdkey.as_deref()) {
            if udkey.is_empty() || gdkey.is_empty() {
                return Some(Self::fail(
                    "ownership.empty_key",
                    Severity::High,
                    0.85,
                    26,
                    String::from("empty device or account key"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
        }
        None
    }

    fn check_admin(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Option<Finding> {
        if !endpoint.to_lowercase().contains("admin") && ctx.is_admin {
            return Some(Self::fail(
                "admin.escalation",
                Severity::Critical,
                0.9,
                55,
                String::from("admin flag on non admin endpoint"),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        if let Some(obj) = ctx.payload.as_object() {
            for key in ["is_admin", "isadmin", "role", "privilege", "permissions"] {
                if obj.contains_key(key) {
                    return Some(Self::fail(
                        "admin.escalation",
                        Severity::Critical,
                        0.88,
                        50,
                        format!("client sent admin field {key}"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                }
            }
        }
        None
    }

    fn check_economy(
        &self,
        ctx: &RequestContext,
        state: &ServerState,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Vec<Finding> {
        let mut out = Vec::new();
        for (currency, delta) in &state.claimed_deltas {
            if *delta == 0 {
                continue;
            }
            let previous = state.previous_balances.get(currency).copied().unwrap_or(0);
            if previous < 0 {
                out.push(Self::fail(
                    "economy.invalid_previous",
                    Severity::High,
                    0.9,
                    32,
                    format!("currency {currency} previous balance invalid"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
            let next = previous.saturating_add(*delta);
            if *delta < 0 && next < 0 {
                out.push(Self::fail(
                    "economy.negative_balance",
                    Severity::Critical,
                    0.95,
                    48,
                    format!("currency {currency} would go negative"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
            if *delta > 0 && state.reward_cause.is_none() {
                let claimed_source = ctx
                    .payload
                    .get("source")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                if claimed_source.is_empty() {
                    out.push(Self::fail(
                        "economy.missing_source",
                        Severity::High,
                        0.85,
                        32,
                        format!("currency {currency} mint without source"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                }
            }
            if delta.abs() > 9_000_000_000 {
                out.push(Self::fail(
                    "economy.overflow",
                    Severity::Critical,
                    0.9,
                    45,
                    format!("currency {currency} delta overflow risk"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
        }
        for key in [
            "coins", "ymoney", "y_points", "hitodama", "stamina", "tickets",
        ] {
            if let Some(value) = ctx.payload.get(key) {
                if let Some(number) = value.as_i64() {
                    if number < 0 {
                        out.push(Self::fail(
                            "economy.client_balance",
                            Severity::Critical,
                            0.92,
                            42,
                            format!("client sent negative {key}"),
                            endpoint,
                            req_fp,
                            act_fp,
                        ));
                    }
                }
                if let Some(unsigned) = value.as_u64() {
                    if unsigned > 100_000_000 {
                        out.push(Self::fail(
                            "economy.impossible_amount",
                            Severity::High,
                            0.75,
                            24,
                            format!("client sent impossible {key} amount"),
                            endpoint,
                            req_fp,
                            act_fp,
                        ));
                    }
                }
            }
        }
        out
    }

    fn check_inventory(
        &self,
        ctx: &RequestContext,
        state: &ServerState,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Option<Finding> {
        let claimed_items: Vec<String> = ctx
            .payload
            .get("items")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|entry| {
                        entry
                            .get("id")
                            .and_then(|id| id.as_str())
                            .map(|text| text.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        for item in &claimed_items {
            if !state.owned_items.contains(item) && state.reward_cause.is_none() {
                return Some(Self::fail(
                    "inventory.no_provenance",
                    Severity::High,
                    0.82,
                    30,
                    format!("item {item} has no valid source"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
        }
        if let Some(count) = ctx.payload.get("count").and_then(|value| value.as_i64()) {
            if count < 0 || count > 9999 {
                return Some(Self::fail(
                    "inventory.bad_count",
                    Severity::High,
                    0.88,
                    28,
                    String::from("item count out of range"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
        }
        None
    }

    fn check_stage(
        &self,
        ctx: &RequestContext,
        state: &ServerState,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
        now_ms: i64,
    ) -> Option<Finding> {
        let lower = endpoint.to_lowercase();
        let is_end = lower.contains("gameend") || lower.contains("game_end");
        let is_start = lower.contains("gamestart") || lower.contains("game_start");
        if !is_end && !is_start {
            return None;
        }
        if is_end {
            match state.stage_state {
                Some(StageState::Started) => {}
                Some(StageState::NotStarted) | None => {
                    return Some(Self::fail(
                        "stage.skipped",
                        Severity::Critical,
                        0.9,
                        44,
                        String::from("reward path without valid stage start"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                }
                Some(StageState::Completed) | Some(StageState::RewardGranted) => {
                    return Some(Self::fail(
                        "stage.duplicate_completion",
                        Severity::High,
                        0.88,
                        32,
                        String::from("duplicate stage completion"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                }
            }
            let elapsed = ctx
                .payload
                .get("elapsed_ms")
                .and_then(|value| value.as_i64())
                .unwrap_or(now_ms.saturating_sub(ctx.timestamp_ms).max(0));
            if elapsed >= 0 && elapsed < self.config.min_stage_ms {
                return Some(Self::fail(
                    "stage.too_fast",
                    Severity::High,
                    0.8,
                    30,
                    format!("completion in {elapsed}ms below minimum"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
            let clear_time = ctx
                .payload
                .get("clearTimeSec")
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            if clear_time > 0
                && clear_time * 1000 > elapsed + self.config.clock_skew_ms
                && elapsed >= 0
            {
                return Some(Self::fail(
                    "stage.impossible_time",
                    Severity::High,
                    0.88,
                    34,
                    String::from("clear time exceeds elapsed time"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
            let score = ctx
                .payload
                .get("score")
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            if score > 0 && elapsed >= 0 {
                let cap = 1_000_000 + (elapsed / 1000) * self.config.max_score_per_second;
                if score > cap {
                    return Some(Self::fail(
                        "stage.impossible_score",
                        Severity::High,
                        0.85,
                        32,
                        format!("score {score} above cap {cap}"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                }
            }
        }
        None
    }

    fn check_reward(
        &self,
        ctx: &RequestContext,
        state: &ServerState,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Option<Finding> {
        let lower = endpoint.to_lowercase();
        let looks_like_reward = lower.contains("reward")
            || lower.contains("present")
            || lower.contains("mission")
            || lower.contains("loginstamp")
            || lower.contains("login_stamp")
            || lower.contains("gameend")
            || lower.contains("game_end");
        if !looks_like_reward {
            return None;
        }
        if state.reward_cause.is_none() {
            let has_cause = ctx
                .payload
                .get("cause")
                .and_then(|value| value.as_str())
                .is_some()
                || ctx
                    .payload
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .is_some()
                || ctx
                    .payload
                    .get("source")
                    .and_then(|value| value.as_str())
                    .is_some();
            if !has_cause && !state.claimed_deltas.is_empty() {
                return Some(Self::fail(
                    "reward.no_provenance",
                    Severity::High,
                    0.85,
                    32,
                    String::from("reward without valid cause"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
        }
        None
    }

    fn check_gacha(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Option<Finding> {
        let lower = endpoint.to_lowercase();
        if !lower.contains("gacha") && !lower.contains("crank") {
            return None;
        }
        if let Some(obj) = ctx.payload.as_object() {
            for key in [
                "rarity", "itemId", "item_id", "result", "reward", "seed", "random",
            ] {
                if obj.contains_key(key) {
                    return Some(Self::fail(
                        "gacha.client_result",
                        Severity::Critical,
                        0.9,
                        46,
                        format!("client sent gacha field {key}; server must roll"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                }
            }
        }
        None
    }

    fn check_progression(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
    ) -> Option<Finding> {
        if let Some(level) = ctx.payload.get("level").and_then(|value| value.as_i64()) {
            if level < 1 || level > 200 {
                return Some(Self::fail(
                    "progression.bad_level",
                    Severity::High,
                    0.88,
                    30,
                    String::from("level outside valid range"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
        }
        if let Some(xp) = ctx.payload.get("xp").and_then(|value| value.as_i64()) {
            if xp < 0 || xp > 100_000_000 {
                return Some(Self::fail(
                    "progression.bad_xp",
                    Severity::High,
                    0.85,
                    28,
                    String::from("xp outside valid range"),
                    endpoint,
                    req_fp,
                    act_fp,
                ));
            }
        }
        None
    }

    fn check_bot(
        &self,
        ctx: &RequestContext,
        endpoint: &str,
        req_fp: &str,
        act_fp: &str,
        now_ms: i64,
    ) -> Option<Finding> {
        let key = format!("bot|{}|{endpoint}", ctx.account_id.value());
        let times = self.stores.push_event_time(key, now_ms, 60000);
        if times.len() >= 120 {
            return Some(Self::fail(
                "bot.flood",
                Severity::High,
                0.75,
                26,
                format!("{} requests in 60s", times.len()),
                endpoint,
                req_fp,
                act_fp,
            ));
        }
        if times.len() >= 12 {
            let mut gaps: Vec<i64> = Vec::new();
            for window in times.windows(2) {
                gaps.push(window[1].saturating_sub(window[0]));
            }
            if !gaps.is_empty() {
                let first = gaps[0];
                let identical = gaps.iter().filter(|gap| (**gap - first).abs() < 25).count();
                if identical >= 10 && first < 1500 && first >= 0 {
                    return Some(Self::fail(
                        "bot.regularity",
                        Severity::Medium,
                        0.7,
                        18,
                        String::from("overly regular request cadence"),
                        endpoint,
                        req_fp,
                        act_fp,
                    ));
                }
            }
        }
        None
    }
}

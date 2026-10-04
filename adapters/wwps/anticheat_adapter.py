from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.request
import uuid
from dataclasses import dataclass, field


@dataclass
class AnticheatState:
    previous_balances: dict = field(default_factory=dict)
    claimed_deltas: dict = field(default_factory=dict)
    stage_state: str | None = None
    owned_items: list = field(default_factory=list)
    owned_yokai: list = field(default_factory=list)
    reward_cause: str | None = None


@dataclass
class AnticheatVerdict:
    allowed: bool
    action: str
    risk_score: int
    findings: list
    audit_id: str


class AnticheatAdapter:
    def __init__(self, base_url="http://127.0.0.1:12777", token="", timeout=0.25, fail_closed=True, mode="enforce"):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.fail_closed = fail_closed
        self.mode = mode
        self._sequence: dict = {}

    def next_sequence(self, session_id: str) -> int:
        current = self._sequence.get(session_id, 0) + 1
        self._sequence[session_id] = current
        return current

    def build_envelope(self, account_id, session_id, request_id, sequence, endpoint, payload, udkey=None, gdkey=None, ip=None, device=None, is_admin=False):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return {
            "account_id": account_id,
            "session_id": session_id,
            "request_id": request_id,
            "sequence": sequence,
            "nonce": uuid.uuid4().hex,
            "timestamp_ms": int(time.time() * 1000),
            "endpoint": endpoint,
            "ip": ip,
            "device_fingerprint": device,
            "udkey": udkey,
            "gdkey": gdkey,
            "is_admin": is_admin,
            "payload": payload,
            "payload_bytes": len(body.encode("utf-8")),
        }

    def sign(self, body: bytes) -> str:
        return hmac.new(self.token.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def check(self, envelope: dict, state: AnticheatState | None = None) -> AnticheatVerdict:
        if self.mode == "off":
            return AnticheatVerdict(True, "Allow", 0, [], "disabled")
        payload = {"account_id": envelope["account_id"]}
        _ = payload
        body = {
            "account_id": envelope["account_id"],
            "session_id": envelope["session_id"],
            "request_id": envelope["request_id"],
            "sequence": envelope["sequence"],
            "nonce": envelope["nonce"],
            "timestamp_ms": envelope["timestamp_ms"],
            "endpoint": envelope["endpoint"],
            "ip": envelope.get("ip"),
            "device_fingerprint": envelope.get("device_fingerprint"),
            "udkey": envelope.get("udkey"),
            "gdkey": envelope.get("gdkey"),
            "is_admin": envelope.get("is_admin", False),
            "payload": envelope.get("payload", {}),
            "state": {
                "previous_balances": (state.previous_balances if state else {}),
                "claimed_deltas": (state.claimed_deltas if state else {}),
                "stage_state": (state.stage_state if state else None),
                "owned_items": (state.owned_items if state else []),
                "owned_yokai": (state.owned_yokai if state else []),
                "reward_cause": (state.reward_cause if state else None),
                "session_known_sequence": None,
                "account_risk_score": 0,
            },
        }
        raw = json.dumps(body).encode("utf-8")
        if len(raw) > 262144:
            return AnticheatVerdict(False, "Deny", 100, [{"rule_id": "request.oversize"}], "local")
        request = urllib.request.Request(
            self.base_url + "/check",
            data=raw,
            headers={
                "Content-Type": "application/json",
                "X-Anticheat-Token": self.sign(raw),
                "X-Request-Id": envelope["request_id"],
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                parsed = json.loads(response.read().decode("utf-8"))
                allowed = bool(parsed.get("allowed", False))
                if self.mode in ("shadow", "log_only"):
                    allowed = True
                return AnticheatVerdict(
                    allowed,
                    str(parsed.get("action", "Deny")),
                    int(parsed.get("risk_score", 0)),
                    list(parsed.get("findings", [])),
                    str(parsed.get("audit_id", "")),
                )
        except Exception:
            if self.fail_closed:
                return AnticheatVerdict(False, "Deny", 100, [{"rule_id": "anticheat.unreachable"}], "local")
            return AnticheatVerdict(True, "AllowAndLog", 0, [{"rule_id": "anticheat.unreachable"}], "local")

    def check_nhn(self, path, payload, gdkey=None, udkey=None, ip=None, device=None) -> AnticheatVerdict:
        account = str(gdkey or payload.get("gdkeyValue") or payload.get("gdkey") or payload.get("level5UserId") or "unknown")
        session = str(payload.get("sessionId") or udkey or device or "unknown")
        sequence = self.next_sequence(session)
        envelope = self.build_envelope(account, session, uuid.uuid4().hex, sequence, path, payload, udkey=udkey, gdkey=gdkey, ip=ip, device=device)
        state = self.extract_state(payload)
        return self.check(envelope, state)

    def extract_state(self, payload: dict) -> AnticheatState:
        state = AnticheatState()
        for key in ("coins", "ymoney", "hitodama", "y_points"):
            if key in payload and isinstance(payload[key], int):
                state.previous_balances[key] = 0
        cause = payload.get("cause") or payload.get("source") or payload.get("reason")
        if isinstance(cause, str) and cause:
            state.reward_cause = cause
        return state

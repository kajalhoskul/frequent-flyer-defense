"""In-memory security state for the loyalty portal."""
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

RATE_WINDOW = 30
BLOCK_SECONDS = 60
POST_RECOVERY_WINDOW = 30 * 60  # 30 minutes


@dataclass
class ClientState:
    login_attempts: deque = field(default_factory=lambda: deque(maxlen=200))
    login_usernames_tried: set = field(default_factory=set)
    recovery_attempts: deque = field(default_factory=lambda: deque(maxlen=200))
    recovery_targets_tried: set = field(default_factory=set)
    score: float = 0.0
    reasons: set = field(default_factory=set)
    blocked_until: float = 0.0


class SecurityStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._clients: dict[str, ClientState] = defaultdict(ClientState)
        self._recovery_events: dict[str, float] = {}  # ff_number -> last recovery timestamp
        self._blocks_log: deque = deque(maxlen=200)
        self._recovery_log: deque = deque(maxlen=200)
        self._fraud_alerts: deque = deque(maxlen=200)

    def lock(self):
        return self._lock

    def client(self, key: str) -> ClientState:
        return self._clients[key]

    def record_recovery(self, ff_number: str, client_key: str):
        now = time.time()
        self._recovery_events[ff_number] = now
        self._recovery_log.append({"ff_number": ff_number, "client": client_key, "ts": now})

    def recent_recovery(self, ff_number: str):
        """Returns the timestamp of the account's most recent recovery
        event if it happened within the correlation window, else None."""
        ts = self._recovery_events.get(ff_number)
        if ts and time.time() - ts <= POST_RECOVERY_WINDOW:
            return ts
        return None

    def record_fraud_alert(self, ff_number: str, action: str, minutes_since_recovery: float):
        self._fraud_alerts.append({
            "ff_number": ff_number, "action": action,
            "minutes_since_recovery": round(minutes_since_recovery, 1),
            "ts": time.time(),
        })

    def record_block(self, key: str, reasons, ts: float):
        self._blocks_log.append({"key": key, "reasons": sorted(reasons), "ts": ts})

    def totals(self):
        return {
            "active_blocks": sum(1 for c in self._clients.values() if c.blocked_until > time.time()),
            "total_blocks_ever": len(self._blocks_log),
            "recovery_events": len(self._recovery_log),
            "fraud_alerts": len(self._fraud_alerts),
        }

    def top_clients(self, n=10):
        with self._lock:
            ranked = sorted(self._clients.items(), key=lambda kv: kv[1].score, reverse=True)
        out = []
        for key, state in ranked[:n]:
            if state.score <= 0:
                continue
            out.append({
                "key": key, "score": round(state.score, 1),
                "reasons": sorted(state.reasons),
                "blocked": state.blocked_until > time.time(),
            })
        return out

    def recent_fraud_alerts(self, n=10):
        return list(self._fraud_alerts)[-n:][::-1]

    def recent_blocks(self, n=10):
        return list(self._blocks_log)[-n:][::-1]

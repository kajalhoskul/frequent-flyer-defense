"""Detection signals modeled directly on the real 2025 Qantas/Hawaiian
Airlines breaches: attackers (attributed to "Scattered Spider") impersonate
employees or customers to trick support/self-service flows into resetting
MFA or passwords, then take over the account. Credential stuffing is the
older, more familiar attack this also defends against, but the account-
RECOVERY abuse pattern is the one that actually mattered in these
incidents -- and it can't be caught by login-page defenses alone, since
the attacker in the real story never had to guess a password.
"""
import time

from .store import BLOCK_SECONDS, POST_RECOVERY_WINDOW, SecurityStore

RATE_WINDOW = 30
BLOCK_THRESHOLD = 8.0

WEIGHTS = {
    "credential_stuffing_burst": 6.0,
    "credential_stuffing_many_usernames": 5.0,
    "recovery_enumeration": 9.0,
}


def evaluate_login(store: SecurityStore, key: str, ff_number: str, success: bool):
    now = time.time()
    with store.lock():
        client = store.client(key)
        reasons = set(client.reasons)

        client.login_attempts.append(now)
        client.login_usernames_tried.add(ff_number)
        recent = [t for t in client.login_attempts if now - t <= RATE_WINDOW]

        if len(recent) >= 6:
            reasons.add("credential_stuffing_burst")
        if len(client.login_usernames_tried) >= 4:
            reasons.add("credential_stuffing_many_usernames")

        client.reasons = reasons
        client.score = sum(WEIGHTS.get(r, 0) for r in reasons)

        blocked = False
        if client.score >= BLOCK_THRESHOLD and client.blocked_until <= now:
            client.blocked_until = now + BLOCK_SECONDS
            blocked = True
            store.record_block(key, reasons, now)

        return client.score, reasons, blocked


def evaluate_recovery_request(store: SecurityStore, key: str, ff_number: str):
    """Models the exact Scattered Spider pattern: someone testing/hitting
    the account-recovery flow for many different accounts in a short
    window -- reconnaissance for "which frequent-flyer numbers are real
    and worth a social-engineering call to support."
    """
    now = time.time()
    with store.lock():
        client = store.client(key)
        reasons = set(client.reasons)

        client.recovery_attempts.append(now)
        client.recovery_targets_tried.add(ff_number)
        recent = [t for t in client.recovery_attempts if now - t <= RATE_WINDOW]

        if len(client.recovery_targets_tried) >= 4 or len(recent) >= 5:
            reasons.add("recovery_enumeration")

        client.reasons = reasons
        client.score = sum(WEIGHTS.get(r, 0) for r in reasons)

        blocked = False
        if client.score >= BLOCK_THRESHOLD and client.blocked_until <= now:
            client.blocked_until = now + BLOCK_SECONDS
            blocked = True
            store.record_block(key, reasons, now)

        return client.score, reasons, blocked


def check_post_recovery_action(store: SecurityStore, ff_number: str, action: str) -> bool:
    """The headline check: a sensitive action (redeem points, add a new
    payment method) happening shortly after an account-recovery event is a
    strong real-world fraud signal, REGARDLESS of whether the login/
    recovery itself looked individually legitimate -- exactly the gap that
    let the real 2025 attacks succeed (each step, alone, passed).

    This does not block the action -- a real recovered-and-now-locked-out
    user redeeming points is completely normal. It raises a fraud alert
    for review, which is the realistic response: a blanket block here
    would punish legitimate users far more often than attackers.
    """
    recovery_ts = store.recent_recovery(ff_number)
    if recovery_ts is None:
        return False
    minutes_since = (time.time() - recovery_ts) / 60.0
    store.record_fraud_alert(ff_number, action, minutes_since)
    return True


def is_currently_blocked(store: SecurityStore, key: str) -> bool:
    with store.lock():
        return store.client(key).blocked_until > time.time()

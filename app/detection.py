"""
Detection engine: runs a set of rules against a new logon event, using the
user's recent history for context. Each rule that fires contributes a
weighted "finding" -- these get summed into a risk score and mapped to a
severity, and a plain-English summary is generated for the dashboard/alert.

This is intentionally rule-based (fast, explainable, no training data
needed) rather than a black-box model, since "why was this flagged" matters
a lot for a security tool. You can swap/extend individual rules, or feed
the same LogonEvent history into a model later (e.g. isolation forest on
[hour_of_day, is_new_device, is_new_country, failed_count] as features)
without changing the API surface below.
"""
from datetime import datetime, timedelta
from typing import List, Tuple

from sqlalchemy.orm import Session

from app.models import LogonEvent

# ---- tunable thresholds -----------------------------------------------
BRUTE_FORCE_WINDOW_MIN = 10
BRUTE_FORCE_FAILED_THRESHOLD = 5

CREDENTIAL_STUFFING_WINDOW_MIN = 10
CREDENTIAL_STUFFING_DISTINCT_USERS = 5

IMPOSSIBLE_TRAVEL_WINDOW_HOURS = 2

OFF_HOURS_START = 22  # 10pm
OFF_HOURS_END = 6     # 6am

SEVERITY_BANDS = [
    (0, 19, "none"),
    (20, 39, "low"),
    (40, 69, "medium"),
    (70, 89, "high"),
    (90, 10_000, "critical"),
]


def _severity_for_score(score: int) -> str:
    for low, high, label in SEVERITY_BANDS:
        if low <= score <= high:
            return label
    return "none"


def evaluate_event(db: Session, event: LogonEvent) -> Tuple[int, str, List[dict]]:
    """
    Runs all detection rules against `event` (already committed with an id).
    Returns (risk_score, severity, findings) where findings is a list of
    {"rule": ..., "weight": ..., "detail": ...} dicts.
    """
    findings: List[dict] = []

    _rule_failed_login_burst(db, event, findings)
    _rule_credential_stuffing(db, event, findings)
    _rule_new_device_or_ip(db, event, findings)
    _rule_impossible_travel(db, event, findings)
    _rule_off_hours_privileged(db, event, findings)

    score = min(sum(f["weight"] for f in findings), 100)
    severity = _severity_for_score(score) if findings else "none"
    return score, severity, findings


def _rule_failed_login_burst(db: Session, event: LogonEvent, findings: list):
    """Many failed logins for the same user in a short window -> brute force."""
    if event.success:
        return
    window_start = event.timestamp - timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)
    failed_count = (
        db.query(LogonEvent)
        .filter(
            LogonEvent.user_id == event.user_id,
            LogonEvent.success.is_(False),
            LogonEvent.timestamp >= window_start,
            LogonEvent.timestamp <= event.timestamp,
        )
        .count()
    )
    if failed_count >= BRUTE_FORCE_FAILED_THRESHOLD:
        findings.append({
            "rule": "brute_force_attempt",
            "weight": 50,
            "detail": f"{failed_count} failed logins for '{event.user_id}' "
                      f"in the last {BRUTE_FORCE_WINDOW_MIN} minutes.",
        })


def _rule_credential_stuffing(db: Session, event: LogonEvent, findings: list):
    """One IP hitting many distinct accounts quickly -> credential stuffing."""
    if not event.ip_address:
        return
    window_start = event.timestamp - timedelta(minutes=CREDENTIAL_STUFFING_WINDOW_MIN)
    distinct_users = (
        db.query(LogonEvent.user_id)
        .filter(
            LogonEvent.ip_address == event.ip_address,
            LogonEvent.timestamp >= window_start,
            LogonEvent.timestamp <= event.timestamp,
        )
        .distinct()
        .count()
    )
    if distinct_users >= CREDENTIAL_STUFFING_DISTINCT_USERS:
        findings.append({
            "rule": "credential_stuffing_pattern",
            "weight": 45,
            "detail": f"IP {event.ip_address} attempted logins for "
                      f"{distinct_users} different accounts within "
                      f"{CREDENTIAL_STUFFING_WINDOW_MIN} minutes.",
        })


def _rule_new_device_or_ip(db: Session, event: LogonEvent, findings: list):
    """First time this user has logged in from this device/IP."""
    if not event.success:
        return
    if event.device_fingerprint:
        seen_device = (
            db.query(LogonEvent)
            .filter(
                LogonEvent.user_id == event.user_id,
                LogonEvent.device_fingerprint == event.device_fingerprint,
                LogonEvent.id != event.id,
            )
            .first()
        )
        if not seen_device:
            findings.append({
                "rule": "new_device",
                "weight": 15,
                "detail": f"First successful login from device "
                          f"'{event.device_fingerprint}' for user '{event.user_id}'.",
            })
    if event.ip_address:
        seen_ip = (
            db.query(LogonEvent)
            .filter(
                LogonEvent.user_id == event.user_id,
                LogonEvent.ip_address == event.ip_address,
                LogonEvent.id != event.id,
            )
            .first()
        )
        if not seen_ip:
            findings.append({
                "rule": "new_ip_address",
                "weight": 10,
                "detail": f"First successful login from IP "
                          f"{event.ip_address} for user '{event.user_id}'.",
            })


def _rule_impossible_travel(db: Session, event: LogonEvent, findings: list):
    """Two successful logins from different countries too close together."""
    if not event.success or not event.country:
        return
    window_start = event.timestamp - timedelta(hours=IMPOSSIBLE_TRAVEL_WINDOW_HOURS)
    prior = (
        db.query(LogonEvent)
        .filter(
            LogonEvent.user_id == event.user_id,
            LogonEvent.success.is_(True),
            LogonEvent.country.isnot(None),
            LogonEvent.timestamp >= window_start,
            LogonEvent.timestamp < event.timestamp,
        )
        .order_by(LogonEvent.timestamp.desc())
        .first()
    )
    if prior and prior.country != event.country:
        elapsed = (event.timestamp - prior.timestamp).total_seconds() / 3600
        findings.append({
            "rule": "impossible_travel",
            "weight": 60,
            "detail": f"Login from {event.country} only {elapsed:.1f}h after a "
                      f"login from {prior.country} for user '{event.user_id}'.",
        })


def _rule_off_hours_privileged(db: Session, event: LogonEvent, findings: list):
    """Privileged account logging in outside normal business hours."""
    if not event.is_privileged or not event.success:
        return
    hour = event.timestamp.hour
    if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
        findings.append({
            "rule": "off_hours_privileged_login",
            "weight": 25,
            "detail": f"Privileged account '{event.user_id}' logged in at "
                      f"{event.timestamp.strftime('%H:%M')} UTC, outside "
                      f"business hours.",
        })


def summarize(findings: List[dict], severity: str) -> str:
    """Plain-English summary for the dashboard/alert feed."""
    if not findings:
        return "No anomalies detected; logon matches expected patterns."
    reasons = "; ".join(f["detail"] for f in findings)
    return f"[{severity.upper()}] {reasons}"

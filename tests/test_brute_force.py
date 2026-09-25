"""
Tests for the brute force detection logic against synthetic log data.

Run with: pytest tests/test_brute_force.py -v
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detections.brute_force import detect_brute_force


def test_detects_real_brute_force_attack():
    """10 failed logins in 3 minutes, then a success -> should alert."""
    start = datetime(2026, 9, 24, 10, 0, 0)
    events = [
        {"time": start + timedelta(seconds=i * 15), "user": "jsmith",
         "src_ip": "203.0.113.55", "status": "fail", "dest": "DC01"}
        for i in range(10)
    ]
    events.append({
        "time": start + timedelta(seconds=10 * 15 + 5), "user": "jsmith",
        "src_ip": "203.0.113.55", "status": "success", "dest": "DC01",
    })

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["user"] == "jsmith"
    assert alerts[0]["src_ip"] == "203.0.113.55"
    assert alerts[0]["fail_count"] >= 8


def test_ignores_normal_user_who_mistypes_password_twice():
    """A user fails twice, then logs in successfully -> should NOT alert."""
    start = datetime(2026, 9, 24, 11, 0, 0)
    events = [
        {"time": start, "user": "mgarcia", "src_ip": "10.1.2.30", "status": "fail", "dest": "DC01"},
        {"time": start + timedelta(seconds=20), "user": "mgarcia", "src_ip": "10.1.2.30", "status": "fail", "dest": "DC01"},
        {"time": start + timedelta(seconds=40), "user": "mgarcia", "src_ip": "10.1.2.30", "status": "success", "dest": "DC01"},
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_ignores_failures_spread_outside_the_time_window():
    """8 failures spread across 2 hours (not a burst) -> should NOT alert,
    since they fall outside the 10-minute sliding window."""
    start = datetime(2026, 9, 24, 12, 0, 0)
    events = [
        {"time": start + timedelta(minutes=i * 15), "user": "bwong",
         "src_ip": "10.1.2.40", "status": "fail", "dest": "DC01"}
        for i in range(8)
    ]
    events.append({
        "time": start + timedelta(minutes=8 * 15 + 1), "user": "bwong",
        "src_ip": "10.1.2.40", "status": "success", "dest": "DC01",
    })

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_does_not_alert_on_failures_with_no_eventual_success():
    """An attacker who never guesses the password correctly -> should NOT
    alert under this detection (a separate 'repeated failures only'
    detection would catch this case — see severity-sla-matrix.md)."""
    start = datetime(2026, 9, 24, 13, 0, 0)
    events = [
        {"time": start + timedelta(seconds=i * 10), "user": "admin",
         "src_ip": "198.51.100.9", "status": "fail", "dest": "DC01"}
        for i in range(15)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0

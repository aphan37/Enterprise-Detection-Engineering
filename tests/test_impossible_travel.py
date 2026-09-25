"""
Tests for the impossible travel detection logic against synthetic login data.

Run with: pytest tests/test_impossible_travel.py -v
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detections.impossible_travel import detect_impossible_travel

# Approximate real-world coordinates used across tests
NEW_YORK = (40.7128, -74.0060)
TOKYO = (35.6762, 139.6503)
LONDON = (51.5074, -0.1278)


def test_detects_login_from_new_york_then_tokyo_10_minutes_later():
    """Physically impossible: ~10,850 km in 10 minutes -> should alert."""
    start = datetime(2026, 9, 24, 9, 0)
    events = [
        {"time": start, "user": "ppatel", "src_ip": "203.0.113.10", "lat": NEW_YORK[0], "lon": NEW_YORK[1]},
        {"time": start + timedelta(minutes=10), "user": "ppatel", "src_ip": "198.51.100.20", "lat": TOKYO[0], "lon": TOKYO[1]},
    ]

    alerts = detect_impossible_travel(events)

    assert len(alerts) == 1
    assert alerts[0]["user"] == "ppatel"
    assert alerts[0]["implied_speed_kmh"] > 900


def test_ignores_two_logins_from_the_same_city():
    """Same approximate location twice (e.g., office wifi then home wifi,
    same metro area) -> distance too small to ever alert."""
    start = datetime(2026, 9, 24, 10, 0)
    events = [
        {"time": start, "user": "rkim", "src_ip": "10.1.1.5", "lat": NEW_YORK[0], "lon": NEW_YORK[1]},
        {"time": start + timedelta(minutes=5), "user": "rkim", "src_ip": "10.1.1.6",
         "lat": NEW_YORK[0] + 0.05, "lon": NEW_YORK[1] + 0.05},
    ]

    alerts = detect_impossible_travel(events)

    assert len(alerts) == 0


def test_ignores_a_real_long_haul_flight():
    """A genuine New York -> London trip with a realistic 7-hour flight
    plus connection time -> implied speed stays under commercial-flight
    threshold, so this should NOT alert."""
    start = datetime(2026, 9, 24, 8, 0)
    events = [
        {"time": start, "user": "tolawale", "src_ip": "10.1.1.9", "lat": NEW_YORK[0], "lon": NEW_YORK[1]},
        {"time": start + timedelta(hours=10), "user": "tolawale", "src_ip": "10.1.1.9",
         "lat": LONDON[0], "lon": LONDON[1]},
    ]

    alerts = detect_impossible_travel(events)

    assert len(alerts) == 0


def test_only_flags_the_affected_user_not_other_users_logging_in_normally():
    """A compromised user's impossible travel shouldn't cause false alerts
    on unrelated users logging in normally around the same time."""
    start = datetime(2026, 9, 24, 12, 0)
    events = [
        # attacker pattern
        {"time": start, "user": "compromised.acct", "src_ip": "203.0.113.1", "lat": NEW_YORK[0], "lon": NEW_YORK[1]},
        {"time": start + timedelta(minutes=8), "user": "compromised.acct", "src_ip": "198.51.100.2", "lat": TOKYO[0], "lon": TOKYO[1]},
        # unrelated normal user, single login, no prior event to compare against
        {"time": start + timedelta(minutes=3), "user": "normal.user", "src_ip": "10.1.1.50", "lat": LONDON[0], "lon": LONDON[1]},
    ]

    alerts = detect_impossible_travel(events)

    assert len(alerts) == 1
    assert alerts[0]["user"] == "compromised.acct"

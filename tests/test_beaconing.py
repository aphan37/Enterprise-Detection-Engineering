"""
Tests for the periodic beaconing (C2) detection logic against synthetic
connection data.

Run with: pytest tests/test_beaconing.py -v
"""

import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detections.beaconing import detect_beaconing


def test_detects_regular_60_second_beacon():
    """25 connections roughly every 60 seconds (small jitter) -> classic
    malware check-in pattern -> should alert."""
    random.seed(42)
    start = datetime(2026, 9, 24, 14, 0)
    times = []
    t = start
    for _ in range(25):
        times.append(t)
        t += timedelta(seconds=60 + random.uniform(-2, 2))

    connections = [{"time": t, "src_ip": "10.1.1.77", "dest_ip": "198.51.100.99"} for t in times]

    alerts = detect_beaconing(connections)

    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "10.1.1.77"
    assert alerts[0]["jitter_ratio"] < 0.15


def test_ignores_irregular_human_browsing_traffic():
    """25 connections to the same site with human-like irregular timing
    (bursts and long pauses) -> high jitter -> should NOT alert."""
    random.seed(7)
    start = datetime(2026, 9, 24, 15, 0)
    times = []
    t = start
    for _ in range(25):
        times.append(t)
        # human browsing: anywhere from 5 seconds to 10 minutes between requests
        t += timedelta(seconds=random.uniform(5, 600))

    connections = [{"time": t, "src_ip": "10.1.1.40", "dest_ip": "203.0.113.5"} for t in times]

    alerts = detect_beaconing(connections)

    assert len(alerts) == 0


def test_ignores_regular_traffic_below_the_connection_count_threshold():
    """Only 5 highly regular connections -> not enough observations yet to
    confidently call it a beacon -> should NOT alert."""
    start = datetime(2026, 9, 24, 16, 0)
    times = [start + timedelta(seconds=60 * i) for i in range(5)]

    connections = [{"time": t, "src_ip": "10.1.1.88", "dest_ip": "198.51.100.77"} for t in times]

    alerts = detect_beaconing(connections)

    assert len(alerts) == 0


def test_ignores_regular_but_very_fast_polling_like_local_health_checks():
    """25 connections exactly every 5 seconds -> regular, but faster than
    the min_avg_interval_sec floor meant to exclude tight local polling
    loops (e.g., a health check) -> should NOT alert."""
    start = datetime(2026, 9, 24, 17, 0)
    times = [start + timedelta(seconds=5 * i) for i in range(25)]

    connections = [{"time": t, "src_ip": "10.1.1.15", "dest_ip": "10.1.1.2"} for t in times]

    alerts = detect_beaconing(connections)

    assert len(alerts) == 0

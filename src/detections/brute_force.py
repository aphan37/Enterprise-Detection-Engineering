"""
brute_force.py

Plain-Python reimplementation of the SPL logic in:
  detections/credential-access/brute-force-auth-failures.md

This lets the detection logic be unit-tested without a Splunk instance.
The SPL `transaction ... maxspan=10m` + fail_count threshold is reproduced
here using a sliding time window per (user, src_ip) pair.
"""

from collections import defaultdict
from datetime import timedelta


def detect_brute_force(events, fail_threshold=8, window_minutes=10):
    """
    events: list of dicts, each with keys:
        time (datetime), user (str), src_ip (str), status ("fail" | "success")

    Returns a list of alert dicts for any (user, src_ip) pair that
    accumulates >= fail_threshold failures within `window_minutes`,
    immediately followed by a success — mirroring the SPL `transaction`
    startswith=fail endswith=success logic.
    """
    window = timedelta(minutes=window_minutes)
    by_pair = defaultdict(list)

    for e in sorted(events, key=lambda x: x["time"]):
        key = (e["user"], e["src_ip"])
        by_pair[key].append(e)

    alerts = []
    for (user, src_ip), pair_events in by_pair.items():
        fail_buffer = []
        for e in pair_events:
            # drop failures outside the sliding window
            fail_buffer = [f for f in fail_buffer if e["time"] - f["time"] <= window]

            if e["status"] == "fail":
                fail_buffer.append(e)
            elif e["status"] == "success" and len(fail_buffer) >= fail_threshold:
                alerts.append({
                    "user": user,
                    "src_ip": src_ip,
                    "fail_count": len(fail_buffer),
                    "success_time": e["time"],
                    "dest": e.get("dest"),
                })
                fail_buffer = []  # reset after firing

    return alerts

"""
beaconing.py

Plain-Python reimplementation of the SPL logic in:
  detections/command-and-control/periodic-beaconing.md

Mirrors the SPL streamstats-based jitter calculation: for each (src, dest)
pair, computes the average and standard deviation of the time between
connections, and flags a low jitter ratio (i.e., highly regular intervals)
as a likely C2 beacon.
"""

import statistics
from collections import defaultdict


def detect_beaconing(connections, min_connections=20, jitter_threshold=0.15, min_avg_interval_sec=30):
    """
    connections: list of dicts, each with keys:
        time (datetime), src_ip (str), dest_ip (str)

    Returns a list of alert dicts for any (src_ip, dest_ip) pair with at
    least min_connections connections, an average interval above
    min_avg_interval_sec (to ignore rapid-fire non-beacon traffic), and a
    jitter_ratio (stdev / mean of the intervals) below jitter_threshold —
    mirroring the SPL streamstats + jitter_ratio logic.
    """
    by_pair = defaultdict(list)
    for c in connections:
        by_pair[(c["src_ip"], c["dest_ip"])].append(c["time"])

    alerts = []
    for (src_ip, dest_ip), times in by_pair.items():
        times.sort()
        if len(times) < min_connections:
            continue

        intervals = [
            (t2 - t1).total_seconds()
            for t1, t2 in zip(times, times[1:])
        ]
        if len(intervals) < 2:
            continue

        avg_interval = statistics.mean(intervals)
        stdev_interval = statistics.stdev(intervals)
        if avg_interval <= 0:
            continue
        jitter_ratio = stdev_interval / avg_interval

        if (
            len(times) >= min_connections
            and jitter_ratio < jitter_threshold
            and avg_interval > min_avg_interval_sec
        ):
            alerts.append({
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "connection_count": len(times),
                "avg_interval_sec": round(avg_interval, 1),
                "jitter_ratio": round(jitter_ratio, 3),
            })

    return alerts

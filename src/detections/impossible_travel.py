"""
impossible_travel.py

Plain-Python reimplementation of the SPL logic in:
  detections/initial-access/impossible-travel-login.md

Mirrors the SPL `streamstats` comparison of each login against the user's
previous login: computes distance via the haversine formula, implied
travel speed, and flags physically implausible speed.
"""

import math
from collections import defaultdict


def _haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two lat/lon points, in kilometers."""
    R = 6371.0  # Earth radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def detect_impossible_travel(events, speed_threshold_kmh=900, distance_threshold_km=500):
    """
    events: list of dicts, each with keys:
        time (datetime), user (str), src_ip (str), lat (float), lon (float)

    Returns a list of alert dicts for any pair of consecutive logins by the
    same user where the implied travel speed exceeds speed_threshold_kmh
    AND the distance exceeds distance_threshold_km — mirroring the SPL
    streamstats + haversine + threshold logic.
    """
    by_user = defaultdict(list)
    for e in events:
        by_user[e["user"]].append(e)

    alerts = []
    for user, user_events in by_user.items():
        user_events.sort(key=lambda x: x["time"])
        for prev, curr in zip(user_events, user_events[1:]):
            distance_km = _haversine_km(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
            time_diff_hr = (curr["time"] - prev["time"]).total_seconds() / 3600
            if time_diff_hr <= 0:
                continue
            implied_speed_kmh = distance_km / time_diff_hr

            if implied_speed_kmh > speed_threshold_kmh and distance_km > distance_threshold_km:
                alerts.append({
                    "user": user,
                    "src_ip": curr["src_ip"],
                    "last_ip": prev["src_ip"],
                    "distance_km": round(distance_km, 1),
                    "time_diff_hr": round(time_diff_hr, 2),
                    "implied_speed_kmh": round(implied_speed_kmh, 0),
                })

    return alerts

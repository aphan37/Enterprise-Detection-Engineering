"""
privileged_group_change.py

Plain-Python reimplementation of the SPL logic in:
  detections/privilege-escalation/privileged-group-membership-change.md

Flags any account addition to a group listed as privileged, mirroring the
SPL `lookup privileged_groups.csv ... where is_privileged="true"` logic.
"""

DEFAULT_PRIVILEGED_GROUPS = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
}


def detect_privileged_group_change(events, privileged_groups=None):
    """
    events: list of dicts, each with keys:
        time (datetime), group_name (str), account_added (str), added_by (str)

    Returns a list of alert dicts for every event where group_name is in
    the privileged group set.
    """
    privileged_groups = privileged_groups or DEFAULT_PRIVILEGED_GROUPS

    alerts = []
    for e in events:
        if e["group_name"] in privileged_groups:
            alerts.append({
                "time": e["time"],
                "group_name": e["group_name"],
                "account_added": e["account_added"],
                "added_by": e["added_by"],
            })
    return alerts

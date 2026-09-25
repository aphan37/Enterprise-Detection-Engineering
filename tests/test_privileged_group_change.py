"""
Tests for the privileged group membership change detection.

Run with: pytest tests/test_privileged_group_change.py -v
"""

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detections.privileged_group_change import detect_privileged_group_change


def test_detects_addition_to_domain_admins():
    events = [
        {"time": datetime(2026, 9, 24, 9, 0), "group_name": "Domain Admins",
         "account_added": "svc-newaccount", "added_by": "jdoe"},
    ]

    alerts = detect_privileged_group_change(events)

    assert len(alerts) == 1
    assert alerts[0]["account_added"] == "svc-newaccount"


def test_ignores_addition_to_a_normal_group():
    events = [
        {"time": datetime(2026, 9, 24, 9, 5), "group_name": "Marketing-ReadOnly",
         "account_added": "new.hire", "added_by": "it-onboarding"},
    ]

    alerts = detect_privileged_group_change(events)

    assert len(alerts) == 0


def test_flags_multiple_privileged_groups_independently():
    events = [
        {"time": datetime(2026, 9, 24, 9, 10), "group_name": "Enterprise Admins",
         "account_added": "attacker.acct", "added_by": "compromised.svc"},
        {"time": datetime(2026, 9, 24, 9, 11), "group_name": "Helpdesk-Tier1",
         "account_added": "new.tech", "added_by": "it-onboarding"},
        {"time": datetime(2026, 9, 24, 9, 12), "group_name": "Schema Admins",
         "account_added": "attacker.acct2", "added_by": "compromised.svc"},
    ]

    alerts = detect_privileged_group_change(events)

    assert len(alerts) == 2
    flagged_groups = {a["group_name"] for a in alerts}
    assert flagged_groups == {"Enterprise Admins", "Schema Admins"}

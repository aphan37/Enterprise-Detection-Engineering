# Severity & SLA Matrix

Defines how detections are triaged once they fire — every detection in this
repo maps to one of these tiers in its metadata table.

| Severity | Example Trigger | Time to Triage | Time to Escalate (if confirmed) | Default Action |
|---|---|---|---|---|
| **Critical** | Impossible travel login, confirmed C2 beacon | 15 min | Immediate | Auto-disable account / isolate host via SOAR, page on-call IR |
| **High** | Brute force success, malware detonation alert | 30 min | 1 hr | Analyst triage required before containment action |
| **Medium** | Repeated failed logins (no success), suspicious PowerShell | 2 hrs | 4 hrs | Analyst review during shift, tune if false positive |
| **Low** | Port scan from internal asset, policy violation | 8 hrs / next business day | 24 hrs | Log for trend analysis, no immediate action |

## Notes
- SLA clock starts at alert creation time, not analyst pickup time.
- Any detection tuned to reduce false positives should have its tuning
  documented in that detection's `.md` file (see `docs/detection-template.md`)
  so severity/SLA decisions stay traceable over time.
- This matrix should be reviewed quarterly, or immediately after any incident
  where SLA was missed and contributed to delayed response.

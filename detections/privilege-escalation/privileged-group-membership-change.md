# User Added to Privileged Active Directory Group

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Privilege Escalation |
| **ATT&CK Technique** | [T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| **Data Source(s)** | Windows Security EventID 4728, 4732, 4756 (member added to security-enabled group) |
| **Severity** | Critical |
| **SLA (time to triage)** | 15 minutes |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-23 |

## Description
Detects any account being added to a highly privileged AD group (Domain
Admins, Enterprise Admins, Schema Admins, Administrators). Legitimate changes
here are rare and should always be traceable to a known change ticket —
untracked additions are one of the highest-confidence signs of privilege
escalation or an insider threat.

## SPL Query
```spl
index=wineventlog sourcetype=WinEventLog:Security
(EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| lookup privileged_groups.csv group_name AS Group_Name OUTPUT is_privileged
| where is_privileged="true"
| table _time, Group_Name, Member_Name, SubjectUserName, dest
| rename SubjectUserName AS added_by, Member_Name AS account_added
| sort - _time
```
> `privileged_groups.csv` is a small lookup listing the group names your org
> treats as Tier-0 (Domain Admins, Enterprise Admins, Schema Admins, local
> Administrators on Tier-0 assets, etc.) — keep this list current as your AD
> structure changes.

## Sigma Equivalent
See [`sigma-rules/privileged-group-membership-change.yml`](../../sigma-rules/privileged-group-membership-change.yml)

## False Positive Tuning Notes
- **Scheduled access reviews / onboarding** can legitimately add users to
  privileged groups — cross-reference `added_by` and timing against the
  change management ticketing system before treating as an incident.
- **Break-glass emergency access accounts** are sometimes added/removed
  outside normal hours — allowlist the specific break-glass account names,
  but still log and review after the fact.
- No threshold tuning needed here — unlike volume-based detections, every
  event in this category should generate a ticket. The tuning work instead
  went into keeping `privileged_groups.csv` accurate as the org's AD
  structure evolved.

## Response Action
1. Analyst immediately checks whether `added_by` matches an approved change
   ticket for this specific addition.
2. If no matching change ticket exists: treat as Critical — contact the
   account owner of `added_by` directly (not via the account itself, in case
   it's compromised) to confirm the action was intentional.
3. If unconfirmed or the `added_by` account itself shows signs of compromise
   (e.g., recent brute force or impossible travel alert): immediately remove
   `account_added` from the group, disable both accounts pending
   investigation, and escalate to IR.
4. Document the outcome and, if legitimate, note the ticket reference in the
   alert for audit trail purposes.

## Testing / Validation
Validated in a lab AD environment by manually adding a test account to
Domain Admins and confirming the alert fired within one polling cycle
(5-minute index latency in this environment).

# Mass File Access / Staging Ahead of Exfiltration

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Collection |
| **ATT&CK Technique** | [T1074.001 – Local Data Staging](https://attack.mitre.org/techniques/T1074/001/) |
| **Data Source(s)** | Windows Security EventID 4663 (object access — file), file server audit logs |
| **Severity** | High |
| **SLA (time to triage)** | 1 hour |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-23 |

## Description
Detects a single account accessing an abnormally high volume of distinct
files — particularly across sensitive shares (HR, Finance, Legal) — in a
short window. This pattern often precedes exfiltration: an attacker (or
malicious insider) gathering and staging data before moving it out.

## SPL Query
```spl
index=fileserver sourcetype=WinEventLog:Security EventCode=4663
AccessMask="0x1" NOT Object_Name="*\\Temp\\*"
| lookup sensitive_shares.csv share_path AS Object_Name OUTPUT sensitivity
| bin _time span=15m
| stats dc(Object_Name) as unique_files_accessed, values(sensitivity) as share_sensitivity by SubjectUserName, _time
| where unique_files_accessed >= 100
| table _time, SubjectUserName, unique_files_accessed, share_sensitivity
| sort - unique_files_accessed
```

## Sigma Equivalent
Not translated — relies on the org-specific `sensitive_shares.csv` lookup
and file server object-access auditing configuration, which varies too much
across environments for a portable Sigma rule. Noted as Splunk-only in the
coverage matrix.

## False Positive Tuning Notes
- **Backup and indexing jobs** (e.g., DLP scanners, backup software,
  search indexers) legitimately touch large numbers of files — allowlist
  their service account names, same pattern as the lateral movement
  detection.
- **Bulk file operations by IT during migrations** (folder restructuring,
  permission audits) can spike this — check the IT change calendar before
  escalating during known migration windows.
- Threshold of `unique_files_accessed >= 100` in a 15-minute window was
  tuned upward from an initial `>= 50` after normal power users (e.g.,
  someone opening a large shared project folder) triggered false positives.

## Response Action
1. Analyst checks whether `SubjectUserName` is a known automation/backup
   account first — if so, close as false positive after quick confirmation.
2. If a human user account: check `share_sensitivity` — access spanning
   HR/Finance/Legal shares outside that user's normal job function is a
   strong red flag.
3. Cross-reference with any recent HR events (e.g., resignation, termination
   notice) — insider data staging often correlates with employment changes.
4. If suspicious: preserve evidence (do not immediately disable the account,
   which can tip off an insider), loop in HR/Legal per your insider threat
   playbook, and monitor for follow-on exfiltration activity.

## Testing / Validation
Simulated using a PowerShell script that recursively opened 150 files across
a test file share within 5 minutes; detection fired as expected and
correctly flagged the sensitive share involved.

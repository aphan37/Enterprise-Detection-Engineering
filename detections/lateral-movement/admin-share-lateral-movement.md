# Lateral Movement via Admin Shares (PsExec-style)

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Lateral Movement |
| **ATT&CK Technique** | [T1021.002 – SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) |
| **Data Source(s)** | Windows Security EventID 5140 (network share accessed), Sysmon EventID 1 (process creation for service binaries) |
| **Severity** | High |
| **SLA (time to triage)** | 30 minutes |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-23 |

## Description
Detects a single account accessing administrative shares (`ADMIN$`, `C$`)
on multiple distinct hosts within a short window, optionally followed by a
newly created Windows service — the classic PsExec/PAExec lateral movement
pattern used to spread through a network after initial compromise.

## SPL Query
```spl
index=wineventlog sourcetype=WinEventLog:Security EventCode=5140
(ShareName="\\\\*\\ADMIN$" OR ShareName="\\\\*\\C$")
| bin _time span=10m
| stats dc(dest) as unique_hosts, values(dest) as hosts by SubjectUserName, _time
| where unique_hosts >= 3
| table _time, SubjectUserName, unique_hosts, hosts
| sort - unique_hosts
```

## Sigma Equivalent
See [`sigma-rules/admin-share-lateral-movement.yml`](../../sigma-rules/admin-share-lateral-movement.yml)

## False Positive Tuning Notes
- **Legitimate IT/helpdesk tools** (SCCM, remote patching tools, backup
  software) use admin shares constantly across many hosts — this is the
  single biggest source of noise. Allowlist known service account names
  used by these tools (e.g., `svc-sccm`, `svc-backup`) rather than trying to
  exclude by host.
- **Domain/Enterprise Admin accounts** performing routine multi-host
  administration will also trip this — consider a higher threshold
  (`unique_hosts >= 5`) for accounts already in a privileged-admin allowlist,
  and a lower threshold for standard user accounts, which should almost
  never touch admin shares on multiple hosts.
- Initial threshold of `unique_hosts >= 2` was too noisy from legitimate
  IT tooling; raising to `>= 3` combined with the service-account allowlist
  reduced daily alert volume by roughly 75%.

## Response Action
1. Analyst checks whether `SubjectUserName` is a known IT/automation service
   account or a standard user account — standard users touching admin shares
   on 3+ hosts is a strong true-positive signal.
2. Pivot to Sysmon EventID 1 on the target hosts around the same timeframe
   to check for a newly created service binary (common PsExec artifact:
   randomly named `.exe` running from `C:\Windows\`).
3. If confirmed unauthorized: isolate the source host and all affected
   destination hosts, disable the account, and begin scoping for further
   spread.
4. If legitimate but undocumented tooling: add the service account to the
   allowlist and note it in this file's tuning section.

## Testing / Validation
Simulated using PsExec against three lab VMs from a single non-admin test
account; detection fired correctly and correlated service-creation events
were visible on all three targets.

# New Autorun Entry via Registry Run Key

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Persistence |
| **ATT&CK Technique** | [T1547.001 – Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |
| **Data Source(s)** | Sysmon EventID 13 (Registry value set), EventID 11 (File created — startup folder) |
| **Severity** | Medium |
| **SLA (time to triage)** | 2 hours |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-23 |

## Description
Detects a new value written to a common autorun registry key
(`Run`, `RunOnce`) or a new file dropped into a user/global Startup folder —
a standard technique for surviving reboot after initial compromise.

## SPL Query
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
(EventCode=13 TargetObject="*\\CurrentVersion\\Run*")
OR (EventCode=11 TargetFilename="*\\Startup\\*")
| eval artifact_type=if(EventCode=13,"registry_run_key","startup_folder_file")
| eval value_or_path=coalesce(Details, TargetFilename)
| table _time, host, user, artifact_type, TargetObject, value_or_path, Image
| sort - _time
```

## Sigma Equivalent
See [`sigma-rules/registry-run-key-persistence.yml`](../../sigma-rules/registry-run-key-persistence.yml)

## False Positive Tuning Notes
- **Legitimate software installers** commonly write Run keys for update
  checkers (e.g., browser updaters, Adobe, Java) — build an allowlist of
  known-good `Image` (writing process) paths under `Program Files`.
- **Endpoint management agents** (SCCM, CrowdStrike, SentinelOne itself) add
  their own Run entries on install — exclude EDR/agent install events by
  process name.
- Tuned by excluding writes where `Image` is signed by a small set of trusted
  vendors (Microsoft, Adobe, Google) — cut noise by roughly 70% while keeping
  visibility on unsigned or unknown binaries writing to Run keys.

## Response Action
1. Analyst checks whether `Image` (the process that wrote the key/file) is
   signed and from a known-good publisher.
2. If unsigned, recently created, or located in a suspicious path
   (`%TEMP%`, `%APPDATA%`, `C:\Users\Public`): treat as high-priority —
   isolate host, collect the binary for analysis.
3. Check the referenced binary/script (`value_or_path`) against VirusTotal
   hash reputation.
4. If confirmed malicious persistence: remove the Run key/startup file,
   terminate the associated process, and scope for lateral spread.

## Testing / Validation
Simulated using [Atomic Red Team T1547.001](https://github.com/redcanaryco/atomic-red-team)
(Run key + Startup folder test cases) in a lab VM; both artifact types were
captured correctly by the query.

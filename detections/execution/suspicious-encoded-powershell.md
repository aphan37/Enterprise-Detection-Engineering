# Suspicious Encoded PowerShell Execution

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Execution |
| **ATT&CK Technique** | [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| **Data Source(s)** | Sysmon EventID 1 (Process Creation), Windows PowerShell EventID 4104 |
| **Severity** | High |
| **SLA (time to triage)** | 30 minutes |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-23 |

## Description
Detects PowerShell invoked with `-EncodedCommand` (Base64-obfuscated scripts)
combined with execution-policy bypass flags — a common pattern for
delivering fileless malware, dropping stage-two payloads, or evading
AV/EDR string-based detection.

## SPL Query
```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| search process_name="powershell.exe" OR process_name="pwsh.exe"
| regex CommandLine="(?i)(-enc|-encodedcommand|-ep\s+bypass|-executionpolicy\s+bypass|-windowstyle\s+hidden)"
| eval decoded_hint=if(match(CommandLine,"(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}"),"likely_base64_payload","flagged_only")
| table _time, host, user, parent_process_name, process_name, CommandLine, decoded_hint
| sort - _time
```

## Sigma Equivalent
See [`sigma-rules/suspicious-encoded-powershell.yml`](../../sigma-rules/suspicious-encoded-powershell.yml)

## False Positive Tuning Notes
- **Legitimate admin/automation scripts** (SCCM, Intune, scheduled maintenance
  tasks) frequently use `-EncodedCommand` for line-wrapping reasons, not
  evasion — allowlist known automation parent processes (`smsexec.exe`,
  `intune*`) via a lookup table.
- **Software deployment tools** that wrap installers in PowerShell can trip
  this — cross-reference `parent_process_name` against the approved software
  deployment inventory before escalating.
- Initial deployment flagged ~40 events/day; after excluding known automation
  parent processes, volume dropped to under 5/day with no loss of true
  positives during a 2-week validation window.

## Response Action
1. Analyst reviews `parent_process_name` — Office apps (`winword.exe`,
   `excel.exe`), browsers, or `cmd.exe` spawning encoded PowerShell is a
   strong red flag.
2. If `decoded_hint=likely_base64_payload`, decode the Base64 string
   (CyberChef or `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))`)
   to inspect actual command content.
3. If payload references external IP/domain, C2 frameworks, or
   download-and-execute patterns: isolate the host and escalate to IR.
4. If confirmed benign automation: add to allowlist and document in this
   file's tuning notes.

## Testing / Validation
Simulated using [Atomic Red Team T1059.001](https://github.com/redcanaryco/atomic-red-team)
(encoded command test case); confirmed detection fired and decoded payload
was recoverable from the raw event.

# Security Tool Disabled or Tampered With

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Defense Evasion |
| **ATT&CK Technique** | [T1562.001 – Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Data Source(s)** | Windows Security EventID 5001 (Defender protection state change), Windows System EventID 7040 (service state change), EDR agent tamper events |
| **Severity** | Critical |
| **SLA (time to triage)** | 15 minutes |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-23 |

## Description
Detects Windows Defender real-time protection being disabled, a security
service (Defender, EDR agent, firewall service) being stopped, or its
startup type changed to disabled — a hallmark defense evasion step attackers
take before deploying malware or ransomware.

## SPL Query
```spl
index=wineventlog
( sourcetype=WinEventLog:Microsoft-Windows-Windows Defender/Operational EventCode=5001 )
OR
( sourcetype=WinEventLog:System EventCode=7040
  (param1="Windows Defender*" OR param1="SentinelOne*" OR param1="*EDR*")
  param3="disabled" )
| eval evasion_type=if(EventCode=5001,"defender_realtime_disabled","service_startup_disabled")
| table _time, host, user, evasion_type, param1, param3
| sort - _time
```

## Sigma Equivalent
See [`sigma-rules/security-tool-tampering.yml`](../../sigma-rules/security-tool-tampering.yml)

## False Positive Tuning Notes
- **Approved EDR agent updates/reinstalls** can briefly stop and restart the
  service — correlate against your patch management change window and
  suppress alerts within a documented maintenance window.
- **IT admins troubleshooting a false-positive AV detection** may legitimately
  disable real-time protection temporarily — this should still alert (never
  silently allowlist a Tier-0 control), but can be downgraded if the admin
  account is confirmed and re-enables protection within a short window
  (e.g., under 15 minutes).
- No aggressive tuning applied here deliberately — this is a category where
  it's safer to over-alert than to build allowlist logic that an attacker
  could learn and exploit.

## Response Action
1. Analyst treats every occurrence as Critical by default — this is not a
   "tune away the noise" detection.
2. Confirm whether the disabling action correlates to an approved maintenance
   window or ticket.
3. If unconfirmed: isolate the host immediately (assume active compromise in
   progress), re-enable protection via a separate trusted channel, and run
   an on-demand scan.
4. Escalate to IR regardless of outcome — even confirmed "legitimate" cases
   should be reviewed for process improvement (e.g., should admins have this
   level of access without additional approval?).

## Testing / Validation
Validated in a lab VM by manually disabling Windows Defender real-time
protection via PowerShell (`Set-MpPreference -DisableRealtimeMonitoring $true`)
and confirming EventID 5001 generation and detection firing.

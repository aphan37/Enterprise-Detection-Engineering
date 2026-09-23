# Excessive Authentication Failures Followed by Success (Brute Force)

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Credential Access |
| **ATT&CK Technique** | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) |
| **Data Source(s)** | Windows Security EventID 4625 (failed logon), 4624 (successful logon) |
| **Severity** | High |
| **SLA (time to triage)** | 30 minutes |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-22 |

## Description
Detects a source IP or account generating an abnormal volume of failed
authentication attempts within a short window, immediately followed by a
successful login — a strong indicator of a successful brute force or
credential-stuffing attack rather than a user who simply mistyped a password.

## SPL Query
```spl
index=wineventlog sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| eval status=if(EventCode=4625,"fail","success")
| transaction user src_ip startswith=eval(status="fail") endswith=eval(status="success") maxspan=10m
| eval fail_count=mvcount(mvfilter(status="fail"))
| where fail_count >= 8
| table _time, user, src_ip, dest, fail_count, status
| sort - fail_count
```

## Sigma Equivalent
See [`sigma-rules/brute-force-auth-failures.yml`](../../sigma-rules/brute-force-auth-failures.yml)

## False Positive Tuning Notes
- **Service accounts with scheduled password rotation** can trigger a burst of
  failures during rollout — allowlist known rotation windows via a lookup table
  (`service_account_rotation.csv`).
- **Shared kiosk/terminal accounts** (common in retail/warehouse environments)
  naturally generate higher failure counts — consider a higher threshold or a
  separate detection tier for these `src_ip` ranges.
- **VPN concentrators** sometimes retry authentication automatically on
  flaky connections — cross-reference `dest` against known VPN gateway IPs
  before escalating.
- Tuned threshold from `fail_count >= 5` to `>= 8` after initial deployment
  reduced false-positive volume by roughly 60% without losing true positives
  (validated against a 30-day historical replay).

## Response Action
1. Analyst confirms `src_ip` is not an internal scanner, known VPN gateway, or
   allowlisted service account.
2. If external IP: check threat intel (AbuseIPDB/VirusTotal) for known
   malicious reputation.
3. If confirmed malicious: disable the account, force password reset, and
   block `src_ip` at the firewall/WAF.
4. Escalate to IR team if the successful login was followed by any
   privilege escalation or lateral movement indicators.

## Testing / Validation
Simulated using [Atomic Red Team T1110.001](https://github.com/redcanaryco/atomic-red-team)
against a lab domain controller; validated detection fired within 2 minutes
of the successful login event.

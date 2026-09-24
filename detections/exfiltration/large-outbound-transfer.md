# Large Outbound Data Transfer to External Destination

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Exfiltration |
| **ATT&CK Technique** | [T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) |
| **Data Source(s)** | Firewall/proxy logs (bytes_out per connection) |
| **Severity** | Critical |
| **SLA (time to triage)** | 15 minutes |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-23 |

## Description
Detects a single host transferring an abnormally large volume of data to an
external destination in a short window — either as one large transfer or an
aggregated total across multiple connections. Catches both "smash and grab"
exfiltration and slower staged transfers.

## SPL Query
```spl
index=firewall sourcetype=proxy OR sourcetype=firewall
| where isnotnull(dest_ip) AND NOT cidrmatch("10.0.0.0/8", dest_ip)
| bin _time span=1h
| stats sum(bytes_out) as total_bytes_out, dc(dest_ip) as unique_destinations by src_ip, _time
| eval total_MB=round(total_bytes_out/1024/1024, 1)
| where total_MB > 500
| table _time, src_ip, total_MB, unique_destinations
| sort - total_MB
```

## Sigma Equivalent
See [`sigma-rules/large-outbound-transfer.yml`](../../sigma-rules/large-outbound-transfer.yml)

## False Positive Tuning Notes
- **Cloud backup jobs and sync clients** (OneDrive, Google Drive, Backblaze,
  Veeam offsite replication) are the largest source of noise — allowlist
  their known destination IP ranges/domains, since most are published by
  the vendor.
- **Video conferencing and large file-share links** (Zoom recordings,
  WeTransfer, large email attachments via web mail) can spike a single
  user's outbound volume — consider correlating with business hours and
  known collaboration-tool destinations before escalating.
- **Software/OS update mirrors** pulled by endpoints can look like large
  transfers depending on how `bytes_out` vs `bytes_in` is logged in your
  proxy — verify directionality of the field before relying on this query,
  since a misconfigured field mapping is a common source of false positives
  here.
- Threshold tuned from `total_MB > 200` (too noisy from legitimate cloud
  backup traffic) to `> 500` after building the destination allowlist,
  which removed roughly 80% of alert volume.

## Response Action
1. Analyst checks `dest_ip` against the cloud-backup/collaboration-tool
   allowlist first.
2. If destination is unknown or low-reputation: check what process/user
   initiated the transfer via EDR telemetry on `src_ip` around the alert
   timestamp.
3. Cross-reference against the Collection detection
   (`mass-file-access-staging.md`) — a spike in file access shortly before
   this alert on the same host strongly suggests a stage-then-exfil pattern.
4. If confirmed unauthorized: isolate the host immediately, block the
   destination, and preserve logs/evidence for IR and, if applicable,
   legal/compliance follow-up.

## Testing / Validation
Simulated by transferring a 700MB test file from a lab host to an external
test server via `curl`; detection correctly flagged the transfer within the
1-hour bucket window.

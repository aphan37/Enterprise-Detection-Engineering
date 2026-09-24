# Periodic Beaconing to External Host (C2 Pattern)

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Command and Control |
| **ATT&CK Technique** | [T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |
| **Data Source(s)** | Firewall/proxy logs (outbound connection logs with timestamp, src, dest, bytes) |
| **Severity** | Critical |
| **SLA (time to triage)** | 15 minutes |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-23 |

## Description
Detects a host making outbound connections to the same external destination
at unusually regular time intervals with low variance — the statistical
signature of malware "checking in" with a C2 server, as opposed to normal
human browsing traffic, which is much more irregular.

## SPL Query
```spl
index=firewall sourcetype=proxy OR sourcetype=firewall
| where isnotnull(dest_ip) AND NOT cidrmatch("10.0.0.0/8", dest_ip)
| sort src_ip, dest_ip, _time
| streamstats current=f window=2 range(_time) as time_since_last by src_ip, dest_ip
| stats count as connection_count, avg(time_since_last) as avg_interval, stdev(time_since_last) as stdev_interval by src_ip, dest_ip
| eval jitter_ratio=round(stdev_interval/avg_interval, 3)
| where connection_count >= 20 AND jitter_ratio < 0.15 AND avg_interval > 30
| table src_ip, dest_ip, connection_count, avg_interval, jitter_ratio
| sort jitter_ratio
```
> Low `jitter_ratio` (close to 0) means the interval between connections is
> highly consistent — the key beaconing signal. Human browsing is bursty and
> irregular by comparison.

## Sigma Equivalent
Not translated — beaconing detection depends on `streamstats`/statistical
functions specific to Splunk's SPL. A conceptually equivalent version could
be built in tools with time-series analytics (e.g., Elastic's `bucket_script`),
but it isn't a 1:1 Sigma translation. Noted as Splunk-only in the coverage
matrix.

## False Positive Tuning Notes
- **Legitimate polling services** are the dominant false-positive source:
  NTP, software update checkers, cloud sync clients (OneDrive, Dropbox),
  monitoring/heartbeat agents, and license-check callbacks all beacon
  regularly by design — build and maintain an allowlist of known-good
  destination domains/IPs for these services.
- **CDN-fronted destinations** can cause `dest_ip` to shift between
  requests even though the underlying service is the same — consider
  grouping by destination domain (via SNI/proxy logs) rather than raw IP
  where available, to avoid missing beacons that rotate IPs.
- Initial `jitter_ratio < 0.1` threshold missed some slower, deliberately
  jittered malware beacons; relaxed to `< 0.15` with `connection_count >= 20`
  to require more observations before alerting, cutting both false negatives
  and short-lived false positives from single browsing sessions.

## Response Action
1. Analyst checks `dest_ip`/domain against threat intel (VirusTotal,
   AbuseIPDB, internal blocklists) and the known-good polling-service
   allowlist.
2. If destination is unknown or has poor reputation: pull full connection
   history for `src_ip` and inspect payload size patterns (consistent small
   uploads can indicate periodic data exfil, not just check-ins).
3. If confirmed malicious: isolate the host, block the destination at the
   firewall/proxy, and begin host forensics to identify the malware/implant.
4. If benign: add the destination to the polling-service allowlist and
   document in this file's tuning notes.

## Testing / Validation
Simulated using a simple Python script making HTTPS requests to a test
endpoint every 60 seconds (±2s jitter) for 30 minutes; detection correctly
flagged the pattern with a jitter_ratio under 0.05.

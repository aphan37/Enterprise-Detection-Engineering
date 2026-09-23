# Impossible Travel — Geographically Implausible Successive Logins

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | Initial Access |
| **ATT&CK Technique** | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Data Source(s)** | Okta/Azure AD sign-in logs (or VPN auth logs with GeoIP enrichment) |
| **Severity** | Critical |
| **SLA (time to triage)** | 15 minutes |
| **Status** | Production |
| **Author / Last Updated** | Anh Phan — 2026-09-22 |

## Description
Flags a single user account successfully authenticating from two
geographically distant locations within a timeframe that would require
physically impossible travel speed — a strong signal of compromised
credentials being used from an attacker-controlled location.

## SPL Query
```spl
index=identity sourcetype=okta:auth OR sourcetype=azure:signin
| iplocation src_ip
| eval lat=lat, lon=lon
| streamstats current=f last(lat) as last_lat, last(lon) as last_lon, last(_time) as last_time, last(src_ip) as last_ip by user
| eval distance_km=round(haversine(lat,lon,last_lat,last_lon),1)
| eval time_diff_hr=round((_time-last_time)/3600,2)
| eval implied_speed_kmh=round(distance_km/time_diff_hr,0)
| where implied_speed_kmh > 900 AND distance_km > 500
| table _time, user, src_ip, last_ip, distance_km, time_diff_hr, implied_speed_kmh
```
> Note: `haversine()` is a custom SPL macro — implementation notes in
> `scripts/haversine_macro.conf`. If unavailable, use a GeoIP distance lookup
> app (e.g., Splunk's `iplocation` + a distance-calculation add-on).

## Sigma Equivalent
Not portable as-is — this detection relies on a custom streamstats/geolocation
macro specific to Splunk. Noted as Splunk-only in the coverage matrix.

## False Positive Tuning Notes
- **Corporate VPN exit nodes** can appear to "teleport" a user's IP —
  allowlist known corporate VPN egress ranges before geolocation.
- **Cloud-based email/collaboration tools** (e.g., mobile device syncing
  through a CDN edge node) can produce false geolocation — filter to
  interactive sign-ins only, exclude background/service sign-ins.
- Initial deployment threshold of `implied_speed_kmh > 500` produced heavy
  noise from CDN-edge false positives; raised to `> 900` (faster than
  commercial flight) after a two-week tuning period.

## Response Action
1. Analyst verifies whether the user has any legitimate travel/VPN reason
   logged (check with IT/HR if uncertain).
2. If unconfirmed: force immediate session revocation and MFA re-challenge.
3. If MFA was bypassed or not present: treat as confirmed compromise —
   disable account, rotate credentials, escalate to IR.
4. Review any actions taken by the account between the two logins for
   lateral movement or data access anomalies.

## Testing / Validation
Validated using synthetic sign-in events generated via a Python script
(`scripts/generate_test_signin_logs.py`) simulating two logins 10 minutes
apart from IPs geolocated ~9,000 km apart.

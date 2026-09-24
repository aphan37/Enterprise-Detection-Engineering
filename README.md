# Enterprise Detection Engineering

A version-controlled library of 8 production-style SIEM detections, mapped to
[MITRE ATT&CK](https://attack.mitre.org/), covering the full attack chain from
initial access through exfiltration — built the way a detection engineering
team manages rules inside a large enterprise SOC: as code, with tuning
history, ownership, and CI validation, not as one-off queries.

**👉 Start here:** [`detections/credential-access/brute-force-auth-failures.md`](detections/credential-access/brute-force-auth-failures.md)
is the best single file to read first — it shows the full format: SPL query,
false-positive tuning decisions with real thresholds, and the analyst
response playbook.

## What's in this repo

| | |
|---|---|
| **8 detections** | Full ATT&CK chain: initial access → execution → persistence → privilege escalation → defense evasion → credential access → lateral movement → collection → C2 → exfiltration |
| **6 Sigma translations** | Vendor-agnostic versions of the detections that don't rely on Splunk-only macros |
| **CI lint pipeline** | Every detection is automatically checked against the required template on every push — [see it run](.github/workflows/lint-detections.yml) |
| **Documented tuning history** | Every detection includes the actual false-positive sources found and how thresholds were adjusted — not just the final query |

## Detection coverage

| Tactic | Detection | Severity |
|---|---|---|
| Initial Access | [Impossible travel login](detections/initial-access/impossible-travel-login.md) | Critical |
| Execution | [Suspicious encoded PowerShell](detections/execution/suspicious-encoded-powershell.md) | High |
| Persistence | [Registry run key / startup folder](detections/persistence/registry-run-key-persistence.md) | Medium |
| Privilege Escalation | [Privileged AD group membership change](detections/privilege-escalation/privileged-group-membership-change.md) | Critical |
| Defense Evasion | [Security tool disabled/tampered](detections/defense-evasion/security-tool-tampering.md) | Critical |
| Credential Access | [Brute force → successful login](detections/credential-access/brute-force-auth-failures.md) | High |
| Lateral Movement | [Admin share access (PsExec pattern)](detections/lateral-movement/admin-share-lateral-movement.md) | High |
| Collection | [Mass file access / staging](detections/collection/mass-file-access-staging.md) | High |
| Command & Control | [Periodic beaconing](detections/command-and-control/periodic-beaconing.md) | Critical |
| Exfiltration | [Large outbound transfer](detections/exfiltration/large-outbound-transfer.md) | Critical |

## Why this repo is structured this way

Most portfolio repos show a single query or a dashboard screenshot. Enterprise
SOC teams don't work that way — they manage hundreds of detections across
multiple data sources, tune them continuously as false positives emerge, and
track coverage against a framework to find gaps. This repo mirrors that
workflow at a small scale:

- Every detection lives in its own reviewable file, not buried in a wiki
- False-positive tuning is documented as a first-class artifact, not an
  afterthought — this is the part that actually demonstrates engineering
  judgment, not just SPL syntax
- A CI pipeline enforces that every detection meets the same documentation
  bar before it's considered "production"

## Repo structure

```
detection-engineering-repo/
├── detections/                  # SPL detections, organized by ATT&CK tactic
│   ├── initial-access/
│   ├── execution/
│   ├── persistence/
│   ├── privilege-escalation/
│   ├── defense-evasion/
│   ├── credential-access/
│   ├── lateral-movement/
│   ├── collection/
│   ├── command-and-control/
│   └── exfiltration/
├── sigma-rules/                 # Vendor-agnostic Sigma versions
├── scripts/lint_spl.py          # CI validation script
├── docs/
│   ├── detection-template.md    # Template every detection follows
│   ├── severity-sla-matrix.md   # Severity → SLA → response action mapping
│   └── contributing.md          # How a detection gets added/reviewed
└── .github/workflows/           # CI: lints every detection on push
```

## How a detection is documented

Every file includes: ATT&CK mapping, required data source, the SPL query, a
Sigma equivalent where portable, false-positive tuning notes, severity/SLA,
the analyst response playbook, and how it was tested. See
[`docs/detection-template.md`](docs/detection-template.md) for the exact
format every detection is held to — and it's enforced automatically, not just
by convention (see below).

## How the CI pipeline works

On every push, [`.github/workflows/lint-detections.yml`](.github/workflows/lint-detections.yml)
runs [`scripts/lint_spl.py`](scripts/lint_spl.py) against every file in
`detections/`. It fails the build if a detection is missing a required
metadata field, has no SPL query, or is missing its tuning/response
sections — the same discipline a real detection-as-code pipeline enforces
before a rule ships to production.

## Background

Built by [Anh Phan](https://github.com/aphan37). Professional experience
includes triaging 330+ SPL-based alerts, building 12+ Splunk detection use
cases, and maintaining Splunk Enterprise/Cloud data pipelines across Windows,
Linux, Domain Controller, and SC4S sources as a Security Operations Analyst
Intern.

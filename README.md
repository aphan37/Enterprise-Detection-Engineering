# Enterprise Detection Engineering

A version-controlled library of production-style SIEM detections, mapped to
[MITRE ATT&CK](https://attack.mitre.org/) and covering the full attack chain
from initial access through exfiltration. Each detection is documented the
way a detection engineering team manages rules inside a large enterprise
SOC: as code, with tuning history, ownership, and automated validation —
not as a one-off query or a dashboard screenshot.

**Start here:** [`brute-force-auth-failures.md`](detections/credential-access/brute-force-auth-failures.md)
is the clearest single example of the format — SPL query, documented
false-positive tuning with real thresholds, and the analyst response
playbook.

## What this demonstrates

| Skill | Where it shows up |
|---|---|
| **ATT&CK-driven detection design** | Every rule maps to a specific tactic and technique ID, not a generic "suspicious activity" alert |
| **False-positive tuning judgment** | Every detection documents the actual noise sources found and the threshold changes made to fix them — this is the part of detection engineering that separates a working rule from a theoretical one |
| **SIEM query engineering (SPL)** | 10 original Splunk searches using `stats`, `streamstats`, `transaction`, and `eval` logic, not copy-pasted starter queries |
| **Cross-platform detection logic (Sigma)** | 6 of the 10 detections are also written as vendor-agnostic Sigma rules, showing the logic isn't tied to one tool |
| **Operational maturity (severity/SLA)** | Every detection is tied to a severity tier and response SLA, and each includes a concrete analyst response playbook, not just "investigate further" |
| **Detection-as-code discipline** | A CI pipeline automatically validates every detection against a required template on every push — enforced by tooling, not just convention |

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

## How each detection is documented

Every file follows a fixed structure:

- **ATT&CK mapping** — tactic and specific technique ID
- **Required data source** — the exact log source/event ID the detection depends on
- **SPL query** — the actual working search logic
- **Sigma equivalent** — a portable version, where the logic isn't Splunk-specific
- **False-positive tuning notes** — what caused noise in practice, and how the threshold or logic was adjusted
- **Severity and SLA** — how fast the detection should be triaged and escalated
- **Analyst response playbook** — the concrete steps to take when it fires
- **Testing/validation** — how the detection was proven to actually fire (Atomic Red Team, synthetic log generation, or lab simulation)

The full format is defined in [`docs/detection-template.md`](docs/detection-template.md)
and enforced automatically — see below.

## How the CI pipeline works

[`.github/workflows/lint-detections.yml`](.github/workflows/lint-detections.yml)
runs [`scripts/lint_spl.py`](scripts/lint_spl.py) on every push. The script
checks every file in `detections/` for the required metadata fields, a
non-empty SPL query, and the tuning/response sections — and fails the build
if any are missing. This is the same discipline a detection-as-code pipeline
enforces before a rule is allowed to ship to production.

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
├── sigma-rules/                 # Vendor-agnostic Sigma translations
├── scripts/lint_spl.py          # CI validation script
├── docs/
│   ├── detection-template.md    # Required format for every detection
│   ├── severity-sla-matrix.md   # Severity → SLA → response mapping
│   └── contributing.md          # Detection lifecycle: draft → validate → tune → production
└── .github/workflows/           # CI: lints every detection on push
```

## Background

Built by [Anh Phan](https://github.com/aphan37), Security Operations Analyst
with hands-on experience triaging 330+ SPL-based alerts, building 12+ Splunk
detection use cases, and maintaining Splunk Enterprise/Cloud data pipelines
across Windows, Linux, Domain Controller, and SC4S sources.

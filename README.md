# Detection Engineering Repository

A structured, version-controlled library of SIEM detection logic mapped to the
[MITRE ATT&CK](https://attack.mitre.org/) framework — built to reflect how a
detection engineering team operates inside a large enterprise SOC.

This repo treats detections as **code**: every rule is documented, peer-reviewable,
tunable, and traceable back to a data source, a severity/SLA tier, and an
ATT&CK technique. It is not a dashboard screenshot dump — it's the actual logic,
version history, and tuning notes behind each alert.

## Why this exists

Most portfolio repos show a dashboard or a single query. Enterprise SOC teams
don't operate that way — they manage hundreds of detections across multiple data
sources, tune them over time as false positives emerge, and map coverage against
a framework to find gaps. This repo is structured the way that actual workflow
looks, using Splunk SPL as the primary query language and Sigma as a
vendor-agnostic translation layer.

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
├── sigma-rules/                 # Vendor-agnostic Sigma versions of key detections
├── scripts/                     # Lint/validation scripts used in CI
├── docs/
│   ├── detection-template.md    # Template every new detection follows
│   ├── severity-sla-matrix.md   # Severity → SLA → response action mapping
│   └── contributing.md          # How a detection gets added/reviewed
└── .github/workflows/           # CI: lints SPL syntax on every PR
```

## Detection coverage matrix

| Tactic | Detections | Status |
|---|---|---|
| Initial Access | 1 | 🟢 |
| Credential Access | 1 | 🟢 |
| Persistence | 0 | ⬜ planned |
| Privilege Escalation | 0 | ⬜ planned |
| Lateral Movement | 0 | ⬜ planned |
| Defense Evasion | 0 | ⬜ planned |
| Command & Control | 0 | ⬜ planned |

*(Update this table as you add detections — it doubles as a visible ATT&CK
coverage tracker, which is exactly what enterprise detection engineering teams
maintain internally.)*

## How each detection is documented

Every detection lives in its own `.md` file and includes:

- **ATT&CK mapping** (tactic + technique ID)
- **Required data source** (e.g., Sysmon EventID 1, Windows Security 4625, EDR)
- **SPL query**
- **Sigma equivalent** (where applicable)
- **False positive tuning notes** — what caused noise, how it was resolved
- **Severity + SLA** — tied to response time expectations
- **Response action** — what the analyst/SOAR should do when it fires

See [`docs/detection-template.md`](docs/detection-template.md) for the exact format.

## Getting started

1. Browse `detections/<tactic>/` for existing rules
2. Use `docs/detection-template.md` to draft a new one
3. Add a Sigma translation in `sigma-rules/` if the logic is portable
4. Run `scripts/lint_spl.py` locally before opening a PR (CI will also run it)

## Background

Built by [Anh Phan](https://github.com/aphan37) — Security Operations Analyst
Intern experience includes triaging 330+ SPL-based alerts, building 12+ Splunk
detection use cases, and maintaining Splunk Enterprise/Cloud data pipelines
across Windows, Linux, Domain Controller, and SC4S sources.

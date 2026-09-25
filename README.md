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

## Proof it works — runnable, not just documented

SPL only runs inside Splunk, so to make this repo verifiable without
enterprise software, four of the detections are reimplemented in plain
Python under `src/detections/` and covered by a `pytest` suite that
generates synthetic attack traffic *and* realistic benign traffic for each
one, then asserts the detection fires on the attack and stays silent on the
benign activity — the same true-positive/true-negative discipline a real
detection engineering team applies before shipping a rule.

**Covered so far:** brute force login, privileged AD group changes,
impossible travel, and C2 beaconing. The other 6 detections are documented
in full as SPL/Sigma but don't yet have a Python test double — see
`docs/contributing.md` for how to add one.

### How to run it

```bash
git clone https://github.com/aphan37/Enterprise-Detection-Engineering.git
cd Enterprise-Detection-Engineering
pip install -r requirements.txt
python -m pytest tests/ -v
```

> On Windows, if the plain `pytest` command isn't found after installing,
> use `python -m pytest tests/ -v` instead — it works regardless of PATH
> setup.

Expected output:

```
tests/test_beaconing.py::test_detects_regular_60_second_beacon PASSED
tests/test_beaconing.py::test_ignores_irregular_human_browsing_traffic PASSED
tests/test_beaconing.py::test_ignores_regular_traffic_below_the_connection_count_threshold PASSED
tests/test_beaconing.py::test_ignores_regular_but_very_fast_polling_like_local_health_checks PASSED
tests/test_brute_force.py::test_detects_real_brute_force_attack PASSED
tests/test_brute_force.py::test_ignores_normal_user_who_mistypes_password_twice PASSED
tests/test_brute_force.py::test_ignores_failures_spread_outside_the_time_window PASSED
tests/test_brute_force.py::test_does_not_alert_on_failures_with_no_eventual_success PASSED
tests/test_impossible_travel.py::test_detects_login_from_new_york_then_tokyo_10_minutes_later PASSED
tests/test_impossible_travel.py::test_ignores_two_logins_from_the_same_city PASSED
tests/test_impossible_travel.py::test_ignores_a_real_long_haul_flight PASSED
tests/test_impossible_travel.py::test_only_flags_the_affected_user_not_other_users_logging_in_normally PASSED
tests/test_privileged_group_change.py::test_detects_addition_to_domain_admins PASSED
tests/test_privileged_group_change.py::test_ignores_addition_to_a_normal_group PASSED
tests/test_privileged_group_change.py::test_flags_multiple_privileged_groups_independently PASSED

15 passed in 0.03s
```

This same command runs automatically in CI on every push — see the
**Actions** tab for the live result.

## What this demonstrates

| Skill | Where it shows up |
|---|---|
| **ATT&CK-driven detection design** | Every rule maps to a specific tactic and technique ID, not a generic "suspicious activity" alert |
| **False-positive tuning judgment** | Every detection documents the actual noise sources found and the threshold changes made to fix them — this is the part of detection engineering that separates a working rule from a theoretical one |
| **SIEM query engineering (SPL)** | 10 original Splunk searches using `stats`, `streamstats`, `transaction`, and `eval` logic, not copy-pasted starter queries |
| **Cross-platform detection logic (Sigma)** | 6 of the 10 detections are also written as vendor-agnostic Sigma rules, showing the logic isn't tied to one tool |
| **Verifiable correctness** | 4 detections are reimplemented in Python with a 15-test `pytest` suite proving each one fires on attack traffic and stays silent on realistic benign traffic |
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

[`.github/workflows/validate-detections.yml`](.github/workflows/validate-detections.yml)
runs two checks on every push:

1. **`scripts/lint_spl.py`** — checks every file in `detections/` for the
   required metadata fields, a non-empty SPL query, and the tuning/response
   sections, failing the build if any are missing.
2. **`pytest tests/`** — runs the synthetic attack/benign-traffic test suite
   described above against the Python reimplementations in `src/detections/`.

Together, these mean a detection in this repo has to be both **documented
to spec** and **verified to actually behave correctly** before the build is
green — the same two-part bar a real detection-as-code pipeline enforces.

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
├── src/detections/              # Python reimplementations (4 of 10 detections)
├── tests/                       # pytest suite: 15 tests, synthetic attack + benign traffic
├── scripts/lint_spl.py          # CI: validates detection doc structure
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

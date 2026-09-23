# [Detection Name]

## Metadata
| Field | Value |
|---|---|
| **ATT&CK Tactic** | e.g., Credential Access |
| **ATT&CK Technique** | e.g., T1110 – Brute Force |
| **Data Source(s)** | e.g., Windows Security EventID 4625, VPN auth logs |
| **Severity** | Low / Medium / High / Critical |
| **SLA (time to triage)** | e.g., 30 min for Critical, 4 hrs for Low |
| **Status** | Draft / In Review / Production / Deprecated |
| **Author / Last Updated** | Name — YYYY-MM-DD |

## Description
Plain-language summary: what behavior this detects and why it matters.

## SPL Query
```spl
index=<index> sourcetype=<sourcetype>
| <your search logic here>
| stats count by src_ip, user, dest
| where count > <threshold>
```

## Sigma Equivalent
> Link to the corresponding file in `/sigma-rules/`, if one exists.

## False Positive Tuning Notes
- What legitimate activity can trigger this?
- What filters/allowlists have been applied, and why?
- Any known noisy sources (e.g., a specific service account, scanner IP range)?

## Response Action
What should the analyst (or SOAR playbook) do when this fires?
1. Step one
2. Step two
3. Escalation path if confirmed malicious

## Testing / Validation
How was this detection tested? (e.g., atomic red team technique ID, manual
simulation, historical incident replay)

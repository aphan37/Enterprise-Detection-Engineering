# Contributing a New Detection

This repo mirrors how a detection engineering team adds and reviews rules in
production. Follow this lifecycle for every new detection.

## 1. Draft
- Copy `docs/detection-template.md` into the correct `detections/<tactic>/`
  folder, named `kebab-case-description.md`.
- Fill in every field — an incomplete metadata table blocks review.
- Map to a real ATT&CK technique ID. If it doesn't map cleanly to one, ask
  whether it's actually a detection or just a log search.

## 2. Validate
- Run `scripts/lint_spl.py` locally to catch syntax issues before opening a PR.
- If the logic is portable across SIEMs, add a Sigma translation in
  `sigma-rules/`. If it relies on Splunk-specific macros/lookups, note that
  explicitly in the detection file instead of forcing a bad translation.
- Test against either a lab environment, Atomic Red Team simulation, or a
  synthetic log generator script (see `scripts/` for examples). Document how
  you tested it in the "Testing / Validation" section.

## 3. Tune before marking Production
- A detection stays in `Draft` or `In Review` status until it has been run
  against real or realistic historical data and tuned for false positives.
- Document every tuning decision — threshold changes, allowlists, exclusions —
  in the "False Positive Tuning Notes" section. This is what separates a
  detection engineering repo from a pile of untested queries.

## 4. Update the coverage matrix
- Add the new detection to the table in the main `README.md` so ATT&CK
  coverage stays visible at a glance.

## 5. Review checklist (self-review before marking Production)
- [ ] Metadata table fully filled in
- [ ] SPL query tested against real or synthetic data
- [ ] False positive scenarios identified and documented
- [ ] Severity/SLA assigned per `docs/severity-sla-matrix.md`
- [ ] Response action is specific enough for a Tier 1 analyst to follow
- [ ] Coverage matrix in README updated

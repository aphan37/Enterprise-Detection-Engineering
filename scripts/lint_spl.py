#!/usr/bin/env python3
"""
lint_spl.py

Validates every detection markdown file under detections/ against the
required template structure. Run locally before opening a PR, or let CI
run it automatically.

Checks:
  1. File contains all required metadata fields
  2. File contains at least one ```spl fenced code block
  3. SPL block is non-empty and doesn't contain obvious placeholder text
  4. File contains a "False Positive Tuning Notes" section
  5. File contains a "Response Action" section

Exit code 0 = all detections pass. Exit code 1 = at least one failure.
"""

import re
import sys
from pathlib import Path

DETECTIONS_DIR = Path(__file__).parent.parent / "detections"

REQUIRED_FIELDS = [
    "ATT&CK Tactic",
    "ATT&CK Technique",
    "Data Source(s)",
    "Severity",
    "SLA",
    "Status",
]

REQUIRED_SECTIONS = [
    "## SPL Query",
    "## False Positive Tuning Notes",
    "## Response Action",
]

PLACEHOLDER_PATTERNS = [
    r"<your search logic here>",
    r"\[Detection Name\]",
    r"e\.g\.,",
]


def lint_file(path: Path) -> list[str]:
    errors = []
    text = path.read_text(encoding="utf-8")

    for field in REQUIRED_FIELDS:
        if field not in text:
            errors.append(f"missing required field: '{field}'")

    for section in REQUIRED_SECTIONS:
        if section not in text:
            errors.append(f"missing required section: '{section}'")

    spl_blocks = re.findall(r"```spl\n(.*?)```", text, re.DOTALL)
    if not spl_blocks:
        errors.append("no ```spl fenced code block found")
    else:
        for block in spl_blocks:
            if not block.strip():
                errors.append("empty SPL code block")
            for pattern in PLACEHOLDER_PATTERNS:
                if re.search(pattern, block):
                    errors.append(f"SPL block still contains placeholder text: '{pattern}'")

    return errors


def main() -> int:
    if not DETECTIONS_DIR.exists():
        print(f"detections/ directory not found at {DETECTIONS_DIR}")
        return 1

    md_files = sorted(DETECTIONS_DIR.rglob("*.md"))
    if not md_files:
        print("No detection files found — nothing to lint.")
        return 0

    total_errors = 0
    for path in md_files:
        errors = lint_file(path)
        rel = path.relative_to(DETECTIONS_DIR.parent)
        if errors:
            total_errors += len(errors)
            print(f"\n[FAIL] {rel}")
            for e in errors:
                print(f"   - {e}")
        else:
            print(f"[PASS] {rel}")

    print(f"\nChecked {len(md_files)} detection file(s), {total_errors} issue(s) found.")
    return 1 if total_errors else 0


if __name__ == "__main__":
    sys.exit(main())

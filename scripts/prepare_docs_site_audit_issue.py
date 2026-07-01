#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_ISSUE_TITLE = "Docs-site audit exception review needed"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare a GitHub issue body from docs-site audit exception warnings."
    )
    parser.add_argument("--result", required=True, help="validator JSON result path")
    parser.add_argument("--output-body", required=True, help="markdown issue body output path")
    parser.add_argument("--github-output", help="optional GITHUB_OUTPUT path")
    parser.add_argument("--issue-title", default=DEFAULT_ISSUE_TITLE, help="GitHub issue title")
    return parser.parse_args()


def non_empty_strings(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value).strip() for value in values if str(value).strip()]


def issue_body(result: dict[str, Any]) -> str:
    status = str(result.get("status") or "unknown")
    warnings = non_empty_strings(result.get("warnings"))
    failures = non_empty_strings(result.get("failures"))

    lines = [
        "# Docs-site audit exception review needed",
        "",
        f"Status: `{status}`",
        "",
    ]
    if failures:
        lines.extend(["## Failures", ""])
        lines.extend(f"- {failure}" for failure in failures)
        lines.append("")
    if warnings:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {warning}" for warning in warnings)
        lines.append("")
    lines.extend(
        [
            "## Review",
            "",
            "- Prefer dependency remediation when a patched version is available.",
            "- Remove stale exceptions when the advisory no longer appears in `npm audit --omit=dev`.",
            "- Renew an exception only with current owner, rationale, expiry, and upgrade trigger evidence.",
            "",
            "## Source",
            "",
            "- `scripts/validate_docs_site_audit.py --repo-root . --json --warn-expiring-within-days 14`",
            "- `docs-site/security-advisory-exceptions.json`",
            "",
        ]
    )
    return "\n".join(lines)


def append_github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            if "\n" not in value:
                handle.write(f"{key}={value}\n")
                continue
            delimiter = f"EOF_{key}"
            while delimiter in value:
                delimiter = f"{delimiter}_X"
            handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")


def main() -> int:
    args = parse_args()
    result_path = Path(args.result)
    output_body_path = Path(args.output_body)
    result = json.loads(result_path.read_text(encoding="utf-8"))

    warnings = non_empty_strings(result.get("warnings"))
    failures = non_empty_strings(result.get("failures"))
    has_notice = bool(warnings or failures)

    if has_notice:
        output_body_path.parent.mkdir(parents=True, exist_ok=True)
        output_body_path.write_text(issue_body(result), encoding="utf-8")

    if args.github_output:
        append_github_output(
            Path(args.github_output),
            {
                "has_notice": "true" if has_notice else "false",
                "audit_status": str(result.get("status") or "unknown"),
                "issue_title": args.issue_title,
            },
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

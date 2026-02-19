#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .github/required-checks.json ]]; then
  echo "missing branch protection contract: .github/required-checks.json" >&2
  exit 3
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for branch protection contract validation" >&2
  exit 7
fi

python3 - <<'PY'
import json
import pathlib
import re
import sys


ROOT = pathlib.Path(".")
required_checks_path = ROOT / ".github" / "required-checks.json"
workflows_dir = ROOT / ".github" / "workflows"

errors = []

try:
    payload = json.loads(required_checks_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"failed to parse {required_checks_path}: {exc}", file=sys.stderr)
    sys.exit(3)

required_checks = payload.get("required_checks")
if not isinstance(required_checks, list) or not all(
    isinstance(item, str) and item.strip() for item in required_checks
):
    errors.append("required_checks must be a non-empty string array")
    required_checks = []

if not required_checks:
    errors.append("required_checks must include at least one check")

if len(set(required_checks)) != len(required_checks):
    errors.append("required_checks must not contain duplicates")

if required_checks != sorted(required_checks):
    errors.append("required_checks must be sorted for deterministic diffs")

workflow_files = sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml"))
if not workflow_files:
    errors.append("no workflow files found under .github/workflows")

def has_pull_request_trigger(text: str) -> bool:
    return re.search(r"(?m)^\s*pull_request\s*:", text) is not None

def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value

def parse_job_checks(text: str) -> set[str]:
    checks: set[str] = set()
    lines = text.splitlines()
    in_jobs = False
    current_job = ""

    for line in lines:
        if not in_jobs:
            if re.match(r"^jobs:\s*$", line):
                in_jobs = True
            continue

        if re.match(r"^\S", line):
            break

        job_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if job_match:
            current_job = job_match.group(1)
            checks.add(current_job)
            continue

        if current_job:
            name_match = re.match(r"^    name:\s*(.+)\s*$", line)
            if name_match:
                raw_name = name_match.group(1).split(" #", 1)[0]
                normalized = strip_quotes(raw_name)
                if normalized:
                    checks.add(normalized)

    return checks

pr_checks: set[str] = set()
pr_workflows: list[str] = []
for workflow in workflow_files:
    text = workflow.read_text(encoding="utf-8")
    if has_pull_request_trigger(text):
        pr_workflows.append(str(workflow))
        pr_checks.update(parse_job_checks(text))

if not pr_workflows:
    errors.append("no pull_request workflow found under .github/workflows")

for check in required_checks:
    if check not in pr_checks:
        errors.append(
            f"required check does not map to a pull_request job/status: {check}"
        )

if errors:
    for err in errors:
        print(err, file=sys.stderr)
    sys.exit(3)

print("branch protection contract: pass")
PY

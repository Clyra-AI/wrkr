#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .github/wave-gates.json ]]; then
  echo "missing wave gate contract: .github/wave-gates.json" >&2
  exit 3
fi

if [[ ! -f .github/required-checks.json ]]; then
  echo "missing branch protection contract: .github/required-checks.json" >&2
  exit 3
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for wave gate validation" >&2
  exit 7
fi

python3 - <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(".")
wave_path = root / ".github" / "wave-gates.json"
required_checks_path = root / ".github" / "required-checks.json"
contracts_dir = root / "testinfra" / "contracts"

errors: list[str] = []

try:
    wave_payload = json.loads(wave_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"failed to parse {wave_path}: {exc}", file=sys.stderr)
    sys.exit(3)

try:
    required_checks_payload = json.loads(required_checks_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"failed to parse {required_checks_path}: {exc}", file=sys.stderr)
    sys.exit(3)

required_checks = required_checks_payload.get("required_checks")
if not isinstance(required_checks, list):
    errors.append("required_checks must be a string array")
    required_checks = []
required_checks = [item.strip() for item in required_checks if isinstance(item, str) and item.strip()]

merge_gates = wave_payload.get("merge_gates")
if not isinstance(merge_gates, dict):
    errors.append("merge_gates must be an object")
    merge_gates = {}

required_pr_checks = merge_gates.get("required_pr_checks")
if not isinstance(required_pr_checks, list) or not required_pr_checks:
    errors.append("merge_gates.required_pr_checks must be a non-empty string array")
    required_pr_checks = []
required_pr_checks = [item.strip() for item in required_pr_checks if isinstance(item, str) and item.strip()]

required_release_commands = merge_gates.get("required_release_commands")
if not isinstance(required_release_commands, list) or not required_release_commands:
    errors.append("merge_gates.required_release_commands must be a non-empty string array")
    required_release_commands = []

waves = wave_payload.get("waves")
if not isinstance(waves, list) or not waves:
    errors.append("waves must be a non-empty array")
    waves = []

wave_ids: list[str] = []
wave_by_id: dict[str, dict] = {}
expected_order = 1
expected_ids = [f"wave-{idx}" for idx in range(1, len(waves) + 1)]

for index, wave in enumerate(waves):
    if not isinstance(wave, dict):
        errors.append(f"wave entry {index} must be an object")
        continue
    wave_id = str(wave.get("id", "")).strip()
    label = str(wave.get("label", "")).strip()
    order = wave.get("order")
    lanes = wave.get("required_lanes")
    checks = wave.get("required_story_checks")
    requires = str(wave.get("requires", "")).strip()
    successor = str(wave.get("successor", "")).strip()

    if not wave_id:
        errors.append(f"wave entry {index} missing id")
        continue
    if wave_id in wave_by_id:
        errors.append(f"duplicate wave id {wave_id}")
        continue
    if not label:
        errors.append(f"{wave_id} missing label")
    if order != expected_order:
        errors.append(f"{wave_id} order must be {expected_order}, got {order}")
    if index < len(expected_ids) and wave_id != expected_ids[index]:
        errors.append(f"wave ids must be sequential wave-1..wave-N, got {wave_id} at index {index}")
    if not isinstance(lanes, list) or sorted(lanes) != ["acceptance", "core", "cross_platform", "fast", "risk"]:
        errors.append(f"{wave_id} required_lanes must be exactly fast/core/acceptance/cross_platform/risk")
    if not isinstance(checks, list) or not checks:
        errors.append(f"{wave_id} required_story_checks must be a non-empty string array")
        checks = []
    else:
        normalized_checks = []
        for check in checks:
            if not isinstance(check, str) or not check.strip():
                errors.append(f"{wave_id} required_story_checks contains an invalid entry")
                continue
            normalized_checks.append(check.strip())
        checks = normalized_checks
        if checks != sorted(checks):
            errors.append(f"{wave_id} required_story_checks must be sorted")
        for filename in checks:
            if not (contracts_dir / filename).is_file():
                errors.append(f"{wave_id} required story contract missing: testinfra/contracts/{filename}")

    if order == 1 and requires:
        errors.append(f"{wave_id} must not declare requires")
    if order > 1 and requires != f"wave-{order - 1}":
        errors.append(f"{wave_id} must require wave-{order - 1}")
    if successor and order < len(waves) and successor != f"wave-{order + 1}":
        errors.append(f"{wave_id} successor must be wave-{order + 1}")
    if order == len(waves) and successor:
        errors.append(f"{wave_id} must not declare successor")

    wave_ids.append(wave_id)
    wave_by_id[wave_id] = wave
    expected_order += 1

if required_pr_checks != sorted(required_pr_checks):
    errors.append("merge_gates.required_pr_checks must be sorted")
if required_pr_checks != required_checks:
    errors.append(
        "merge_gates.required_pr_checks must exactly match .github/required-checks.json required_checks"
    )

for command in required_release_commands:
    if not isinstance(command, str) or not command.strip():
        errors.append("merge_gates.required_release_commands contains an invalid command")

if errors:
    for err in errors:
        print(err, file=sys.stderr)
    sys.exit(3)

print("wave gate contract: pass")
PY

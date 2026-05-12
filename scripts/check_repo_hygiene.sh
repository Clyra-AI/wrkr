#!/usr/bin/env bash
set -euo pipefail

required_paths=(
  "cmd/wrkr"
  "core"
  "internal"
  "schemas/v1"
  "scripts"
  "testinfra"
  "scenarios"
  ".github/workflows"
  ".github/workflows/pr.yml"
  ".github/workflows/main.yml"
  ".github/workflows/nightly.yml"
  ".github/workflows/release.yml"
  ".github/required-checks.json"
  ".goreleaser.yaml"
  "product/PLAN_v1.md"
  "product/wrkr.md"
  "product/dev_guides.md"
)

for path in "${required_paths[@]}"; do
  if [[ ! -e "$path" ]]; then
    echo "missing required path: $path" >&2
    exit 3
  fi
done

for plan_doc in "product/PLAN_v1.md" "product/wrkr.md" "product/dev_guides.md"; do
  if git check-ignore -q "$plan_doc"; then
    echo "plan artifact is ignored but must be tracked: $plan_doc" >&2
    exit 3
  fi
done

tracked_wrkr_state="$(git ls-files -- '.wrkr/*')"
if [[ -n "${tracked_wrkr_state}" ]]; then
  echo "transient wrkr local state must not be tracked:" >&2
  echo "${tracked_wrkr_state}" >&2
  exit 3
fi

license_markers=(
  "1. Definitions."
  "2. Grant of Copyright License."
  "3. Grant of Patent License."
  "4. Redistribution."
  "7. Disclaimer of Warranty."
  "8. Limitation of Liability."
  "APPENDIX: How to apply the Apache License to your work."
)

for marker in "${license_markers[@]}"; do
  if ! grep -Fq "$marker" LICENSE; then
    echo "LICENSE missing Apache-2.0 full-text marker: $marker" >&2
    exit 3
  fi
done

if [[ -d factory/profiles ]]; then
  python3 scripts/validate_profiles.py --repo-root . --profile wrkr >/dev/null
else
  echo "skipping profile path validation: factory/profiles not present in checkout" >&2
fi

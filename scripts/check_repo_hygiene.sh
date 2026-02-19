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
  "product/Clyra_AI.md"
)

for path in "${required_paths[@]}"; do
  if [[ ! -e "$path" ]]; then
    echo "missing required path: $path" >&2
    exit 3
  fi
done

for plan_doc in "product/PLAN_v1.md" "product/wrkr.md" "product/dev_guides.md" "product/Clyra_AI.md"; do
  if git check-ignore -q "$plan_doc"; then
    echo "plan artifact is ignored but must be tracked: $plan_doc" >&2
    exit 3
  fi
done

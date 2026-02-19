#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .github/required-checks.json ]]; then
  echo "missing branch protection contract: .github/required-checks.json" >&2
  exit 3
fi

required_jobs=(
  "fast-lane:.github/workflows/pr.yml"
  "windows-smoke:.github/workflows/pr.yml"
  "core-matrix:.github/workflows/main.yml"
  "acceptance:.github/workflows/main.yml"
  "codeql:.github/workflows/main.yml"
  "release-artifacts:.github/workflows/release.yml"
)

for item in "${required_jobs[@]}"; do
  job="${item%%:*}"
  file="${item##*:}"
  if [[ ! -f "$file" ]]; then
    echo "missing workflow file for required job $job: $file" >&2
    exit 3
  fi
  if ! rg -n "^[[:space:]]{2}${job}:$" "$file" >/dev/null; then
    echo "required job $job not found in $file" >&2
    exit 3
  fi
done

#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .github/required-checks.json ]]; then
  echo "missing branch protection contract: .github/required-checks.json" >&2
  exit 3
fi

required_jobs=(
  "fast-lane:.github/workflows/pr.yml"
  "windows-smoke:.github/workflows/pr.yml"
)

required_checks=(
  "fast-lane"
  "windows-smoke"
)

disallowed_checks=(
  "core-matrix-ubuntu-latest"
  "core-matrix-macos-latest"
  "core-matrix-windows-latest"
  "acceptance"
  "codeql"
  "release-artifacts"
)

for item in "${required_jobs[@]}"; do
  job="${item%%:*}"
  file="${item##*:}"
  if [[ ! -f "$file" ]]; then
    echo "missing workflow file for required job $job: $file" >&2
    exit 3
  fi
  if command -v rg >/dev/null 2>&1; then
    job_found_cmd=(rg -n "^[[:space:]]{2}${job}:$" "$file")
  else
    job_found_cmd=(grep -nE "^[[:space:]]{2}${job}:$" "$file")
  fi

  if ! "${job_found_cmd[@]}" >/dev/null; then
    echo "required job $job not found in $file" >&2
    exit 3
  fi
done

for check in "${required_checks[@]}"; do
  if ! grep -Eq "\"${check}\"" .github/required-checks.json; then
    echo "required check missing from branch protection contract: ${check}" >&2
    exit 3
  fi
done

for check in "${disallowed_checks[@]}"; do
  if grep -Eq "\"${check}\"" .github/required-checks.json; then
    echo "branch protection contract includes non-PR check: ${check}" >&2
    exit 3
  fi
done

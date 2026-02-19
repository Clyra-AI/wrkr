#!/usr/bin/env bash
set -euo pipefail

files=()
if [[ -f Makefile ]]; then
  files+=("Makefile")
fi
if [[ -f .pre-commit-config.yaml ]]; then
  files+=(".pre-commit-config.yaml")
fi
while IFS= read -r workflow; do
  files+=("$workflow")
done < <(find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | sort)

if [[ ${#files[@]} -eq 0 ]]; then
  exit 0
fi

if rg -n "@latest" "${files[@]}" >/dev/null; then
  echo "floating @latest reference found in build/CI configs" >&2
  rg -n "@latest" "${files[@]}" >&2
  exit 3
fi

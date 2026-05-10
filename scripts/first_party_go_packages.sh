#!/usr/bin/env bash
set -euo pipefail

go_cmd="${GO:-go}"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

roots=(
  "cmd"
  "core"
  "internal"
  "testinfra"
  "scripts"
  "scenarios"
)

patterns=()
for root in "${roots[@]}"; do
  if [[ ! -d "$root" ]]; then
    echo "missing first-party Go package root: $root" >&2
    exit 3
  fi
  patterns+=("./${root}/...")
done

"$go_cmd" list "${patterns[@]}"

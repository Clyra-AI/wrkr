#!/usr/bin/env bash
set -euo pipefail

mode="${1:-scheduled}"
top="${2:-5}"

if [[ "${mode}" != "scheduled" && "${mode}" != "pr" ]]; then
  echo "unsupported mode: ${mode}" >&2
  exit 6
fi

run_wrkr() {
  if command -v wrkr >/dev/null 2>&1; then
    wrkr "$@"
    return
  fi
  if command -v go >/dev/null 2>&1 && [[ -f "./cmd/wrkr/main.go" ]]; then
    go run ./cmd/wrkr "$@"
    return
  fi
  echo "wrkr runtime is missing: install wrkr binary or provide Go toolchain" >&2
  exit 7
}

run_wrkr scan --json
run_wrkr report --top "${top}" --json
run_wrkr score --json

# Deterministic mode marker for workflow consumers.
echo "wrkr_action_mode=${mode}"

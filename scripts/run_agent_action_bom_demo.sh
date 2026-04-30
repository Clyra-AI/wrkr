#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-before}"
fixture_root="$repo_root/scenarios/wrkr/agent-action-bom-demo/$mode"
scan_root="$fixture_root/repos"
output_root="${2:-$repo_root/.tmp/agent-action-bom-demo/$mode}"
state_path="$output_root/state.json"
evidence_json_path="$output_root/agent-action-bom-evidence.json"
bundle_output="$output_root/evidence-bundle"

if [[ ! -d "$scan_root" ]]; then
  echo "missing demo fixture at $scan_root" >&2
  exit 1
fi

mkdir -p "$output_root"

go run ./cmd/wrkr scan \
  --path "$scan_root" \
  --state "$state_path" \
  --json >"$output_root/scan.json"

if [[ -f "$fixture_root/runtime-evidence.json" ]]; then
  go run ./cmd/wrkr ingest \
    --state "$state_path" \
    --input "$fixture_root/runtime-evidence.json" \
    --json >"$output_root/ingest.json"
fi

go run ./cmd/wrkr report \
  --state "$state_path" \
  --template agent-action-bom \
  --json \
  --evidence-json \
  --evidence-json-path "$evidence_json_path" >"$output_root/report.json"

go run ./cmd/wrkr evidence \
  --frameworks soc2 \
  --state "$state_path" \
  --output "$bundle_output" \
  --json >"$output_root/evidence.json"

echo "$output_root"

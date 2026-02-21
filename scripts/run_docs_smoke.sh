#!/usr/bin/env bash
set -euo pipefail

mode="full"
if [[ "${1:-}" == "--subset" ]]; then
  mode="subset"
  shift
fi

bin_path="${WRKR_BIN:-}"
if [[ -z "$bin_path" ]]; then
  bin_path=".tmp/wrkr-docs-smoke"
  mkdir -p .tmp
  go build -o "$bin_path" ./cmd/wrkr
fi
if [[ "$bin_path" != /* ]]; then
  bin_path="$(pwd)/$bin_path"
fi

if [[ ! -x "$bin_path" ]]; then
  echo "wrkr binary is not executable: $bin_path" >&2
  exit 7
fi

tmp_dir="$(mktemp -d .tmp/docs-smoke.XXXXXX)"
tmp_dir="$(cd "$tmp_dir" && pwd)"
trap 'rm -rf "$tmp_dir"' EXIT

fixture_path="scenarios/wrkr/scan-mixed-org/repos"
state_path="$tmp_dir/state.json"
config_path="$tmp_dir/config.yaml"
baseline_path="$tmp_dir/wrkr-regress-baseline.json"
evidence_dir="$tmp_dir/evidence"
report_pdf="$tmp_dir/wrkr-report.pdf"
manifest_path="$tmp_dir/wrkr-manifest.yaml"

"$bin_path" init --non-interactive --path "$fixture_path" --config "$config_path" --json >/dev/null
"$bin_path" scan --path "$fixture_path" --state "$state_path" --json >"$tmp_dir/scan.json"
"$bin_path" scan --path "$fixture_path" --state "$state_path" --profile standard --json >"$tmp_dir/scan-standard.json"
(
  cd "$tmp_dir"
  "$bin_path" evidence --frameworks eu-ai-act,soc2 --state "$state_path" --json >"$tmp_dir/evidence-default.json"
)
"$bin_path" evidence --frameworks eu-ai-act,soc2 --state "$state_path" --output "$evidence_dir" --json >"$tmp_dir/evidence-managed.json"
"$bin_path" score --state "$state_path" --json >"$tmp_dir/score.json"
"$bin_path" verify --chain --state "$state_path" --json >"$tmp_dir/verify.json"
"$bin_path" regress init --baseline "$state_path" --output "$baseline_path" --json >"$tmp_dir/regress-init.json"
"$bin_path" regress run --baseline "$baseline_path" --state "$state_path" --json >"$tmp_dir/regress-run.json"

mkdir -p "$tmp_dir/non-managed"
printf "stale\n" >"$tmp_dir/non-managed/stale.txt"
set +e
"$bin_path" evidence --frameworks soc2 --state "$state_path" --output "$tmp_dir/non-managed" --json >"$tmp_dir/unsafe.out" 2>"$tmp_dir/unsafe.err"
unsafe_code=$?
set -e
if [[ $unsafe_code -ne 8 ]]; then
  echo "expected evidence unsafe output to fail with exit 8, got $unsafe_code" >&2
  exit 3
fi

python3 - "$tmp_dir" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

required = {
    "scan.json": ["status", "findings", "ranked_findings", "inventory", "profile", "posture_score"],
    "scan-standard.json": ["status", "profile", "posture_score"],
    "evidence-default.json": ["status", "output_dir", "framework_coverage"],
    "evidence-managed.json": ["status", "output_dir", "manifest_path", "chain_path"],
    "score.json": ["score", "grade", "weighted_breakdown", "trend_delta"],
    "verify.json": ["status", "chain"],
    "regress-init.json": ["status", "baseline_path", "tool_count"],
    "regress-run.json": ["status", "drift_detected", "reason_count", "reasons"],
}

for name, keys in required.items():
    payload = json.loads((root / name).read_text(encoding="utf-8"))
    for key in keys:
        if key not in payload:
            raise SystemExit(f"{name} missing key {key}")

unsafe_payload = json.loads((root / "unsafe.err").read_text(encoding="utf-8"))
err = unsafe_payload.get("error", {})
if err.get("code") != "unsafe_operation_blocked" or err.get("exit_code") != 8:
    raise SystemExit(f"unsafe output contract mismatch: {unsafe_payload}")
PY

if [[ "$mode" == "full" ]]; then
  "$bin_path" report --state "$state_path" --top 5 --pdf --pdf-path "$report_pdf" --json >"$tmp_dir/report.json"
  "$bin_path" export --state "$state_path" --format inventory --json >"$tmp_dir/export.json"
  "$bin_path" manifest generate --state "$state_path" --output "$manifest_path" --json >"$tmp_dir/manifest.json"
  "$bin_path" lifecycle --state "$state_path" --org local --json >"$tmp_dir/lifecycle.json"
  "$bin_path" identity list --state "$state_path" --json >"$tmp_dir/identity-list.json"
  "$bin_path" fix --state "$state_path" --top 3 --json >"$tmp_dir/fix.json"

  python3 - "$tmp_dir" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

checks = {
    "report.json": ["status", "top_findings", "total_tools", "pdf_path"],
    "export.json": ["export_version", "exported_at", "org", "tools"],
    "manifest.json": ["status", "manifest_path", "identity_count"],
    "lifecycle.json": ["status", "identities"],
    "identity-list.json": ["status", "identities"],
    "fix.json": ["status", "fingerprint", "remediation_count", "unsupported_findings"],
}

for name, keys in checks.items():
    payload = json.loads((root / name).read_text(encoding="utf-8"))
    for key in keys:
        if key not in payload:
            raise SystemExit(f"{name} missing key {key}")
PY
fi

echo "docs smoke (${mode}): pass"

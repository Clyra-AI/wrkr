#!/usr/bin/env bash
set -uo pipefail

mode="local"
if [[ "${1:-}" == "--mode" ]]; then
  mode="${2:-local}"
  shift 2
elif [[ "${1:-}" == --mode=* ]]; then
  mode="${1#--mode=}"
  shift
fi

case "$mode" in
  local|main|nightly|release) ;;
  *)
    echo "unsupported mode: $mode (expected local|main|nightly|release)" >&2
    exit 6
    ;;
esac

mkdir -p .tmp/release
mkdir -p .tmp/acceptance

ac_json_log=".tmp/acceptance/v1-acceptance-go-test.jsonl"
ac_status_json=".tmp/acceptance/v1-acceptance-ac-status.json"
log_dir=".tmp/acceptance/logs"
mkdir -p "$log_dir"

overall=0

run_cmd() {
  local name="$1"
  local cmd="$2"
  local log_path="$log_dir/${name}.log"
  echo "[acceptance] ${name}: ${cmd}"
  bash -lc "$cmd" >"$log_path" 2>&1
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "[acceptance] ${name}: FAIL (exit ${rc})"
    overall=1
  else
    echo "[acceptance] ${name}: PASS"
  fi
  return $rc
}

lane_fast="fail"
lane_core="fail"
lane_acceptance="fail"
lane_cross="fail"
lane_risk="fail"

touch "$ac_json_log"

# Acceptance AC1-AC20 matrix.
go test ./internal/acceptance -run '^TestV1AcceptanceMatrix$' -count=1 -json >"$ac_json_log" 2>"$log_dir/ac_matrix.stderr.log"
ac_rc=$?
if [[ $ac_rc -ne 0 ]]; then
  overall=1
fi

python3 - "$ac_json_log" "$ac_status_json" <<'PY'
import json
import pathlib
import re
import sys

log_path = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])

status = {f"AC{i:02d}": {"status": "fail", "test": f"TestV1AcceptanceMatrix/AC{i:02d}"} for i in range(1, 21)}

pattern = re.compile(r"TestV1AcceptanceMatrix/(AC\d{2})_")
for line in log_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    action = event.get("Action")
    test_name = event.get("Test", "")
    match = pattern.search(test_name)
    if not match or action not in {"pass", "fail", "skip"}:
        continue
    ac_id = match.group(1)
    mapped = "pass" if action == "pass" else "fail"
    status[ac_id] = {"status": mapped, "test": test_name}

out_path.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if [[ $ac_rc -eq 0 ]]; then
  lane_acceptance="pass"
fi

# Fast lane checks.
if run_cmd "lane_fast" "make lint-fast"; then
  lane_fast="pass"
fi

# Core lane checks.
if run_cmd "lane_core" "go test ./... -count=1"; then
  lane_core="pass"
fi

# Acceptance lane docs smoke.
if run_cmd "lane_docs_smoke" "scripts/run_docs_smoke.sh"; then
  if [[ "$lane_acceptance" == "pass" ]]; then
    lane_acceptance="pass"
  else
    lane_acceptance="fail"
  fi
else
  lane_acceptance="fail"
fi

# Cross-platform build safety lane.
if run_cmd "lane_cross_platform" "GOOS=linux GOARCH=amd64 go build -o .tmp/wrkr-linux ./cmd/wrkr && GOOS=darwin GOARCH=amd64 go build -o .tmp/wrkr-darwin ./cmd/wrkr && GOOS=windows GOARCH=amd64 go build -o .tmp/wrkr-windows.exe ./cmd/wrkr"; then
  lane_cross="pass"
fi

risk_cmd="make test-contracts && scripts/validate_scenarios.sh && go test ./internal/scenarios -count=1 -tags=scenario && go test ./internal/integration/interop -count=1"
if [[ "$mode" == "nightly" || "$mode" == "release" ]]; then
  risk_cmd+=" && scripts/test_hardening_core.sh && scripts/test_perf_budgets.sh"
fi
if run_cmd "lane_risk" "$risk_cmd"; then
  lane_risk="pass"
fi

scorecard_json=".tmp/release/v1-scorecard.json"
scorecard_md=".tmp/release/v1-scorecard.md"

python3 - "$ac_status_json" "$scorecard_json" "$scorecard_md" "$mode" "$lane_fast" "$lane_core" "$lane_acceptance" "$lane_cross" "$lane_risk" "$log_dir" <<'PY'
import datetime as dt
import json
import pathlib
import sys

ac_path = pathlib.Path(sys.argv[1])
json_path = pathlib.Path(sys.argv[2])
md_path = pathlib.Path(sys.argv[3])
mode = sys.argv[4]
lane_fast, lane_core, lane_acceptance, lane_cross, lane_risk = sys.argv[5:10]
log_dir = sys.argv[10]

ac_status = json.loads(ac_path.read_text(encoding="utf-8"))
lanes = {
    "fast": lane_fast,
    "core": lane_core,
    "acceptance": lane_acceptance,
    "cross_platform": lane_cross,
    "risk": lane_risk,
}

failed_acs = sorted([ac for ac, record in ac_status.items() if record.get("status") != "pass"])
failed_lanes = sorted([name for name, status in lanes.items() if status != "pass"])

scorecard = {
    "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    "mode": mode,
    "lanes": {name: {"status": status} for name, status in lanes.items()},
    "ac_status": ac_status,
    "known_exceptions": [],
    "mandatory_pass": len(failed_acs) == 0 and len(failed_lanes) == 0,
    "failed_acs": failed_acs,
    "failed_lanes": failed_lanes,
    "logs_dir": log_dir,
}

json_path.write_text(json.dumps(scorecard, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    "# Wrkr v1 Acceptance Scorecard",
    "",
    f"- Mode: `{mode}`",
    f"- Generated at (UTC): `{scorecard['generated_at']}`",
    f"- Mandatory pass: `{str(scorecard['mandatory_pass']).lower()}`",
    "",
    "## Lane status",
    "",
    "| Lane | Status |",
    "|------|--------|",
]
for lane_name in ["fast", "core", "acceptance", "cross_platform", "risk"]:
    lines.append(f"| {lane_name} | {lanes[lane_name]} |")

lines.extend([
    "",
    "## AC status",
    "",
    "| AC | Status | Test |",
    "|----|--------|------|",
])
for ac_id in sorted(ac_status.keys()):
    record = ac_status[ac_id]
    lines.append(f"| {ac_id} | {record.get('status', 'fail')} | `{record.get('test', '')}` |")

if failed_lanes:
    lines.extend(["", "## Failed lanes", ""])
    for lane in failed_lanes:
        lines.append(f"- `{lane}`")

if failed_acs:
    lines.extend(["", "## Failed ACs", ""])
    for ac in failed_acs:
        lines.append(f"- `{ac}`")

lines.extend(["", f"Logs: `{log_dir}`", ""])
md_path.write_text("\n".join(lines), encoding="utf-8")
PY

if [[ $overall -ne 0 ]]; then
  echo "v1 acceptance: FAIL (scorecard: $scorecard_json)" >&2
  exit 1
fi

if ! python3 - "$scorecard_json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
if not payload.get("mandatory_pass", False):
    raise SystemExit(1)
PY
then
  echo "v1 acceptance: FAIL (mandatory checks not all passing)" >&2
  exit 1
fi

echo "v1 acceptance: PASS"
echo "scorecard json: $scorecard_json"
echo "scorecard md:   $scorecard_md"

#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for agent benchmark execution" >&2
  exit 7
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_PATH="${REPO_ROOT}/.tmp/agent-benchmarks.json"
PRINT_JSON=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      PRINT_JSON=1
      shift
      ;;
    --output)
      if [[ $# -lt 2 ]]; then
        echo "--output requires a value" >&2
        exit 6
      fi
      OUTPUT_PATH="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 6
      ;;
  esac
done

mkdir -p "$(dirname "$OUTPUT_PATH")"

python3 - "$REPO_ROOT" "$OUTPUT_PATH" "$PRINT_JSON" <<'PY'
import json
import pathlib
import subprocess
import sys
import tempfile

repo_root = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
print_json = sys.argv[3] == "1"

corpus = json.loads((repo_root / "testinfra" / "benchmarks" / "agents" / "corpus.json").read_text(encoding="utf-8"))
thresholds = json.loads((repo_root / "testinfra" / "benchmarks" / "agents" / "thresholds.json").read_text(encoding="utf-8"))

target_detectors = set(corpus["target_detectors"])
positive_types = set(corpus["positive_finding_types"])
cases = sorted(corpus["cases"], key=lambda item: item["id"])

wrkr_bin = repo_root / ".tmp" / "wrkr"
wrkr_bin.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(["go", "build", "-o", str(wrkr_bin), "./cmd/wrkr"], cwd=repo_root, check=True)

results = []
tp = fp = tn = fn = 0

for case in cases:
  case_id = case["id"]
  case_kind = case["kind"]
  case_path = repo_root / case["path"]
  expected_detectors = sorted(case.get("expected_detectors", []))

  state_path = pathlib.Path(tempfile.mkdtemp(prefix=f"agent-bench-{case_id}-")) / "state.json"
  cmd = [str(wrkr_bin), "scan", "--path", str(case_path), "--state", str(state_path), "--json", "--quiet"]
  proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
  if proc.returncode != 0:
    print(f"benchmark case {case_id} failed scan with exit {proc.returncode}: {proc.stderr.strip()}", file=sys.stderr)
    sys.exit(1)

  payload = json.loads(proc.stdout)
  findings = payload.get("findings", [])
  matched = []
  for finding in findings:
    detector = str(finding.get("detector", "")).strip()
    finding_type = str(finding.get("finding_type", "")).strip()
    if detector in target_detectors and finding_type in positive_types:
      matched.append({"detector": detector, "finding_type": finding_type})

  matched_detectors = sorted({item["detector"] for item in matched})
  predicted_positive = len(matched_detectors) > 0

  if case_kind == "positive":
    expected_hit = all(detector in matched_detectors for detector in expected_detectors)
    if predicted_positive and expected_hit:
      tp += 1
      outcome = "tp"
    else:
      fn += 1
      outcome = "fn"
  elif case_kind == "negative":
    if predicted_positive:
      fp += 1
      outcome = "fp"
    else:
      tn += 1
      outcome = "tn"
  else:
    print(f"benchmark case {case_id} has unsupported kind {case_kind}", file=sys.stderr)
    sys.exit(1)

  results.append(
    {
      "id": case_id,
      "kind": case_kind,
      "path": case["path"],
      "expected_detectors": expected_detectors,
      "matched_detectors": matched_detectors,
      "outcome": outcome,
    }
  )

precision_denominator = tp + fp
recall_denominator = tp + fn
precision = 1.0 if precision_denominator == 0 else tp / precision_denominator
recall = 1.0 if recall_denominator == 0 else tp / recall_denominator

metrics = {
  "tp": tp,
  "fp": fp,
  "tn": tn,
  "fn": fn,
  "precision": round(precision, 6),
  "recall": round(recall, 6),
}

minimum_precision = float(thresholds["minimum_precision"])
minimum_recall = float(thresholds["minimum_recall"])
baseline_recall = float(thresholds["baseline_recall"])
max_recall_regression = float(thresholds["max_recall_regression"])
recall_floor = baseline_recall - max_recall_regression

violations = []
if precision < minimum_precision:
  violations.append(
    f"precision {precision:.4f} below minimum threshold {minimum_precision:.4f}"
  )
if recall < minimum_recall:
  violations.append(
    f"recall {recall:.4f} below minimum threshold {minimum_recall:.4f}"
  )
if recall < recall_floor:
  violations.append(
    f"recall {recall:.4f} below regression floor {recall_floor:.4f} (baseline={baseline_recall:.4f}, max_regression={max_recall_regression:.4f})"
  )

output = {
  "version": "v1",
  "thresholds": {
    "minimum_precision": minimum_precision,
    "minimum_recall": minimum_recall,
    "baseline_recall": baseline_recall,
    "max_recall_regression": max_recall_regression,
    "recall_regression_floor": round(recall_floor, 6),
  },
  "metrics": metrics,
  "cases": results,
  "status": "pass" if not violations else "fail",
  "violations": violations,
}

output_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if print_json:
  print(json.dumps(output, indent=2, sort_keys=True))
else:
  print(f"agent benchmark status={output['status']} precision={precision:.4f} recall={recall:.4f} -> {output_path}")

if violations:
  for violation in violations:
    print(violation, file=sys.stderr)
  sys.exit(1)
PY

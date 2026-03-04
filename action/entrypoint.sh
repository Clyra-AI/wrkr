#!/usr/bin/env bash
set -euo pipefail

mode="${1:-scheduled}"
top="${2:-5}"
target_mode="${3:-}"
target_value="${4:-}"
config_path="${5:-}"
sarif_path="${6:-${WRKR_ACTION_SARIF_PATH:-./.tmp/wrkr.sarif}}"
summary_path="${WRKR_ACTION_SUMMARY_PATH:-./.tmp/wrkr-action-summary.md}"
comment_fingerprint="${WRKR_ACTION_COMMENT_FINGERPRINT:-wrkr-action-pr-mode-v1}"
block_threshold="${WRKR_ACTION_BLOCK_THRESHOLD:-0}"

if [[ "${mode}" != "scheduled" && "${mode}" != "pr" && "${mode}" != "sarif" ]]; then
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

scan_args=(--json)

if [[ -n "${target_mode}" && -z "${target_value}" ]]; then
  echo "incomplete explicit target: target_mode requires target_value" >&2
  exit 6
fi
if [[ -z "${target_mode}" && -n "${target_value}" ]]; then
  echo "incomplete explicit target: target_value requires target_mode" >&2
  exit 6
fi

if [[ -n "${target_mode}" && -n "${target_value}" ]]; then
  case "${target_mode}" in
    repo)
      scan_args+=(--repo "${target_value}")
      ;;
    org)
      scan_args+=(--org "${target_value}")
      ;;
    path)
      scan_args+=(--path "${target_value}")
      ;;
    *)
      echo "unsupported target mode: ${target_mode}" >&2
      exit 6
      ;;
  esac
elif [[ -n "${config_path}" ]]; then
  scan_args+=(--config "${config_path}")
elif [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
  scan_args+=(--repo "${GITHUB_REPOSITORY}")
else
  echo "missing scan target: set target_mode+target_value, config_path, or GITHUB_REPOSITORY" >&2
  exit 6
fi

if [[ "${mode}" == "sarif" ]]; then
  scan_args+=(--sarif --sarif-path "${sarif_path}")
fi

scan_json="$(run_wrkr scan "${scan_args[@]}")"
run_wrkr report --top "${top}" --md --md-path "${summary_path}" --template operator --share-profile internal --json >/dev/null
score_json="$(run_wrkr score --json)"

extract_number_from_json() {
  local json_payload="$1"
  local expression="$2"
  python3 - "$expression" "$json_payload" <<'PY'
import json
import sys

expr = sys.argv[1]
payload = json.loads(sys.argv[2] or "{}")
current = payload
for token in expr.split("."):
    if not token:
        continue
    if not isinstance(current, dict):
        print("0")
        raise SystemExit(0)
    current = current.get(token)
if current is None:
    print("0")
elif isinstance(current, (int, float)):
    print(str(current))
else:
    try:
        print(str(float(current)))
    except Exception:
        print("0")
PY
}

detect_changed_paths() {
  if [[ -n "${WRKR_ACTION_CHANGED_PATHS:-}" ]]; then
    printf '%s\n' "${WRKR_ACTION_CHANGED_PATHS}"
    return
  fi

  if [[ -n "${GITHUB_BASE_REF:-}" ]] && command -v git >/dev/null 2>&1; then
    git fetch --no-tags --depth=1 origin "${GITHUB_BASE_REF}" >/dev/null 2>&1 || true
    if changed_paths="$(git diff --name-only "origin/${GITHUB_BASE_REF}...HEAD" 2>/dev/null)"; then
      printf '%s\n' "${changed_paths}"
      return
    fi
  fi

  if [[ -n "${GITHUB_EVENT_PATH:-}" && -f "${GITHUB_EVENT_PATH}" ]]; then
    python3 - <<'PY' "${GITHUB_EVENT_PATH}" || true
import json
import pathlib
import sys

event_path = pathlib.Path(sys.argv[1])
payload = json.loads(event_path.read_text(encoding="utf-8"))
paths = []
for commit in payload.get("commits", []):
    for key in ("added", "modified", "removed"):
        for path in commit.get(key, []):
            if isinstance(path, str) and path.strip():
                paths.append(path.strip())
seen = set()
for item in paths:
    if item in seen:
        continue
    seen.add(item)
    print(item)
PY
    return
  fi
}

extract_pr_number() {
  if [[ -n "${WRKR_PR_NUMBER:-}" ]]; then
    printf '%s\n' "${WRKR_PR_NUMBER}"
    return
  fi
  if [[ -n "${GITHUB_EVENT_PATH:-}" && -f "${GITHUB_EVENT_PATH}" ]]; then
    python3 - <<'PY' "${GITHUB_EVENT_PATH}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
number = payload.get("pull_request", {}).get("number")
if isinstance(number, int):
    print(number)
else:
    print("0")
PY
    return
  fi
  echo "0"
}

if [[ "${mode}" == "pr" ]]; then
  changed_paths="$(detect_changed_paths)"
  risk_delta="$(extract_number_from_json "${score_json}" "trend_delta")"
  compliance_delta="$(extract_number_from_json "${scan_json}" "profile.delta_percent")"

  owner="${GITHUB_REPOSITORY%%/*}"
  repo="${GITHUB_REPOSITORY#*/}"
  if [[ -z "${GITHUB_REPOSITORY:-}" || "${owner}" == "${repo}" ]]; then
    owner="${WRKR_REPO_OWNER:-}"
    repo="${WRKR_REPO_NAME:-}"
  fi
  pr_number="$(extract_pr_number)"

  token="${WRKR_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
  run_wrkr action pr-comment \
    --changed-paths "${changed_paths}" \
    --risk-delta "${risk_delta}" \
    --compliance-delta "${compliance_delta}" \
    --block-threshold "${block_threshold}" \
    --owner "${owner}" \
    --repo "${repo}" \
    --pr-number "${pr_number}" \
    --github-api "${GITHUB_API_URL:-https://api.github.com}" \
    --github-token "${token}" \
    --fingerprint "${comment_fingerprint}" \
    --json >/dev/null
fi

# Deterministic mode marker for workflow consumers.
echo "wrkr_action_mode=${mode}"
echo "wrkr_action_summary=${summary_path}"
if [[ "${mode}" == "sarif" ]]; then
  echo "wrkr_action_sarif=${sarif_path}"
fi

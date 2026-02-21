#!/usr/bin/env bash
set -euo pipefail

mode="${1:-scheduled}"
top="${2:-5}"
target_mode="${3:-}"
target_value="${4:-}"
config_path="${5:-}"
summary_path="${WRKR_ACTION_SUMMARY_PATH:-./.tmp/wrkr-action-summary.md}"

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

run_wrkr scan "${scan_args[@]}"
run_wrkr report --top "${top}" --md --md-path "${summary_path}" --template operator --share-profile internal --json
run_wrkr score --json

# Deterministic mode marker for workflow consumers.
echo "wrkr_action_mode=${mode}"
echo "wrkr_action_summary=${summary_path}"

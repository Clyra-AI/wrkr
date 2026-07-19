#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ( "$1" != "--check" && "$1" != "--update" ) ]]; then
  echo "usage: scripts/generate_action_contract_conformance.sh --check|--update" >&2
  exit 6
fi
mode="$1"

if ! command -v go >/dev/null 2>&1; then
  echo '{"error":{"code":"dependency_missing","exit_code":7,"message":"go is required for Action Contract fixture generation"}}' >&2
  exit 7
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo '{"error":{"code":"dependency_missing","exit_code":7,"message":"python3 is required for Action Contract fixture generation"}}' >&2
  exit 7
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
spec_path="${repo_root}/scenarios/cross-product/action-contract-interop/inputs/scenario-specs.json"
expected_root="${repo_root}/scenarios/cross-product/action-contract-interop/expected"
manifest_root="scenarios/cross-product/action-contract-interop/expected"
base_scan_root="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["base_scan_root"])' "${spec_path}")"
tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/wrkr-action-contract-interop-XXXXXX")"
trap 'rm -rf "${tmp_root}"' EXIT

wrkr_bin="${tmp_root}/wrkr"
base_state="${tmp_root}/base-state.json"
scenario_states="${tmp_root}/states"
scenario_index="${tmp_root}/scenario-index.tsv"
generated_root="${tmp_root}/expected"

mkdir -p "${scenario_states}" "${generated_root}"
(cd "${repo_root}" && go build -o "${wrkr_bin}" ./cmd/wrkr)
(cd "${repo_root}" && "${wrkr_bin}" scan --path "${base_scan_root}" --state "${base_state}" --progress none --json >/dev/null)
(cd "${repo_root}" && go run ./scripts/action_contract_conformance prepare \
  --state "${base_state}" \
  --spec "${spec_path}" \
  --output-dir "${scenario_states}" \
  --index "${scenario_index}")

while IFS=$'\t' read -r scenario_id state_path contract_id; do
  if [[ -z "${scenario_id}" || -z "${state_path}" || -z "${contract_id}" ]]; then
    echo "invalid generated scenario index row" >&2
    exit 1
  fi
  scenario_dir="${generated_root}/${scenario_id}"
  mkdir -p "${scenario_dir}"
  "${wrkr_bin}" export action-contracts --state "${state_path}" --contract-id "${contract_id}" --output-dir "${scenario_dir}" --json >/dev/null
  "${wrkr_bin}" report --state "${state_path}" --template action-contract-packet --contract-id "${contract_id}" --share-profile internal --json >"${scenario_dir}/packet.json"
  "${wrkr_bin}" report --state "${state_path}" --template action-contract-packet --contract-id "${contract_id}" --share-profile internal >"${scenario_dir}/packet.md"
done <"${scenario_index}"

(cd "${repo_root}" && go run ./scripts/action_contract_conformance finalize \
  --repo-root "${repo_root}" \
  --spec "${spec_path}" \
  --generated-dir "${generated_root}" \
  --manifest-root "${manifest_root}" \
  --producer-version "${WRKR_FIXTURE_PRODUCER_VERSION:-devel}" \
  --output "${generated_root}/fixture-manifest.json")

if [[ "${mode}" == "--update" ]]; then
  required_target="${repo_root}/scenarios/cross-product/action-contract-interop/expected"
  if [[ "${expected_root}" != "${required_target}" ]]; then
    echo "refusing unsafe fixture update target: ${expected_root}" >&2
    exit 8
  fi
  rm -rf -- "${expected_root}"
  mkdir -p "$(dirname "${expected_root}")"
  cp -R "${generated_root}" "${expected_root}"
  echo "updated Action Contract conformance fixtures: ${expected_root}"
  exit 0
fi

if ! diff -ruN "${expected_root}" "${generated_root}"; then
  echo "Action Contract conformance fixtures are stale; review with --update" >&2
  exit 1
fi
echo "Action Contract conformance fixtures: exact bytes pass"

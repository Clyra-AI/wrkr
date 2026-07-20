#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest_path="${repo_root}/scenarios/cross-product/action-contract-interop/expected/fixture-manifest.json"
receipt_dir="${WRKR_ACTION_CONTRACT_RECEIPT_DIR:-${repo_root}/.tmp/action-contract-interop-receipts}"

if ! command -v python3 >/dev/null 2>&1; then
  echo '{"error":{"code":"dependency_missing","exit_code":7,"message":"python3 is required for Tier 12 Action Contract interoperability"}}' >&2
  exit 7
fi
if [[ ! -f "${manifest_path}" ]]; then
  echo '{"error":{"code":"dependency_missing","exit_code":7,"message":"Action Contract fixture manifest is missing; run the generator first"}}' >&2
  exit 7
fi

for env_name in WRKR_GAIT_ACTION_CONTRACT_CONSUMER WRKR_AXYM_ACTION_CONTRACT_CONSUMER; do
  consumer="${!env_name:-}"
  if [[ -z "${consumer}" ]]; then
    printf '{"error":{"code":"dependency_missing","exit_code":7,"message":"%s is required for Tier 12 Action Contract interoperability"}}\n' "${env_name}" >&2
    exit 7
  fi
  if [[ ! -x "${consumer}" ]]; then
    printf '{"error":{"code":"dependency_missing","exit_code":7,"message":"configured consumer is not executable: %s"}}\n' "${consumer}" >&2
    exit 7
  fi
done

mkdir -p "${receipt_dir}"
scenario_index="$(mktemp "${TMPDIR:-/tmp}/wrkr-action-contract-consumers-XXXXXX")"
trap 'rm -f "${scenario_index}"' EXIT
fixture_metadata="$(python3 - "${manifest_path}" <<'PY'
import hashlib
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = path.read_bytes()
manifest = json.loads(payload)
schemas = manifest["schemas"]
print("\t".join((
    manifest["fixture_version"],
    "sha256:" + hashlib.sha256(payload).hexdigest(),
    manifest["producer"]["version"],
    schemas["artifact"],
    schemas["contract"],
    schemas["packet"],
)))
PY
)"
IFS=$'\t' read -r fixture_version fixture_manifest_sha256 producer_version artifact_schema_version contract_schema_version packet_schema_version <<<"${fixture_metadata}"

python3 - "${manifest_path}" "${repo_root}" >"${scenario_index}" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
root = pathlib.Path(sys.argv[2]).resolve()
expected_consumers = {
    "gait": "WRKR_GAIT_ACTION_CONTRACT_CONSUMER",
    "axym": "WRKR_AXYM_ACTION_CONTRACT_CONSUMER",
}
actual_consumers = {name: item["command_env"] for name, item in manifest["external_consumers"].items()}
if actual_consumers != expected_consumers:
    raise SystemExit(f"fixture manifest consumer contract drift: {actual_consumers!r}")
if len(manifest["scenarios"]) != 9:
    raise SystemExit("fixture manifest must contain nine scenarios")
for scenario in manifest["scenarios"]:
    artifact = (root / scenario["artifact_path"]).resolve()
    if root not in artifact.parents or not artifact.is_file():
        raise SystemExit(f"unsafe or missing artifact path: {artifact}")
    actual_digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual_digest != scenario["artifact_sha256"]:
        raise SystemExit(f"artifact digest mismatch before consumer invocation: {artifact}")
    print("\t".join((scenario["scenario_id"], str(artifact), scenario["artifact_sha256"])))
PY

run_consumer() {
  local consumer_name="$1"
  local consumer_path="$2"
  local aggregate_path="${receipt_dir}/${consumer_name}.json"
  local rows_dir
  local row_path
  rows_dir="$(mktemp -d "${TMPDIR:-/tmp}/wrkr-${consumer_name}-receipts-XXXXXX")"
  while IFS=$'\t' read -r scenario_id artifact_path artifact_digest; do
    row_path="${rows_dir}/${scenario_id}.json"
    "${consumer_path}" "${artifact_path}" >"${row_path}"
    python3 - "${row_path}" "${consumer_name}" "${scenario_id}" "${artifact_path}" "${artifact_digest}" <<'PY'
import hashlib
import json
import pathlib
import sys

receipt_path, consumer, scenario, artifact_path, expected_digest = sys.argv[1:]
receipt = json.loads(pathlib.Path(receipt_path).read_text(encoding="utf-8"))
actual_digest = "sha256:" + hashlib.sha256(pathlib.Path(artifact_path).read_bytes()).hexdigest()
required = {
    "consumer": consumer,
    "scenario_id": scenario,
    "artifact_sha256": expected_digest,
    "status": "pass",
}
if actual_digest != expected_digest:
    raise SystemExit("artifact bytes changed during consumer invocation")
for key, expected in required.items():
    if receipt.get(key) != expected:
        raise SystemExit(f"consumer receipt mismatch for {key}: got={receipt.get(key)!r} want={expected!r}")
if not str(receipt.get("version", "")).strip():
    raise SystemExit("consumer receipt is missing version")
PY
  done <"${scenario_index}"
  python3 - "${consumer_name}" "${rows_dir}" "${aggregate_path}" "${fixture_version}" "${fixture_manifest_sha256}" "${producer_version}" "${artifact_schema_version}" "${contract_schema_version}" "${packet_schema_version}" <<'PY'
import json
import pathlib
import sys

consumer, rows_dir, output, fixture_version, manifest_digest, producer_version, artifact_schema, contract_schema, packet_schema = sys.argv[1:]
rows = []
for path in sorted(pathlib.Path(rows_dir).glob("*.json")):
    rows.append(json.loads(path.read_text(encoding="utf-8")))
payload = {
    "receipt_version": "1",
    "fixture_version": fixture_version,
    "fixture_manifest_sha256": manifest_digest,
    "producer_version": producer_version,
    "schemas": {"artifact": artifact_schema, "contract": contract_schema, "packet": packet_schema},
    "consumer": consumer,
    "status": "pass",
    "scenario_receipts": rows,
}
pathlib.Path(output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  rm -rf -- "${rows_dir}"
}

run_consumer "gait" "${WRKR_GAIT_ACTION_CONTRACT_CONSUMER}"
run_consumer "axym" "${WRKR_AXYM_ACTION_CONTRACT_CONSUMER}"
printf '{"status":"pass","fixture_manifest":"%s","receipt_dir":"%s"}\n' "${manifest_path}" "${receipt_dir}"

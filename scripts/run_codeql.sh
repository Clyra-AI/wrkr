#!/usr/bin/env bash
set -euo pipefail

codeql_bin="$(command -v codeql 2>/dev/null || true)"
if [[ -z "${codeql_bin}" ]] && [[ -n "${CODEQL_DIST:-}" ]] && [[ -x "${CODEQL_DIST}/codeql" ]]; then
  codeql_bin="${CODEQL_DIST}/codeql"
fi
if [[ -z "${codeql_bin}" ]]; then
  echo "codeql CLI not found (PATH and CODEQL_DIST/codeql)" >&2
  exit 7
fi

db_dir=".tmp/codeql-db"
results_file=".tmp/codeql-results.sarif"
rm -rf "$db_dir"
mkdir -p .tmp

detect_total_memory_mb() {
  if [[ -r /proc/meminfo ]]; then
    awk '/MemTotal/ { printf "%d", $2 / 1024 }' /proc/meminfo
    return
  fi
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.memsize 2>/dev/null | awk '{ printf "%d", $1 / 1024 / 1024 }'
  fi
}

detect_cpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
    return
  fi
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu 2>/dev/null
  fi
}

codeql_ram_mb="${CODEQL_RAM_MB:-}"
if [[ -z "$codeql_ram_mb" && "${CODEQL_AUTO_RAM:-1}" != "0" ]]; then
  total_memory_mb="$(detect_total_memory_mb || true)"
  if [[ "$total_memory_mb" =~ ^[0-9]+$ ]] && (( total_memory_mb >= 15360 )); then
    codeql_ram_mb=12288
  fi
fi

codeql_analyze_args=(
  "$db_dir"
  codeql/go-queries:codeql-suites/go-security-and-quality.qls
  --format=sarif-latest
  --output "$results_file"
)
if [[ -n "$codeql_ram_mb" ]]; then
  codeql_analyze_args+=(--ram="$codeql_ram_mb")
fi
codeql_threads="${CODEQL_THREADS:-}"
if [[ -z "$codeql_threads" && -n "$codeql_ram_mb" && "${CODEQL_AUTO_THREADS:-1}" != "0" ]]; then
  cpu_count="$(detect_cpu_count || true)"
  if [[ "$cpu_count" =~ ^[0-9]+$ ]] && (( cpu_count > 1 )); then
    codeql_threads=0
  fi
fi
if [[ -n "$codeql_threads" ]]; then
  codeql_analyze_args+=(--threads="$codeql_threads")
fi
if [[ "${CODEQL_RELEASE_COMPATIBILITY:-0}" != "1" ]]; then
  codeql_analyze_args+=(--no-release-compatibility)
fi
if [[ -n "${CODEQL_MAX_DISK_CACHE_MB:-}" ]]; then
  codeql_analyze_args+=(--max-disk-cache="$CODEQL_MAX_DISK_CACHE_MB")
elif [[ -n "$codeql_ram_mb" ]]; then
  codeql_analyze_args+=(--max-disk-cache=8192)
fi

"${codeql_bin}" database create "$db_dir" \
  --language=go \
  --source-root . \
  --overwrite \
  --command "go build -o .tmp/wrkr ./cmd/wrkr"

"${codeql_bin}" database analyze "${codeql_analyze_args[@]}"

echo "CodeQL analysis completed: $results_file"

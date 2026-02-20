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

"${codeql_bin}" database create "$db_dir" \
  --language=go \
  --source-root . \
  --overwrite \
  --command "go build -o .tmp/wrkr ./cmd/wrkr"

"${codeql_bin}" database analyze "$db_dir" \
  codeql/go-queries:codeql-suites/go-security-and-quality.qls \
  --format=sarif-latest \
  --output "$results_file"

echo "CodeQL analysis completed: $results_file"

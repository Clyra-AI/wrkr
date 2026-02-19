#!/usr/bin/env bash
set -euo pipefail

if ! command -v codeql >/dev/null 2>&1; then
  echo "codeql CLI not found" >&2
  exit 7
fi

db_dir=".tmp/codeql-db"
results_file=".tmp/codeql-results.sarif"
rm -rf "$db_dir"
mkdir -p .tmp

codeql database create "$db_dir" \
  --language=go \
  --source-root . \
  --overwrite \
  --command "go build -o .tmp/wrkr ./cmd/wrkr"

codeql database analyze "$db_dir" \
  codeql/go-queries:codeql-suites/go-security-and-quality.qls \
  --format=sarif-latest \
  --output "$results_file"

echo "CodeQL analysis completed: $results_file"

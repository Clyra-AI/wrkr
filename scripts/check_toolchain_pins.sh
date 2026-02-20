#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f .tool-versions ]]; then
  echo "missing .tool-versions" >&2
  exit 3
fi

expected=(
  "golang 1.25.7"
  "python 3.13.1"
  "nodejs 22.14.0"
)
for line in "${expected[@]}"; do
  if ! grep -Fxq "$line" .tool-versions; then
    echo "missing pinned toolchain line: $line" >&2
    exit 3
  fi
done

if grep -Eq '^toolchain go1\.25\.7$' go.mod; then
  exit 0
fi

if grep -Eq '^go 1\.25\.7$' go.mod; then
  exit 0
fi

echo "go.mod must pin go toolchain version 1.25.7 (toolchain or go directive)" >&2
exit 3

#!/usr/bin/env bash
set -euo pipefail

playbook="docs/examples/operator-playbooks.md"
quickstart="docs/examples/quickstart.md"

for file in "$playbook" "$quickstart"; do
  if [[ ! -f "$file" ]]; then
    echo "missing docs storyline file: $file" >&2
    exit 3
  fi
done

required_playbook_tokens=(
  "Scan workflow"
  "Fix workflow"
  "Evidence workflow"
  "Verify workflow"
  "Regress workflow"
  "Identity lifecycle workflow"
  "FR11"
  "FR12"
  "FR13"
  "unsafe_operation_blocked"
)

for token in "${required_playbook_tokens[@]}"; do
  if ! grep -Fq "$token" "$playbook"; then
    echo "operator playbook missing token: $token" >&2
    exit 3
  fi
done

required_quickstart_tokens=(
  "AI-DSPM"
  "See -> Prove -> Control"
  "wrkr scan"
  "wrkr evidence"
  "wrkr verify"
  "wrkr regress"
)

for token in "${required_quickstart_tokens[@]}"; do
  if ! grep -Fq "$token" "$quickstart"; then
    echo "quickstart missing token: $token" >&2
    exit 3
  fi
done

echo "docs storyline checks: pass"

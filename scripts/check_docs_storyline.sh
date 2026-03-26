#!/usr/bin/env bash
set -euo pipefail

playbook="docs/examples/operator-playbooks.md"
quickstart="docs/examples/quickstart.md"
readme="README.md"

for file in "$playbook" "$quickstart" "$readme"; do
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
  "wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json"
  "wrkr scan"
  "wrkr evidence"
  "wrkr verify"
  "wrkr regress"
  "repo-root fixture noise"
)

for token in "${required_quickstart_tokens[@]}"; do
  if ! grep -Fq "$token" "$quickstart"; then
    echo "quickstart missing token: $token" >&2
    exit 3
  fi
done

required_readme_tokens=(
  "wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json"
  "wrkr evidence --frameworks"
  "wrkr verify --chain"
  "wrkr regress init"
  "repo-root fixture noise"
)

for token in "${required_readme_tokens[@]}"; do
  if ! grep -Fq "$token" "$readme"; then
    echo "README missing token: $token" >&2
    exit 3
  fi
done

echo "docs storyline checks: pass"

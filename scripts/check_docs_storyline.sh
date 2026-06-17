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
  "Design-partner control validation workflow"
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
  "Focused repo review first"
  "wrkr scan --path ./your-repo --profile assessment --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scan-summary.md"
  "wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --md --md-path ./.tmp/focused-agent-action-bom.md"
  "Automation / CI equivalent"
  "wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --json"
  "wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scenario-summary.md"
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
  "Focused Repo Review (Recommended first path)"
  "wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --md --md-path ./.tmp/focused-agent-action-bom.md"
  "Automation / CI equivalent"
  "wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --json"
  "wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scenario-summary.md"
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

required_scan_tokens=(
  "For manual large scans"
  "wrkr scan --path ./your-repo --profile assessment --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scan-summary.md"
  "Automation / CI workflow:"
  "wrkr scan --path ./your-repo --profile assessment --state ./.wrkr/last-scan.json --json --json-path ./.wrkr/scan.json"
)

for token in "${required_scan_tokens[@]}"; do
  if ! grep -Fq "$token" "docs/commands/scan.md"; then
    echo "scan command docs missing token: $token" >&2
    exit 3
  fi
done

required_report_tokens=(
  "Human/manual artifact handoff:"
  "wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --md --md-path ./.tmp/focused-agent-action-bom.md"
  "Automation / CI workflow:"
  "wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --json"
)

for token in "${required_report_tokens[@]}"; do
  if ! grep -Fq "$token" "docs/commands/report.md"; then
    echo "report command docs missing token: $token" >&2
    exit 3
  fi
done

required_evidence_tokens=(
  "Human/manual handoff:"
  "wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence"
  "Automation / CI workflow:"
  "wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./wrkr-evidence --json"
)

for token in "${required_evidence_tokens[@]}"; do
  if ! grep -Fq "$token" "docs/commands/evidence.md"; then
    echo "evidence command docs missing token: $token" >&2
    exit 3
  fi
done

required_assess_tokens=(
  "Human/manual handoff:"
  "wrkr assess --path ./your-repo --output-dir ./.wrkr/assessment --template agent-action-bom --share-profile customer-redacted"
  "Automation / CI workflow:"
  "wrkr assess --path ./your-repo --output-dir ./.wrkr/assessment --json"
)

for token in "${required_assess_tokens[@]}"; do
  if ! grep -Fq "$token" "docs/commands/assess.md"; then
    echo "assess command docs missing token: $token" >&2
    exit 3
  fi
done

echo "docs storyline checks: pass"

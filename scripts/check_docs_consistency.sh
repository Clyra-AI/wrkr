#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

HAS_RG=0
if command -v rg >/dev/null 2>&1; then
  HAS_RG=1
fi

fail() {
  echo "docs consistency failure: $1" >&2
  FAILURES=$((FAILURES + 1))
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    fail "missing file ${path}"
  fi
}

require_pattern() {
  local path="$1"
  local pattern="$2"
  local reason="$3"
  if ! search_regex "$pattern" "$path"; then
    fail "${reason} (${path})"
  fi
}

search_regex() {
  local pattern="$1"
  local path="$2"
  if [[ "${HAS_RG}" -eq 1 ]]; then
    rg -q --pcre2 "$pattern" "$path"
  else
    grep -Eq "$pattern" "$path"
  fi
}

search_fixed_ci() {
  local needle="$1"
  local path="$2"
  if [[ "${HAS_RG}" -eq 1 ]]; then
    rg -qi --fixed-strings "$needle" "$path"
  else
    grep -Fqi -- "$needle" "$path"
  fi
}

extract_exit_codes() {
  local source_path="$1"
  if [[ "${HAS_RG}" -eq 1 ]]; then
    rg -o --no-filename "exit[A-Za-z]+\\s*=\\s*[0-9]+" "${source_path}" | rg -o "[0-9]+" | sort -n | uniq
  else
    grep -Eo "exit[A-Za-z]+[[:space:]]*=[[:space:]]*[0-9]+" "${source_path}" | grep -Eo "[0-9]+" | sort -n | uniq
  fi
}

for path in \
  "${REPO_ROOT}/README.md" \
  "${REPO_ROOT}/CODE_OF_CONDUCT.md" \
  "${REPO_ROOT}/CHANGELOG.md" \
  "${REPO_ROOT}/docs/README.md" \
  "${REPO_ROOT}/docs/adopt_in_one_pr.md" \
  "${REPO_ROOT}/docs/integration_checklist.md" \
  "${REPO_ROOT}/docs/architecture.md" \
  "${REPO_ROOT}/docs/map.md" \
  "${REPO_ROOT}/docs/governance/content-visibility.md" \
  "${REPO_ROOT}/docs/state_lifecycle.md" \
  "${REPO_ROOT}/docs/concepts/mental_model.md" \
  "${REPO_ROOT}/docs/policy_authoring.md" \
  "${REPO_ROOT}/docs/failure_taxonomy_exit_codes.md" \
  "${REPO_ROOT}/docs/threat_model.md" \
  "${REPO_ROOT}/docs/contracts/compatibility_matrix.md" \
  "${REPO_ROOT}/docs/contracts/readme_contract.md" \
  "${REPO_ROOT}/docs/roadmap/cross-repo-readme-alignment.md" \
  "${REPO_ROOT}/docs/positioning.md" \
  "${REPO_ROOT}/docs/evidence_templates.md" \
  "${REPO_ROOT}/docs/faq.md" \
  "${REPO_ROOT}/docs/examples/quickstart.md" \
  "${REPO_ROOT}/docs/intent/scan-org-repos-for-ai-agents-configs.md" \
  "${REPO_ROOT}/docs/intent/detect-headless-agent-risk.md" \
  "${REPO_ROOT}/docs/intent/generate-compliance-evidence-from-scans.md" \
  "${REPO_ROOT}/docs/intent/gate-on-drift-and-regressions.md" \
  "${REPO_ROOT}/docs/trust/detection-coverage-matrix.md" \
  "${REPO_ROOT}/docs/trust/deterministic-guarantees.md" \
  "${REPO_ROOT}/docs/trust/proof-chain-verification.md" \
  "${REPO_ROOT}/docs/trust/contracts-and-schemas.md" \
  "${REPO_ROOT}/docs/trust/compatibility-and-versioning.md" \
  "${REPO_ROOT}/docs/trust/security-and-privacy.md" \
  "${REPO_ROOT}/docs/trust/release-integrity.md" \
  "${REPO_ROOT}/docs-site/src/lib/navigation.ts" \
  "${REPO_ROOT}/docs-site/src/app/page.tsx" \
  "${REPO_ROOT}/docs-site/src/app/docs/page.tsx" \
  "${REPO_ROOT}/docs-site/public/llms.txt" \
  "${REPO_ROOT}/docs-site/public/llms-full.txt" \
  "${REPO_ROOT}/docs-site/public/llm/product.md" \
  "${REPO_ROOT}/docs-site/public/llm/quickstart.md" \
  "${REPO_ROOT}/docs-site/public/llm/security.md" \
  "${REPO_ROOT}/docs-site/public/llm/contracts.md" \
  "${REPO_ROOT}/docs-site/public/llm/faq.md" \
  "${REPO_ROOT}/.github/ISSUE_TEMPLATE/bug_report.yml" \
  "${REPO_ROOT}/.github/ISSUE_TEMPLATE/feature_request.yml" \
  "${REPO_ROOT}/.github/ISSUE_TEMPLATE/docs_change.yml" \
  "${REPO_ROOT}/.github/pull_request_template.md" \
  "${REPO_ROOT}/product/README.md" \
  "${REPO_ROOT}/.agents/skills/README.md" \
  "${REPO_ROOT}/docs-site/public/sitemap.xml" \
  "${REPO_ROOT}/docs-site/public/ai-sitemap.xml" \
  "${REPO_ROOT}/docs-site/public/robots.txt"; do
  require_file "$path"
done

for path in \
  "${REPO_ROOT}/docs/intent/scan-org-repos-for-ai-agents-configs.md" \
  "${REPO_ROOT}/docs/intent/detect-headless-agent-risk.md" \
  "${REPO_ROOT}/docs/intent/generate-compliance-evidence-from-scans.md" \
  "${REPO_ROOT}/docs/intent/gate-on-drift-and-regressions.md"; do
  require_pattern "$path" "^## Exact commands$" "intent page missing exact commands section"
  require_pattern "$path" "^## Expected JSON keys$" "intent page missing expected json keys section"
  require_pattern "$path" "^## Exit codes$" "intent page missing exit codes section"
  require_pattern "$path" "^## Sample output snippet$" "intent page missing sample output section"
  require_pattern "$path" "^## Deterministic guarantees$" "intent page missing deterministic guarantees section"
  require_pattern "$path" "^## When not to use$" "intent page missing when-not-to-use section"
done

for cmd in \
  "wrkr scan" \
  "wrkr report" \
  "wrkr score" \
  "wrkr evidence" \
  "wrkr verify" \
  "wrkr regress" \
  "wrkr fix"; do
  if ! search_fixed_ci "$cmd" "${REPO_ROOT}/docs-site/public/llms.txt"; then
    fail "llms command surface missing '${cmd}'"
  fi
done

require_pattern "${REPO_ROOT}/docs-site/public/llms.txt" "^## When To Use$" "llms.txt missing when-to-use section"
require_pattern "${REPO_ROOT}/docs-site/public/llms.txt" "^## When Not To Use$" "llms.txt missing when-not-to-use section"
require_pattern "${REPO_ROOT}/docs-site/public/llms.txt" "/llms-full.txt" "llms.txt missing llms-full resource"

for route in \
  "/docs/start-here" \
  "/docs/adopt_in_one_pr" \
  "/docs/integration_checklist" \
  "/docs/architecture" \
  "/docs/concepts/mental_model" \
  "/docs/policy_authoring" \
  "/docs/failure_taxonomy_exit_codes" \
  "/docs/threat_model" \
  "/docs/contracts/compatibility_matrix" \
  "/docs/positioning" \
  "/docs/evidence_templates" \
  "/docs/faq" \
  "/docs/intent/scan-org-repos-for-ai-agents-configs" \
  "/docs/intent/detect-headless-agent-risk" \
  "/docs/intent/generate-compliance-evidence-from-scans" \
  "/docs/intent/gate-on-drift-and-regressions" \
  "/docs/trust/deterministic-guarantees" \
  "/docs/trust/detection-coverage-matrix" \
  "/docs/trust/proof-chain-verification" \
  "/docs/trust/contracts-and-schemas"; do
  require_pattern "${REPO_ROOT}/docs-site/src/lib/navigation.ts" "$route" "required docs route missing from side nav"
  require_pattern "${REPO_ROOT}/docs-site/src/app/docs/page.tsx" "$route" "required docs route missing from docs home tracks"
done

for url in \
  "https://clyra-ai.github.io/wrkr/scan/" \
  "https://clyra-ai.github.io/wrkr/llms.txt" \
  "https://clyra-ai.github.io/wrkr/llms-full.txt" \
  "https://clyra-ai.github.io/wrkr/docs/adopt_in_one_pr/" \
  "https://clyra-ai.github.io/wrkr/docs/integration_checklist/" \
  "https://clyra-ai.github.io/wrkr/docs/architecture/" \
  "https://clyra-ai.github.io/wrkr/docs/concepts/mental_model/" \
  "https://clyra-ai.github.io/wrkr/docs/policy_authoring/" \
  "https://clyra-ai.github.io/wrkr/docs/failure_taxonomy_exit_codes/" \
  "https://clyra-ai.github.io/wrkr/docs/threat_model/" \
  "https://clyra-ai.github.io/wrkr/docs/contracts/compatibility_matrix/" \
  "https://clyra-ai.github.io/wrkr/docs/positioning/" \
  "https://clyra-ai.github.io/wrkr/docs/evidence_templates/" \
  "https://clyra-ai.github.io/wrkr/docs/faq/" \
  "https://clyra-ai.github.io/wrkr/docs/intent/scan-org-repos-for-ai-agents-configs/" \
  "https://clyra-ai.github.io/wrkr/docs/intent/detect-headless-agent-risk/" \
  "https://clyra-ai.github.io/wrkr/docs/intent/generate-compliance-evidence-from-scans/" \
  "https://clyra-ai.github.io/wrkr/docs/intent/gate-on-drift-and-regressions/"; do
  require_pattern "${REPO_ROOT}/docs-site/public/sitemap.xml" "$url" "required URL missing from sitemap.xml"
done

require_pattern "${REPO_ROOT}/docs-site/public/ai-sitemap.xml" "https://clyra-ai.github.io/wrkr/llms.txt" "ai sitemap missing llms.txt"
require_pattern "${REPO_ROOT}/docs-site/public/ai-sitemap.xml" "https://clyra-ai.github.io/wrkr/llms-full.txt" "ai sitemap missing llms-full.txt"
require_pattern "${REPO_ROOT}/docs-site/public/robots.txt" "Sitemap: https://clyra-ai.github.io/wrkr/sitemap.xml" "robots.txt missing sitemap.xml pointer"
require_pattern "${REPO_ROOT}/docs-site/public/robots.txt" "Sitemap: https://clyra-ai.github.io/wrkr/ai-sitemap.xml" "robots.txt missing ai-sitemap pointer"
require_pattern "${REPO_ROOT}/docs-site/public/robots.txt" "User-agent: PerplexityBot" "robots.txt missing PerplexityBot allow rule"
require_pattern "${REPO_ROOT}/docs-site/public/robots.txt" "User-agent: ChatGPT-User" "robots.txt missing ChatGPT-User allow rule"

require_pattern "${REPO_ROOT}/README.md" "brew install Clyra-AI/tap/wrkr" "README missing canonical Homebrew install command"
require_pattern "${REPO_ROOT}/README.md" "go install github.com/Clyra-AI/wrkr/cmd/wrkr@\"\\$\\{WRKR_VERSION\\}\"" "README missing canonical pinned go install command"
require_pattern "${REPO_ROOT}/README.md" "docs/state_lifecycle.md" "README missing canonical state lifecycle reference"
require_pattern "${REPO_ROOT}/docs/trust/release-integrity.md" "scripts/test_uat_local.sh --release-version v1.0.0 --brew-formula Clyra-AI/tap/wrkr" "release integrity doc missing published install-path parity command"
require_pattern "${REPO_ROOT}/docs-site/src/app/page.tsx" "/docs/start-here#install" "docs-site homepage missing start-here install pointer"
require_pattern "${REPO_ROOT}/docs-site/src/app/page.tsx" "/scan" "docs-site homepage missing web bootstrap pointer"
require_pattern "${REPO_ROOT}/docs/state_lifecycle.md" "^## Canonical artifact locations$" "state lifecycle doc missing canonical artifact table section"
require_pattern "${REPO_ROOT}/docs/state_lifecycle.md" "\\.wrkr/last-scan\\.json" "state lifecycle doc missing canonical state path"
require_pattern "${REPO_ROOT}/docs/state_lifecycle.md" "\\.wrkr/wrkr-regress-baseline\\.json" "state lifecycle doc missing canonical baseline path"
require_pattern "${REPO_ROOT}/docs/state_lifecycle.md" "\\.wrkr/wrkr-manifest\\.yaml" "state lifecycle doc missing canonical manifest path"
require_pattern "${REPO_ROOT}/docs/state_lifecycle.md" "\\.wrkr/proof-chain\\.json" "state lifecycle doc missing canonical proof chain path"
require_pattern "${REPO_ROOT}/docs/examples/quickstart.md" "docs/state_lifecycle.md" "quickstart missing canonical lifecycle reference"
require_pattern "${REPO_ROOT}/docs/commands/scan.md" "docs/state_lifecycle.md" "scan command docs missing lifecycle reference"
require_pattern "${REPO_ROOT}/docs/commands/regress.md" "docs/state_lifecycle.md" "regress command docs missing lifecycle reference"
require_pattern "${REPO_ROOT}/docs/commands/evidence.md" "docs/state_lifecycle.md" "evidence command docs missing lifecycle reference"
require_pattern "${REPO_ROOT}/docs/commands/fix.md" "docs/state_lifecycle.md" "fix command docs missing lifecycle reference"
require_pattern "${REPO_ROOT}/docs/examples/quickstart.md" "\\.wrkr/wrkr-regress-baseline\\.json" "quickstart regress examples missing canonical baseline path"
require_pattern "${REPO_ROOT}/docs/examples/operator-playbooks.md" "\\.wrkr/wrkr-regress-baseline\\.json" "operator playbook regress examples missing canonical baseline path"
require_pattern "${REPO_ROOT}/README.md" "wrkr fix computes a deterministic remediation plan from existing scan state and emits plan metadata; it does not mutate repository files unless --open-pr is set\\." "README missing explicit wrkr fix side-effect contract sentence one"
require_pattern "${REPO_ROOT}/README.md" "When --open-pr is set, wrkr fix writes deterministic artifacts under \\.wrkr/remediations/<fingerprint>/ and then creates or updates one remediation PR for the target repo\\." "README missing explicit wrkr fix side-effect contract sentence two"
require_pattern "${REPO_ROOT}/docs/commands/fix.md" "wrkr fix computes a deterministic remediation plan from existing scan state and emits plan metadata; it does not mutate repository files unless --open-pr is set\\." "fix command docs missing explicit side-effect contract sentence one"
require_pattern "${REPO_ROOT}/docs/commands/fix.md" "When --open-pr is set, wrkr fix writes deterministic artifacts under \\.wrkr/remediations/<fingerprint>/ and then creates or updates one remediation PR for the target repo\\." "fix command docs missing explicit side-effect contract sentence two"
require_pattern "${REPO_ROOT}/README.md" "^## Trust and Project Relationship$" "README missing trust and project relationship section"
require_pattern "${REPO_ROOT}/README.md" "docs/map\\.md" "README missing docs source-of-truth map reference"
require_pattern "${REPO_ROOT}/docs/faq.md" "^### Do I need Axym or Gait to run Wrkr\\?$" "FAQ missing standalone vs ecosystem entry"
require_pattern "${REPO_ROOT}/CONTRIBUTING.md" "^## Docs Source of Truth$" "CONTRIBUTING missing docs source-of-truth section"
require_pattern "${REPO_ROOT}/CONTRIBUTING.md" "make docs-site-install" "CONTRIBUTING missing docs-site validation command guidance"
require_pattern "${REPO_ROOT}/CONTRIBUTING.md" "^## Required Toolchain$" "CONTRIBUTING missing required toolchain section"
require_pattern "${REPO_ROOT}/CONTRIBUTING.md" "^## Optional Toolchain$" "CONTRIBUTING missing optional toolchain section"
require_pattern "${REPO_ROOT}/CONTRIBUTING.md" "^## Go-Only Contributor Path \\(Default\\)$" "CONTRIBUTING missing Go-only contributor path section"
require_pattern "${REPO_ROOT}/CONTRIBUTING.md" "^## CI Lane Map$" "CONTRIBUTING missing CI lane map section"
require_pattern "${REPO_ROOT}/CONTRIBUTING.md" "^## Determinism Requirements$" "CONTRIBUTING missing determinism requirements section"
require_pattern "${REPO_ROOT}/CONTRIBUTING.md" "^## Detector Authoring Guidance$" "CONTRIBUTING missing detector authoring guidance section"
require_pattern "${REPO_ROOT}/CONTRIBUTING.md" "^## Pull Request Workflow$" "CONTRIBUTING missing pull request workflow section"
require_pattern "${REPO_ROOT}/docs/map.md" "^## Source-of-truth model$" "docs map missing source-of-truth model section"
require_pattern "${REPO_ROOT}/docs/map.md" "^## Required validation bundle$" "docs map missing required validation bundle section"
require_pattern "${REPO_ROOT}/docs-site/public/llms.txt" "/docs/map/" "llms.txt missing docs source map reference"
require_pattern "${REPO_ROOT}/.github/ISSUE_TEMPLATE/bug_report.yml" "^name: Bug report$" "bug issue template missing name header"
require_pattern "${REPO_ROOT}/.github/ISSUE_TEMPLATE/bug_report.yml" "Contract surface affected" "bug issue template missing contract surface prompt"
require_pattern "${REPO_ROOT}/.github/ISSUE_TEMPLATE/feature_request.yml" "^name: Feature request$" "feature issue template missing name header"
require_pattern "${REPO_ROOT}/.github/ISSUE_TEMPLATE/feature_request.yml" "Contract impact" "feature issue template missing contract impact prompt"
require_pattern "${REPO_ROOT}/.github/ISSUE_TEMPLATE/docs_change.yml" "^name: Docs improvement$" "docs issue template missing name header"
require_pattern "${REPO_ROOT}/.github/ISSUE_TEMPLATE/docs_change.yml" "Validation commands" "docs issue template missing validation commands prompt"
require_pattern "${REPO_ROOT}/.github/pull_request_template.md" "^## Contract Impact$" "PR template missing contract impact section"
require_pattern "${REPO_ROOT}/.github/pull_request_template.md" "^## Tests and Lane Evidence$" "PR template missing tests/lane evidence section"
require_pattern "${REPO_ROOT}/README.md" "CODE_OF_CONDUCT\\.md" "README missing code of conduct link"
require_pattern "${REPO_ROOT}/README.md" "CHANGELOG\\.md" "README missing changelog link"
require_pattern "${REPO_ROOT}/docs/trust/release-integrity.md" "CHANGELOG\\.md" "release integrity docs missing changelog linkage"
require_pattern "${REPO_ROOT}/CHANGELOG.md" "^## \\[Unreleased\\]$" "CHANGELOG missing Unreleased section"
require_pattern "${REPO_ROOT}/CHANGELOG.md" "^## Changelog maintenance process$" "CHANGELOG missing maintenance process section"
require_pattern "${REPO_ROOT}/README.md" "^## Install$" "README missing install section"
require_pattern "${REPO_ROOT}/README.md" "^## First 10 Minutes \\(Offline, No Setup\\)$" "README missing first 10 minutes section"
require_pattern "${REPO_ROOT}/README.md" "^## Integration \\(One PR\\)$" "README missing integration section"
require_pattern "${REPO_ROOT}/README.md" "^## Command Surface$" "README missing command surface section"
require_pattern "${REPO_ROOT}/README.md" "^## Governance and Support$" "README missing governance and support section"
require_pattern "${REPO_ROOT}/docs/contracts/readme_contract.md" "^## Required sections$" "readme contract doc missing required sections"
require_pattern "${REPO_ROOT}/docs/contracts/readme_contract.md" "^1\\. Install$" "readme contract doc missing install section requirement"
require_pattern "${REPO_ROOT}/docs/contracts/readme_contract.md" "^2\\. First 10 Minutes$" "readme contract doc missing first 10 minutes requirement"
require_pattern "${REPO_ROOT}/docs/contracts/readme_contract.md" "^3\\. Integration$" "readme contract doc missing integration requirement"
require_pattern "${REPO_ROOT}/docs/contracts/readme_contract.md" "^4\\. Command Surface$" "readme contract doc missing command surface requirement"
require_pattern "${REPO_ROOT}/docs/contracts/readme_contract.md" "^5\\. Governance and Support$" "readme contract doc missing governance/support requirement"
require_pattern "${REPO_ROOT}/docs/roadmap/cross-repo-readme-alignment.md" "Clyra-AI/proof" "cross-repo roadmap missing proof follow-up"
require_pattern "${REPO_ROOT}/docs/roadmap/cross-repo-readme-alignment.md" "Clyra-AI/gait" "cross-repo roadmap missing gait follow-up"
require_pattern "${REPO_ROOT}/docs/roadmap/cross-repo-readme-alignment.md" "20[0-9]{2}-[0-9]{2}-[0-9]{2}" "cross-repo roadmap missing explicit due date"
require_pattern "${REPO_ROOT}/docs/governance/content-visibility.md" "^## Policy A: .*product/.*visibility$" "content visibility policy missing product section"
require_pattern "${REPO_ROOT}/docs/governance/content-visibility.md" "^## Policy B: .*\\.agents/skills/.*visibility$" "content visibility policy missing skills section"
require_pattern "${REPO_ROOT}/docs/governance/content-visibility.md" "^## Directory notices and review checklist$" "content visibility policy missing directory notices section"
require_pattern "${REPO_ROOT}/product/README.md" "docs/governance/content-visibility.md" "product directory notice missing governance policy link"
require_pattern "${REPO_ROOT}/.agents/skills/README.md" "docs/governance/content-visibility.md" "skills directory notice missing governance policy link"
require_pattern "${REPO_ROOT}/README.md" "docs/governance/content-visibility.md" "README missing governance policy link"

ROOT_SOURCE="${REPO_ROOT}/core/cli/root.go"
ROOT_DOC="${REPO_ROOT}/docs/commands/root.md"
LLM_CONTRACTS="${REPO_ROOT}/docs-site/public/llm/contracts.md"

if [[ ! -f "${ROOT_SOURCE}" ]]; then
  fail "missing root source for exit-code parsing: ${ROOT_SOURCE}"
else
  EXIT_CODES=()
  while IFS= read -r code; do
    EXIT_CODES+=("${code}")
  done < <(extract_exit_codes "${ROOT_SOURCE}" || true)
  if [[ "${#EXIT_CODES[@]}" -eq 0 ]]; then
    EXIT_CODES=(0 1 2 3 4 5 6 7 8)
  fi
  for code in "${EXIT_CODES[@]}"; do
    require_pattern "${ROOT_DOC}" "\`${code}\`" "exit code ${code} missing in root docs"
    require_pattern "${LLM_CONTRACTS}" "\`${code}\`" "exit code ${code} missing in llm contracts surface"
  done
fi

if [[ "${FAILURES}" -ne 0 ]]; then
  echo "docs consistency: fail (${FAILURES} issue(s))" >&2
  exit 1
fi

echo "docs consistency: pass"

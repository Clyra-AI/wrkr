#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILURES=0

ONE_LINER='Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.'
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
  "${REPO_ROOT}/docs/README.md" \
  "${REPO_ROOT}/docs/adopt_in_one_pr.md" \
  "${REPO_ROOT}/docs/integration_checklist.md" \
  "${REPO_ROOT}/docs/architecture.md" \
  "${REPO_ROOT}/docs/concepts/mental_model.md" \
  "${REPO_ROOT}/docs/policy_authoring.md" \
  "${REPO_ROOT}/docs/failure_taxonomy_exit_codes.md" \
  "${REPO_ROOT}/docs/threat_model.md" \
  "${REPO_ROOT}/docs/contracts/compatibility_matrix.md" \
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
  "${REPO_ROOT}/docs-site/public/sitemap.xml" \
  "${REPO_ROOT}/docs-site/public/ai-sitemap.xml" \
  "${REPO_ROOT}/docs-site/public/robots.txt"; do
  require_file "$path"
done

for path in \
  "${REPO_ROOT}/README.md" \
  "${REPO_ROOT}/docs/examples/quickstart.md" \
  "${REPO_ROOT}/docs-site/src/app/page.tsx" \
  "${REPO_ROOT}/docs-site/public/llms.txt" \
  "${REPO_ROOT}/docs-site/public/llm/product.md"; do
  require_pattern "$path" "${ONE_LINER}" "canonical one-liner missing"
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

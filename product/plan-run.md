# Wrkr Runbook: Generate "The State of AI Tool Sprawl" Report

Date: 2026-02-23
Primary plan source: `product/report_plan.md`
Report structure source: `product/report_structure.md`
Required publishing structure: `product/report_structure.md`

## Goal

Produce a publication-ready report package (Sections 1-10) with deterministic, reproducible Wrkr artifacts for:

- Headline metrics
- Methodology evidence
- Inventory, privilege, approval, and regulatory analysis
- Prompt-channel exposure analysis
- Cross-agent attack-path analysis
- Optional enrich-backed MCP advisory/registry analysis (with `as_of` provenance)
- Anonymized case-study inputs
- Benchmark segments
- Appendix-grade JSON/CSV tables

## Scope and Constraints

- Deterministic pipeline only (no LLM in scan/risk/report paths).
- Treat enrich mode as optional and time-sensitive; do not mix enrich claims into deterministic baseline claims without explicit provenance.
- No production-write percentage claims unless production targets are configured.
- Prefer machine-generated outputs as source of truth; manual writing should only format and narrate generated outputs.
- Final written report must follow `product/report_structure.md` section order and headings.

## Inputs Required Before Run

1. Target list:
- Either org list (`orgs.txt`) or repo list (`repos.txt`) for the campaign sample.
2. GitHub API base and token (for `--org` / `--repo` acquisition):
- `WRKR_GITHUB_API_BASE`
- `WRKR_GITHUB_TOKEN` (recommended)
3. Policy/config files:
- Approved list (optional but recommended): `docs/examples/approved-tools.v1.yaml` or custom.
- Production targets (required if publishing production-write claims): `docs/examples/production-targets.v1.yaml` or custom.
- Segment metadata (optional, recommended for benchmarks): `docs/examples/campaign-segments.v1.yaml` or custom.
4. Enrich decision:
- `ENABLE_ENRICH=1` only if publishing advisory/registry findings.
- Capture enrich window timestamp (`ENRICH_AS_OF`) for narrative provenance.
5. Structure contract:
- The editorial output must be composed against `product/report_structure.md`.

## Standard Output Layout

Use one immutable run ID per campaign:

```bash
RUN_ID="q1-2026-public-$(date -u +%Y%m%dT%H%M%SZ)"
BASE=".tmp/campaign/${RUN_ID}"
mkdir -p "${BASE}"/{states,states-enrich,scans,agg,appendix,report}
```

## Step 1: Preflight and Tooling Validation

```bash
make lint-fast
make test-fast
wrkr --json
```

If planning public production-write claims, validate targets first:

```bash
test -f docs/examples/production-targets.v1.yaml
```

## Step 2: Execute Campaign Scans

### Option A: Scan organizations

Create `orgs.txt` (one org per line), then run:

```bash
while IFS= read -r org; do
  [ -z "${org}" ] && continue
  slug="$(echo "${org}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._-' '-')"
  state_path="${BASE}/states/${slug}.json"
  enrich_state_path="${BASE}/states-enrich/${slug}.json"
  scan_path="${BASE}/scans/${slug}.scan.json"

  wrkr scan \
    --org "${org}" \
    --github-api "${WRKR_GITHUB_API_BASE}" \
    --github-token "${WRKR_GITHUB_TOKEN}" \
    --state "${state_path}" \
    --approved-tools docs/examples/approved-tools.v1.yaml \
    --production-targets docs/examples/production-targets.v1.yaml \
    --json > "${scan_path}"

  if [ "${ENABLE_ENRICH:-0}" = "1" ]; then
    wrkr scan \
      --org "${org}" \
      --github-api "${WRKR_GITHUB_API_BASE}" \
      --github-token "${WRKR_GITHUB_TOKEN}" \
      --state "${enrich_state_path}" \
      --approved-tools docs/examples/approved-tools.v1.yaml \
      --production-targets docs/examples/production-targets.v1.yaml \
      --enrich \
      --json > "${BASE}/scans/${slug}.scan.enrich.json"
  fi
done < orgs.txt
```

### Option B: Scan repos

Create `repos.txt` with `owner/repo`, then run:

```bash
while IFS= read -r repo; do
  [ -z "${repo}" ] && continue
  slug="$(echo "${repo}" | tr '[:upper:]' '[:lower:]' | tr '/:' '-' | tr -cs 'a-z0-9._-' '-')"
  state_path="${BASE}/states/${slug}.json"
  enrich_state_path="${BASE}/states-enrich/${slug}.json"
  scan_path="${BASE}/scans/${slug}.scan.json"

  wrkr scan \
    --repo "${repo}" \
    --github-api "${WRKR_GITHUB_API_BASE}" \
    --github-token "${WRKR_GITHUB_TOKEN}" \
    --state "${state_path}" \
    --approved-tools docs/examples/approved-tools.v1.yaml \
    --production-targets docs/examples/production-targets.v1.yaml \
    --json > "${scan_path}"

  if [ "${ENABLE_ENRICH:-0}" = "1" ]; then
    wrkr scan \
      --repo "${repo}" \
      --github-api "${WRKR_GITHUB_API_BASE}" \
      --github-token "${WRKR_GITHUB_TOKEN}" \
      --state "${enrich_state_path}" \
      --approved-tools docs/examples/approved-tools.v1.yaml \
      --production-targets docs/examples/production-targets.v1.yaml \
      --enrich \
      --json > "${BASE}/scans/${slug}.scan.enrich.json"
  fi
done < repos.txt
```

## Step 3: Validate Raw Scan Artifacts

```bash
for f in "${BASE}"/scans/*.scan.json; do
  jq -e '.status=="ok"' "$f" >/dev/null
done

if ls "${BASE}"/scans/*.scan.enrich.json >/dev/null 2>&1; then
  for f in "${BASE}"/scans/*.scan.enrich.json; do
    jq -e '.status=="ok"' "$f" >/dev/null
  done
fi

make test-contracts
```

## Step 4: Build Campaign Aggregate + Public Markdown

Deterministic baseline aggregate:

```bash
wrkr campaign aggregate \
  --input-glob "${BASE}/scans/*.scan.json" \
  --output "${BASE}/agg/campaign-summary.json" \
  --segment-metadata docs/examples/campaign-segments.v1.yaml \
  --md \
  --md-path "${BASE}/agg/campaign-public.md" \
  --template public \
  --json > "${BASE}/agg/campaign-envelope.json"
```

Optional enrich aggregate (for enrich-only claim support):

```bash
if ls "${BASE}"/scans/*.scan.enrich.json >/dev/null 2>&1; then
  wrkr campaign aggregate \
    --input-glob "${BASE}/scans/*.scan.enrich.json" \
    --output "${BASE}/agg/campaign-summary-enrich.json" \
    --segment-metadata docs/examples/campaign-segments.v1.yaml \
    --json > "${BASE}/agg/campaign-envelope-enrich.json"
fi
```

## Step 5: Build Appendix Data (Anonymized, Table-Ready)

Generate per-scan appendix exports:

```bash
for state in "${BASE}"/states/*.json; do
  slug="$(basename "${state}" .json)"
  wrkr export \
    --state "${state}" \
    --format appendix \
    --anonymize \
    --csv-dir "${BASE}/appendix/${slug}" \
    --json > "${BASE}/appendix/${slug}.appendix.json"
done
```

Optional enrich appendix exports (for enrich-only evidence trails):

```bash
if ls "${BASE}"/states-enrich/*.json >/dev/null 2>&1; then
  for state in "${BASE}"/states-enrich/*.json; do
    slug="$(basename "${state}" .json)"
    wrkr export \
      --state "${state}" \
      --format appendix \
      --anonymize \
      --csv-dir "${BASE}/appendix/${slug}.enrich" \
      --json > "${BASE}/appendix/${slug}.enrich.appendix.json"
  done
fi
```

Merge all appendix JSON tables into one combined matrix (supports legacy and new rows):

```bash
# Keep baseline and enrich inputs disjoint to prevent double-counting.
appendix_inputs=()

for f in "${BASE}"/appendix/*.appendix.json; do
  [ -e "${f}" ] || continue
  case "${f}" in
    *.enrich.appendix.json) continue ;;
  esac
  appendix_inputs+=( "${f}" )
done

for f in "${BASE}"/appendix/*.enrich.appendix.json; do
  [ -e "${f}" ] || continue
  appendix_inputs+=( "${f}" )
done

[ "${#appendix_inputs[@]}" -gt 0 ] || {
  echo "no appendix exports found at ${BASE}/appendix" >&2
  exit 1
}

jq -s '
{
  export_version: "1",
  schema_version: "v1",
  inventory_rows: (map(.appendix.inventory_rows // []) | add | sort_by(.org,.tool_type,.tool_id)),
  privilege_rows: (map(.appendix.privilege_rows // []) | add | sort_by(.org,.tool_type,.agent_id)),
  approval_gap_rows: (map(.appendix.approval_gap_rows // []) | add | sort_by(.org,.approval_classification,.tool_id)),
  regulatory_rows: (map(.appendix.regulatory_rows // []) | add | sort_by(.regulation,.control_id,.org,.tool_id)),
  prompt_channel_rows: (map(.appendix.prompt_channel_rows // []) | add | sort_by(.org,.repo,.location,.pattern_family)),
  attack_path_rows: (map(.appendix.attack_path_rows // []) | add | sort_by(.org,.path_id,.path_score)),
  mcp_enrich_rows: (map(.appendix.mcp_enrich_rows // []) | add | sort_by(.org,.server,.as_of,.source))
}' "${appendix_inputs[@]}" > "${BASE}/appendix/combined-appendix.json"
```

## Step 6: Map Artifacts to Report Sections (1-10)

1. Headline Findings  
Source: `${BASE}/agg/campaign-summary.json` (`metrics`, `methodology`) plus enrich summary when used.

2. Methodology  
Source: `${BASE}/agg/campaign-summary.json` (`methodology`) + `${BASE}/agg/campaign-public.md` + enrich window metadata when used.

3. AI Tool Inventory Breakdown  
Source: `${BASE}/appendix/combined-appendix.json` (`inventory_rows`, `prompt_channel_rows`).

4. Privilege and Access Map  
Source: `${BASE}/appendix/combined-appendix.json` (`privilege_rows`, `attack_path_rows`) + per-scan tier fields.

5. Approval Gap  
Source: `${BASE}/appendix/combined-appendix.json` (`approval_gap_rows`) + campaign approval ratios.

6. Regulatory Exposure  
Source: `${BASE}/appendix/combined-appendix.json` (`regulatory_rows`) + per-scan regulatory summaries.

7. Case Studies (Anonymized)  
Source: per-scan appendix exports + joined prompt/path rows.

8. Benchmarks and Comparisons  
Source: campaign segments and prevalence deltas (inventory, prompt, path, enrich when enabled).

9. Recommendations  
Source: measured gaps from sections 1-8.

10. Appendix: Full Data Tables  
Source: `${BASE}/appendix/combined-appendix.json` + per-scan CSV directories `${BASE}/appendix/<slug>/`.

## Step 7: Publication Guardrails (Must Pass)

1. Campaign output valid:
```bash
jq -e '.schema_version=="v1"' "${BASE}/agg/campaign-summary.json" >/dev/null
```

2. Production-write claim eligibility:
```bash
jq -e '.metrics.production_write_status=="configured"' "${BASE}/agg/campaign-summary.json" >/dev/null
```

If this check fails, do not publish numeric production-write percentages or counts.

3. Anonymization check for case-study data:
```bash
jq -e '
  (
    [.inventory_rows[].org] +
    [.privilege_rows[].org] +
    [.approval_gap_rows[].org] +
    [.regulatory_rows[].org] +
    [.prompt_channel_rows[].org] +
    [.attack_path_rows[].org] +
    [.mcp_enrich_rows[].org]
  ) | all(test("^org-[a-f0-9]+$"))
' "${BASE}/appendix/combined-appendix.json" >/dev/null
```

4. Determinism spot-check (baseline aggregate rerun must match):
```bash
wrkr campaign aggregate \
  --input-glob "${BASE}/scans/*.scan.json" \
  --output "${BASE}/agg/campaign-summary-rerun.json" \
  --segment-metadata docs/examples/campaign-segments.v1.yaml \
  --json >/dev/null
diff -u "${BASE}/agg/campaign-summary.json" "${BASE}/agg/campaign-summary-rerun.json"
```

5. Prompt-channel claim eligibility:
```bash
jq -e '(.prompt_channel_rows // [] | length) > 0' "${BASE}/appendix/combined-appendix.json" >/dev/null
```

If this check fails, do not publish prevalence or count claims for prompt poisoning indicators.

6. Attack-path claim eligibility:
```bash
jq -e '(.attack_path_rows // [] | length) > 0' "${BASE}/appendix/combined-appendix.json" >/dev/null
```

If this check fails, do not publish critical-path count or top-path score claims.

7. Enrich claim eligibility (only for enrich-backed supply-chain claims):
```bash
jq -e '
  (.mcp_enrich_rows // []) as $rows |
  ($rows | length) > 0 and
  ($rows | all((.as_of // "") != "" and (.source // "") != ""))
' "${BASE}/appendix/combined-appendix.json" >/dev/null
```

If this check fails, do not publish advisory/registry prevalence claims.

## Step 8: Package Deliverables

Minimum package to hand off to editorial and PR:

- `${BASE}/agg/campaign-summary.json`
- `${BASE}/agg/campaign-public.md`
- `${BASE}/appendix/combined-appendix.json`
- `${BASE}/appendix/*/*.csv` (inventory, privilege_map, approval_gap, regulatory_matrix, plus new row CSVs when available)
- `${BASE}/agg/campaign-summary-enrich.json` (if enrich run was enabled)
- A short methodology note referencing commit SHA, run window, and enrich window (`ENRICH_AS_OF`) when applicable.

## Step 9: Final Quality Gate Before Publishing

Run repo-level checks used by release posture:

```bash
make test-docs-consistency
make test-contracts
make test-scenarios
make prepush-full
```

## Definition of Done for a Report Run

- All required scan artifacts are `status=ok`.
- Campaign aggregate generated with deterministic methodology and segment outputs.
- Appendix combined JSON and CSV tables generated, including prompt/path/enrich rows when available.
- Production-write claim policy enforced (`configured` required for numeric claims).
- Prompt/path/enrich claims are published only when corresponding guardrail checks pass.
- Anonymized case-study source data is publication-safe.
- Report sections 1-10 are fully populated from generated artifacts plus editorial narrative.

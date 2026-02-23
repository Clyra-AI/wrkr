# Wrkr Runbook: Generate "The State of AI Tool Sprawl" Report

Date: 2026-02-23  
Primary plan source: `/Users/davidahmann/Projects/wrkr/product/report_plan.md`  
Report structure source: `/Users/davidahmann/Downloads/wrkr_report_structure.docx`
Required publishing structure: `/Users/davidahmann/Projects/wrkr/product/report_structure.md`

## Goal

Produce a publication-ready report package (Sections 1-10) with deterministic, reproducible Wrkr artifacts for:

- Headline metrics
- Methodology evidence
- Inventory/privilege/approval/regulatory analysis
- Anonymized case-study inputs
- Benchmark segments
- Appendix-grade JSON/CSV tables

## Scope and Constraints

- Deterministic pipeline only (no LLM in scan/risk/report paths).
- No production-write percentage claims unless production targets are configured.
- Prefer machine-generated outputs as source of truth; manual writing should only format/narrate those outputs.
- Final written report must follow `/Users/davidahmann/Projects/wrkr/product/report_structure.md` section order and headings.

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
4. Structure contract:
- The editorial output must be composed against `/Users/davidahmann/Projects/wrkr/product/report_structure.md`.

## Standard Output Layout

Use one immutable run ID per campaign:

```bash
RUN_ID="q1-2026-public-$(date -u +%Y%m%dT%H%M%SZ)"
BASE=".tmp/campaign/${RUN_ID}"
mkdir -p "${BASE}"/{states,scans,agg,appendix,report}
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
  scan_path="${BASE}/scans/${slug}.scan.json"

  wrkr scan \
    --org "${org}" \
    --github-api "${WRKR_GITHUB_API_BASE}" \
    --github-token "${WRKR_GITHUB_TOKEN}" \
    --state "${state_path}" \
    --approved-tools docs/examples/approved-tools.v1.yaml \
    --production-targets docs/examples/production-targets.v1.yaml \
    --json > "${scan_path}"
done < orgs.txt
```

### Option B: Scan repos

Create `repos.txt` with `owner/repo`, then run:

```bash
while IFS= read -r repo; do
  [ -z "${repo}" ] && continue
  slug="$(echo "${repo}" | tr '[:upper:]' '[:lower:]' | tr '/:' '-' | tr -cs 'a-z0-9._-' '-')"
  state_path="${BASE}/states/${slug}.json"
  scan_path="${BASE}/scans/${slug}.scan.json"

  wrkr scan \
    --repo "${repo}" \
    --github-api "${WRKR_GITHUB_API_BASE}" \
    --github-token "${WRKR_GITHUB_TOKEN}" \
    --state "${state_path}" \
    --approved-tools docs/examples/approved-tools.v1.yaml \
    --production-targets docs/examples/production-targets.v1.yaml \
    --json > "${scan_path}"
done < repos.txt
```

## Step 3: Validate Raw Scan Artifacts

```bash
for f in "${BASE}"/scans/*.scan.json; do
  jq -e '.status=="ok"' "$f" >/dev/null
done
make test-contracts
```

## Step 4: Build Campaign Aggregate + Public Markdown

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

Merge all appendix JSON tables into one combined matrix:

```bash
jq -s '
{
  export_version: "1",
  schema_version: "v1",
  inventory_rows: (map(.appendix.inventory_rows) | add | sort_by(.org,.tool_type,.tool_id)),
  privilege_rows: (map(.appendix.privilege_rows) | add | sort_by(.org,.tool_type,.agent_id)),
  approval_gap_rows: (map(.appendix.approval_gap_rows) | add | sort_by(.org,.approval_classification,.tool_id)),
  regulatory_rows: (map(.appendix.regulatory_rows) | add | sort_by(.regulation,.control_id,.org,.tool_id))
}' "${BASE}"/appendix/*.appendix.json > "${BASE}/appendix/combined-appendix.json"
```

## Step 6: Map Artifacts to Report Sections (1-10)

1. Headline Findings  
Source: `${BASE}/agg/campaign-summary.json` (`metrics` + `methodology`)

2. Methodology  
Source: `${BASE}/agg/campaign-summary.json` (`methodology`) + `${BASE}/agg/campaign-public.md`

3. AI Tool Inventory Breakdown  
Source: `${BASE}/appendix/combined-appendix.json` (`inventory_rows`)

4. Privilege and Access Map  
Source: `${BASE}/appendix/combined-appendix.json` (`privilege_rows`) + per-scan `inventory.tools[*].permission_tier/risk_tier`

5. Approval Gap  
Source: `${BASE}/appendix/combined-appendix.json` (`approval_gap_rows`) + campaign approval ratios from `metrics`

6. Regulatory Exposure  
Source: `${BASE}/appendix/combined-appendix.json` (`regulatory_rows`) + per-scan `inventory.regulatory_summary`

7. Case Studies (Anonymized)  
Source: per-scan `${BASE}/appendix/*.appendix.json` and anonymized rows

8. Benchmarks and Comparisons  
Source: `${BASE}/agg/campaign-summary.json` (`segments`)

9. Recommendations  
Source: derived narrative from measured gaps in sections 1-8

10. Appendix: Full Data Tables  
Source: `${BASE}/appendix/combined-appendix.json` + per-scan CSV directories `${BASE}/appendix/<slug>/`

## Step 7: Publication Guardrails (Must Pass)

1. Campaign output valid:
```bash
jq -e '.schema_version=="v1"' "${BASE}/agg/campaign-summary.json" >/dev/null
```

2. Production-write claim eligibility:
```bash
jq -e '.metrics.production_write_status=="configured"' "${BASE}/agg/campaign-summary.json" >/dev/null
```

If this check fails, do not publish numeric production-write percentages/count claims.

3. Anonymization check for case-study data:
```bash
jq -e '
  (
    [.inventory_rows[].org] +
    [.privilege_rows[].org] +
    [.approval_gap_rows[].org] +
    [.regulatory_rows[].org]
  ) | all(test("^org-[a-f0-9]+$"))
' "${BASE}/appendix/combined-appendix.json" >/dev/null
```

4. Determinism spot-check (rerun aggregate, compare):
```bash
wrkr campaign aggregate \
  --input-glob "${BASE}/scans/*.scan.json" \
  --output "${BASE}/agg/campaign-summary-rerun.json" \
  --segment-metadata docs/examples/campaign-segments.v1.yaml \
  --json >/dev/null
diff -u "${BASE}/agg/campaign-summary.json" "${BASE}/agg/campaign-summary-rerun.json"
```

## Step 8: Package Deliverables

Minimum package to hand off to editorial/PR:

- `${BASE}/agg/campaign-summary.json`
- `${BASE}/agg/campaign-public.md`
- `${BASE}/appendix/combined-appendix.json`
- `${BASE}/appendix/*/*.csv` (inventory, privilege_map, approval_gap, regulatory_matrix)
- A short methodology note referencing Wrkr commit SHA and run window.

## Step 9: Final Quality Gate Before Publishing

Run repo-level checks used by release posture:

```bash
make test-docs-consistency
make test-contracts
make prepush-full
```

## Definition of Done for a Report Run

- All scan artifacts are `status=ok`.
- Campaign aggregate generated with deterministic methodology + segment outputs.
- Appendix combined JSON + CSV tables generated.
- Production-write claim policy enforced (`configured` required for numeric claims).
- Anonymized case-study source data is publication-safe.
- Report sections 1-10 can be fully populated from generated artifacts plus editorial narrative.

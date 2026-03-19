# Operator Playbooks

Canonical local artifact locations are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

## Scan workflow

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --report-md --report-md-path ./.tmp/scan-summary.md --report-template operator --json
```

Check `top_findings`, `attack_paths`, `top_attack_paths`, `repo_exposure_summaries`, `profile`, and optional `report.md_path`.
For prompt-channel and enrich-enabled MCP findings, confirm stable evidence metadata fields are present (`pattern_family`, `evidence_snippet_hash`, `enrich_quality`, `as_of`, `source`).

## Shareable report workflow

```bash
wrkr report --md --md-path ./.tmp/wrkr-summary.md --template operator --share-profile internal --json
wrkr report --md --md-path ./.tmp/wrkr-summary-public.md --template public --share-profile public --json
wrkr report --pdf --pdf-path ./.tmp/wrkr-summary.pdf --template exec --json
```

Use internal profile for engineering/security reviews. Use public profile for external packets with deterministic redaction.

## Fix workflow

```bash
wrkr fix --top 3 --json
```

Check `remediation_count`, deterministic `fingerprint`, and unsupported finding reasons.

## Evidence workflow

```bash
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
```

Check `framework_coverage`, `report_artifacts`, and manifest/chain paths.
When risk state includes attack-path scoring, evidence output includes deterministic `attack-paths.json`.

`framework_coverage` reflects evidence currently present in scanned state.

- Low/0% coverage indicates documented control gaps in current evidence.
- Low/0% does not imply Wrkr lacks support for that framework.
- Treat low coverage as an action queue: remediate, rescan, and regenerate report/evidence artifacts.
- When current findings do not yet map to bundled controls, the generated report summary explicitly says framework mappings are still available and that the current state is evidence-sparse.

Recommended low-coverage response:

1. Run `wrkr report --top 5 --json` to prioritize the highest-risk missing controls.
2. Complete control implementation or lifecycle approvals for the affected identities/tools.
3. Re-run `wrkr scan --json`, then `wrkr evidence --frameworks ... --json` and `wrkr report --json`, and compare the updated `framework_coverage` plus report summary guidance.

### Unsafe output-path handling

If output directory is non-empty and not Wrkr-managed, evidence fails closed with exit `8` and `unsafe_operation_blocked`.

## Verify workflow

```bash
wrkr verify --chain --json
```

Check `chain.intact` and `chain.head_hash`.

## Regress workflow

```bash
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --summary-md --summary-md-path ./.tmp/regress-summary.md --template operator --json
```

Use exit `5` and drift reasons as gate criteria.
For attack-path divergence above thresholds, expect one summarized `critical_attack_path_drift` reason with nested `attack_path_drift` details (`added`, `removed`, `score_changed`, counts, thresholds).

## Identity lifecycle workflow

```bash
wrkr identity list --json
wrkr identity show <agent_id> --json
wrkr identity approve <agent_id> --approver @maria --scope read-only --expires 90d --json
wrkr identity deprecate <agent_id> --reason "tool retired" --json
wrkr identity revoke <agent_id> --reason "policy violation" --json
wrkr lifecycle --org local --summary-md --summary-md-path ./.tmp/lifecycle-summary.md --template audit --json
```

Use lifecycle transitions and proof-chain history to track approval and revocation.

## Scenario references (Tier 11)

- FR11: policy checks
- FR12: profile compliance
- FR13: posture score

Reference scenario suites in `internal/scenarios/` and coverage mapping in `internal/scenarios/coverage_map.json`.

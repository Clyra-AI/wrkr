# Operator Playbooks

## Scan workflow

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --report-md --report-md-path ./.tmp/scan-summary.md --report-template operator --json
```

Check `top_findings`, `repo_exposure_summaries`, `profile`, and optional `report.md_path`.

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

`framework_coverage` reflects evidence currently present in scanned state.

- Low/0% coverage indicates documented control gaps in current evidence.
- Low/0% does not imply Wrkr lacks support for that framework.
- Treat low coverage as an action queue: remediate, rescan, and regenerate evidence.

Recommended low-coverage response:

1. Run `wrkr report --top 5 --json` to prioritize the highest-risk missing controls.
2. Complete control implementation or lifecycle approvals for the affected identities/tools.
3. Re-run `wrkr scan --json`, then `wrkr evidence --frameworks ... --json` and compare updated `framework_coverage`.

### Unsafe output-path handling

If output directory is non-empty and not Wrkr-managed, evidence fails closed with exit `8` and `unsafe_operation_blocked`.

## Verify workflow

```bash
wrkr verify --chain --json
```

Check `chain.intact` and `chain.head_hash`.

## Regress workflow

```bash
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --summary-md --summary-md-path ./.tmp/regress-summary.md --template operator --json
```

Use exit `5` and drift reasons as gate criteria.

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

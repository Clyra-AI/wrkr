# Operator Playbooks

## Scan workflow

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --json
```

Check `top_findings`, `repo_exposure_summaries`, and `profile`.

## Fix workflow

```bash
wrkr fix --top 3 --json
```

Check `remediation_count`, deterministic `fingerprint`, and unsupported finding reasons.

## Evidence workflow

```bash
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
```

Check `framework_coverage` and manifest/chain paths.

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
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
```

Use exit `5` and drift reasons as gate criteria.

## Identity lifecycle workflow

```bash
wrkr identity list --json
wrkr identity show <agent_id> --json
wrkr identity approve <agent_id> --approver @maria --scope read-only --expires 90d --json
wrkr identity deprecate <agent_id> --reason "tool retired" --json
wrkr identity revoke <agent_id> --reason "policy violation" --json
wrkr lifecycle --org local --json
```

Use lifecycle transitions and proof-chain history to track approval and revocation.

## Scenario references (Tier 11)

- FR11: policy checks
- FR12: profile compliance
- FR13: posture score

Reference scenario suites in `internal/scenarios/` and coverage mapping in `internal/scenarios/coverage_map.json`.

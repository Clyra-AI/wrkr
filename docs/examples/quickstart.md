# Wrkr Quickstart (Offline-safe)

## Positioning

Wrkr is the AI-DSPM discovery layer in the See -> Prove -> Control sequence:

- See: Wrkr discovers tools, permissions, autonomy context, and risk.
- Prove: Axym consumes proof records and maps controls.
- Control: Gait enforces policy decisions.

Wrkr is useful standalone and interoperates with Axym/Gait through shared proof contracts.

## Deterministic local scan

```bash
wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --json
wrkr report --top 5 --json
wrkr score --json
```

Expected outputs:

- `scan`: `findings`, `ranked_findings`, `inventory`, `repo_exposure_summaries`, `profile`, `posture_score`
- `report`: `top_findings`, `total_tools`, `compliance_gap_count`
- `score`: `score`, `grade`, `weighted_breakdown`, `trend_delta`

## Evidence + verification

```bash
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
wrkr verify --chain --json
```

Expected outputs:

- `evidence`: `output_dir`, `manifest_path`, `chain_path`, `framework_coverage`
- `verify`: `chain.intact=true`

## Regression baseline

```bash
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
```

Expected outputs:

- `regress init`: `baseline_path`, `tool_count`
- `regress run`: deterministic drift status with stable reason fields

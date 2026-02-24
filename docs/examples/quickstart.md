# Wrkr Quickstart (Offline-safe)

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## Positioning

Wrkr is the AI-DSPM discovery layer in the See -> Prove -> Control sequence:

- See: Wrkr discovers tools, permissions, autonomy context, and risk.
- Prove: Axym consumes proof records and maps controls.
- Control: Gait enforces policy decisions.

Wrkr is useful standalone and interoperates with Axym/Gait through shared proof contracts.

For hosted source modes, `scan --repo` and `scan --org` require `--github-api` (or `WRKR_GITHUB_API_BASE`) and fail closed when acquisition is unavailable.

## Deterministic local scan

```bash
wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --json
wrkr report --top 5 --json
wrkr score --json
```

Expected outputs:

- `scan`: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `attack_paths`, `top_attack_paths`, `inventory`, `repo_exposure_summaries`, `profile`, `posture_score`
- `report`: `status`, `generated_at`, `top_findings`, `attack_paths`, `top_attack_paths`, `total_tools`, `tool_type_breakdown`, `compliance_gap_count`, `summary`
- `score`: `score`, `grade`, `breakdown`, `weighted_breakdown`, `weights`, `trend_delta` (optional: `attack_paths`, `top_attack_paths`)

Optional enrich-mode note:

- `scan --enrich` adds MCP evidence metadata (`source`, `as_of`, `advisory_count`, `registry_status`, `enrich_quality`, schema IDs, and adapter error classes).

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
- `regress run`: `status`, `drift_detected`, `reason_count`, `reasons`, `baseline_path` (when attack-path drift is critical, reasons include one `critical_attack_path_drift` summary with `attack_path_drift` details)

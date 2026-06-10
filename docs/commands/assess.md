# wrkr assess

## Synopsis

```bash
wrkr assess [--json] [--quiet] [--explain] [--path <dir> | --my-setup | --target <mode>:<value> ...] [--output-dir <path>] [--state <path>] [--template exec|operator|audit|public|ciso|appsec|platform|customer-draft|agent-action-bom|design-partner-summary] [--share-profile internal|public|customer-redacted|design-partner|external-redacted|investor-safe] [--paired-share-profile customer-redacted|design-partner|external-redacted|investor-safe] [--focus bom|release|write-deploy|approval-evidence-unknown|owner-evidence-unknown|evidence-gaps|contradictions|drift-review|recommendations] [--focus-path <path_id>] [--baseline <path>] [--runtime-input <path>] [--frameworks <ids>] [--ticket-format jira|github|servicenow] [--profile baseline|standard|strict|assessment] [--top <n>]
```

## Flags

- `--json`
- `--quiet`
- `--explain`
- `--path`
- `--my-setup`
- `--target`
- `--output-dir`
- `--state`
- `--template`
- `--share-profile`
- `--paired-share-profile`
- `--focus`
- `--focus-path`
- `--baseline`
- `--runtime-input`
- `--frameworks`
- `--ticket-format`
- `--profile`
- `--top`

## Example

```bash
wrkr assess --path ./your-repo --baseline ./.wrkr/wrkr-regress-baseline.json --template design-partner-summary --share-profile design-partner --ticket-format jira --json
wrkr assess --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr assess --path ./scenarios/wrkr/scan-mixed-org/repos --focus release --share-profile customer-redacted --json
wrkr assess --path ./scenarios/wrkr/scan-mixed-org/repos --runtime-input ./fixtures/runtime-session.json --frameworks soc2,eu-ai-act --json
wrkr assess --path ./scenarios/wrkr/scan-mixed-org/repos --baseline ./.wrkr/wrkr-regress-baseline.json --focus drift-review --json
wrkr assess --path ./scenarios/wrkr/scan-mixed-org/repos --paired-share-profile customer-redacted --ticket-format jira --json
```

## Behavior contract

`wrkr assess` is a deterministic local-first workflow that orchestrates:

1. `scan`
2. optional `ingest`
3. `evidence`
4. `export`
5. optional `export tickets --dry-run`
6. optional `regress run`
7. final `report`

The command writes one output directory plus an `assessment-manifest.json` that lists stage status, command metadata, state/proof refs, report artifacts, evidence bundle refs, export pack refs, optional paired redacted artifacts, optional private join map, and optional drift artifacts.

Stage failures return the underlying stage exit code and do not publish an assessment manifest. When `--baseline` is supplied and drift is detected, `wrkr assess` still writes the manifest and returns exit code `5`.

The default report template is `agent-action-bom`, the default share profile is `internal`, the default scan profile is `assessment`, and the default evidence framework set is `soc2`.

Use the `design-partner-summary` template plus a regress baseline when you want a
bounded before/after workflow review instead of a one-time report. The final
report artifacts from `assess` now reflect local repeat-use signals from the same
assessment directory, including evidence export, ticket export, action-contract
export, and drift artifacts when those stages ran successfully.

State, lifecycle, proof-chain, and proof-attestation files are local assessment artifacts. Share only the explicitly redacted report or evidence artifacts that match your intended audience.

Expected JSON keys: `status`, `output_dir`, `manifest_path`, `stages`, and `artifacts`. When `--baseline` is supplied, `stages.regress` now also carries additive `comparison_status` and `drift_category_count` fields so recurring assessment automation can tell the difference between actionable drift, unavailable baseline comparison data, and clean re-runs.

## Output layout

Wrkr uses stable file names under the selected `--output-dir`:

- `assessment-manifest.json`
- `internal/scan-state.json` plus neighboring state-managed manifest/lifecycle/proof artifacts
- `report/wrkr-report.md`
- `report/wrkr-report-evidence.json`
- `report/wrkr-control-backlog.csv`
- `evidence/`
- `export/inventory.json`
- `export/appendix.json`
- `export/export-pack.json`
- optional `export/tickets-<format>.json`
- optional `regress/drift.json`
- optional `regress/wrkr-regress-summary.md`

## Focus presets

`--focus` reuses the same workflow-first buyer presets as `wrkr report`.

- `bom`
- `release`
- `write-deploy`
- `approval-evidence-unknown`
- `owner-evidence-unknown`
- `evidence-gaps`
- `contradictions`
- `drift-review`
- `recommendations`

Use `--focus-path` with `--template agent-action-bom` when you also want one explicit workflow BOM path to lead the report output.

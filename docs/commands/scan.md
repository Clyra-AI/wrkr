# wrkr scan

## Synopsis

```bash
wrkr scan [--repo <owner/repo> | --org <org> | --path <dir>] [--diff] [--enrich] [--baseline <path>] [--config <path>] [--state <path>] [--policy <path>] [--profile baseline|standard|strict] [--github-api <url>] [--github-token <token>] [--report-md] [--report-md-path <path>] [--report-template exec|operator|audit|public] [--report-share-profile internal|public] [--report-top <n>] [--json] [--quiet] [--explain]
```

Exactly one target source is required: `--repo`, `--org`, or `--path`.

## Flags

- `--json`
- `--explain`
- `--quiet`
- `--repo`
- `--org`
- `--path`
- `--diff`
- `--enrich`
- `--baseline`
- `--config`
- `--state`
- `--policy`
- `--profile`
- `--github-api`
- `--github-token`
- `--report-md`
- `--report-md-path`
- `--report-template`
- `--report-share-profile`
- `--report-top`

## Example

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --report-md --report-md-path ./.tmp/scan-summary.md --report-template operator --json
```

Expected JSON keys include `status`, `target`, `findings`, `ranked_findings`, `inventory`, `repo_exposure_summaries`, `profile`, `posture_score`, and optional `report` when summary output is requested.

# wrkr regress

## Subcommands

```bash
wrkr regress init --baseline <scan-state-path> [--output <baseline-path>] [--json]
wrkr regress run --baseline <baseline-path> [--state <state-path>] [--summary-md] [--summary-md-path <path>] [--template exec|operator|audit|public] [--share-profile internal|public] [--top <n>] [--json]
```

## Flags

### regress init

- `--json`
- `--baseline`
- `--output`

### regress run

- `--json`
- `--baseline`
- `--state`
- `--summary-md`
- `--summary-md-path`
- `--template`
- `--share-profile`
- `--top`

## Example

```bash
wrkr regress init --baseline ./.tmp/state.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.tmp/state.json --summary-md --summary-md-path ./.tmp/regress-summary.md --template operator --json
```

Expected JSON keys include `status`, `baseline_path`, `tool_count` (init) and drift fields plus optional `summary_md_path` (run).

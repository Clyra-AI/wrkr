# wrkr regress

## Subcommands

```bash
wrkr regress init --baseline <scan-state-path> [--output <baseline-path>] [--json]
wrkr regress run --baseline <baseline-path> [--state <state-path>] [--json]
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

## Example

```bash
wrkr regress init --baseline ./.tmp/state.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.tmp/state.json --json
```

Expected JSON keys include `status`, `baseline_path`, `tool_count` (init) and drift fields (run).

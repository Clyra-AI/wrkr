# wrkr score

## Synopsis

```bash
wrkr score [--state <path>] [--json] [--quiet] [--explain]
```

## Flags

- `--json`
- `--quiet`
- `--explain`
- `--state`

## Example

```bash
wrkr score --state ./.tmp/state.json --json
```

Expected JSON keys: `score`, `grade`, `weighted_breakdown`, `weights`, `trend_delta`.

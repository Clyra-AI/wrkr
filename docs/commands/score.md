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

Expected JSON keys: `score`, `grade`, `breakdown`, `weighted_breakdown`, `weights`, `trend_delta`.
When attack-path scoring is present in state, output also includes `attack_paths` and `top_attack_paths`.
Malformed or type-invalid saved scan state fails with `runtime_failure` (exit `1`) instead of returning cached score output, even when the saved snapshot still contains `posture_score`.

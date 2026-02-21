# wrkr verify

## Synopsis

```bash
wrkr verify --chain [--state <path>] [--path <chain-path>] [--json]
```

## Flags

- `--json`
- `--chain`
- `--state`
- `--path`

## Example

```bash
wrkr verify --chain --state ./.tmp/state.json --json
```

Expected JSON keys: `status`, `chain.path`, `chain.intact`, `chain.count`, `chain.head_hash`.

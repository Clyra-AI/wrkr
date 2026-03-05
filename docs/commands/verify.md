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

Failure taxonomy:

- Chain parse/integrity/read verification failures emit `verification_failure` with exit `2`.
- CLI argument misuse (`--chain` missing, unsupported positional args) emits `invalid_input` with exit `6`.
- JSON verification failures include stable fields: `code`, `message`, `reason`, `exit_code`; `break_index` and `break_point` are included when available.

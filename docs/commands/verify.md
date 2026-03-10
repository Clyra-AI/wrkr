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

Expected JSON keys: `status`, `chain.path`, `chain.intact`, `chain.count`, `chain.head_hash`, `chain.reason`, `chain.verification_mode`, `chain.authenticity_status`.

Failure taxonomy:

- Chain parse/integrity/read verification failures emit `verification_failure` with exit `2`.
- Invalid or unreadable verifier-key material emits `verification_failure` with exit `2`.
- If no verifier key is available, a structurally intact chain still succeeds, but JSON explicitly reports `chain.verification_mode = chain_only` and `chain.authenticity_status = unavailable`.
- CLI argument misuse (`--chain` missing, unsupported positional args) emits `invalid_input` with exit `6`.
- JSON verification failures include stable fields: `code`, `message`, `reason`, `exit_code`; `break_index` and `break_point` are included when available.

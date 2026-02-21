# wrkr (root)

## Synopsis

```bash
wrkr [--json] [--quiet] [--explain]
```

## Flags

- `--json`: emit machine-readable output.
- `--quiet`: suppress non-error output.
- `--explain`: emit human-readable rationale.

## Stable exit codes

- `0`: success
- `1`: runtime failure
- `2`: verification failure
- `3`: policy/schema violation
- `4`: approval required
- `5`: regression drift
- `6`: invalid input
- `7`: dependency missing
- `8`: unsafe operation blocked

## Example

```bash
wrkr --json
```

Expected JSON keys: `status`, `message`.

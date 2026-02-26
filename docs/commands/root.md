# wrkr (root)

## Synopsis

```bash
wrkr <command> [flags]
wrkr [--json] [--quiet] [--explain]
wrkr help [command]
```

Root help output emits a deterministic command catalog plus global flags.

## Flags

- `--json`: emit machine-readable output.
- `--quiet`: suppress non-error output.
- `--explain`: emit human-readable rationale.

## Discoverability

- `wrkr help`: root usage + command catalog
- `wrkr help <command>`: shows help output for a specific command

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
wrkr help scan
```

Expected JSON keys for root-flag mode (`wrkr --json`): `status`, `message`.

# wrkr (root)

## Synopsis

```bash
wrkr <command> [flags]
wrkr [--json] [--quiet] [--explain] [--version]
wrkr --version [--json]
wrkr help [command]
```

Root help output emits a deterministic command catalog plus global flags.

## Flags

- `--json`: emit machine-readable output.
- `--quiet`: suppress non-error output.
- `--explain`: emit human-readable rationale.
- `--version`: print Wrkr version (supports `--json`).

## Discoverability

- `wrkr help`: root usage + command catalog
- `wrkr help <command>`: shows help output for a specific command
- `wrkr mcp-list --json`: quick MCP server catalog from saved state
- `wrkr inventory`: developer-facing inventory export and drift review entrypoint

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

Command taxonomy notes:

- `wrkr evidence --json` uses deterministic error mapping:
  - `runtime_failure` -> `1`
  - `invalid_input` -> `6`
  - `unsafe_operation_blocked` -> `8`

## Example

```bash
wrkr help scan
```

Expected JSON keys for root-flag mode (`wrkr --json`): `status`, `message`.
Expected JSON keys for version mode (`wrkr --version --json`): `status`, `version`.

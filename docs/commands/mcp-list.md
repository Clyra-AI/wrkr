# wrkr mcp-list

## Synopsis

```bash
wrkr mcp-list [--state <path>] [--gait-trust <path>] [--json]
```

`mcp-list` reads the current Wrkr scan state and projects MCP declarations into a concise server catalog.

## Flags

- `--json`
- `--state`
- `--gait-trust`

## Example

```bash
wrkr mcp-list --json
wrkr mcp-list --state ./.wrkr/last-scan.json --gait-trust ~/.gait/trust-registry.yaml --json
```

Expected JSON keys: `status`, `generated_at`, `rows`, optional `warnings`.

Each row includes:

- `server_name`
- `org`
- `repo`
- `location`
- `transport`
- `requested_permissions`
- `privilege_surface`
- `gateway_coverage`
- `trust_status`
- `risk_note`

## Trust overlay contract

- `--gait-trust <path>` points to an optional local-only YAML overlay with per-server trust states.
- `WRKR_GAIT_TRUST_PATH` is also honored when `--gait-trust` is not set.
- If no explicit overlay path is set, Wrkr will opportunistically read `.gait/trust-registry.yaml` or `.gait/trust-registry.yml` from the current working directory or user home directory when present.
- Missing or unreadable overlay files degrade explicitly to `trust_status=unavailable`; the command does not fail closed on optional trust metadata.

## Scope boundary

`mcp-list` is discovery and privilege mapping only.

- Wrkr inventories MCP posture from saved state.
- Wrkr does not probe MCP endpoints live.
- Wrkr does not replace package or vulnerability scanners. Use dedicated tools such as Snyk for that class of assessment.
- Gait remains an optional control-layer integration, not a hard prerequisite for Wrkr.

Canonical state path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).

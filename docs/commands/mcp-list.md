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

## Developer personal-hygiene example

```bash
wrkr mcp-list --state ./.wrkr/last-scan.json --json
```

Run this after a saved state snapshot already exists from `wrkr scan`.

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

## Security-team org example

```bash
wrkr mcp-list --state ./.wrkr/last-scan.json --gait-trust ~/.gait/trust-registry.yaml --json
```

This is the inventory overlay view for MCP posture after a saved repo/org scan. It is useful for security reviews and control handoff, but it is still derived from saved Wrkr state rather than live endpoint probing.

## Scope boundary

`mcp-list` is discovery and privilege mapping only.

- Wrkr inventories MCP posture from saved state.
- Wrkr does not probe MCP endpoints live.
- Wrkr does not replace package or vulnerability scanners. Use dedicated tools such as Snyk for that class of assessment.
- Gait remains an optional control-layer integration, not a hard prerequisite for Wrkr.

Canonical state path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).

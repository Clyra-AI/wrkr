# wrkr mcp-list

## Synopsis

```bash
wrkr mcp-list [--state <path>] [--gait-trust <path>] [--repo <repo>] [--expect-server <name>] [--json]
```

`mcp-list` reads the current Wrkr scan state and projects MCP declarations into a concise server catalog.

## Flags

- `--json`
- `--state`
- `--gait-trust`
- `--repo`
- `--expect-server`

## Developer personal-hygiene example

```bash
wrkr mcp-list --state ./.wrkr/last-scan.json --json
```

Run this after a saved state snapshot already exists from `wrkr scan`.

Expected JSON keys: `status`, `generated_at`, additive `repo_filter`, `rows`, additive `candidates`, additive `diagnostics`, optional `warnings`, and additive coverage-qualified absence fields `absence_status`, `absence_reasons`, and `absence_impact` when no authoritative MCP server rows are emitted.

`warnings` is also used when Wrkr can prove the saved state may have incomplete MCP posture because known MCP-bearing declaration files failed to parse.

Each row includes:

- `server_name`
- `org`
- `repo`
- `location`
- `transport`
- `requested_permissions`
- `privilege_surface`
- `gateway_coverage`
- `trust_depth`
- `trust_status`
- `risk_note`

`requested_permissions` now preserves additive MCP action-surface hints such as `mcp.read`, `mcp.write`, and `mcp.admin` when static declaration fields support them. `privilege_surface` and `risk_note` also incorporate saved gateway posture so an unprotected write/admin-capable declaration is called out explicitly without any live probing.

`trust_depth` is additive metadata derived from saved detector evidence. It exposes normalized auth strength, delegation model, exposure, policy binding, gateway binding/coverage, sanitization claims, trust gaps, and the derived `trust_depth_score`.

`candidates[]` is additive saved-state evidence for MCP-like package scripts, package dependencies, workspace hints, source literals, and WebMCP declarations that are not yet authoritative servers. Each candidate includes `candidate_name`, `org`, `repo`, `location`, `evidence_type`, `confidence`, `declaration_type`, `transport_hint`, optional `credential_refs`, and optional `unsupported_reason`.

`diagnostics[]` is additive miss-explanation output. It is designed for questions like “we expected server X in repo Y; why was it not emitted?” Each diagnostic includes deterministic `status` (`found`, `candidate_only`, `reduced_coverage`, or `not_detected`), additive `absence_status`, additive `absence_impact`, and the supporting `candidate_files_scanned`, `parsed_configs`, `candidates_found`, `parse_failures`, `generated_suppressions`, and `unsupported_declarations`.

When `rows[]` is empty, Wrkr now qualifies absence claims instead of always saying “no MCP servers found.” The additive `absence_status` values are:

- `not_found_with_complete_coverage`: complete MCP coverage found no authoritative servers.
- `not_found_with_reduced_coverage`: coverage was reduced or only candidate evidence exists.
- `not_scanned`: the saved state does not include MCP coverage facts for this repo/scope.
- `unsupported_surface`: only unsupported MCP-style surfaces were encountered.
- `candidate_parse_failed`: at least one MCP candidate surface failed to parse.

## Trust overlay contract

- `--gait-trust <path>` points to an optional local-only YAML overlay with per-server trust states.
- `WRKR_GAIT_TRUST_PATH` is also honored when `--gait-trust` is not set.
- If no explicit overlay path is set, Wrkr will opportunistically read `.gait/trust-registry.yaml` or `.gait/trust-registry.yml` from the current working directory or user home directory when present.
- Missing or unreadable overlay files degrade explicitly to `trust_status=unavailable`; the command does not fail closed on optional trust metadata.

## Security-team org example

```bash
wrkr mcp-list --state ./.wrkr/last-scan.json --gait-trust ~/.gait/trust-registry.yaml --json
wrkr mcp-list --state ./.wrkr/last-scan.json --repo acme/payments --expect-server payments-mcp --json
```

This is the inventory overlay view for MCP posture after a saved repo/org scan. It is useful for security reviews and control handoff, but it is still derived from saved Wrkr state rather than live endpoint probing.

## Runtime evidence boundary

Use `wrkr ingest` when you have runtime policy or gateway evidence to correlate with saved control paths. `mcp-list` remains a static saved-state catalog; ingested runtime evidence is surfaced by `wrkr report` and `wrkr evidence` as corroborating metadata without changing the scan truth.

## Scope boundary

`mcp-list` is discovery and privilege mapping only.

- Wrkr inventories MCP posture from saved state.
- Wrkr can explain candidate-only, parse-failed, unsupported-surface, or coverage-reduced MCP misses from saved state, but it still does not probe endpoints live.
- Wrkr does not probe MCP endpoints live.
- Wrkr does not replace package or vulnerability scanners. Use dedicated tools such as Snyk for that class of assessment.
- Gait remains an optional control-layer integration, not a hard prerequisite for Wrkr.

Canonical state path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).

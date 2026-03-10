# Personal Machine Hygiene

Use this workflow when a developer wants a deterministic answer to "what AI tooling is already configured on this machine, what MCP servers are asking for, and what changed since my last clean snapshot?"

## Exact commands

```bash
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

## Expected JSON keys

- `scan --my-setup`: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `inventory`, `profile`, `posture_score`
- `mcp-list`: `status`, `generated_at`, `rows`, optional `warnings`
- `inventory --diff`: `status`, `drift_detected`, `baseline_path`, `added_count`, `removed_count`, `changed_count`

## What to look for

- High-privilege MCP servers requesting `shell` or write permissions from user-home configs.
- `process:env` findings showing key presence without exposing secret values.
- Local `AGENTS.md`, `.agents/`, `.claude/`, `.cursor/`, or `.codex/` project markers that widen the effective AI tooling surface.
- `warnings` on `mcp-list` showing that known MCP-bearing config files failed to parse, which means a zero-row MCP catalog is incomplete rather than clean.

## Scope boundary

Wrkr inventories saved posture and local config state. It does not probe MCP endpoints live and it does not replace package or vulnerability scanners such as Snyk.

Canonical state and baseline paths are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

# ADR: Wave 2 Command Surfaces

Date: 2026-03-09
Status: accepted

## Context

Wave 2 adds two developer-facing command surfaces:

- `wrkr mcp-list`
- `wrkr inventory [--diff]`

The plan requires additive CLI behavior, deterministic output, and strict reuse of existing architecture boundaries instead of embedding new scan or diff logic in the CLI layer.

## Decision

1. `mcp-list` projects from saved Wrkr scan state rather than re-running detectors.
2. Optional Gait trust data is treated as a thin local overlay only.
3. `inventory --json` remains a compatibility wrapper over `export --format inventory --json`.
4. `inventory --diff` compares current and baseline scan states through existing deterministic diff primitives rather than a new ad hoc comparator.

## Rationale

- Saved-state projection keeps the CLI orchestration layer thin and preserves Source -> Detection -> Aggregation -> Risk boundaries.
- Optional trust overlay metadata must never become a hard runtime dependency for Wrkr.
- Reusing export and diff primitives keeps contracts aligned and reduces drift between machine-facing surfaces.
- Baseline comparison against Wrkr scan state preserves MCP server, tool, and key-presence finding detail for deterministic drift review.

## Consequences

- `mcp-list` requires an existing state snapshot and does not probe live MCP endpoints.
- Missing or unreadable Gait trust overlay input degrades to `trust_status=unavailable` with warning context.
- `inventory --diff` expects a prior scan state snapshot baseline by default at `.wrkr/inventory-baseline.json`.
- `export --format inventory` and `regress` remain supported as the lower-level compatibility surfaces.

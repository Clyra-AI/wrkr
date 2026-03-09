# ADR: Wave 3 Compliance Rollups and Evidence Artifacts

Date: 2026-03-09
Status: accepted

## Context

Wave 3 requires additive compliance rollups in `scan` and `report`, plus additive evidence bundle artifacts that stay compatible with existing proof-chain verification and evidence consumers.

The plan also requires:

- deterministic framework/control/article counts
- reuse of existing proof and compliance primitives
- fail-closed behavior when bundled framework mappings become invalid

## Decision

1. Compliance rollups are built once from existing Wrkr rule mappings plus proof-framework definitions.
2. `scan`, `report`, and `evidence` all reuse the same rollup builder rather than projecting separate summary shapes.
3. Report human-readable output reuses the same rollup summary for `--explain` lines and additive section facts.
4. Evidence bundles add deterministic JSON artifacts for compliance summary, personal inventory snapshot when the source target is `my_setup`, and MCP catalog snapshot when MCP declarations exist.

## Rationale

- One rollup builder keeps framework/control counts aligned across CLI JSON, human-readable rendering, and evidence packaging.
- Reusing proof framework definitions preserves stable control IDs and coverage math instead of inventing a second compliance contract.
- Additive evidence files preserve current `verify` and proof-record semantics while improving auditor and personal-baseline handoff.

## Consequences

- `scan --json` and `report --json` now expose additive `compliance_summary` output.
- `scan --explain` and `report --explain` now surface short deterministic compliance mapping lines.
- Evidence bundles now include `compliance-summary.json` plus optional `personal-inventory-snapshot.json` and `mcp-catalog.json`.
- If bundled framework loading fails, compliance summary generation fails closed instead of silently emitting partial counts.

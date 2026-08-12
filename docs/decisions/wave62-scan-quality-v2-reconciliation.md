# ADR: Wave 62 Scan Quality V2 And Reconciliation

Date: 2026-08-12
Status: accepted

## Context

Scan quality previously reconstructed detector denominators through a second filesystem walk. That could drift from the files a detector actually selected and could make negative coverage claims inconsistent with parser diagnostics or report counts.

## Decision

1. Detectors emit coverage receipts from the same candidate set they process.
2. `scan_quality_version=2` adds per-surface discovered, selected, attempted, parsed, partial, unsupported, suppressed, resolved, and unresolved counts with reason codes.
3. Add a reconciliation ledger for discovered, selected, parsed, observations, normalized facts, bindings, effective authority, eligible paths, confirmed/candidate/unresolved lanes, and displayed/suppressed output.
4. Fail ledger validation on impossible transitions. Scope negative claims to the named surface and its recorded coverage.
5. Keep v1 detector-health and compact summaries as compatibility projections.

## Consequences

Operators can reconcile raw occurrences to grouped buyer paths and see why detail was suppressed. Reduced coverage qualifies absence claims without hiding positive findings. Existing v1 readers continue to accept the additive fields.

## Validation

- Ledger invariant and negative-claim tests
- Detector-owned MCP, WebMCP, identity, OpenAPI, and workflow receipts
- Report count-unit, size, redaction, and deterministic-byte tests
- 96/384/674-repository customer execution-truth scenarios

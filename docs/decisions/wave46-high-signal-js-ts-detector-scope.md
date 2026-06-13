# ADR: Wave 46 High-Signal JS/TS Detector Scope

## Context

Wrkr's JS/TS-adjacent detectors were already deterministic, but Wave 42
fixtures showed an avoidable problem on enterprise-shaped repos: broad source
walking pushed WebMCP, MCP-candidate, prompt-channel, and source-framework
inspection into generated bundles, vendored trees, Yarn-managed artifacts, and
low-signal source files that were unlikely to hold authoritative declarations.

That inflated parse-noise and detector work without improving trustworthy
discovery coverage.

## Decision

1. Treat only explicit high-signal JS/TS entrypoints as authoritative detector
   inputs for these detectors: package manifests and scripts, workflow files,
   `.well-known` declarations, route files, known tool-config locations, and
   agent entrypoint paths.
2. Keep generated, bundled, vendored, and build-output JS-family paths out of
   these detectors even in deep scans unless an explicit allow rule applies.
3. Prefer lightweight string/import extraction for source-only MCP-candidate
   and agent-framework scans; reserve structured JavaScript parsing for
   high-signal WebMCP declaration files.
4. Preserve parser-edge behavior as `scan_quality` coverage facts and committed
   synthetic receipts, not ranked security findings.

## Consequences

- Enterprise JS/TS scans keep reduced coverage honest while avoiding broad
  parser fan-out from low-signal files.
- Low-signal generic source files are intentionally not authoritative detector
  inputs unless they live in one of the explicit high-signal path classes.
- Future detector-scope changes must keep the committed synthetic receipt and
  acceptance coverage green before customer-scale scans are treated as proof.

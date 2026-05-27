# ADR: Wave 25 Portable Bundle Boundaries

Date: 2026-05-27
Status: accepted

## Context

Wrkr already produced signed evidence bundles, but operators needed a richer portable manifest, paired internal and customer-redacted report artifacts, and explicit claim-discipline labels so downstream readers would not confuse static discovery with approval or enforcement evidence.

## Decision

1. Keep the existing signed `manifest.json` as the cryptographic bundle integrity surface.
2. Add a richer `artifact-manifest.json` that records stable relative paths, artifact kind, variant kind, schema version, redaction version, boundary label, proof refs, source privacy metadata, evidence-state summaries, and digests.
3. Generate internal and customer-redacted report artifacts from the same saved state and timestamp, with deterministic pair ids and a local-only private join map stored outside shareable bundle roots.
4. Add additive `boundary_label` fields across runtime/session summaries, action paths, control-path graphs, and BOM items with conservative values: `discovery_only`, `report_only`, `approval_capable`, and `enforcement_capable`.

## Consequences

- Portable bundles are forwardable without losing redaction context or boundary meaning.
- Private join maps remain local-only and are excluded from shareable bundle contents and manifests.
- Buyer-facing markdown and JSON can show when Wrkr only discovered a path, when it can report on it, and when attached evidence actually supports approval-capable or enforcement-capable claims.

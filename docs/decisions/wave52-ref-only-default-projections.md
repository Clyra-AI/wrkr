# ADR: Wave 52 Ref-Only Default Projections

Date: 2026-06-16
Status: accepted

## Context

Wave 3 of the site-assets, OpenAPI authority, and BOM hardening plan found that
Wrkr had already learned how to strip repeated canonical payload clones at
shareable/save time, but several default analysis-facing projections still kept
those clones alive earlier in the pipeline. In practice that meant the same
credential-authority, authority-binding, and mutable-endpoint payloads could be
copied into:

1. govern-first action paths
2. control path graph nodes
3. control backlog items
4. Agent Action BOM items

That duplication increased heap pressure on enterprise-shaped scans before the
later serialization strip step could help.

## Decision

1. Keep canonical refs and grouped endpoint receipts as the default projection
   contract for repeated analysis surfaces.
2. Backfill canonical refs before default graph, backlog, BOM, and returned
   summary action-path projections escape their builders.
3. Strip embedded `credential_authority`, `authority_bindings`, and
   `mutable_endpoint_semantics` payloads from those default projections once
   their canonical refs and grouped endpoint receipts are present.
4. Preserve local/internal detail recovery through the existing canonical-store
   hydration paths instead of relying on repeated inline clones.
5. Keep markdown and buyer-facing guidance additive by deriving the human text
   before stripping or by falling back to grouped/provenance summaries where
   inline authority detail is no longer present.

## Consequences

- Enterprise-shaped scans retain less repeated payload fanout before artifact
  serialization, which lowers the chance that the analysis phase fails on heap.
- Default JSON/report/control surfaces become more consistent because they all
  expose the same ref-first contract instead of mixing inline detail and refs.
- Consumers that need full detail must hydrate through canonical stores or other
  explicit internal/debug rebuild paths instead of assuming every repeated
  projection carries its own full payload clone.

## Validation Plan

- `go test ./core/aggregate/attackpath -run 'Test.*Canonical|Test.*Projection|Test.*Embedded|Test.*Payload|Test.*Ref|Test.*Authority' -count=1`
- `go test ./core/aggregate/controlbacklog -run 'Test.*Canonical|Test.*Projection|Test.*Embedded|Test.*Payload|Test.*Ref|Test.*Closure|Test.*ActionContract' -count=1`
- `go test ./core/report -run 'Test.*Canonical|Test.*Projection|Test.*Embedded|Test.*Payload|Test.*Ref|Test.*AgentActionBOM|Test.*Markdown' -count=1`
- `go test ./internal/acceptance -run 'Test.*Sprint0|Test.*SizeSignal|Test.*Embedded|Test.*Heap' -count=1`
- `go test ./internal/scenarios -run 'Test.*EnterprisePressure|Test.*SizeSignal' -count=1 -tags=scenario`
- `make test-perf`
- `make prepush-full`

Acceptance criteria:

- default graph, backlog, BOM, and returned report action-path projections keep
  canonical refs and grouped endpoint receipts while omitting embedded clones
- local canonical-store hydration continues to recover full detail when explicit
  internal/debug rebuild paths need it
- enterprise-pressure and size-signal fixtures fail when repeated embedded
  payload clones return to default analysis-facing projections

# ADR: Wave 52 Stable Resolution And Review Disposition Declarations

Date: 2026-06-25
Status: accepted

## Context

Wave 1 of the control-resolution-loop plan requires Wrkr to remember customer
review work across reruns without relying on presentation-scoped `path_id`
alone. Before this wave:

1. recurring review decisions could only attach cleanly to the current run's
   `path_id`
2. harmless path-id churn could strand otherwise valid customer review context
3. declaration inputs could express owner, target, and control context, but not
   normalized review dispositions that survive into later lifecycle work

## Decision

1. Add an additive `resolution_key` to governable action-path, BOM, report, and
   regress-baseline surfaces as the durable review join key beside `path_id`.
2. Allow review declarations to correlate by direct `path_id`,
   `resolution_key`, `finding_key`, or a structured selector when direct joins
   no longer match.
3. Keep selector fallback fail-closed: ambiguous matches stay unresolved and
   surface deterministic selector mismatch/ambiguity reasons instead of
   suppressing findings.
4. Normalize review declarations into additive review-lifecycle input metadata
   (`review_lifecycle_state`, rationale, owner/source, scope, and freshness
   context) without yet changing later-wave queue placement or appendix policy.

## Alternatives Considered

1. Keep `path_id` as the only declaration join key.
   Rejected because harmless line-range, ordering, and source-shape churn would
   keep breaking durable customer review loops.
2. Move declaration matching into report-only rendering.
   Rejected because regress, backlog, and risk projections would then invent
   inconsistent resolution behavior.
3. Match broad selectors fail-open when more than one current path fits.
   Rejected because it would silently attach customer review context to the
   wrong governable path.

## Tradeoffs

- The additive selector trace fields make public contracts larger, but they keep
  review-correlation behavior explainable instead of implicit.
- Review dispositions are normalized early, while later waves still own queue
  movement, resolved-appendix behavior, and reopen semantics.

## Rollback Plan

1. Revert `resolution_key` and selector trace fields from action-path, BOM,
   report, and regress-baseline projections.
2. Remove review-disposition parsing from control declarations and restore
   owner/target/control-only declaration behavior.
3. Re-run the focused risk/report/backlog/regress, contract, and full prepush
   lanes to confirm the old single-key behavior is fully restored.

## Validation Plan

- `go test ./core/risk -run 'Test.*ResolutionKey|Test.*Selector|Test.*ReviewDisposition|Test.*Expired' -count=1`
- `go test ./core/report ./core/aggregate/controlbacklog ./core/regress -run 'Test.*ResolutionKey|Test.*Selector|Test.*Drift' -count=1`
- `go test ./core/config ./core/attribution -run 'Test.*ControlDeclaration|Test.*ReviewDisposition|Test.*Expired|Test.*Contradict' -count=1`
- `make test-contracts`
- `make prepush-full`

Acceptance criteria:

- governable action paths expose a stable `resolution_key` beside `path_id`
- selector fallback can recover a reviewed path after `path_id` churn without
  silently resolving ambiguous candidates
- expired review declarations stay visible as inactive review input instead of
  resolving the path

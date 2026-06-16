# ADR: Wave 51 Static Target Authority Correlation

Date: 2026-06-16
Status: accepted

## Context

Wave 2 of the site-assets, OpenAPI authority, and BOM hardening plan found that
Wrkr still let static target surfaces inherit governable posture from unrelated
repo-wide workflow evidence. In practice, a repo that contained:

1. an OpenAPI or route surface
2. an unrelated workflow secret or release workflow elsewhere in the repo

could project the static target as a partially bound action path instead of
plain target context. That overclaimed authority, crowded Top Action Paths, and
blurred the difference between:

1. static target context that needs caller correlation
2. path-scoped authority evidence
3. real workflow or runtime execution evidence

## Decision

1. Strip repo-wide credential and authority signals before they are merged into
   `openapi` and `route` target surfaces during privilege-budget aggregation.
2. Keep repo-wide context that is still useful for buyer-readable production
   framing, but do not treat that context as enough to promote static target
   surfaces into governable action paths.
3. Require path-scoped authority evidence before target-context surfaces can use
   credential or authority metadata as correlation proof.
4. Preserve the existing distinction between production context and action-path
   eligibility: static targets may remain production-adjacent context without
   automatically becoming governable action paths.

## Alternatives Considered

1. Remove all repo-wide context from OpenAPI and route surfaces.
   Rejected because it would also erase useful production-adjacent context that
   still helps buyers understand why the surface matters.
2. Leave aggregation unchanged and only rewrite markdown or readiness copy.
   Rejected because JSON, scenario, and govern-first consumers would still see
   false action-path eligibility.
3. Treat any workflow, delivery-harness, or matched-target metadata as direct
   correlation for static targets.
   Rejected because the unrelated-credential failure class would remain fail-open.

## Tradeoffs

- The model is more conservative, so some static target surfaces move out of Top
  Action Paths and back into Target Surface Context until stronger evidence is
  present.
- Direct path-scoped evidence is now more important than broad repo adjacency,
  which is a better fit for Wrkr's deterministic, explainable posture model.

## Rollback Plan

1. Revert the repo-wide authority filtering for `openapi` and `route` surfaces.
2. Restore the old target-context correlation gate that accepted repo-derived
   authority metadata as sufficient binding evidence.
3. Re-run the focused privilege-budget, risk, scenario, contract, and final
   lanes to confirm the old semantics are fully restored.

## Validation Plan

- `go test ./core/aggregate/privilegebudget -run 'Test.*OpenAPI|Test.*Swagger|Test.*Route|Test.*Authority|Test.*Credential' -count=1`
- `go test ./core/risk -run 'Test.*ActionBinding|Test.*OpenAPI|Test.*TargetSurface|Test.*Authority' -count=1`
- `go test ./internal/scenarios -run 'TestWave3ActionPathSemanticScenario|TestSwaggerWithUnrelatedWorkflowCredentialStaysTargetContext|TestWave4HighStakesAuthorityScenario' -count=1 -tags=scenario`
- `scripts/validate_scenarios.sh`
- `make test-contracts`
- `make test-hardening`
- `make prepush-full`

Acceptance criteria:

- static OpenAPI and route surfaces stay in Target Surface Context when the only
  evidence is an unrelated workflow secret or workflow elsewhere in the repo
- target-context surfaces strip uncorrelated authority payloads instead of
  treating them as binding proof
- production-adjacent context can remain visible without promoting the static
  surface into a governable action path

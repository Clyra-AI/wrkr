# ADR: Wave 58 Bounded Multi-Stage Reachability

Date: 2026-07-21
Status: accepted

## Context

Wrkr's original composed action paths joined one source and one sink. That
kept output deterministic, but it could not preserve a consequential route
that crosses repository, CI, package, cloud, SaaS, or communications systems.
General graph traversal would create path explosion and could turn weak shared
metadata into an asserted authority chain.

Wrkr remains a deterministic discovery product. It can describe evidence-backed
possible reachability, while Gait owns runtime control and Axym owns downstream
effect verification.

## Decision

1. Support only five explicit multi-stage pattern families:
   `sensitive_read_to_egress_multistage`,
   `secret_to_network_multistage`, `code_to_deploy_multistage`,
   `workflow_mutation_to_production_multistage`, and
   `package_change_to_release_multistage`.
2. Each template contains an ordered entry role, one or more transforms, and a
   sink; the workflow-mutation family retains its existing transform entry
   role. A route has three to five stages. System order is constrained to the
   configured repo, CI, package, cloud, SaaS, and communications classes; no
   raw-file traversal or arbitrary graph query is introduced.
3. Every adjacent transition requires a shared stable workflow-chain,
   attack-path, authority-binding, prior-composition, imported-evidence, or
   normalized lineage graph-edge reference. Endpoint groups, policy refs, and
   source findings can explain a stage but cannot create a transition by
   themselves. Unknown system boundaries and missing correlations produce no
   match.
4. Traversal is deterministic and bounded per pattern to depth 5, 6 neighbors
   per stage, 64 examined candidates, and 16 emitted paths. Alternate-route
   refs are capped at 8 and transition correlation refs at 16. Depth,
   candidate, path, alternate-route, and correlation-reference pruning is
   emitted as structured truncation metadata.
5. `composition_id` covers the pattern plus ordered durable stage role,
   resolution key, system class, trust boundary, action/target semantics, and
   final target/outcome. It excludes timestamps and volatile `path_id` values.
   Duplicate resolution keys cannot recur in one route.
6. `reachability_state=possible` describes a statically correlated route.
   `observed_execution=true` and `reachability_state=observed` require verified
   runtime state and action-outcome evidence at every stage. Partial evidence
   never upgrades a route to observed.
7. The final bounded path set flows through the existing equivalent-outcome
   parity, version 3 proposed Action Contract, artifact, packet, redaction,
   proof/evidence join, and regress projections. The packet remains opt-in and
   the default report finding inventory does not expand.

## Consequences

- Buyers gain an ordered, explainable authority route with trust-boundary and
  transition evidence instead of a prose-only graph claim.
- Unsupported or weakly correlated real-world routes are intentionally omitted.
  This is safer than guessing a join, but it can under-report paths until a
  supported stable correlation reference is available.
- New pattern IDs and fields are additive within schema v1. Existing pairwise
  patterns and IDs remain unchanged.
- High fan-out work is capped and benchmarked. A cap can return deterministic
  partial results, and the truncation receipt tells consumers why.

## Rollback Plan

1. Stop invoking the multi-stage pattern builder while retaining all original
   pairwise patterns and version 2/3 contract readers.
2. Keep readers tolerant of the additive stage, transition, reachability, and
   truncation fields already persisted in saved state.
3. Re-run contract, scenario, risk, redaction, performance, and pre-push lanes
   before removing the public pattern IDs from a future major-version plan.

## Validation

- `go test ./core/risk -run 'Test.*MultiStage|Test.*CrossSystem|Test.*CompositionID|Test.*Reachability' -count=1`
- `go test ./core/aggregate/attackpath ./core/regress ./core/report ./core/proofmap -run 'Test.*Composition|Test.*ActionContract' -count=1`
- `make test-scenarios`
- `make test-risk-lane`
- `make test-chaos`
- `make test-perf`
- `make prepush-full`
- `make codeql`

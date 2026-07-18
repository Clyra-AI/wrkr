# ADR: Wave 53 Composed Action-Path Contracts

Date: 2026-07-18
Status: accepted

## Context

Wrkr could already describe individual action paths, workflow chains, evidence,
Gait coverage, and recommended controls. It could not represent the bounded
case where individually permitted capabilities compose into one consequential
authority path. Adding separate source/transform/sink fields to action paths,
workflow chains, reports, and graphs would create competing classifications and
unstable cross-product joins.

This change crosses the aggregation, risk, proof-emission, and evidence-output
boundaries. It adds public, additive contracts for compositions and proposed
Action Contracts, while preserving Wrkr as a deterministic discovery product;
Gait remains authoritative for runtime transition enforcement and Axym for
cross-system evidence reconstruction.

## Decision

1. Derive one bounded, deterministic `composed_action_path` risk artifact from
   normalized action paths and workflow-chain context. Its ordered stages use
   `source`, `transform`, and sink roles; these roles are not a second detector
   or source-layer classification system.
2. Support only the explicitly bounded sensitive-read-to-egress,
   secret-to-network, code-to-deploy, workflow-mutation-to-production, and
   package-change-to-release patterns. Candidate expansion is capped and
   records truncation or unsupported surfaces explicitly.
3. Use `composition_id` and `outcome_key` as durable, deterministic joins from
   pattern, ordered stage roles, stable member resolution keys, target identity,
   and outcome semantics. Keep volatile `path_id` and input ordering out of
   durable identity material; retain them only as references.
4. Reuse canonical evidence state, freshness, policy coverage, Gait coverage,
   autonomy tier, and recommended-control semantics at each composition stage
   and transition. A declared policy or static reachability must never be
   reported as runtime control without the required transition enforcement and
   outcome/proof evidence.
5. Emit an additive, versioned `proposed_action_contract` for a composition.
   It is always `report_only: true`, preserves the compatible
   `recommended_action_contract` projection, and can include transitions,
   target constraints, credential/delegation requirements, evidence,
   countersigners, outcome, compensation, and deterministic source digests.
   It neither enforces a transition nor claims that Wrkr observed one.
6. Use explicit composition, proposed-contract, workflow-chain, and
   resolution-key references in reports, BOMs, decision traces, proof maps,
   evidence bundles, and regression snapshots. Do not reconstruct those joins
   with prose parsing or heuristics.
7. Detect equivalent outcomes only for bounded deploy, egress,
   privileged-mutation, and release outcomes. Stable target identity remains in
   the grouping key; authority, credential, workflow, approval, policy, Gait,
   and evidence differences are comparison deltas used for approval-evasion
   signals.

## Alternatives Considered

1. Add composition fields independently to action paths, workflow chains,
   graphs, and reports. Rejected because consumers could derive incompatible
   compositions and evidence rollups.
2. Make Wrkr enforce proposed contracts or track runtime sequence state.
   Rejected because it would collapse the See -> Prove -> Control boundary and
   misrepresent static discovery as runtime authority.
3. Introduce composition-specific evidence or recommendation enums. Rejected
   because it would fork canonical evidence and control semantics.
4. Implement arbitrary graph queries or LLM classification. Rejected because
   the resulting behavior would be unbounded or non-deterministic.
5. Group equivalent outcomes by repository, tool family, or asset alone.
   Rejected because it would over-group unrelated targets and create noisy
   approval-evasion findings.

## Tradeoffs

- Additive schemas, fixtures, and report projections increase artifact size,
  so the Sprint 0 public-surface freeze receipt, output budgets, redaction, and
  bounded primary view remain release gates.
- Bounded patterns can omit real but unsupported compositions; they must report
  that limit explicitly rather than infer unsupported behavior.
- Runtime evidence sidecars can strengthen a claim, but missing, stale, or
  contradictory evidence deliberately produces a conservative result.

## Rollback Plan

1. Stop emitting `composed_action_paths` and proposed-contract projections
   while keeping existing action paths, workflow chains, and
   `recommended_action_contract` fields intact.
2. Remove the additive schema/report/proof/evidence/regress references and
   restore the previous primary-view selection when no composition projection
   is available.
3. Retain saved-state compatibility: older composition-less baselines continue
   through existing action-path comparison, while requested composition
   comparison reports unavailable baseline data explicitly.
4. Re-run contract, scenario, risk, and full-prepush lanes before release.

## Validation Plan

- `go test ./core/risk -run 'Test.*Composition|Test.*ProposedActionContract|Test.*EquivalentOutcome|Test.*ApprovalEvasion' -count=1`
- `go test ./core/report ./core/proofmap ./core/proofemit ./core/regress -run 'Test.*Composition|Test.*DecisionTrace|Test.*Drift' -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario -run 'Test.*ComposedActionPath'`
- `make test-contracts`
- `make test-scenarios`
- `make test-risk-lane`
- `make prepush-full`

Acceptance criteria:

- Composition IDs and proposed-contract IDs remain deterministic across
  harmless input and `path_id` churn.
- Customer-redacted and public outputs preserve safe references without
  exposing sensitive composition or contract payloads.
- Static reachability, declared policy, runtime control, and observed execution
  remain distinct claims in schemas, reports, fixtures, and regress output.
- Equivalent-outcome and drift output remain bounded, deterministic, and do
  not treat unrelated targets as the same authority path.

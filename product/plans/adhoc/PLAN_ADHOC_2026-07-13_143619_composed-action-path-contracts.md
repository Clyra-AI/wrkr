# Adhoc Plan: Composed Action Path Contracts

Date: 2026-07-13
Profile: `wrkr`
Slug: `composed-action-path-contracts`
Recommendation source: user-provided recommendations for composed action-path modeling, proposed Action Contracts, cross-product correlation, composition evidence and Gait coverage, focused buyer output, cross-product fixtures, delegation relationship projection, composition-aware controls, equivalent-outcome signals, and composition drift.

All local checkout paths from the recommendation source are normalized to repo-relative paths. Story repo paths below resolve from `$REPO_ROOT`.

## Global Decisions (Locked)

- Wrkr remains the deterministic See product in the See -> Prove -> Control sequence. This plan adds discovery, correlation, report, proof-reference, and contract-proposal artifacts only; it does not add Gait runtime enforcement or Axym compliance engine behavior.
- `composed_action_path` is the single composition object reused by risk reports, Agent Action BOM output, proposed Action Contracts, proof/decision trace references, regress drift, and control recommendations.
- Composition uses bounded deterministic patterns, not LLM judgment, arbitrary graph queries, or runtime event reconstruction.
- Source, transform, sink, privileged sink, destructive sink, and external sink roles live inside the one `composed_action_path.stages[]` model. They are not a parallel classification system outside the composition object.
- Static reachability and observed execution stay separate. Wrkr may say a composition is possible or statically inferred; it must not claim that the sequence executed unless imported runtime evidence explicitly proves execution.
- Existing `resolution_key`, action-path IDs, workflow-chain IDs, evidence states, freshness semantics, autonomy tiers, canonical recommendations, policy coverage, and Gait coverage remain canonical.
- `path_id` remains an instance identifier. Durable cross-product joins use `resolution_key`, `composition_id`, `proposed_action_contract_ref`, workflow-chain refs, and decision-trace refs.
- A declared policy, matched policy file, or static Gait config is not runtime-proven enforcement. Runtime control claims require sufficient `gait_coverage` and outcome/proof evidence.
- The action contract surface is named `proposed_action_contract` in new artifacts because Wrkr is not runtime-authoritative. Existing `recommended_action_contract` output must remain compatible during migration and may be backfilled from the proposed contract where needed.
- Proposed Action Contracts are report-only proposals from Wrkr with `report_only: true`; Gait remains authoritative for runtime transition checks, sequence state, approvals, credentials, attenuation, revocation, and execution closure.
- Cross-product compatibility fixtures are release-level API surfaces. Wrkr must not ship a composition artifact that Gait cannot validate or Axym cannot correlate without a failing fixture or contract test.
- Buyer-facing output leads with the highest-risk consequential composition, affected asset, authority, evidence posture, current control gap, proposed Action Contract, and closure requirements. Deep stage/path detail belongs in appendices.
- Public scan/report/schema surface expansion is blocked until the Sprint 0 freeze gate is explicitly green. Size, redaction, recursive redaction, clone-strip, readability, and finding-noise gates must pass before `composed_action_paths[]`, proposed contract fields, or primary-view composition fields can become public JSON/schema output.
- No scan-time LLM calls, live tool execution, raw payload inspection, secret extraction, default network calls, or scan-data exfiltration are allowed.

## Current Baseline (Observed)

- `core/risk/action_paths.go` already builds `risk.ActionPath` records with `path_id`, `resolution_key`, canonical evidence states, policy coverage, Gait coverage, workflow-chain refs, decision-trace refs, autonomy tier, delegation readiness, recommended control, closure requirements, and an existing `recommended_action_contract`.
- `core/risk/evidence_state.go`, `core/evidencepolicy/evidencepolicy.go`, and `core/risk/evidence_context.go` already model canonical evidence states, source precedence, freshness, contradictions, closure requirements, and evidence completeness. New composition evidence should reuse these semantics.
- `core/risk/gait_coverage.go` and `core/report/gait_coverage.go` already model Gait coverage for policy decision, approval, JIT credential, freeze window, kill switch, action outcome, and proof verification.
- `core/risk/policy_coverage.go` already distinguishes `none`, `declared`, `matched`, `runtime_proven`, `stale`, and `conflict` policy coverage.
- `core/risk/workflow_chain.go` and `core/aggregate/agentresolver/workflow_chain.go` already build deterministic workflow-chain artifacts from action paths and control-path graph refs.
- `core/aggregate/attackpath/graph.go` already builds graph nodes and edges over entry, pivot, target, workflow, tool, credential, and action-capability contexts. Composition should consume this context where useful without becoming an arbitrary graph query engine.
- `core/report/agent_action_bom.go`, `core/report/primary_view.go`, and `core/report/render_markdown.go` already expose a focused Agent Action BOM, primary view, buyer-safe redaction, closure actions, and action contract wording. The BOM does not yet lead with a first-class composition object.
- `schemas/v1/risk/risk-report.schema.json`, `schemas/v1/agent-action-bom.schema.json`, and `schemas/v1/report/report-summary.schema.json` already carry action-path, evidence-state, Gait coverage, workflow-chain, and recommended action contract fields. There is no `composed_action_path` schema or `proposed_action_contract` schema today.
- `schemas/v1/proof-outputs/decision-trace-record.schema.json` already defines additive decision-trace proof output, but it does not require or project `resolution_key`, `composition_ids`, `proposed_action_contract_ref`, workflow-chain refs, autonomy tier, canonical recommendation, or stage evidence references.
- `core/regress/action_path_drift.go` already compares action paths across baselines using `resolution_key`, authority, evidence, target class, lifecycle, and risk fields. It does not yet compare composed action paths or detect composition drift.
- Existing docs in `docs/commands/report.md`, `docs/commands/ingest.md`, and `schemas/v1/README.md` already explain action paths, Agent Action BOM evidence, Gait coverage, freshness, and Wrkr/Gait boundaries. They do not yet document composed action paths or proposed Action Contracts.
- Search found no existing `composed_action_path`, `composition_id`, or composition stage-role artifact in `core/`, `schemas/`, `internal/`, `scenarios/`, or docs.

## Exit Criteria

- Wrkr emits a bounded `composed_action_paths[]` artifact from existing action paths, workflow chains, graph refs, evidence decisions, and runtime evidence sidecars, with deterministic `composition_id`, pattern ID, ordered stages, transitions, target identity, recommendation, and proof/evidence refs.
- Composition IDs remain stable across harmless `path_id` churn, input ordering changes, duplicate stage candidates, and repeated runs. IDs change only when durable members, roles, pattern, target identity, or consequential outcome semantics change.
- Sprint 0 freeze gates are green before any new public scan/report/schema surface lands, with validation receipts for size, redaction, recursive redaction, clone-strip, readability, and finding-noise budgets.
- Composition evidence reuses canonical evidence states, freshness, `policy_coverage_status`, and `gait_coverage`; it does not introduce a second evidence vocabulary.
- Wrkr distinguishes possible static composition from observed execution in JSON, Markdown, proof refs, and docs.
- Wrkr emits additive `proposed_action_contract` objects that reference compositions and include allowed/prohibited transitions, approval-required transitions, target constraints, credential mode, delegation depth, evidence requirements, countersigner requirements, expected outcome class, compensation requirements, expiry, source digests, and `report_only: true`.
- Existing `recommended_action_contract` consumers remain compatible during migration, with docs leading on the proposed Action Contract name.
- Decision trace records and evidence bundle exports carry explicit `resolution_key`, `composition_ids`, `proposed_action_contract_ref`, workflow-chain refs, autonomy tier, recommended control, and evidence-state fields for Gait and Axym joins without heuristic matching.
- The Agent Action BOM primary view and Markdown report lead with the highest-risk composition and required control closure before broad graph or inventory appendices.
- Canonical scenarios cover sensitive-read-to-egress, secret-to-network, code-to-deploy, workflow-mutation-to-production, package-change-to-release, standing credentials, incomplete outcomes, and controlled versus uncontrolled transitions.
- Regress detects meaningful composition drift, including introduced compositions, removed compositions, member changes, newly introduced sinks, coverage degradation, evidence degradation, alternate routes, newly ungoverned transitions, and worsened recommendations without reporting harmless ordering or instance-ID churn.

## Public API and Contract Map

- Public-surface prerequisite:
  - Story 0.1 must pass before implementation stories expose new top-level or schema-documented public fields.
  - If Story 0.1 is not green, composition work may proceed only as an internal/private projection or fixture experiment with public JSON/schema/report expansion deferred.
  - Validation receipts must identify the exact size, redaction, recursive-redaction, clone-strip, readability, and finding-noise commands or tests used.
- Risk report JSON:
  - Add top-level `composed_action_paths[]` and `composed_action_path_to_control_first`.
  - Add `composition_refs[]` or `composition_ids[]` on relevant `action_paths[]` entries.
  - Keep `action_paths[]`, `workflow_chains`, `control_path_graph`, and `recommended_action_contract` backward compatible.
- Agent Action BOM JSON:
  - Add `summary.primary_view.composition_id`, composition path map fields, and a focused composition block.
  - Add `items[*].composition_ids[]` where an item contributes to one or more compositions.
  - Add a top-level or summary-level `composed_action_paths[]` reference list only when it can be derived from saved state.
- Schemas:
  - Add `schemas/v1/composed-action-path.schema.json`.
  - Add `schemas/v1/proposed-action-contract.schema.json`.
  - Extend `schemas/v1/risk/risk-report.schema.json`, `schemas/v1/agent-action-bom.schema.json`, `schemas/v1/report/report-summary.schema.json`, and evidence bundle schemas additively.
  - Extend `schemas/v1/proof-outputs/decision-trace-record.schema.json` additively for cross-product refs.
- Proof and evidence:
  - Continue using existing proof primitives and record types unless a later implementation story explicitly versions a new proof record type.
  - Composition proof refs point to existing proof records, decision traces, runtime evidence packets, workflow-chain refs, graph refs, and source finding refs.
  - Decision traces carry composition and contract references; they do not become runtime-authoritative execution logs.
- CLI/report:
  - `wrkr report --template agent-action-bom --json` and buyer-focused Markdown/PDF output lead with the primary composition when one exists.
  - `wrkr scan --json` may expose additive composition data only if built from deterministic scan/risk state without report-only dependencies.
  - `--json`, `--explain`, `--quiet`, and exit-code contracts remain stable.
- Regress:
  - Extend saved-state comparison to composition states and composition drift categories.
  - Continue exit `5` for regression drift.
- Architecture boundaries:
  - Aggregation and risk derive composition from normalized existing artifacts.
  - Detection does not know composition stage roles.
  - Report/evidence render and export the derived artifact.
  - Proof emission references composition IDs and source digests without reclassifying source data.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/regress.md`
  - `docs/commands/evidence.md`
  - `docs/commands/ingest.md`
  - `docs/examples/security-team.md`
  - `docs/examples/operator-playbooks.md`
  - `docs/contracts/compatibility_matrix.md`
  - `docs/map.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Docs must state:
  - What a composed action path is and how it differs from an action path, workflow chain, and observed execution.
  - Why source/transform/sink roles are stage roles inside `composed_action_path`, not a second classification system.
  - Why Wrkr emits a proposed Action Contract and why Gait remains runtime-authoritative.
  - Which composition patterns are supported and which are explicitly out of scope.
  - How composition IDs, resolution keys, workflow-chain refs, proposed contract refs, decision trace refs, and proof refs join.
  - How policy coverage, Gait coverage, freshness, and runtime evidence affect the difference between possible, partially controlled, controlled, and observed claims.
  - How to reproduce canonical composition fixtures and validate their JSON, Markdown, schema, redaction, and drift outputs.
- Docs parity gates:
  - `scripts/check_docs_cli_parity.sh`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/run_docs_smoke.sh`
  - `make test-docs-consistency`
- OSS trust and release readiness:
  - New public contracts need changelog entries with semver markers.
  - Schema examples must avoid developer-specific absolute paths.
  - Scenario expected outputs remain human-reviewed spec artifacts.
  - Buyer-facing Markdown length and finding-noise budgets must stay bounded.

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage |
|---|---:|---|
| Sprint 0 public surface freeze gate | P0 | Story 0.1 |
| 1. Composed Action-Path Contract and Pattern Engine | P0 | Stories 1.1, 1.2, 2.3 |
| 2. Proposed Action Contract V2 | P0 | Story 1.3 |
| 3. Cross-Product Composition Correlation | P0 | Story 2.1 |
| 4. Composition Evidence and Enforcement-Coverage Truth | P0 | Story 1.2 |
| 5. Focused Buyer-Facing Composed Authority Output | P0 | Story 2.2 |
| 6. End-to-End Composition Contract Fixtures | P0 | Story 2.3 |
| 7. Delegated Authority Relationship Projection | P1 | Story 3.1 |
| 8. Composition-Aware Control Recommendations | P1 | Story 3.2 |
| 9. Equivalent-Outcome and Approval-Evasion Signals | P1 | Story 3.3 |
| 10. Composition Drift and Regression | P1 | Story 3.4 |

## Test Matrix Wiring

- Fast lane: focused Go unit tests for composition pattern matching, stable IDs, stage evidence rollups, proposed contract building, report primary view selection, decision trace refs, and regress state snapshots, plus `make lint-fast`.
- Core CI lane: `make test-fast`, `make test-contracts`, schema validation tests, report/evidence JSON contract tests, CLI help/docs parity tests, and byte-stable golden fixtures.
- Acceptance lane: `make test-scenarios`, `scripts/validate_scenarios.sh`, scenario-tagged tests for composition fixture packs, and `scripts/run_v1_acceptance.sh --mode=local` after P0 public contract stories land.
- Cross-platform lane: Linux, macOS, and Windows coverage for JSON/schema/report/regress command behavior, with platform-neutral fixture paths and newline normalization.
- Risk lane: `make test-risk-lane`, `make test-hardening`, `make test-chaos`, `make test-perf`, and `make codeql` for public risk, proof/evidence, fail-closed, and buyer-output surfaces.
- Release/UAT lane: `make prepush-full`, release smoke, docs-site gates, schema compatibility checks, CodeQL, and local UAT before a release candidate.
- Gating rule: no story is complete until declared lanes are green, first failing tests are committed, golden outputs are byte-stable except explicit timestamp/version fields, docs/changelog/schema changes are synchronized, and no committed plan, fixture, doc, schema, or generated artifact contains developer-specific absolute checkout paths.

## Minimum-Now Sequence

- Wave 0 - Freeze gate prerequisite:
  - Story 0.1: verify Sprint 0 size, redaction, recursive-redaction, clone-strip, readability, and finding-noise gates before public composition surface expansion.
- Wave 1 - Composition contract spine:
  - Story 1.1: define the `composed_action_path` model, schema, stable ID, and bounded pattern engine.
  - Story 1.2: project canonical evidence, policy coverage, Gait coverage, freshness, and static-versus-observed claims onto composition stages and transitions.
  - Story 1.3: add `proposed_action_contract` v2 while preserving recommended contract compatibility.
- Wave 2 - Cross-product and buyer output:
  - Story 2.1: extend decision traces, proof/evidence exports, and schemas with explicit composition and proposed contract refs.
  - Story 2.2: lead the Agent Action BOM and buyer Markdown with the highest-risk composition and closure requirements.
  - Story 2.3: add canonical composition contract fixtures, schema goldens, and scenario acceptance coverage.
- Wave 3 - Composition intelligence:
  - Story 3.1: compare delegated authority relationships inside composed paths.
  - Story 3.2: apply canonical recommendations to whole compositions with transition-level rationale.
  - Story 3.3: detect bounded equivalent-outcome and approval-evasion alternatives.
  - Story 3.4: extend regress to composition drift and baseline comparison.

## Explicit Non-Goals

- No runtime tool-call enforcement, sequence state machine, kill switch, approval service, credential minting, or live session monitor in Wrkr.
- No Gait or Axym product implementation beyond shared proof, schema, and fixture interoperability contracts.
- No arbitrary graph-query language, generalized complex-event-processing language, or event-sourced agent runtime.
- No scan-time LLM classification or generated risk judgment.
- No raw payload-content inspection, DLP replacement, secret value extraction, or secret value hashing.
- No broad provider expansion unless required by a design-partner composition fixture and kept inside existing output/noise budgets.
- No claim that a statically reachable composition actually executed.
- No breaking removal or rename of existing `action_paths`, `workflow_chains`, `control_path_graph`, `agent_action_bom`, or `recommended_action_contract` fields in this plan.

## Definition of Done

- Wrkr identifies when individually permitted capabilities form a dangerous possible composed authority path and explains the ordered source-to-sink stages with bounded deterministic pattern IDs.
- Composition output reuses existing evidence state, freshness, policy coverage, Gait coverage, autonomy tier, recommendation, resolution key, and workflow-chain semantics.
- Proposed Action Contracts are machine-consumable, report-only, composition-aware proposals that Gait can validate without parsing prose or reproducing Wrkr discovery logic.
- Decision traces, evidence bundles, Agent Action BOM output, and regress states preserve explicit composition and contract references for Gait and Axym correlation.
- Buyer-facing output answers which permitted capabilities compose into the most consequential authority path, what evidence proves or fails to prove control, and what closure is required.
- Canonical scenarios and schema fixtures prove deterministic composition, proposed contract, decision trace, evidence requirements, redaction, and drift behavior.
- Docs, schemas, command help, examples, changelog, and scenario goldens agree with executable behavior.

## Epic 0: Sprint 0 Freeze Gate and Output-Safety Prerequisite

Objective: keep the existing temporary freeze on new scan/report surface area enforceable while allowing composition planning to proceed only after buyer-output size, redaction, and readability gates are green.

### Story 0.1: Verify Sprint 0 gates before public composition fields

Priority: P0
Recommendation coverage: prerequisite for all public composition output
Strategic direction: Treat the repo's temporary freeze as a hard public-surface gate, not a note buried in implementation stories.
Expected benefit: Composition work cannot reintroduce output-size, redaction, readability, clone-strip, or finding-noise regressions while Wrkr is still stabilizing buyer-facing surfaces.

Tasks:
- Read the current `AGENTS.md`, `product/PLAN_NEXT.md`, `product/dev_guides.md`, and `docs/commands/report.md` freeze language before implementing any public composition JSON/schema/report field.
- Identify the exact local and CI gates that prove output-size budgets, redaction, recursive redaction, clone-strip contracts, readability, and finding-noise budgets are green for current buyer-facing surfaces.
- Add or update a small freeze-gate receipt artifact or test note in the implementation PR description that records the commands, fixture names, and pass/fail result before Story 1.1 exposes public fields.
- If any freeze gate is missing or red, keep composition work internal/private and defer public `composed_action_paths[]`, proposed contract schema exposure, and Agent Action BOM primary-view expansion until the gate is green.
- Require every later story that adds public scan/report/schema output to reference the Story 0.1 validation receipt in its PR description.
- Add a docs note that new composition fields are intentionally gated by the Sprint 0 output-safety freeze.
- Add changelog entry only if implementation adds a new automated freeze-gate check or public docs note.

Repo paths:
- `AGENTS.md`
- `product/PLAN_NEXT.md`
- `product/dev_guides.md`
- `docs/commands/report.md`
- `docs/commands/scan.md`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `testinfra/contracts/`
- `CHANGELOG.md`

Run commands:
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/check_docs_cli_parity.sh`
- `go test ./testinfra/contracts -run 'Test.*Redaction|Test.*Clone|Test.*Report|Test.*Output|Test.*Noise' -count=1`
- `make test-focused-docs`
- `make test-contracts`
- `make lint-fast`

Test requirements:
- A failing or missing freeze-gate fixture must block public composition fields.
- Redaction tests must cover recursive redaction and clone-strip behavior for any new composition fixture before it becomes public output.
- Readability and output-size checks must use buyer-facing report fixtures, not only unit-level JSON snapshots.
- Negative test or documented receipt proving public fields are deferred when gates are red or unavailable.

Matrix wiring:
- Fast lane: docs parity/storyline checks, focused contract tests, and `make lint-fast`.
- Core CI lane: `make test-contracts`, `make test-focused-docs`, and `make test-fast` when implementation changes tests/scripts.
- Acceptance lane: scenario validation becomes required before Story 2.3 public fixtures land.
- Cross-platform lane: redaction and clone-strip path normalization checks must run on at least Linux plus the existing Windows smoke lane when public output changes.
- Risk lane: `make test-risk-lane` when any public report/risk/schema surface is exposed.
- Release/UAT lane: `make prepush-full` before release promotion.
- Gating rule: Story 1.1 through Story 3.4 cannot expose public composition fields unless this story's gate receipt is green or the later PR explicitly keeps the work internal/private.

Acceptance criteria:
- Public composition JSON/schema/report expansion is blocked until the Sprint 0 output-safety gate has green receipts.
- The gate receipt names size, redaction, recursive-redaction, clone-strip, readability, and finding-noise validations.
- Later implementation PRs have a clear go/no-go decision for public composition output.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Documented the Sprint 0 public-surface freeze gate that composition work must satisfy before exposing new scan/report/schema fields.
Semver marker override: none
Contract/API impact: No new public fields by itself; gates future public composition surface area.
Versioning/migration impact: No migration; this story is a prerequisite and enforcement receipt.
Architecture constraints: The gate must preserve existing buyer-output contracts before risk/report/schema expansion begins.
ADR required: no
TDD first failing test(s): `TestCompositionPublicSurfaceRequiresSprint0FreezeGateReceipt`.
Cost/perf impact: low
Chaos/failure hypothesis: If redaction, clone-strip, readability, or output-size gates are missing or red, public composition output remains disabled/deferred instead of shipping a noisy or unsafe buyer-facing surface.

## Epic 1: Composition Contract Spine

Objective: create the single deterministic composition artifact and make its evidence and proposed control semantics contract-safe before any buyer or drift output depends on it.

### Story 1.1: Define the composed action-path model and bounded pattern engine

Priority: P0
Recommendation coverage: 1
Strategic direction: Build `composed_action_path` from existing action paths, workflow chains, graph refs, action classes, target classes, credentials, and resolution keys instead of spreading composition fields across parallel models.
Expected benefit: Wrkr can detect sensitive-read-to-egress, secret-to-network, code-to-deploy, workflow-mutation-to-production, and package-change-to-release paths before deployment while keeping static reachability distinct from observed execution.

Tasks:
- Add `risk.ComposedActionPath`, `CompositionStage`, `CompositionTransition`, `CompositionPattern`, and summary types in a new composition-focused risk file.
- Define stage roles as `source`, `transform`, `internal_sink`, `external_sink`, `privileged_sink`, and `destructive_sink`.
- Implement bounded deterministic patterns for sensitive-read-to-egress, secret-to-network, code-to-deploy, workflow-mutation-to-production, and package-change-to-release using existing `ActionPath`, workflow-chain, action class, credential, target class, mutable endpoint, and graph ref fields.
- Derive `composition_id` from pattern ID, ordered stage roles, member `resolution_key` values, target identity, and outcome class. Exclude volatile `path_id` from the durable ID.
- Include member `path_ids[]` and workflow-chain refs as references, not ID material.
- Sort candidates, stages, transitions, evidence refs, and output compositions deterministically.
- Deduplicate duplicate stage candidates and cap candidate expansion with explicit `unsupported_surfaces[]` or `truncated_candidates[]` when bounds are reached.
- Add `schemas/v1/composed-action-path.schema.json`.
- Add additive `composed_action_paths[]` and `composed_action_path_to_control_first` to `risk.Report` and risk report schema.
- Add changelog entry under `Added`.

Repo paths:
- `core/risk/composition.go`
- `core/risk/composition_test.go`
- `core/risk/action_paths.go`
- `core/risk/workflow_chain.go`
- `core/report/types.go`
- `schemas/v1/composed-action-path.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/README.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*Composition|Test.*ActionPath' -count=1`
- `go test ./core/report -run 'Test.*ComposedActionPath|Test.*Report' -count=1`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:
- TDD tests for each supported composition pattern.
- Reordered input and duplicate-stage tests proving stable IDs and output ordering.
- Negative tests for missing intermediates, unsupported surfaces, unknown stage roles, and non-consequential paths.
- Contract tests for schema validity and additive risk-report JSON fields.

Matrix wiring:
- Fast lane: focused `core/risk` and `core/report` tests plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make test-fast`.
- Acceptance lane: scenario coverage lands in Story 2.3.
- Cross-platform lane: pure deterministic Go and schema tests are platform-neutral.
- Risk lane: include in `make test-risk-lane` and `make test-perf` because composition affects public risk ranking and candidate expansion.
- Release/UAT lane: include in `make prepush-full` before release.

Acceptance criteria:
- Wrkr emits bounded possible compositions with explicit ordered stage roles and transition refs.
- Same input emits identical compositions and IDs across repeated runs, regardless of input ordering.
- Static reachability fields cannot be mistaken for observed execution.
- No new detector or source layer imports the composition model.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a deterministic `composed_action_path` artifact that identifies bounded multi-stage authority paths from existing action paths and workflow chains without claiming observed execution.
Semver marker override: [semver:minor]
Contract/API impact: Additive risk/report JSON fields and a new schema file; existing action-path fields remain compatible.
Versioning/migration impact: New optional v1 artifact; older saved states omit compositions and continue to load.
Architecture constraints: Risk layer owns composition derivation from normalized aggregation and action-path state; detection remains unaware of composition roles.
ADR required: yes
TDD first failing test(s): `TestBuildComposedActionPathsStableIDIgnoresPathIDChurn` and `TestBuildComposedActionPathsSensitiveReadToEgress`.
Cost/perf impact: medium
Chaos/failure hypothesis: Large repos with many candidate paths are bounded deterministically and emit an explicit truncation/unsupported-surface reason instead of timing out or producing nondeterministic ordering.

### Story 1.2: Reuse canonical evidence and enforcement coverage on composition stages

Priority: P0
Recommendation coverage: 4
Strategic direction: Project existing evidence state, freshness, policy coverage, Gait coverage, runtime absence, and contradictions onto every composition stage and transition.
Expected benefit: Buyers can distinguish statically inferred compositions from those backed by runtime decisions, approvals, credentials, outcomes, and proof verification without Wrkr overstating control.

Tasks:
- Add stage-level and transition-level fields for evidence state, freshness penalties, policy coverage status, Gait coverage, runtime evidence absence status, contradictions, evidence refs, proof refs, and source decision refs.
- Reuse `risk.EvidenceState*`, `evidencepolicy.FreshnessState*`, `risk.PolicyCoverageStatus*`, and `risk.GaitCoverage` values without creating composition-specific evidence enums.
- Add a conservative rollup function that selects the most restrictive stage/transition evidence and coverage state.
- Define `control_claim_state` values such as `static_only`, `partially_evidenced`, `declared_policy_only`, `runtime_controlled`, `observed_execution`, `contradictory`, and `unknown`, derived from existing fields.
- Require runtime enforcement coverage and outcome/proof evidence before a composition can be described as `runtime_controlled`.
- Attach missing evidence and closure requirements to compositions using existing closure/evidence completeness helpers.
- Add schema and docs updates explaining static, declared, runtime-controlled, and observed claims.
- Add changelog entry under `Changed`.

Repo paths:
- `core/risk/composition.go`
- `core/risk/evidence_state.go`
- `core/risk/evidence_context.go`
- `core/risk/gait_coverage.go`
- `core/risk/policy_coverage.go`
- `core/report/gait_coverage.go`
- `schemas/v1/composed-action-path.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `docs/commands/ingest.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*Composition.*Evidence|Test.*GaitCoverage|Test.*EvidenceCompleteness' -count=1`
- `go test ./core/report -run 'Test.*GaitCoverage|Test.*Composition' -count=1`
- `make test-contracts`
- `make test-risk-lane`
- `make test-fast`

Test requirements:
- Mixed stage evidence rollup tests for verified, declared, inferred, unknown, contradictory, stale, and expired evidence.
- Tests for declared policy without runtime enforcement, partial Gait coverage, stale approvals, missing outcomes, and contradictory evidence.
- Schema tests proving no composition-specific evidence enum is introduced.
- Golden report test proving claim wording does not say an inferred composition executed.

Matrix wiring:
- Fast lane: focused risk/report evidence tests.
- Core CI lane: `make test-contracts` and `make test-fast`.
- Acceptance lane: scenario coverage in Story 2.3.
- Cross-platform lane: deterministic JSON/schema tests on all platforms.
- Risk lane: `make test-risk-lane`, `make test-hardening`, and `make test-chaos`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Every composition explains what is verified, declared, inferred, stale, unknown, contradictory, or not collected.
- A composition is never described as controlled unless every consequential transition has sufficient runtime enforcement and required outcome/proof evidence.
- Existing evidence and Gait coverage vocabulary remains canonical.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Projected existing evidence state, freshness, policy coverage, and Gait coverage onto composed action-path stages so reports distinguish static reachability from runtime-proven control.
Semver marker override: [semver:minor]
Contract/API impact: Additive evidence and coverage fields on the new composition artifact.
Versioning/migration impact: No migration for existing action paths; composition rollups are absent for older saved states.
Architecture constraints: Evidence projection must consume existing evidence decisions and runtime sidecars; it must not bypass source precedence or freshness logic.
ADR required: yes
TDD first failing test(s): `TestCompositionCoverageDoesNotTreatDeclaredPolicyAsRuntimeControl`.
Cost/perf impact: low
Chaos/failure hypothesis: Contradictory or stale runtime evidence forces conservative composition rollups rather than allowing report wording to imply control.

### Story 1.3: Add Proposed Action Contract V2

Priority: P0
Recommendation coverage: 2
Strategic direction: Extend the current action contract projection into a versioned, machine-consumable proposed contract linked to compositions while preserving Wrkr's non-authoritative runtime role.
Expected benefit: Teams can convert discovered composition risk into Gait controls without manually interpreting report prose or making Wrkr responsible for runtime policy.

Tasks:
- Add `risk.ProposedActionContract` with `contract_id`, `contract_family_id`, `contract_content_digest`, `contract_version`, `contract_kind`, `composition_ref`, `resolution_key`, `allowed_transitions`, `prohibited_transitions`, `approval_required_transitions`, `target_constraints`, `required_credential_mode`, `maximum_delegation_depth`, `evidence_requirements`, `acceptable_countersigners`, `expected_outcome_class`, `compensation_required`, `expires_at`, `source_digests`, `report_only`, `readiness_state`, and reason codes.
- Derive `contract_family_id` from composition ID, target identity, and stable control intent, then derive `contract_id` and `contract_content_digest` from all semantically meaningful contract fields, including transitions, target constraints, credential mode, delegation depth, evidence requirements, countersigners, outcome class, compensation requirement, expiry, source digests, report-only posture, readiness state, and contract version.
- Keep `report_only: true` for Wrkr-produced contracts.
- Add `schemas/v1/proposed-action-contract.schema.json`.
- Add additive `proposed_action_contract` on compositions, action paths, Agent Action BOM primary view, and report JSON where deterministically available.
- Preserve `recommended_action_contract` as a compatibility projection or alias during migration; document the preferred proposed contract name.
- Add contradictory evidence and incomplete correlation states that block `ready_for_report_only`.
- Add docs, schema README, compatibility matrix, and changelog updates.

Repo paths:
- `core/risk/agentic_projection.go`
- `core/risk/composition.go`
- `core/risk/proposed_action_contract.go`
- `core/risk/agentic_projection_test.go`
- `core/report/agent_action_bom.go`
- `core/report/primary_view.go`
- `core/report/render_markdown.go`
- `schemas/v1/proposed-action-contract.schema.json`
- `schemas/v1/composed-action-path.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/contracts/compatibility_matrix.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*ProposedActionContract|Test.*RecommendedActionContract' -count=1`
- `go test ./core/report -run 'Test.*ProposedActionContract|Test.*PrimaryView|Test.*Markdown' -count=1`
- `make test-contracts`
- `make test-docs-consistency`
- `make test-fast`

Test requirements:
- Stable generation and stable digest tests.
- Schema compatibility tests for both `proposed_action_contract` and existing `recommended_action_contract`.
- Tests for contradictory evidence, incomplete correlation, standing credentials, prohibited transitions, countersignature requirements, expiry, and report-only flag.
- Markdown tests proving wording says "Proposed Action Contract" and does not imply Wrkr enforcement.

Matrix wiring:
- Fast lane: focused risk/report tests and docs consistency.
- Core CI lane: `make test-contracts`, `make test-fast`.
- Acceptance lane: scenario coverage in Story 2.3.
- Cross-platform lane: deterministic schema and report tests.
- Risk lane: `make test-risk-lane`, `make test-hardening`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Gait can validate the proposed contract shape without parsing prose or re-running Wrkr discovery/composition logic.
- Wrkr output and docs consistently call the new object a proposed Action Contract.
- Existing `recommended_action_contract` consumers are not broken.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a report-only proposed Action Contract schema that links composed action paths to allowed, prohibited, approval-required, credential, evidence, outcome, and expiry requirements for downstream control systems.
Semver marker override: [semver:minor]
Contract/API impact: Additive JSON/schema fields and migration wording from recommended to proposed contract naming.
Versioning/migration impact: Proposed contract v2 is optional; legacy `recommended_action_contract` remains available during the compatibility window.
Architecture constraints: Risk derives contract proposals; Gait owns runtime enforcement semantics.
ADR required: yes
TDD first failing test(s): `TestProposedActionContractIncludesCompositionTransitionsAndReportOnly`.
Cost/perf impact: low
Chaos/failure hypothesis: Incomplete correlation or contradictory evidence yields a blocked/not-ready proposed contract instead of an enforceable-looking contract.

## Epic 2: Cross-Product Correlation and Buyer Output

Objective: make composition artifacts easy for Gait, Axym, and buyers to consume without heuristic matching or broad report spelunking.

### Story 2.1: Add explicit cross-product composition correlation refs

Priority: P0
Recommendation coverage: 3
Strategic direction: Extend the existing stable correlation model to compositions, proposed contracts, decision traces, proof map output, and evidence bundle exports.
Expected benefit: Discovery, policy, approval, credential, outcome, and evidence records remain joinable across rescans and products even when path instance IDs churn.

Tasks:
- Add `resolution_key`, `composition_ids`, `proposed_action_contract_ref`, `workflow_chain_refs`, `autonomy_tier`, `recommended_control`, `evidence_states`, and relevant Gait coverage summaries to decision-trace events and schema.
- Add composition refs to proof map and evidence bundle exports without duplicating proof content.
- Add mapping helpers that join action paths, compositions, workflow chains, proposed contracts, and decision traces by explicit refs.
- Backfill refs into `AgentActionBOMItem`, `AgentActionBOMPrimaryView`, and risk report summaries where saved state has the required data.
- Preserve existing IDs and make all new fields additive.
- Add redaction tests for public/customer-redacted share profiles.
- Update docs and compatibility matrix.
- Add changelog entry under `Added`.

Repo paths:
- `core/proofmap/proofmap.go`
- `core/proofmap/proofmap_test.go`
- `core/proofemit/proofemit.go`
- `core/report/build.go`
- `core/report/agent_action_bom.go`
- `core/report/primary_view.go`
- `core/report/artifacts.go`
- `schemas/v1/proof-outputs/decision-trace-record.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/contracts/compatibility_matrix.md`
- `docs/commands/evidence.md`
- `docs/commands/ingest.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/proofmap ./core/proofemit -run 'Test.*DecisionTrace|Test.*Composition|Test.*ProofMap' -count=1`
- `go test ./core/report -run 'Test.*DecisionTrace|Test.*CompositionRefs|Test.*Redaction' -count=1`
- `make test-contracts`
- `make test-risk-lane`
- `make test-fast`

Test requirements:
- Path-ID churn tests proving `resolution_key` and composition refs survive harmless instance changes.
- Tests for missing references, additive schema compatibility, redaction, and downstream fixture consumption.
- Golden evidence bundle tests proving refs are deterministic and sorted.

Matrix wiring:
- Fast lane: focused proofmap, proofemit, and report tests.
- Core CI lane: contracts plus `make test-fast`.
- Acceptance lane: cross-product fixture coverage in Story 2.3.
- Cross-platform lane: JSON and file-output tests on all platforms.
- Risk lane: `make test-risk-lane`, `make test-hardening`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Gait and Axym can join compositions and proposed contracts through explicit references without heuristic matching.
- New correlation fields are additive and redacted appropriately in shareable outputs.
- Decision trace refs point to the relevant composition and proposed contract when available.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added explicit composition, proposed contract, workflow-chain, and resolution-key references to decision traces and evidence exports for stable Gait and Axym correlation.
Semver marker override: [semver:minor]
Contract/API impact: Additive proof-output, report, evidence, and schema fields.
Versioning/migration impact: Older decision traces remain valid; new fields are optional and populated when composition data exists.
Architecture constraints: Proof/evidence layers reference derived artifacts but do not recompute risk or composition logic.
ADR required: no
TDD first failing test(s): `TestDecisionTraceCarriesCompositionAndProposedContractRefs`.
Cost/perf impact: low
Chaos/failure hypothesis: Missing composition refs leave explicit absent fields or reasons instead of causing proof/evidence export failure.

### Story 2.2: Lead buyer output with the highest-risk composition

Priority: P0
Recommendation coverage: 5
Strategic direction: Make the focused Agent Action BOM and Markdown report lead with one consequential composition, affected asset, authority, control gap, proposed Action Contract, and closure requirements.
Expected benefit: A platform or security leader can understand the most important agent action path and required control in a few minutes.

Tasks:
- Extend `AgentActionBOMPrimaryView` with `composition_id`, ordered stage map, credential/delegation/target summary, current coverage, proposed control, expected outcome, and closure requirements.
- Select the default primary composition by risk tier, recommended control severity, production/customer impact, evidence gaps, runtime coverage gap, and deterministic tie-breakers.
- Update Markdown rendering to show the primary composition before broad path listings or appendices.
- Keep stage/path detail bounded in default output and move full stage evidence to appendices or JSON.
- Add report JSON and Markdown golden tests for long values, unknown stages, redaction, and bounded output.
- Update docs and examples to make composition-first Agent Action BOM the design-partner path.
- Add changelog entry under `Changed`.

Repo paths:
- `core/report/agent_action_bom.go`
- `core/report/primary_view.go`
- `core/report/render_markdown.go`
- `core/report/render_markdown_test.go`
- `core/report/primary_view_test.go`
- `docs/commands/report.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/report -run 'Test.*PrimaryView|Test.*Composed|Test.*Markdown|Test.*AgentActionBOM' -count=1`
- `go test ./core/cli -run 'TestReport.*AgentActionBOM|TestReport.*Focus' -count=1`
- `scripts/check_docs_cli_parity.sh`
- `make test-docs-consistency`
- `make test-contracts`
- `make test-fast`

Test requirements:
- Golden Markdown test proving the primary composition leads the buyer report.
- Stable ranking tests for composition selection and tie-breakers.
- Redaction tests for customer-redacted and public profiles.
- Bounds tests for long values, unknown stages, and composition grouping.

Matrix wiring:
- Fast lane: focused report and CLI tests plus docs parity.
- Core CI lane: `make test-contracts`, `make test-docs-consistency`, and `make test-fast`.
- Acceptance lane: scenario coverage in Story 2.3.
- Cross-platform lane: Markdown/JSON golden tests with newline normalization.
- Risk lane: `make test-risk-lane`, `make test-perf`.
- Release/UAT lane: `make prepush-full` and release smoke.

Acceptance criteria:
- The primary report directly answers which permitted capabilities compose into the most consequential authority path and what should govern it.
- Default buyer output stays bounded and does not become a broad graph appendix.
- Existing non-composition report paths remain compatible.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Updated Agent Action BOM reporting to lead with the highest-risk composed authority path, current evidence posture, control gap, and proposed Action Contract.
Semver marker override: [semver:minor]
Contract/API impact: Additive Agent Action BOM primary-view fields and report rendering changes.
Versioning/migration impact: Existing BOM consumers retain current fields; composition-first fields are optional.
Architecture constraints: Report selects and renders derived composition data; risk remains the source of composition ranking.
ADR required: no
TDD first failing test(s): `TestAgentActionBOMPrimaryViewSelectsHighestRiskComposition`.
Cost/perf impact: low
Chaos/failure hypothesis: Reports with no valid composition fall back to current primary action-path behavior and emit an explicit empty-state reason.

### Story 2.3: Add end-to-end composition contract fixtures

Priority: P0
Recommendation coverage: 6
Strategic direction: Treat cross-product composition contracts as release-level API surfaces with canonical scenario and schema fixtures.
Expected benefit: Wrkr cannot ship a composition, proposed contract, evidence requirement, or decision trace artifact that Gait cannot validate or Axym cannot correlate without tests failing.

Tasks:
- Add scenario fixture packs for sensitive read to external send, secret access to network call, workflow mutation to production deploy, package modification to release, standing credentials, incomplete outcomes, and controlled versus uncontrolled transitions.
- Add expected JSON goldens for `composed_action_paths`, proposed Action Contracts, Agent Action BOM primary view, decision traces, evidence refs, and regress baseline snapshots.
- Add schema-valid valid/invalid fixtures for `composed-action-path` and `proposed-action-contract`.
- Add scenario tests under `internal/scenarios` with deterministic fixture roots and no network calls.
- Add cross-product compatibility fixture docs that show expected Gait validation input and Axym correlation refs without implementing Gait/Axym behavior in this repo.
- Add redaction and absolute-path guards for all fixture outputs.
- Update `scenarios/README.md`, schema README, docs, and changelog.

Repo paths:
- `scenarios/wrkr/composed-action-paths/`
- `scenarios/cross-product/composed-action-contracts/`
- `internal/scenarios/composed_action_paths_scenario_test.go`
- `testinfra/contracts/`
- `schemas/v1/testdata/`
- `schemas/v1/composed-action-path.schema.json`
- `schemas/v1/proposed-action-contract.schema.json`
- `docs/contracts/compatibility_matrix.md`
- `scenarios/README.md`
- `CHANGELOG.md`

Run commands:
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario -run 'Test.*ComposedActionPath'`
- `go test ./testinfra/contracts -run 'Test.*Composed|Test.*ProposedActionContract' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-fast`

Test requirements:
- Byte-stable JSON fixtures for every canonical scenario.
- Schema validation tests for valid and invalid composition/contract examples.
- Stable identifier and expected recommendation tests.
- Redaction tests and downstream parsing smoke tests.

Matrix wiring:
- Fast lane: schema and contract fixture smoke tests.
- Core CI lane: `make test-contracts`, `make test-fast`.
- Acceptance lane: `make test-scenarios` and scenario-tagged tests.
- Cross-platform lane: fixture path normalization and JSON golden tests.
- Risk lane: `make test-risk-lane`, `make test-hardening`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Every canonical scenario emits deterministic composition, proposed Action Contract, decision trace refs, and expected evidence requirements.
- Fixture outputs contain no developer-specific absolute paths or secret values.
- Cross-product fixture docs make Gait/Axym expected refs explicit without adding their product logic to Wrkr.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added canonical composed action-path fixtures and contract tests covering sensitive egress, secret-to-network, deploy, release, standing credential, incomplete outcome, and controlled transition scenarios.
Semver marker override: [semver:minor]
Contract/API impact: Adds public compatibility fixtures and schema examples.
Versioning/migration impact: Existing scenarios remain unchanged; new fixtures are additive.
Architecture constraints: Scenario fixtures are specification artifacts; implementation tests must not redefine expected behavior.
ADR required: no
TDD first failing test(s): `TestComposedActionPathScenarioSensitiveReadToExternalSend`.
Cost/perf impact: medium
Chaos/failure hypothesis: Fixture validation fails closed when generated outputs drift from expected composition IDs, schema shape, redaction, or evidence refs.

## Epic 3: Composition Intelligence and Regression

Objective: build higher-order composition decisions only after the core artifact, evidence truth, and buyer output are stable.

### Story 3.1: Project delegated authority relationships inside compositions

Priority: P1
Recommendation coverage: 7
Strategic direction: Compare parent and child authority inside composed paths and report potential authority widening without claiming static evidence proves runtime token propagation.
Expected benefit: Security can find shared credentials, broader child targets, excessive delegation depth, and missing expiry evidence inside consequential compositions.

Tasks:
- Add delegation relationship fields to composition stages and transitions: `relationship`, `parent_authority_ref`, `child_authority_ref`, `scope_delta`, `target_delta`, `credential_delta`, `expiry_delta`, evidence refs, and reason codes.
- Classify relationships as `narrowed`, `equal`, `broadened`, `unknown`, or `contradictory`.
- Compare credential identity, issuer, scopes, access level, action classes, target classes, data classes, expiry, and delegation depth using existing credential authority bindings and workflow-chain dimensions.
- Feed broadened or contradictory delegation into proposed Action Contract evidence requirements and buyer output.
- Add docs and changelog updates.

Repo paths:
- `core/risk/composition.go`
- `core/risk/workflow_chain.go`
- `core/aggregate/agentresolver/workflow_chain.go`
- `core/aggregate/inventory/privileges.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/composed-action-path.schema.json`
- `schemas/v1/proposed-action-contract.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*DelegatedAuthority|Test.*Composition' -count=1`
- `go test ./core/aggregate/agentresolver -run 'Test.*WorkflowChain|Test.*Delegation' -count=1`
- `go test ./core/report -run 'Test.*Delegation|Test.*Composed' -count=1`
- `make test-contracts`
- `make test-risk-lane`
- `make test-fast`

Test requirements:
- Tests for narrowed scopes, equal shared credentials, broader targets, missing parent identity, multi-hop delegation, contradictions, and unknown runtime propagation.
- Schema tests for delegation relationship fields.
- Markdown tests proving static evidence wording is conservative.

Matrix wiring:
- Fast lane: focused risk, agentresolver, and report tests.
- Core CI lane: `make test-contracts`, `make test-fast`.
- Acceptance lane: extend composition scenarios where delegation relationships exist.
- Cross-platform lane: deterministic pure Go tests.
- Risk lane: `make test-risk-lane`, `make test-hardening`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Wrkr identifies potential delegation escalation while clearly stating static evidence cannot prove runtime token propagation.
- Broadened and contradictory relationships escalate evidence requirements and proposed contract readiness.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added delegated authority relationship projection for composed action paths so reports can identify narrowed, equal, broadened, unknown, and contradictory authority transitions.
Semver marker override: [semver:minor]
Contract/API impact: Additive composition and proposed contract fields.
Versioning/migration impact: Older compositions omit delegation relationship fields.
Architecture constraints: Risk compares normalized authority bindings; Gait remains responsible for runtime attenuation and revocation.
ADR required: no
TDD first failing test(s): `TestCompositionDelegationRelationshipDetectsBroadenedChildAuthority`.
Cost/perf impact: low
Chaos/failure hypothesis: Missing parent identity produces `unknown` with evidence requirements instead of a false broadened or narrowed claim.

### Story 3.2: Apply canonical control recommendations to complete compositions

Priority: P1
Recommendation coverage: 8
Strategic direction: Reuse the canonical recommendation enum and most-restrictive result across an entire composition instead of creating composition-specific verdicts.
Expected benefit: Buyers and Gait receive one recommended outcome and the exact transition that caused escalation.

Tasks:
- Add composition-level `recommended_control`, `recommended_control_reasons`, `escalating_transition_refs`, and `most_restrictive_source` fields.
- Combine autonomy tier, credential posture, source/sink boundary, evidence state, target consequence, delegation relationship, policy coverage, and Gait transition coverage.
- Preserve all contributing reason codes and transition refs.
- Keep `risk.RecommendedControl*` as the only recommendation enum.
- Update proposed Action Contract generation to use the composition recommendation.
- Add report, schema, docs, and changelog updates.

Repo paths:
- `core/risk/composition.go`
- `core/risk/govern_first_model.go`
- `core/risk/agentic_projection.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/composed-action-path.schema.json`
- `schemas/v1/proposed-action-contract.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*Composition.*Recommendation|Test.*RecommendedControl' -count=1`
- `go test ./core/aggregate/controlbacklog -run 'Test.*Composition|Test.*Recommendation|Test.*Control' -count=1`
- `go test ./core/report -run 'Test.*Composition.*Recommendation' -count=1`
- `make test-contracts`
- `make test-risk-lane`
- `make test-fast`

Test requirements:
- Most-restrictive selection tests for standing credentials, incomplete evidence, alternate routes, contradictory recommendations, and stable reason codes.
- Contract tests proving the canonical enum is reused.
- Report tests proving transition-level rationale is concise and bounded.

Matrix wiring:
- Fast lane: focused risk/controlbacklog/report tests.
- Core CI lane: `make test-contracts`, `make test-fast`.
- Acceptance lane: extend canonical scenarios with expected recommendations.
- Cross-platform lane: pure deterministic tests.
- Risk lane: `make test-risk-lane`, `make test-hardening`, `make test-perf`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Every supported composition receives one deterministic recommendation with transition-level rationale.
- The recommendation uses the existing enum and stable reason codes.
- Proposed Action Contracts and buyer output agree on the recommendation.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Applied canonical control recommendations across composed action paths with transition-level rationale and most-restrictive rollups.
Semver marker override: [semver:minor]
Contract/API impact: Additive recommendation fields on compositions and proposed contracts; no new recommendation enum.
Versioning/migration impact: Older composition-less reports continue to use action-path recommendations.
Architecture constraints: Composition recommendations must reuse existing risk/controlbacklog enums and not introduce Gait runtime verdicts.
ADR required: no
TDD first failing test(s): `TestCompositionRecommendationUsesMostRestrictiveTransition`.
Cost/perf impact: low
Chaos/failure hypothesis: Conflicting stage recommendations preserve all reasons and choose the safest deterministic recommendation instead of dropping a contributing risk.

### Story 3.3: Detect bounded equivalent outcomes and approval-evasion alternatives

Priority: P1
Recommendation coverage: 9
Strategic direction: Start with bounded outcome equivalence for deploy, external egress, privileged mutation, and release rather than building a generalized graph-query engine.
Expected benefit: Security can find uncontrolled alternatives to a protected path without grouping unrelated actions merely because they share a repo or tool family.

Tasks:
- Add `outcome_key` derivation from affected asset, target class, outcome class, environment, and authority identity.
- Add bounded equivalence matching for deploy, external egress, privileged mutation, and package/release outcomes.
- Compare equivalent compositions for materially different approval requirements, policy coverage, Gait coverage, credential mode, and evidence state.
- Emit `equivalent_outcome_refs[]`, `approval_evasion_signal`, `coverage_delta_reasons[]`, and `materiality` fields.
- Keep grouping deterministic and capped by outcome class and target identity.
- Add report, schema, docs, and changelog updates.

Repo paths:
- `core/risk/composition.go`
- `core/risk/action_lineage.go`
- `core/aggregate/attackpath/graph.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/composed-action-path.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*EquivalentOutcome|Test.*ApprovalEvasion|Test.*Composition' -count=1`
- `go test ./core/aggregate/controlbacklog -run 'Test.*EquivalentOutcome|Test.*Composition' -count=1`
- `go test ./core/report -run 'Test.*EquivalentOutcome|Test.*Composition' -count=1`
- `make test-contracts`
- `make test-risk-lane`
- `make test-fast`

Test requirements:
- Equivalent deploy route, multiple egress connector, direct-versus-workflow mutation, and multiple release mechanism tests.
- Negative tests for materially different outcomes, unknown targets, and unrelated shared repo/tool family matches.
- Stable ordering and output bounds tests.

Matrix wiring:
- Fast lane: focused risk/controlbacklog/report tests.
- Core CI lane: `make test-contracts`, `make test-fast`.
- Acceptance lane: extend scenarios for alternate route coverage.
- Cross-platform lane: deterministic pure Go/schema tests.
- Risk lane: `make test-risk-lane`, `make test-hardening`, `make test-perf`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Wrkr reports plausible approval-evasion paths with exact coverage deltas.
- Unrelated actions are not grouped merely by repo or tool family.
- Equivalent-outcome output remains bounded and deterministic.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added bounded equivalent-outcome signals for composed paths that can reach the same deploy, egress, privileged mutation, or release outcome with weaker controls.
Semver marker override: [semver:minor]
Contract/API impact: Additive composition fields and risk-report fields.
Versioning/migration impact: Older reports omit equivalent-outcome refs.
Architecture constraints: Bounded deterministic matching only; no arbitrary graph query engine.
ADR required: yes
TDD first failing test(s): `TestEquivalentOutcomeDoesNotGroupUnrelatedRepoActions`.
Cost/perf impact: medium
Chaos/failure hypothesis: Unknown target identity disables equivalence grouping and emits an explicit reason instead of over-grouping unrelated outcomes.

### Story 3.4: Extend regress to composition drift

Priority: P1
Recommendation coverage: 10
Strategic direction: Extend the existing action-path regress model instead of creating a separate composition lifecycle.
Expected benefit: Teams can block newly introduced dangerous compositions and reopened control gaps in CI even when individual findings appear unchanged.

Tasks:
- Add `CompositionState` snapshots with `composition_id`, pattern ID, member resolution keys, target identity, outcome key, risk, recommendation, evidence states, policy coverage, Gait coverage, delegation relationship, and equivalent-outcome refs.
- Compare baseline and current composition states by durable match key, not volatile path IDs.
- Emit drift categories for introduced, removed, changed members, newly introduced sinks, coverage degraded, evidence degraded, newly ungoverned, worsened recommendation, alternate route appeared, and outcome changed.
- Preserve existing action-path drift categories and exit `5`.
- Add focused report and Agent Action BOM drift summaries for compositions.
- Add CLI/docs/schema/changelog updates.

Repo paths:
- `core/regress/action_path_drift.go`
- `core/regress/composition_drift.go`
- `core/regress/composition_drift_test.go`
- `core/risk/composition.go`
- `core/report/types.go`
- `core/report/render_markdown.go`
- `core/cli/regress.go`
- `schemas/v1/regress/`
- `docs/commands/regress.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/regress -run 'Test.*CompositionDrift|Test.*ActionPathDrift' -count=1`
- `go test ./core/report -run 'Test.*Composition.*Drift|Test.*DriftReview' -count=1`
- `go test ./core/cli -run 'TestRegress.*Composition|TestRegress.*ExitCode' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-risk-lane`
- `make test-fast`

Test requirements:
- Harmless path-ID churn tests proving no false composition drift.
- Tests for member changes, newly introduced sinks, coverage degradation, stale evidence, alternate path appearance, removed compositions, and stable output.
- Backward-compatible baseline tests for states with no composition material.
- CLI exit-code tests preserving exit `5`.

Matrix wiring:
- Fast lane: focused regress/report/CLI tests.
- Core CI lane: `make test-contracts`, `make test-fast`.
- Acceptance lane: scenario drift fixture through `make test-scenarios`.
- Cross-platform lane: regress JSON and Markdown golden tests.
- Risk lane: `make test-risk-lane`, `make test-hardening`, `make test-chaos`, `make test-perf`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Wrkr deterministically detects meaningful composition drift without reporting harmless ordering or identifier changes as new risk.
- Composition drift is visible in regress JSON, buyer report drift review, and Agent Action BOM summaries.
- Baselines lacking compositions fail closed only when comparison is required and otherwise preserve existing action-path drift behavior.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added composition drift detection for introduced, changed, newly ungoverned, evidence-degraded, coverage-degraded, and alternate-route composed authority paths.
Semver marker override: [semver:minor]
Contract/API impact: Additive regress JSON/report fields; exit code contract remains unchanged.
Versioning/migration impact: Older baselines without compositions remain compatible and report composition comparison availability explicitly.
Architecture constraints: Regress compares normalized composition states and does not create an independent composition lifecycle.
ADR required: no
TDD first failing test(s): `TestCompositionDriftIgnoresPathIDChurnAndDetectsNewExternalSink`.
Cost/perf impact: medium
Chaos/failure hypothesis: Missing baseline composition data yields an explicit comparison status rather than silently comparing against an empty set.

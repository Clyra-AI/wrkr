# Adhoc Plan: Control Evidence State Model

Date: 2026-05-23
Profile: `wrkr`
Slug: `control-evidence-state-model`
Recommendation source: user-provided recommendations covering control resolution state, evidence confidence, buyer-safe language, target and action-path classification, consistency rules, negative-claim discipline, report QA, scan-quality summarization, and runtime evidence absence framing.

All paths in this plan are repo-relative. User-provided absolute checkout paths have been normalized to repo-relative paths. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, scenario, or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control loop. This plan must not implement Axym compliance-engine behavior, Gait runtime enforcement, scan-time LLM calls, live endpoint probing, or default network enrichment.
- Control findings must be evidence-scoped. Wrkr may say evidence was not found in scanned surfaces; it must not imply an enterprise control does not exist unless detector coverage and linked evidence support that absence claim.
- Canonical control resolution states are `detected_control`, `declared_control`, `external_control_reference`, `no_visible_control`, `not_applicable`, and `contradictory_control`.
- Canonical evidence confidence states are `verified`, `declared`, `inferred`, `unknown`, and `contradictory`. `verified` requires linked evidence refs, `declared` requires customer/provider metadata or sidecars, `inferred` requires deterministic weak signals, `unknown` means no evidence in covered inputs, and `contradictory` means conflicting signals.
- Canonical evidence-state fields are `approval_evidence_state`, `owner_evidence_state`, `proof_evidence_state`, `runtime_evidence_state`, `target_evidence_state`, and `credential_evidence_state`.
- Compatibility aliases may remain for one v1 transition where removal would break existing JSON users, but new report, backlog, schema, and markdown language must lead with evidence-state fields instead of `missing_*` terminology.
- Target classification values are `production_impacting`, `release_adjacent`, `customer_data_adjacent`, `internal_tooling`, `developer_productivity`, `test_demo_sandbox`, and `unknown`.
- Action path type values are `ai_assisted_workflow`, `agent_framework`, `automation_bot`, `ci_cd_workflow`, `legacy_script`, `plain_source_code`, and `unknown_executable_path`.
- Buyer-facing text must use centralized wording helpers so markdown, JSON summaries, backlog rows, closure guidance, redacted artifacts, and docs describe the same evidence state in the same way.
- Absence and "not found" claims require coverage status. Canonical absence statuses are `not_found_with_complete_coverage`, `not_found_with_reduced_coverage`, `not_scanned`, `unsupported_surface`, and `candidate_parse_failed`.
- Runtime evidence absence is not a finding by itself in static-only scans. Canonical runtime absence statuses are `not_collected`, `not_applicable`, `missing_required`, and `missing_for_control_claim`.
- Deterministic ordering, stable IDs, proof-chain integrity, no-secret serialization, local-first operation, and the existing exit-code contract remain non-negotiable.
- Changelog entries are required for implementation PRs because this work changes public report JSON, schemas, markdown wording, docs, risk semantics, and buyer-facing trust language.

## Current Baseline (Observed)

- `core/risk/action_paths.go` already defines `ActionPathSummary` counters such as `MissingApprovalPaths`, `MissingPolicyPaths`, `MissingProofPaths`, `UnresolvedOwnerPaths`, and confidence-lane counters. `ActionPath` carries `ApprovalGap`, `PolicyMissingReasons`, `GaitCoverage`, `ControlState`, `RiskTier`, `ReviewBurden`, and `ConfidenceLane`, but not first-class control resolution or evidence confidence fields.
- `core/risk/buyer_projection.go` already projects confidence lanes, `control_state`, `risk_zone`, `review_burden`, `control_priority`, `risk_tier`, and empty-state eligibility. It still derives blocker reasons with `missing_approval_paths_present`, `missing_policy_paths_present`, `missing_proof_paths_present`, `approval_gap:true`, `proof_gap:true`, and can emit `safe_by_default` for controlled paths when current policy/proof predicates do not fire.
- `core/aggregate/controlbacklog/controlbacklog.go` emits backlog items with owner state, approval status, evidence gaps, `control_state`, queue, remediation, confidence, and policy missing reasons. It still exposes labels such as `SecretOwnerMissing`, `SecretRotationEvidenceMissing`, `ApprovalStatus`, and `EvidenceGaps` without the proposed evidence-state model.
- `core/report/agent_action_bom.go` emits Agent Action BOM summary fields such as `missing_approval_items`, `missing_policy_items`, `missing_proof_items`, `runtime_proven_items`, and `unresolved_owner_items`. BOM items carry `approval_gap`, `policy_status`, `proof_coverage`, `runtime_evidence_status`, `control_state`, `queue`, `risk_tier`, and `remediation`, but not the canonical evidence-state or control-resolution fields.
- `core/report/render_markdown.go` currently renders buyer-visible phrases and counters including `missing_approval`, `missing_policy`, `missing_proof`, `Ownerless exposure`, `proof=missing`, and full detector-level scan-quality rows inline.
- `core/report/control_proof.go` and report proof coverage helpers currently treat path-specific proof coverage as `covered`, `missing`, or `chain_attached`, which is useful but too blunt for static-only and externally controlled paths.
- `core/attribution/provider_metadata.go` already loads deterministic provider sidecars from `.wrkr/provenance/source-metadata.json`, `.wrkr/provenance/github-event.json`, and `.wrkr/provenance/gitlab-event.json`. It is a natural place to extend declared and external-control metadata without adding network calls.
- `core/detect/workflowcap/analyze.go` parses GitHub workflow YAML with `gopkg.in/yaml.v3` and extracts deployment environments, approval source, proof requirements, headless execution, dangerous flags, and secret access. These are good inputs for declared or detected controls, target class, and action path type.
- `core/detect/openapi/detector.go` and `core/detect/routes/detector.go` already detect mutable endpoint semantics from OpenAPI and source route declarations. `core/risk/mutable_endpoint.go` maps those semantics to risk-zone behavior but does not expose the proposed target class enum.
- `core/aggregate/agentresolver/resolver.go` resolves bound tools, data sources, auth surfaces, and missing bindings from inventory-bearing findings. It still assumes "agent" framing for the resolver boundary and does not produce the proposed action path type enum.
- `core/detect/dependency/detector.go` already avoids promoting dependency-only evidence into source-level agent framework findings in tests. This supports the new action-path type discipline that dependency-only signals should not be called agents.
- `core/aggregate/scanquality/scanquality.go` emits detector statuses `complete`, `partial`, `reduced`, and `blocked` with coverage reasons, parse failures, unsupported declarations, and suppressed generated files. It does not yet expose absence claim statuses such as `not_found_with_complete_coverage` or a compact buyer summary.
- `core/ingest/ingest.go` uses runtime correlation statuses `matched`, `unmatched`, `stale`, and `conflict`. `core/risk/gait_coverage.go` uses `present`, `missing`, `stale`, `conflict`, and `not_applicable`. Neither model distinguishes static-only `not_collected` from `missing_required`.
- Schemas under `schemas/v1` already validate Agent Action BOM, report summary, risk report, findings, evidence bundles, policy configs, and proof outputs. They will need additive fields and, where compatibility aliases remain, explicit deprecation notes.
- Existing scenario and acceptance tests cover ownership quality, action-path control-first projection, Agent Action BOM, buyer action registry hardening, mutable endpoints, workflow capabilities, MCP action surfaces, report PDF acceptance, and v1 acceptance. They provide the outside-in harness for this plan.

## Exit Criteria

- Every risky action path, BOM item, control backlog item, report summary, risk report path, and relevant schema carries control resolution state and evidence confidence fields for approval, owner, proof, runtime, target, and credential evidence.
- Report and backlog terminology leads with evidence-state language. Blunt aliases such as `missing_approval_paths`, `missing_policy_paths`, and `missing_proof_paths` are either compatibility-only, deprecated in schemas/docs, or replaced by canonical evidence-state counters.
- Buyer-facing Markdown, JSON summaries, closure guidance, remediation, redacted artifacts, and docs no longer overclaim controls as absent when Wrkr only lacks scanned evidence.
- Control resolution consumes deterministic evidence from scanned artifacts, provider metadata sidecars, customer declarations, external references, inferred signals, runtime evidence sidecars, proof coverage, ownership signals, policy files, and contradiction checks.
- Target class and action path type are first-class additive fields on action paths, Agent Action BOM items, control backlog items, risk reports, report summaries where useful, and schemas.
- `control_state`, evidence states, `control_priority`, queue, `review_burden`, `risk_tier`, and remediation are semantically consistent by deterministic tests. Critical review burden cannot quietly route to inventory hygiene or safe-by-default language.
- Absence claims for MCP, WebMCP, dependency, workflow, route, OpenAPI, runtime, and proof surfaces include coverage status and do not say "none found" unless complete coverage supports that claim.
- Buyer-facing reports show compact scan coverage confidence, reduced detector count, parse-failure count, suppressed generated-file count, and an impact statement, while detector-level details move to appendix or evidence JSON.
- Static-only runtime evidence is rendered as `not_collected` or `not_applicable` unless runtime evidence was required or used to substantiate a control claim.
- Generated-report QA tests or a report linter fail on risky phrases such as "approval missing", "owner missing", "no approval", "uncontrolled", "not governed", and unsupported "agent" labels unless verified absence and path type evidence support the wording.
- Docs and changelog entries ship with implementation PRs, including user-facing command docs under `docs/commands`, schema docs under `schemas/v1`, and trust/detection coverage docs where absence semantics change.

## Public API and Contract Map

- CLI contracts:
  - Preserve existing exit codes: `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, and `8` unsafe operation blocked.
  - `wrkr scan --json`, `wrkr report --json`, `wrkr report --md`, `wrkr mcp-list --json`, `wrkr score --json`, and evidence bundle outputs remain deterministic from the same saved state.
  - Any new flags for customer declarations or external-control sidecars must be opt-in, local-file based, structured, validated, and fail closed on invalid input with exit `6`.
- JSON and schema contracts:
  - Additive fields include `control_resolution_state`, `control_resolution_reasons`, `control_evidence_refs`, `approval_evidence_state`, `owner_evidence_state`, `proof_evidence_state`, `runtime_evidence_state`, `target_evidence_state`, `credential_evidence_state`, `target_class`, `target_class_reasons`, `target_class_evidence_refs`, `action_path_type`, `action_path_type_reasons`, and absence coverage fields where relevant.
  - Compatibility aliases may retain existing `missing_approval_*`, `missing_policy_*`, `missing_proof_*`, `approval_gap`, and `policy_missing_reasons` fields for v1 consumers. New code must calculate aliases from the canonical evidence-state projection, not maintain parallel logic.
  - Schemas impacted include `schemas/v1/agent-action-bom.schema.json`, `schemas/v1/report/report-summary.schema.json`, `schemas/v1/risk/risk-report.schema.json`, `schemas/v1/findings/finding.schema.json`, `schemas/v1/evidence/evidence-bundle.schema.json`, and any control-path or inventory schemas that serialize the new states.
- Detection contracts:
  - Structured parsers remain mandatory for YAML, JSON, TOML, OpenAPI, package manifests, workflow files, and policy declarations wherever feasible.
  - Detector outputs may carry control and target evidence refs, but must not extract raw secret values or require default network access.
  - Dependency-only and plain-source signals must not be promoted to agentic action paths without executable binding, framework, workflow, MCP/tool binding, bot identity, or script-entrypoint evidence.
- Risk and aggregation contracts:
  - `core/risk` owns canonical projection and consistency rules for control resolution, evidence states, target class, action path type, control state, risk tier, review burden, and recommended action.
  - `core/aggregate/controlbacklog` and report builders consume this projection instead of re-deriving contradictory summaries.
  - Ambiguous high-risk conditions continue to fail closed or route to evidence-required review rather than clean-state language.
- Proof and runtime contracts:
  - Proof record types remain consistent with Wrkr and `Clyra-AI/proof` primitives: `scan_finding`, `risk_assessment`, `approval`, and `lifecycle_transition`.
  - Static proof and runtime evidence absence must be represented as evidence state, not as proof that an external control is absent.
  - Chain integrity, proof verification, and artifact portability are preserved.
- Documentation contracts:
  - User-facing docs explain the distinction between detected, declared, externally referenced, inferred, unknown, contradictory, not collected, and not applicable evidence.
  - Docs must show examples using profile commands from the `wrkr` profile, such as `wrkr scan --json`, `wrkr regress run --baseline <baseline-path> --json`, and `wrkr score --json`.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/mcp-list.md`
  - `docs/commands/evidence.md`
  - `docs/commands/ingest.md`
  - `docs/trust/detection-coverage-matrix.md`
  - `docs/trust/contracts-and-schemas.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Contract and scenario docs impacted:
  - `internal/scenarios/coverage_map.json`
  - relevant scenario fixture READMEs under `scenarios/wrkr/**`
  - report and acceptance test expectations under `internal/acceptance`
- OSS trust baseline:
  - No generated customer reports, local scan output, runtime evidence bundles, proof chains, credentials, private repo paths, or transient state files should be committed outside deterministic test fixtures.
  - Example metadata sidecars and declarations must use fake owners, fake provider URLs, fake repo names, fake tickets, and no real service credentials.
  - Public docs must say Wrkr reports static evidence and optional local sidecars; it does not assert enterprise controls are absent across GitHub branch protection, GitHub teams, deployment environments, ServiceNow, Jira, app catalogs, or customer mappings unless those sources were provided and verified.
- Docs must answer:
  - What each control resolution and evidence confidence state means.
  - Why `verified`, `declared`, `inferred`, `unknown`, and `contradictory` are different.
  - How static-only scans frame runtime evidence as `not_collected` rather than "missing".
  - When "not found" is credible and when it is only a reduced-coverage statement.
  - Why Wrkr says "action path" by default and reserves "agent" for evidenced agentic paths.

## Recommendation Traceability

| Recommendation / Finding | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| Control resolution and evidence-state model | P0 | Stories 1.1, 1.2 | Current output can imply approval, owner, or proof is absent when only local evidence is absent. | Add canonical control resolution and evidence confidence fields from scanned, declared, external, inferred, and contradictory signals. | Buyer-safe control posture with less false certainty. |
| Contract cleanup and terminology migration | P0 | Story 1.2 | `missing_*` fields conflict with evidence-state semantics. | Make evidence-state fields canonical and aliases compatibility-only. | Cleaner schemas and safer integration contracts. |
| Buyer-safe control language | P0 | Stories 1.3, 5.1 | Markdown and backlog text still overstate gaps. | Centralize wording and report QA. | Consistent, evidence-bounded buyer reports. |
| Target classification model | P1 | Story 2.1 | Internal tooling should not rank like production release paths. | Derive target class from policies, CI/CD environments, endpoints, package publish signals, metadata, and naming. | Better prioritization and lower noise. |
| Action path type classification | P1 | Story 2.2 | Not every path is an agent. | Classify path type from provenance, workflow, framework, bot, script, dependency, and executable-binding evidence. | More accurate report language and fewer agent overclaims. |
| Control state consistency cleanup | P0 | Story 3.1 | Current combinations can say safe-by-default while also demanding critical review. | Add deterministic consistency rules across state, queue, risk tier, review burden, and remediation. | Predictable remediation and fewer contradictory artifacts. |
| Negative claim discipline | P0 | Story 3.2 | "No MCP servers found" is only credible with complete coverage. | Add coverage-qualified absence statuses and enforce them in reports and CLI. | Credible absence claims and better audit posture. |
| Report QA gate for overclaiming | P0 | Story 5.1 | Overclaiming can regress through wording drift. | Add linter/tests for risky phrases and unsupported agent labels. | CI catches buyer-hostile language before release. |
| Buyer summary over raw scan quality noise | P1 | Story 4.1 | Detector-level rows are useful but too noisy for buyer Markdown. | Render compact coverage summary and move detail to appendix/evidence JSON. | More readable reports without hiding diagnostics. |
| Runtime evidence absence framing | P0 | Story 4.2 | Static-only scans should not imply runtime evidence is missing in the customer environment. | Add runtime absence statuses and render them calmly unless runtime evidence is required. | Accurate static posture narrative. |

## Test Matrix Wiring

- Fast lane:
  - Focused Go unit tests for projection helpers, evidence-state derivation, wording helpers, target classification, action path type classification, control-state consistency, absence statuses, runtime absence statuses, and markdown render snippets.
  - Candidate commands: `go test ./core/risk ./core/report ./core/aggregate/controlbacklog ./core/aggregate/scanquality -count=1`.
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `go test ./internal/acceptance -run 'Test.*Report|Test.*AgentActionBOM|Test.*Evidence|Test.*Overclaim' -count=1`
- Cross-platform lane:
  - Windows smoke must cover path normalization, sidecar loading, report Markdown, schema validation, and deterministic coverage summaries without POSIX-only assumptions.
- Risk lane:
  - `make test-hardening` for fail-closed invalid declarations, unsupported sidecars, contradictory evidence, unsafe external references, no-secret serialization, and overclaim phrase blocking.
  - `make test-chaos` for partial scans, parse failures, stale runtime sidecars, contradictory provider metadata, unreadable local declarations, and report artifact generation failures.
  - `make test-perf` if target/action-path classification or report QA materially changes scan/report runtime.
- Release/UAT lane:
  - `scripts/run_v1_acceptance.sh --mode=local`
  - `make test-release-smoke` when docs, schema examples, or release-facing report examples change.
- Gating rule:
  - Wave 1 is required before any buyer-language or schema cleanup PR ships.
  - Wave 2 is required before reports use target class or action path type in ranking and labels.
  - Wave 3 is required before absence claims or consistency rules become release-gating.
  - Wave 4 is required before buyer-facing Markdown hides detector details behind compact summaries.
  - Wave 5 is required before final docs and release notes claim overclaim protection.

## Minimum-Now Sequence

- Wave 1 - Evidence-state contracts and buyer language:
  - Story 1.1 adds canonical control resolution and evidence confidence projection.
  - Story 1.2 migrates contracts and terminology while preserving compatibility aliases.
  - Story 1.3 centralizes buyer-safe wording.
- Wave 2 - Classification:
  - Story 2.1 adds target classification.
  - Story 2.2 adds action path type classification and agent-label discipline.
- Wave 3 - Consistency and absence discipline:
  - Story 3.1 adds consistency rules across control state, queue, burden, tier, and remediation.
  - Story 3.2 adds coverage-qualified absence statuses for negative claims.
- Wave 4 - Report readability and runtime framing:
  - Story 4.1 replaces inline scan-quality noise with compact coverage summaries.
  - Story 4.2 reframes runtime evidence absence for static-only scans.
- Wave 5 - Guardrails, scenarios, and docs:
  - Story 5.1 adds report QA gates and outside-in scenarios.
  - Story 5.2 updates docs, schema guidance, and changelog entries.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No Axym product logic, Gait runtime enforcement, or runtime interception in Wrkr.
- No scan-time LLM calls, model-generated findings, default telemetry, live endpoint probing, or default provider/API enrichment.
- No extraction, hashing, display, or persistence of raw secret values.
- No incompatible removal of existing v1 fields without an explicit versioned migration and compatibility period.
- No claim that external enterprise controls are absent unless verified inputs and coverage support the claim.
- No promotion of dependency-only, docs-only, prompt-only, or plain-source evidence to "agent" language without executable or agentic evidence.
- No generated reports, proof chains, runtime sidecars, local state, binaries, or private fixture data committed outside approved deterministic test fixtures.
- No branch-protection, CI, schema validation, proof verification, or exit-code bypass.

## Definition of Done

- Every story starts with failing tests or scenario fixtures that encode the intended evidence-state behavior.
- New public fields are additive, schema-validated, documented, and deterministic.
- Compatibility aliases are derived from canonical evidence-state projection and documented as aliases, not independent truth.
- Buyer-facing text is generated through shared wording helpers and cannot regress to unsupported "missing", "uncontrolled", or "not governed" claims without failing tests.
- Target class and action path type are stable, reason-coded, and evidence-ref backed.
- Runtime absence, proof absence, control absence, owner uncertainty, and negative scan claims are coverage-qualified.
- No raw secret values, local developer roots, or customer identifiers appear in fixtures, reports, docs examples, or test goldens.
- Final implementation PRs record exact validation commands and results for focused tests, `make lint-fast`, `make test-fast`, `make test-contracts`, scenarios, docs checks, and required risk lanes.

## Stories

### Story 1.1: Canonical Control Resolution And Evidence Confidence Projection

Priority: P0

Tasks:

- Add canonical enum constants and validation helpers in `core/risk` for control resolution states and evidence confidence states.
- Extend `risk.ActionPath` with `ControlResolutionState`, `ControlResolutionReasons`, `ControlEvidenceRefs`, and canonical evidence-state fields for approval, owner, proof, runtime, target, and credential evidence.
- Build a deterministic resolver that combines scanned governance controls, `ApprovalGapReasons`, ownership state, policy refs, proof coverage, runtime correlations, credential authority, provider metadata sidecars, customer declarations, external references, inferred signals, and contradiction checks.
- Extend `core/attribution/provider_metadata.go` or an adjacent attribution module to parse local declaration and external-control sidecars using structured JSON with stable sorting and no network access.
- Use `verified` only when linked evidence refs exist, `declared` for sidecar/customer/provider metadata, `inferred` for weak deterministic signals, `unknown` for no covered evidence, and `contradictory` for conflicts.
- Route Agent Action BOM items, control backlog items, and risk summaries through the canonical projection instead of independently deriving approval, owner, proof, runtime, target, and credential state.
- Add additive schema fields and examples under `schemas/v1`.
- Update `CHANGELOG.md` with an operator-facing entry for evidence-state control resolution.

Repo paths:

- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/control_proof.go`
- `core/attribution/provider_metadata.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report ./core/attribution -run 'Test.*EvidenceState|Test.*ControlResolution|Test.*Contradictory|Test.*ProviderMetadata' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make prepush-full`

Test requirements:

- Unit tests for each control resolution and evidence confidence state.
- Contract tests proving additive JSON fields validate and aliases are derived from canonical states.
- Hardening tests for invalid sidecars, contradictory controls, malformed external references, and no-secret serialization.
- Determinism tests proving stable sort/order and byte-stable summaries for repeated runs.

Matrix wiring:

- Fast lane: focused `core/risk`, `core/report`, `controlbacklog`, and `attribution` tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixture with detected, declared, external, inferred, unknown, and contradictory controls.
- Cross-platform lane: sidecar path normalization and JSON ordering on Windows.
- Risk lane: `make test-hardening` and `make test-chaos` for invalid and contradictory evidence.

Acceptance criteria:

- Every risky action path has populated control resolution and evidence-state fields.
- `verified` is impossible without at least one evidence ref.
- Contradictory owner, approval, proof, runtime, target, or credential signals produce `contradictory` or `contradictory_control`.
- BOM, backlog, markdown, risk report, and schemas agree on the same canonical states.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added canonical control resolution and evidence confidence fields for action paths, reports, backlog items, and v1 schemas so control gaps are evidence-scoped instead of inferred from local absence.
Semver marker override: [semver:minor]
Contract/API impact: Additive JSON/schema fields; existing `missing_*` fields remain compatibility aliases until a later versioned migration.
Versioning/migration impact: v1 additive migration with documented aliases and no field removals.
Architecture constraints: Preserve Risk as the owner of canonical projection; Attribution may load local sidecars; Aggregation and Report consume projections without re-deriving semantics.
ADR required: yes
TDD first failing test(s): `TestControlResolutionStateVerifiedRequiresEvidenceRef`, `TestEvidenceStateContradictoryOwnerSignals`, `TestAgentActionBOMCarriesCanonicalEvidenceStates`.
Cost/perf impact: low
Chaos/failure hypothesis: Malformed sidecars, unreadable declaration files, and contradictory provider metadata fail closed to `unknown` or `contradictory` without crashing report generation.

### Story 1.2: Contract Cleanup And Evidence-State Terminology Migration

Priority: P0

Tasks:

- Replace primary internal/report references to `missing_approval_paths`, `missing_policy_paths`, `missing_proof_paths`, `missing_approval_items`, `missing_policy_items`, and `missing_proof_items` with evidence-state counters and reason-coded summaries.
- Keep compatibility aliases only where existing v1 schemas or tests prove downstream users depend on them; mark aliases in schema descriptions and docs.
- Derive alias values from canonical states such as `approval_evidence_state == unknown`, `proof_evidence_state == unknown`, and `runtime_evidence_state == missing_required` instead of maintaining parallel booleans.
- Rename buyer-visible `approval_gap`, `policy_missing_reasons`, and `proof_coverage:missing` wording to evidence-state wording while preserving machine-readable legacy fields as needed.
- Update report summary schemas, Agent Action BOM schemas, risk-report schemas, and command docs to describe canonical fields first.
- Add tests that fail when new public schemas introduce blunt "missing control" terminology without an evidence-state companion.

Repo paths:

- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/render_markdown.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `docs/commands/score.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/report ./core/aggregate/controlbacklog -run 'Test.*EvidenceStateAlias|Test.*MissingTerminology|Test.*ReportSummary' -count=1`
- `make test-contracts`
- `make test-docs-consistency`
- `make prepush-full`

Test requirements:

- Contract tests for compatibility aliases and canonical field precedence.
- Schema tests confirming descriptions do not make unsupported negative claims.
- Markdown/report tests proving public headings and counters use evidence-state wording.

Matrix wiring:

- Fast lane: focused risk/report/controlbacklog tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: existing Agent Action BOM and report acceptance fixtures updated for canonical fields.
- Cross-platform lane: schema fixtures remain path-portable.
- Risk lane: hardening test for unknown evidence state not becoming a control absence claim.

Acceptance criteria:

- New code and docs use evidence-state terminology as canonical.
- Compatibility aliases, where retained, are documented and derived.
- Existing JSON consumers can still read legacy fields in v1 artifacts when compatibility is required.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed report and schema terminology to present approval, owner, proof, policy, runtime, target, and credential findings as evidence states rather than unsupported missing-control claims.
Semver marker override: [semver:minor]
Contract/API impact: Additive canonical fields plus compatibility alias descriptions; no unversioned removal.
Versioning/migration impact: v1 compatibility period for legacy field names.
Architecture constraints: Risk projection remains source of truth; schemas and report builders follow it.
ADR required: no
TDD first failing test(s): `TestMissingApprovalAliasDerivedFromApprovalEvidenceState`, `TestReportSummaryUsesEvidenceStateTerminology`.
Cost/perf impact: low
Chaos/failure hypothesis: Unknown or omitted evidence-state fields in older saved state are normalized deterministically without panic.

### Story 1.3: Centralized Buyer-Safe Control Language

Priority: P0

Tasks:

- Add a small report wording helper that maps control resolution, evidence states, runtime absence states, proof coverage, target class, and action path type to buyer-safe labels and remediation fragments.
- Replace handwritten Markdown, backlog, closure criteria, remediation, redacted artifact, and design-partner text with centralized wording.
- Use phrases such as "approval evidence not found", "owner evidence unknown", "path-specific proof not found", "runtime evidence not collected", and "external control reference declared" based on canonical state.
- Ensure "approval missing", "owner missing", "proof missing", "uncontrolled", and "not governed" do not appear in buyer-facing output unless a verified absence rule explicitly allows them.
- Update docs with terminology examples and clarify that absence is scoped to scanned/provided evidence.

Repo paths:

- `core/report/render_markdown.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/control_proof.go`
- `docs/commands/report.md`
- `docs/commands/export.md`
- `docs/commands/evidence.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/report ./core/aggregate/controlbacklog -run 'Test.*BuyerLanguage|Test.*Remediation|Test.*Closure|Test.*Redacted' -count=1`
- `make test-contracts`
- `make test-docs-consistency`

Test requirements:

- Golden markdown tests for each evidence state.
- Backlog row tests for closure criteria and remediation text.
- Redaction tests proving wording remains safe after owner/repo/path values are hidden.

Matrix wiring:

- Fast lane: report and backlog unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: report PDF/Markdown acceptance snapshot with buyer-safe language.
- Cross-platform lane: markdown wrapping and deterministic ordering on Windows.
- Risk lane: hardening check for risky phrase denial list.

Acceptance criteria:

- Buyer-visible artifacts use centralized language helpers.
- Static absence is scoped to evidence, never enterprise reality.
- Redacted artifacts preserve evidence-state meaning without leaking hidden values.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed buyer-facing report, backlog, and remediation wording to use evidence-scoped language for approval, ownership, proof, policy, runtime, target, and credential states.
Semver marker override: [semver:patch]
Contract/API impact: Markdown/backlog wording changes; JSON values follow Story 1.1 and Story 1.2.
Versioning/migration impact: No field removal; public prose and docs update.
Architecture constraints: Report wording helper consumes canonical state only; it must not perform detector or risk inference.
ADR required: no
TDD first failing test(s): `TestMarkdownApprovalUnknownUsesEvidenceNotFound`, `TestBacklogClosureDoesNotSayOwnerMissing`.
Cost/perf impact: low
Chaos/failure hypothesis: Empty or unknown state values render neutral fallback text and never panic.

### Story 2.1: Target Classification Model

Priority: P1

Tasks:

- Add target class enum constants, reason codes, and evidence refs in `core/risk`.
- Derive target class from production-target policy matches, CI/CD environments, deployment commands, package publish and release signals, route/OpenAPI mutable endpoint semantics, repo metadata, naming conventions, customer mappings, and source evidence.
- Extend workflow capability analysis to preserve environment and deployment evidence needed for target classification.
- Extend route and OpenAPI detectors to emit target classification evidence refs without claiming live reachability.
- Surface `target_class`, `target_class_reasons`, and `target_class_evidence_refs` in action paths, Agent Action BOM items, control backlog items, report summaries where useful, and schemas.
- Ensure internal tooling, developer productivity, test/demo/sandbox, release-adjacent, customer-data-adjacent, and production-impacting paths rank differently in govern-first projection.

Repo paths:

- `core/risk/mutable_endpoint.go`
- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/detect/workflowcap/analyze.go`
- `core/detect/routes/detector.go`
- `core/detect/openapi/detector.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/detect/workflowcap ./core/detect/routes ./core/detect/openapi ./core/report -run 'Test.*TargetClass|Test.*MutableEndpoint|Test.*WorkflowEnvironment' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:

- Unit table tests for all target class enum values.
- Detector tests proving OpenAPI/routes and workflows emit target evidence without live probing.
- Risk ranking tests proving internal tooling does not rank like production-impacting release paths.
- Scenario tests with mixed production, release, customer data, internal tooling, developer productivity, sandbox, and unknown targets.

Matrix wiring:

- Fast lane: risk and detector focused tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: multi-target scenario and Agent Action BOM acceptance.
- Cross-platform lane: environment/path classification without OS-specific separators.
- Risk lane: `make test-hardening` for ambiguous target mappings and fail-closed invalid customer mappings.

Acceptance criteria:

- Every relevant action path has a deterministic target class or `unknown`.
- Target class is reason-coded and evidence-ref backed.
- Buyer reports can distinguish internal tooling from production-impacting or customer-data-adjacent paths.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added target classification for action paths so reports distinguish production-impacting, release-adjacent, customer-data-adjacent, internal tooling, developer productivity, test/demo/sandbox, and unknown targets.
Semver marker override: [semver:minor]
Contract/API impact: Additive fields and schema enum values.
Versioning/migration impact: v1 additive; unknown default for older saved state.
Architecture constraints: Detection emits evidence; Risk classifies; Report renders; no detector should make buyer-language decisions.
ADR required: yes
TDD first failing test(s): `TestTargetClassInternalToolingDoesNotRankAsProduction`, `TestOpenAPITargetClassCustomerDataAdjacent`.
Cost/perf impact: low to medium
Chaos/failure hypothesis: Malformed target mappings and ambiguous route metadata fall back to `unknown` or weaker class without overclaiming production impact.

### Story 2.2: Action Path Type Classification And Agent Label Discipline

Priority: P1

Tasks:

- Add action path type enum constants, reason codes, and evidence refs in `core/risk`.
- Derive path type from detector provenance, workflow evidence, framework signals, agent configs, MCP/tool bindings, bot identities, script entrypoints, route/OpenAPI source evidence, and dependency-only signals.
- Update `core/aggregate/agentresolver/resolver.go` so action-path classification is not coupled to agent-only naming.
- Ensure dependency-only evidence can produce `agent_framework` only when framework and executable binding evidence support it; otherwise classify as `plain_source_code`, `developer_productivity`, or `unknown_executable_path` as appropriate.
- Update report/BOM labels to say "action path" by default and "agent" only when `action_path_type` supports agentic wording.
- Add schemas and docs for action path type.

Repo paths:

- `core/aggregate/agentresolver/resolver.go`
- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/detect/dependency/detector.go`
- `core/detect/workflowcap/analyze.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `CHANGELOG.md`

Run commands:

- `go test ./core/aggregate/agentresolver ./core/risk ./core/detect/dependency ./core/detect/workflowcap ./core/report -run 'Test.*ActionPathType|Test.*AgentLabel|Test.*DependencyOnly' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:

- Unit tests for each action path type enum value.
- Regression tests proving dependency-only AI package evidence does not create unsupported agent claims.
- Markdown/BOM tests proving labels switch between "action path", "AI-assisted workflow", "agent framework", and "automation bot" only when evidence supports them.

Matrix wiring:

- Fast lane: agentresolver, dependency, risk, and report focused tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: agent source frameworks and buyer action registry scenarios.
- Cross-platform lane: script entrypoint and path classification on Windows.
- Risk lane: report QA overclaim checks for unsupported "agent" wording.

Acceptance criteria:

- Every action path has an action path type or `unknown_executable_path`.
- Report text says "agent" only for evidenced agentic path types.
- Dependency-only signals remain review context unless executable or agentic evidence exists.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added action path type classification so reports distinguish AI-assisted workflows, agent frameworks, automation bots, CI/CD workflows, legacy scripts, plain source code, and unknown executable paths.
Semver marker override: [semver:minor]
Contract/API impact: Additive fields and schema enum values.
Versioning/migration impact: v1 additive; older saved state normalizes to `unknown_executable_path` where needed.
Architecture constraints: Detection provenance remains separate from Risk classification; Report must not infer agentic type from prose.
ADR required: yes
TDD first failing test(s): `TestDependencyOnlyFindingIsNotAgenticActionPath`, `TestReportAgentLabelRequiresAgenticPathType`.
Cost/perf impact: low
Chaos/failure hypothesis: Ambiguous source or dependency evidence degrades to non-agentic or unknown path type without changing exit codes.

### Story 3.1: Control State Consistency Rules

Priority: P0

Tasks:

- Define deterministic consistency rules between `control_state`, control resolution state, evidence states, `control_priority`, queue, `review_burden`, `risk_tier`, and remediation.
- Prevent `safe_by_default` from appearing on control-first paths unless the state is renamed or a reason-coded exception is introduced.
- Ensure `review_burden == critical` forces `approval_required`, `evidence_required`, or `block_recommended`, and a queue of `control_first` or equivalent fail-closed review path.
- Ensure contradictory control/evidence states cannot render clean remediation or low-risk tier.
- Route consistency corrections through `core/risk` projection so BOM, backlog, report markdown, and risk summaries agree.
- Add tests for current confusing combinations such as safe-by-default plus control-first plus critical review.

Repo paths:

- `core/risk/buyer_projection.go`
- `core/risk/govern_first.go`
- `core/risk/action_paths.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `schemas/v1/report/report-summary.schema.json`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report -run 'Test.*ControlStateConsistency|Test.*ReviewBurden|Test.*Queue|Test.*RiskTier' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make prepush-full`

Test requirements:

- Unit tests for all rule combinations.
- Contract tests proving serialized BOM/backlog/report agree.
- Hardening tests proving contradictory control states fail to clean-state language.

Matrix wiring:

- Fast lane: focused risk, report, and controlbacklog tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: control backlog governance and action path to control-first scenarios.
- Cross-platform lane: deterministic ordering of corrected reasons.
- Risk lane: `make test-hardening` and `make test-chaos` for inconsistent saved state.

Acceptance criteria:

- No serialized action path or BOM item contains semantically incompatible control state, queue, burden, tier, and remediation.
- Critical review burden always routes to required approval, required evidence, block, or equivalent fail-closed queue.
- Contradictory controls rank and render as review-needed, not clean.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Fixed control-state projection so review burden, queue, risk tier, remediation, and safe-by-default language stay semantically consistent for risky paths.
Semver marker override: [semver:patch]
Contract/API impact: Value semantics become stricter; fields remain compatible.
Versioning/migration impact: Saved state is normalized during projection; no stored migration required.
Architecture constraints: Consistency rules live in Risk projection and feed Aggregation/Report.
ADR required: no
TDD first failing test(s): `TestSafeByDefaultCannotBeControlFirstCritical`, `TestCriticalReviewBurdenForcesRequiredControlState`.
Cost/perf impact: low
Chaos/failure hypothesis: Corrupt or older saved state with inconsistent fields is corrected deterministically or marked evidence-required.

### Story 3.2: Coverage-Qualified Negative Claim Discipline

Priority: P0

Tasks:

- Add absence status enum constants and derivation helpers in `core/aggregate/scanquality`.
- Emit `not_found_with_complete_coverage`, `not_found_with_reduced_coverage`, `not_scanned`, `unsupported_surface`, and `candidate_parse_failed` for detector/surface claims.
- Update MCP list report and CLI output to avoid "no MCP servers found" unless MCP coverage is complete for the scanned surfaces.
- Extend report markdown and Agent Action BOM evidence JSON with absence coverage status and impact statements.
- Ensure parse failures, generated-file suppression, unsupported declarations, blocked paths, and unscanned surfaces prevent unsupported negative claims.
- Add schemas for absence status in report summary and any MCP list artifacts that need it.

Repo paths:

- `core/aggregate/scanquality/scanquality.go`
- `core/report/agent_action_bom.go`
- `core/report/mcp_list.go`
- `core/cli/mcp_list.go`
- `core/report/render_markdown.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/mcp-list.md`
- `docs/trust/detection-coverage-matrix.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/aggregate/scanquality ./core/report ./core/cli -run 'Test.*AbsenceStatus|Test.*MCPList|Test.*NegativeClaim|Test.*ScanQuality' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make prepush-full`

Test requirements:

- Scan-quality unit tests for complete, reduced, blocked, unsupported, parse-failed, and not-scanned surfaces.
- CLI contract tests for `wrkr mcp-list --json` and Markdown text.
- QA tests proving unsupported "no MCP servers found" fails unless complete coverage exists.

Matrix wiring:

- Fast lane: scanquality, report, and CLI focused tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: MCP action surface and report scenarios with complete and reduced coverage.
- Cross-platform lane: generated-path suppression and blocked path behavior on Windows.
- Risk lane: `make test-hardening` for parse failures and blocked paths.

Acceptance criteria:

- Every "not found" claim carries absence status and coverage rationale.
- Reduced coverage and parse failure reports avoid absolute absence language.
- MCP list JSON and Markdown remain deterministic and schema-valid.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed negative scan claims to include coverage-qualified absence statuses so reports do not assert surfaces are absent when coverage is reduced or unsupported.
Semver marker override: [semver:minor]
Contract/API impact: Additive absence status fields; buyer-visible wording changes.
Versioning/migration impact: v1 additive; older summaries render conservative unknown/reduced coverage.
Architecture constraints: Scan Quality owns coverage facts; Report and CLI consume them.
ADR required: no
TDD first failing test(s): `TestMCPListNoServersRequiresCompleteCoverage`, `TestReducedCoverageUsesQualifiedNotFound`.
Cost/perf impact: low
Chaos/failure hypothesis: Detector parse failures and blocked paths downgrade absence claims instead of producing false negatives.

### Story 4.1: Compact Buyer Scan Coverage Summary

Priority: P1

Tasks:

- Add a compact buyer coverage summary that includes overall coverage confidence, count of reduced detectors, parse-failure count, suppressed generated-file count, blocked detector count, unsupported declaration count, and a short impact statement.
- Render compact coverage in buyer-facing Markdown and Agent Action BOM sections.
- Move detector-level scan-quality rows to appendix/evidence JSON, preserving full details for operators and auditors.
- Update `core/report/build.go` to include both compact summary and detailed evidence JSON without duplicating logic.
- Update report summary schema with compact coverage fields.
- Update docs to show where buyers see the summary and where operators find detector details.

Repo paths:

- `core/report/render_markdown.go`
- `core/report/build.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/scanquality/scanquality.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`
- `docs/trust/detection-coverage-matrix.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/report ./core/aggregate/scanquality -run 'Test.*CoverageSummary|Test.*ScanQualityAppendix|Test.*BuyerMarkdown' -count=1`
- `make test-contracts`
- `make test-docs-consistency`

Test requirements:

- Markdown tests proving buyer reports show compact summary instead of detector row spam.
- JSON/evidence tests proving detailed detector rows remain available.
- Schema tests for compact summary fields.

Matrix wiring:

- Fast lane: report and scanquality focused tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: report acceptance fixture with reduced detectors and parse failures.
- Cross-platform lane: deterministic summary sorting and wrapping.
- Risk lane: hardening check for blocked detector impact statement.

Acceptance criteria:

- Buyer-facing Markdown includes compact coverage summary and impact statement.
- Detector details remain in appendix/evidence JSON.
- Coverage confidence aligns with absence status and empty-state eligibility.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed buyer-facing reports to show compact scan coverage summaries while preserving detector-level scan-quality details in appendix and evidence JSON.
Semver marker override: [semver:patch]
Contract/API impact: Additive summary fields and Markdown layout change.
Versioning/migration impact: No field removal; detailed scan-quality payload remains available.
Architecture constraints: Report builds compact summary from Scan Quality output only.
ADR required: no
TDD first failing test(s): `TestBuyerMarkdownUsesCompactCoverageSummary`, `TestEvidenceJSONRetainsDetectorDetails`.
Cost/perf impact: low
Chaos/failure hypothesis: Missing scan-quality report renders `coverage_confidence=unknown` with a neutral impact statement.

### Story 4.2: Runtime Evidence Absence Framing

Priority: P0

Tasks:

- Add runtime absence statuses `not_collected`, `not_applicable`, `missing_required`, and `missing_for_control_claim`.
- Normalize existing runtime correlation and Gait coverage statuses into canonical runtime evidence state for reports and risk projection.
- Render static-only scans as `not_collected` unless runtime evidence is required by policy, declaration, or a control claim.
- Use `missing_for_control_claim` when a path claims runtime-proven control but supporting runtime evidence cannot be linked.
- Use `missing_required` when runtime evidence is explicitly required by policy or report mode.
- Update report markdown, Agent Action BOM JSON, Gait coverage report, risk summaries, and schemas.

Repo paths:

- `core/ingest/ingest.go`
- `core/report/gait_coverage.go`
- `core/risk/gait_coverage.go`
- `core/risk/buyer_projection.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/evidence/evidence-bundle.schema.json`
- `docs/commands/ingest.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/ingest ./core/risk ./core/report -run 'Test.*RuntimeEvidence|Test.*GaitCoverage|Test.*StaticOnly|Test.*ControlClaim' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make prepush-full`

Test requirements:

- Unit tests for each runtime absence status.
- Contract tests for BOM and evidence bundle schema updates.
- Scenario tests where static-only, runtime-required, and control-claim cases render differently.

Matrix wiring:

- Fast lane: ingest, risk, and report focused tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: Agent Action BOM and report acceptance with runtime sidecar variants.
- Cross-platform lane: runtime evidence path normalization.
- Risk lane: `make test-hardening` and `make test-chaos` for stale, corrupt, conflicting, and absent runtime sidecars.

Acceptance criteria:

- Static-only scans do not say runtime evidence is missing.
- Runtime evidence absence escalates only when required or used to substantiate a control claim.
- Gait coverage and BOM runtime fields agree.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed runtime evidence reporting so static-only scans render runtime evidence as not collected or not applicable unless runtime evidence is required or needed for a control claim.
Semver marker override: [semver:minor]
Contract/API impact: Additive runtime absence fields and refined status semantics.
Versioning/migration impact: Existing runtime statuses normalize into canonical evidence states.
Architecture constraints: Ingest owns runtime records; Risk projects state; Report renders state.
ADR required: no
TDD first failing test(s): `TestStaticOnlyRuntimeEvidenceNotCollected`, `TestMissingRuntimeForControlClaimEscalates`.
Cost/perf impact: low
Chaos/failure hypothesis: Corrupt or stale runtime sidecars render conflict/stale/unknown states without overclaiming customer runtime posture.

### Story 5.1: Report QA Gate For Overclaiming

Priority: P0

Tasks:

- Add generated-report QA tests or a small report linter that checks Markdown, JSON summaries, backlog rows, redacted artifacts, and docs snippets for risky phrases.
- Flag "approval missing", "owner missing", "proof missing", "no approval", "uncontrolled", "not governed", and unsupported "agent" labels.
- Allow exceptions only when verified absence coverage and action path type evidence support the phrase, with explicit test fixtures.
- Wire the linter into report tests and CLI contract tests without adding runtime dependencies to scan/risk/proof paths.
- Add scenario fixtures that cover complete coverage, reduced coverage, static-only runtime, external declared controls, contradictory controls, and non-agent action paths.

Repo paths:

- `core/report/report_test.go`
- `core/cli/report_contract_test.go`
- `core/report/render_markdown.go`
- `internal/acceptance`
- `internal/scenarios`
- `scripts/validate_scenarios.sh`
- `CHANGELOG.md`

Run commands:

- `go test ./core/report ./core/cli -run 'Test.*Overclaim|Test.*ReportContract|Test.*AgentLabel' -count=1`
- `go test ./internal/acceptance -run 'Test.*Overclaim|Test.*AgentActionBOM|Test.*Report' -count=1`
- `scripts/validate_scenarios.sh`
- `make test-scenarios`
- `make test-hardening`

Test requirements:

- Phrase-deny tests with allowed exception fixtures.
- Agent-label tests tied to action path type.
- Acceptance tests proving buyer reports pass the linter in internal and redacted share profiles.

Matrix wiring:

- Fast lane: report and CLI focused tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: `internal/acceptance` and scenario fixtures.
- Cross-platform lane: markdown and JSON artifact checks on Windows.
- Risk lane: `make test-hardening` because this is a buyer-trust guardrail.

Acceptance criteria:

- Report QA fails on unsupported overclaim phrases.
- Supported verified-absence exceptions are explicit, narrow, and covered by tests.
- Non-agent action paths cannot be labeled "agent" in generated buyer output.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added report QA coverage that blocks unsupported overclaiming and prevents non-agent action paths from being labeled as agents in generated buyer artifacts.
Semver marker override: [semver:patch]
Contract/API impact: Test/QA contract for generated artifacts; no new user-facing fields beyond previous stories.
Versioning/migration impact: No stored migration required.
Architecture constraints: QA gate tests generated artifacts; it must not alter scan/risk/proof runtime behavior.
ADR required: no
TDD first failing test(s): `TestReportQABlocksUnsupportedApprovalMissing`, `TestReportQABlocksAgentLabelForPlainSourcePath`.
Cost/perf impact: low
Chaos/failure hypothesis: Redacted and partially generated artifacts still lint deterministically without needing external services.

### Story 5.2: Documentation, Schemas, And Release Handoff

Priority: P1

Tasks:

- Update command docs, trust docs, schema README, and examples to explain control resolution, evidence confidence, target class, action path type, coverage-qualified absence, runtime absence framing, and overclaim QA.
- Add schema descriptions and examples for all new enum values.
- Update `CHANGELOG.md` with entries from implementation stories in the correct sections.
- Update scenario coverage map for new outside-in fixtures.
- Add docs consistency checks for terminology and field names.
- Ensure implementation PR descriptions include TDD evidence, commands run, result summaries, cost/perf notes, and changelog impact.

Repo paths:

- `README.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/commands/mcp-list.md`
- `docs/commands/evidence.md`
- `docs/commands/ingest.md`
- `docs/trust/detection-coverage-matrix.md`
- `docs/trust/contracts-and-schemas.md`
- `schemas/v1/README.md`
- `internal/scenarios/coverage_map.json`
- `CHANGELOG.md`

Run commands:

- `make test-docs-consistency`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/run_docs_smoke.sh`
- `make test-contracts`
- `make test-release-smoke`

Test requirements:

- Docs consistency tests for field names and buyer-safe terminology.
- Schema validation examples for new states and enum values.
- Scenario coverage map validation.

Matrix wiring:

- Fast lane: docs and schema consistency scripts.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: `scripts/run_v1_acceptance.sh --mode=local` when public examples change.
- Cross-platform lane: docs examples use portable paths and profile commands only.
- Risk lane: hardening check for docs examples that could imply secret extraction or runtime enforcement.

Acceptance criteria:

- Docs explain new states and avoid unsupported absence claims.
- Schema docs and command docs match executable behavior.
- Changelog entries are present and release-ready.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Updated command, trust, and schema documentation for evidence-state control resolution, target classification, action path type classification, coverage-qualified absence, and runtime evidence framing.
Semver marker override: none
Contract/API impact: Documentation and schema descriptions for public contract fields.
Versioning/migration impact: Docs explain additive v1 fields and compatibility aliases.
Architecture constraints: Docs must describe Wrkr as deterministic, static/local-first, and evidence-bounded.
ADR required: no
TDD first failing test(s): `TestDocsDoNotUseUnsupportedMissingControlLanguage`, `TestSchemaReadmeListsEvidenceStateEnums`.
Cost/perf impact: low
Chaos/failure hypothesis: Docs examples remain valid when copied into clean checkouts without local developer paths.

# Adhoc Plan: Buyer Action Registry Hardening

Date: 2026-05-10
Profile: `wrkr`
Slug: `buyer-action-registry-hardening`
Recommendation source: user-provided design-partner hardening recommendations covering Agent Action BOM consistency, credential authority, purpose and version metadata, confidence lanes, mutable endpoint semantics, action lineage, registry output, ranking, buyer-ready report modes, redaction, remediation, scenarios, and buyer-facing docs.

All paths in this plan are repo-relative. User-provided absolute checkout paths have been normalized to repo-relative paths. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, scenario, or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control loop. These stories must not implement Gait enforcement, Axym compliance logic, runtime interception, or scan-time LLM behavior.
- Default scan, risk, proof, report, and evidence behavior remains local-first, file-based, zero-egress by default, and deterministic for the same input except explicit timestamp/version fields.
- Buyer-ready output must be a projection of structured evidence, not prose inference. Plain-language report text can be templated, but the underlying facts must come from deterministic action-path, inventory, control-graph, proof, and runtime-evidence structures.
- No detector, parser, report artifact, redaction path, or scenario may extract or serialize raw secret values. Credential hardening in this plan classifies references, authority, usability, source, access type, and rotation evidence only.
- The canonical action-path projection becomes the single source for `write_capable`, `credential_access`, `production_target_status`, `risk_tier`, `control_state`, empty-state eligibility, and buyer-facing report counters.
- Evidence confidence must be explicit. Prompt, instruction, and semantic findings are useful review signals, but they must not read like confirmed executable action paths unless workflow, credential, permission, and target linkage proves execution.
- Purpose, version/config metadata, mutable endpoint semantics, and action lineage are additive v1 contract fields unless an implementation PR explicitly proposes a versioned migration.
- Production and mutation claims remain evidence-bounded. Wrkr may classify static declared endpoints and target categories, but it must not claim live reachability or runtime control without runtime evidence sidecars.
- Share profiles and configurable redaction must preserve joinability inside one artifact set while redacting selected sensitive fields. Redaction decisions must be visible in metadata and covered by contract tests.
- Scenarios are outside-in product specifications. New scenario expected outputs must be human-reviewable and must never contain real secrets, customer names, or local developer paths.
- Changelog entries are required because the work changes public report/BOM JSON, schemas, CLI flags, markdown templates, docs, risk semantics, and buyer-facing trust language.

## Current Baseline (Observed)

- `core/risk/action_paths.go` currently builds `ActionPath` from inventory privilege-map entries, decorates paths, links attack-path scores, applies the govern-first model, and sorts paths deterministically.
- `core/risk/buyer_projection.go` already projects `control_state`, `risk_zone`, and `review_burden` onto action paths, but report/BOM fields, risk items, empty-state rendering, and summary counters still have independent projection logic.
- `core/report/render_markdown.go` currently emits `Positive Empty State` when the Agent Action BOM has no items or `ControlFirstItems == 0`; that rule can contradict standing credentials, write-capable paths, production target matches, missing proof, or elevated review burden.
- `core/report/agent_action_bom.go` already emits Agent Action BOM items with action classes, credential rollups, standing privilege, production target status, proof coverage, runtime evidence status, Gait coverage, graph refs, reachability, queue, visibility, and remediation fields.
- `core/aggregate/inventory/privileges.go` already models credential provenance fields such as `type`, `subject`, `scope`, `confidence`, `credential_kind`, `access_type`, `standing_access`, `likely_jit`, `evidence_location`, `classification_reasons`, and `risk_multiplier`.
- Existing credential fields do not yet separate credential presence, workflow reference, path usability, rotation evidence status, and credential source as first-class fields across inventory, action paths, BOM, report summary, and schemas.
- `core/aggregate/inventory/inventory.go`, `core/risk/action_paths.go`, `core/report/agent_action_bom.go`, and `core/aggregate/attackpath/graph.go` do not currently carry first-class `purpose`, `purpose_source`, or `purpose_confidence` fields.
- `core/detect/mcp/detector.go` already extracts MCP package/version candidates and optional enrich evidence, but config fingerprints, config source, version source, workflow file hash, package lock evidence, and cross-surface version metadata are not yet normalized through inventory, action paths, and BOM.
- `core/policy/productiontargets/builtin.go` has coarse built-in production target labels for deploy, Terraform/IaC, Kubernetes, package publish, release automation, database migration, and customer-impacting signals. It does not classify declared mutable endpoint operations such as `refund`, `payment`, `user_admin`, `data_export`, or `production_mutation`.
- `core/aggregate/attackpath/graph.go` already builds a versioned control-path graph with repo, workflow, agent, execution identity, credential, tool, target, action capability, and governance-control nodes. It does not yet emit a compact per-BOM `action_lineage` object with ordered buyer-readable labels and linked node IDs.
- `core/report/types.go` currently supports report templates `exec`, `operator`, `audit`, `public`, `ciso`, `appsec`, `platform`, `customer-draft`, and `agent-action-bom`; share profiles are `internal`, `public`, and `customer-redacted`.
- `core/cli/report.go` exposes `--template`, `--share-profile`, `--top`, markdown, PDF, evidence JSON, and backlog CSV output. It does not yet expose `--share-profile design-partner` or explicit redaction selectors such as `--redact owners,repos,paths`.
- `docs/commands/report.md`, `docs/commands/scan.md`, and README already describe static posture boundaries, action paths, Agent Action BOM, Gait coverage projection, production target claim limits, redaction for public/customer profiles, and credential reference handling.
- Schema files under `schemas/v1` already include additive action-path, Agent Action BOM, report summary, risk report, credential provenance, and control-path graph contracts that will need surgical additive updates for this plan.

## Exit Criteria

- Agent Action BOM, evidence JSON, report summary, top-risk items, inventory privilege-map entries, and markdown output agree on write capability, credential authority, production target status, risk tier, control state, confidence lane, and empty-state eligibility.
- A shared action-path projection owns buyer-facing derived fields, and report/BOM/rendering code consumes that projection instead of duplicating ranking or empty-state logic.
- Empty-state markdown is only emitted when action paths, scan quality, control-first counts, standing credentials, write paths, production/mutable targets, missing proof, and confidence lanes all support a clean buyer-facing state.
- Credential authority is modeled with explicit fields for `credential_present`, `credential_referenced_by_workflow`, `credential_usable_by_path`, `credential_kind`, `access_type`, `standing_access`, `likely_jit`, `rotation_evidence_status`, and `credential_source` without exposing secret values.
- Action paths, BOM items, registry entries, and control-path graph nodes carry purpose metadata with deterministic source and confidence.
- Findings and action paths are assigned to `confirmed_action_path`, `likely_action_path`, `semantic_review_candidate`, or `context_only`, and all buyer-facing rankings and summaries respect those lanes.
- MCP servers, CI workflows, agent configs, package-script tools, and relevant report artifacts carry deterministic version/config metadata where available: `version`, `version_source`, `config_fingerprint`, and `config_source`.
- Static mutable endpoint detection classifies declared operations as `read`, `write`, `delete`, `deploy`, `refund`, `payment`, `user_admin`, `data_export`, or `production_mutation` with confidence and evidence refs.
- BOM and evidence JSON include a deterministic `action_lineage` object for each path: repo -> workflow/agent -> action -> credential -> target -> owner -> approval/proof.
- Report artifacts include a deterministic `action_surface_registry` grouped by tool/server/workflow with owner, purpose, version/config, authority, reachable actions, credentials, proof status, and graph refs.
- Top govern-first paths prioritize standing credentials, release/write/deploy paths, mutable endpoints, MCP egress, production-impacting targets, and confirmed confidence lanes above generic inventory.
- `wrkr report` supports a buyer-ready design partner report mode focused on the top validated findings with plain-language problem, likely explanation, threat, and recommended control sections.
- Users can configure redaction for owners, repos, paths, credential subjects, authors, and filesystem-local values through explicit flags and share profiles.
- Remediation text is path-specific and actionable: rotate or convert standing credentials, add release gates, confirm owner, bind policy, require CODEOWNERS approval, restrict token scope, attach proof, or rescan.
- Scenario fixtures prove purpose, credential authority, versioned config, mutable endpoints, MCP reachability, missing proof, and redaction in one deterministic end-to-end flow.
- Docs explain the hardened boundary without overclaiming runtime control: static action registry, purpose/version metadata, mutable endpoint semantics, credential authority, redaction, proof gaps, and known out-of-scope areas.

## Public API and Contract Map

- CLI contracts:
  - Preserve existing exit codes, including `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, and `8` unsafe operation blocked.
  - `wrkr report --json`, `--md`, `--pdf`, `--evidence-json`, and `--csv-backlog` remain deterministic from saved scan state.
  - Additive report flags may include `--share-profile design-partner`, `--share-profile external-redacted`, `--share-profile investor-safe`, `--template design-partner-summary`, and `--redact <fields>`.
  - Invalid share profiles, templates, or redaction selectors must fail closed with `invalid_input` and exit `6`.
- JSON and schema contracts:
  - Additive fields land in `summary.action_paths[]`, top-level `action_paths[]`, `agent_action_bom.items[]`, `risk_report.action_paths[]`, `inventory.agent_privilege_map[]`, control-path graph nodes, and evidence JSON bundles.
  - Candidate additive fields include `purpose`, `purpose_source`, `purpose_confidence`, `confidence_lane`, `credential_authority`, `mutable_endpoint_semantics`, `version`, `version_source`, `config_fingerprint`, `config_source`, `action_lineage`, and registry artifacts.
  - Existing fields such as `credential_access`, `credential_provenance`, `credentials[]`, `control_state`, `risk_zone`, `review_burden`, `production_write`, `production_target_status`, and `proof_coverage` remain backward-compatible.
  - Schema updates must cover `schemas/v1/agent-action-bom.schema.json`, `schemas/v1/report/report-summary.schema.json`, `schemas/v1/risk/risk-report.schema.json`, `schemas/v1/control-path-graph.schema.json`, and any inventory/evidence schemas that serialize new fields.
- Detection contracts:
  - Use structured parsers for YAML, JSON, TOML, OpenAPI, package manifests, lockfiles, and route definitions whenever feasible.
  - Endpoint and credential detection must emit references, hashes, categories, and evidence labels, not raw secret values or live endpoint probes.
  - Optional enrich behavior remains explicit and non-default; version/config metadata from local files must not require network access.
- Risk and report contracts:
  - Confidence lanes gate buyer-facing language. Semantic-only findings can appear as review candidates or appendix/context, not confirmed executable paths.
  - Govern-first ranking is deterministic and reason-coded. Mutable endpoint, credential, release, deployment, production, proof-gap, and confidence-lane boosts must be explainable.
  - Positive empty state requires scan quality and action-path projection support, not just zero control-first items.
- Proof/evidence contracts:
  - Proof record types remain consistent with Wrkr and `Clyra-AI/proof` primitives.
  - New proof-gap and lineage fields are report/evidence projections unless an implementation story explicitly adds new proof event data.
  - Chain integrity and verifiability are preserved.
- Redaction contracts:
  - Redaction is deterministic, profile-aware, documented, and schema-visible through `share_profile_metadata`.
  - Redaction must preserve joinability within a generated artifact set and must not leak local filesystem roots, repo names, owner names, credential subjects, authors, or customer identifiers when those fields are selected.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/trust/detection-coverage-matrix.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Contract and fixture docs impacted:
  - `scenarios/README.md`
  - `internal/scenarios/coverage_map.json`
  - relevant `scenarios/wrkr/**/README.md` files for new fixtures
- OSS trust baseline:
  - No generated reports, binaries, local proof outputs, live customer data, or transient scan state should be committed.
  - New sample artifacts must be generated from deterministic fixtures with fake owners, fake repos, fake credential references, and no real service credentials.
  - Documentation must call out that Wrkr identifies static action authority and proof gaps; it does not enforce runtime controls or observe live traffic by default.
- Docs must answer:
  - Why a path is confirmed, likely, semantic review, or context-only.
  - Which tool/server/workflow owns an action surface, why it exists, which version/config introduced it, what it can mutate, and what proof is missing.
  - How credential references differ from credential usability and standing access.
  - How to choose internal, design-partner, customer-redacted, external-redacted, and investor-safe sharing modes.
  - Which remediation playbook applies to a credential, release gate, mutable endpoint, owner gap, policy gap, proof gap, or stale report.

## Recommendation Traceability

| Recommendation / Finding | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| Report artifact consistency across BOM, evidence JSON, inventory, and summary output | P0 | Story 1.1 | Contradictory buyer fields undermine trust. | Centralize derived buyer projection and empty-state eligibility. | One coherent report story across JSON, markdown, and evidence artifacts. |
| Normalized credential authority model | P0 | Story 2.1 | Standing credentials in release/build workflows are the strongest scan signals. | Split presence, reference, usability, kind, access type, rotation, source, and standing/JIT semantics. | Precise credential findings without secret leakage or conflicting fields. |
| First-class purpose on action paths | P1 | Story 2.2 | Registry value depends on knowing owner and purpose. | Derive purpose from structured names, descriptions, scripts, instructions, metadata, and annotations. | Buyer-readable action inventory with fewer ambiguous paths. |
| Evidence confidence lanes | P0 | Story 1.2 | Semantic findings should not masquerade as confirmed execution. | Classify evidence into confirmed, likely, semantic review, and context-only lanes. | Cleaner buyer reports and lower false urgency. |
| Versioned tool and config metadata | P1 | Story 2.2 | Buyers need to know which version/config introduced authority. | Normalize version source, config source, and deterministic fingerprints across MCP, CI, agent config, and scripts. | Drift-friendly registry and stronger change review. |
| Mutable endpoint semantics | P1 | Story 3.1 | Business risk depends on what can mutate state. | Add static OpenAPI, route, MCP tool declaration, proto/service, and verb parsers with confidence. | More meaningful risk zones and govern-first ranking. |
| Explicit action lineage chain | P0 | Story 2.3 | Repo -> workflow/agent -> action -> credential -> target -> owner -> approval/proof is the core buyer value. | Emit deterministic `action_lineage` linked to graph refs and readable labels. | Clear board/AppSec narrative without parsing raw evidence. |
| Action surface registry view | P1 | Story 3.2 | BOM is readable, but registry grouping makes Wrkr feel like an agent registry plus exposure map. | Build `action_surface_registry` from inventory, action paths, BOM, and graph refs. | Easier design-partner review and team handoff. |
| Top mutable paths to govern first | P0 | Story 3.2 | Buyers need operational consequence, not generic inventory. | Fold credential, release, deployment, mutable endpoint, MCP egress, production, and confidence-lane signals into ranking. | Top 5-10 items point to paths that matter most. |
| Buyer-ready design partner report mode | P1 | Story 4.1 | Current output is still raw for design partners. | Add concise design-partner template/share profile focused on validated findings. | Shareable artifact for sales/design-partner loops without overclaiming. |
| Configurable redaction and share profiles | P1 | Story 4.2 | External sharing needs field-level privacy choices. | Add redaction selectors and profiles for internal, customer, external, and investor-safe artifacts. | Safer artifact sharing while preserving evidence utility. |
| Buyer-ready remediation playbooks | P1 | Story 4.1 | Generic remediation does not tell buyers what to do next. | Generate path-specific remediation from finding type and control gap. | More actionable AppSec/platform workflow. |
| Purpose, credential, endpoint, and redaction test scenarios | P0 | Story 5.1 | Hardened output must prove itself end to end. | Add fixtures covering MCP, CI, OpenAPI/routes, credentials, owner metadata, missing proof, and redaction. | Outside-in confidence for customer-facing output. |
| Documentation and buyer language update | P1 | Story 5.2 | Docs must clarify value and limits. | Update scan/report docs, detection matrix, README, schemas docs, and examples. | Accurate positioning and lower overclaim risk. |

## Test Matrix Wiring

- Fast lane:
  - Focused unit and contract tests for action-path projection consistency, confidence lane classification, credential authority fields, purpose derivation, version/config fingerprints, mutable endpoint parsing, lineage, registry grouping, ranking, redaction, templates, and remediation.
  - Candidate commands: `go test ./core/risk ./core/report ./core/aggregate/inventory ./core/aggregate/attackpath -count=1`, `go test ./core/detect/mcp ./core/policy/productiontargets -count=1`, and focused `go test ./core/cli -run 'Test.*Report|Test.*ShareProfile|Test.*Redact' -count=1`.
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `go test ./internal/acceptance -run 'Test.*AgentActionBOM|Test.*Report|Test.*DesignPartner|Test.*Redaction' -count=1`
- Cross-platform lane:
  - Windows smoke must cover path normalization, config fingerprint stability, filesystem redaction, markdown wrapping, JSON determinism, and OpenAPI/routes fixtures without POSIX-only assumptions.
- Risk lane:
  - `make test-hardening` for fail-closed invalid redaction selectors/templates, no-secret serialization, unsafe output paths, schema contract failures, and ambiguous endpoint/credential confidence.
  - `make test-chaos` for stale/missing runtime evidence sidecars, partial scan-quality states, corrupt report inputs, and redaction artifact generation failures.
  - `make test-perf` if endpoint parsing, config hashing, or registry grouping materially changes scan/report runtime.
- Release/UAT lane:
  - `scripts/run_v1_acceptance.sh --mode=local`
  - `make test-release-smoke` if CLI docs, report examples, or public artifacts change release-facing examples.
- Gating rule:
  - Wave 1 is required before any buyer-facing design partner report is shipped.
  - Wave 2 is required before registry artifacts claim purpose/version/lineage completeness.
  - Wave 3 is required before mutable endpoint language appears in top-path ranking or buyer docs.
  - Final implementation requires `make prepush-full`, `make test-contracts`, scenario validation, docs consistency checks, and explicit changelog entries.

## Minimum-Now Sequence

- Wave 1 - Contract consistency and confidence:
  - Story 1.1 centralizes action-path projection and fixes empty-state truth.
  - Story 1.2 adds evidence confidence lanes and buyer-language gating.
- Wave 2 - Authority, purpose, metadata, and lineage:
  - Story 2.1 normalizes credential authority.
  - Story 2.2 adds purpose plus version/config metadata.
  - Story 2.3 emits explicit action lineage linked to the control graph.
- Wave 3 - Mutable surfaces and registry:
  - Story 3.1 detects mutable endpoint semantics.
  - Story 3.2 builds the action surface registry and upgrades govern-first ranking.
- Wave 4 - Shareable buyer output:
  - Story 4.1 adds design-partner summary mode and remediation playbooks.
  - Story 4.2 adds configurable redaction and expanded share profiles.
- Wave 5 - Outside-in proof and docs:
  - Story 5.1 adds scenario and acceptance coverage.
  - Story 5.2 updates docs, schemas guidance, README, and buyer language.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No Axym compliance-engine implementation and no Gait runtime enforcement in Wrkr.
- No scan-time LLM calls, model-generated findings, default telemetry, live endpoint probing, or default provider/API enrichment.
- No extraction, hashing, display, or persistence of raw secret values.
- No incompatible removal or renaming of existing v1 report, risk, inventory, BOM, or graph fields.
- No production-write claim when production targets or mutable endpoint evidence do not support it.
- No treating semantic review candidates as confirmed executable action paths.
- No redaction mode that destroys in-artifact joinability without explicit metadata.
- No generated customer reports, local scan outputs, transient evidence bundles, binaries, or private fixture data committed outside approved test fixtures.
- No branch-protection, CI, proof verification, schema validation, or exit-code bypass.

## Definition of Done

- Every story starts with failing tests or scenario fixtures that encode the intended behavior.
- New public fields are additive, schema-validated, documented, and present in report/BOM/evidence artifacts where applicable.
- Derived report values have a single authoritative projection path, with tests proving BOM, summary, evidence JSON, and markdown agree.
- Deterministic sorting and stable IDs are preserved for action paths, lineage objects, registry entries, graph nodes/edges, and redacted pseudonyms.
- Credential authority operates on references and metadata only, with tests proving raw secret values are not serialized.
- Purpose, version/config, confidence lane, endpoint semantics, redaction, and remediation all carry reason/evidence refs.
- Design-partner output is concise, top-path-first, and bounded to static posture claims unless runtime evidence is explicitly present.
- Docs and changelog entries ship in the same implementation PRs as externally visible behavior changes.
- Final validation records exact commands and results for `make lint-fast`, `make test-fast`, `make test-contracts`, scenario validation, docs consistency checks, and all risk lanes required by touched surfaces.

## Stories

### Story 1.1: Shared Action-Path Projection And Empty-State Truth

Priority: P0

Tasks:

- Introduce a shared buyer/action-path projection in `core/risk` that owns derived values for `write_capable`, `credential_access`, `production_target_status`, `risk_tier`, `control_state`, `risk_zone`, `review_burden`, summary counters, and empty-state eligibility.
- Route `core/report/build.go`, `core/report/agent_action_bom.go`, `core/report/render_markdown.go`, risk item rendering, evidence JSON output, and report summary counters through the shared projection.
- Replace the current `Positive Empty State` condition in `core/report/render_markdown.go` with a reason-coded eligibility result that considers scan quality, all action paths, write-capable paths, standing credentials, production or mutable targets, missing proof, unresolved owners, confidence lanes, and control-first counts.
- Add deterministic `empty_state_status` and `empty_state_reasons` metadata to the report summary and Agent Action BOM summary only if the implementation team confirms the field is useful in customer artifacts.
- Preserve existing field names and values where already serialized; only add new fields when needed for explainability.
- Ensure report artifacts do not contradict the saved inventory privilege budget or action-path facts when share-profile redaction is active.
- Update schemas and docs for any additive projection/empty-state metadata.
- Update `CHANGELOG.md` with the report consistency fix.

Repo paths:

- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/risk/govern_first_model.go`
- `core/report/build.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/types.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/report -run 'Test.*Projection|Test.*EmptyState|Test.*AgentActionBOM|Test.*Report' -count=1`
- `go test ./core/cli -run 'TestReport.*AgentActionBOM|TestReport.*EvidenceJSON|TestReport.*ShareProfile' -count=1`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add failing tests where a report previously rendered `Positive Empty State` while action paths still had standing credentials, write capability, missing proof, or high review burden.
- Add table tests proving BOM item, report summary, top-risk item, and evidence JSON fields agree for the same action path.
- Add redacted share-profile tests proving pseudonymized fields do not change derived risk/control/empty-state decisions.
- Add schema contract tests for any new `empty_state_status` or projection metadata fields.
- Add byte-stability tests for markdown and evidence JSON output.

Matrix wiring:

- Fast lane: focused `core/risk`, `core/report`, and `core/cli` projection tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: covered by Story 5.1 design-partner scenario.
- Cross-platform lane: markdown line wrapping and filesystem path redaction must pass on Windows smoke.
- Risk lane: `make test-hardening` for no-secret output and fail-closed schema mismatches.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=local` if report examples change.

Acceptance criteria:

- A fixture with high exposure, standing credentials, write paths, missing proof, and zero control-first count no longer renders as a clean positive empty state.
- `agent_action_bom.items[]`, `summary.action_paths[]`, top-level `action_paths[]`, `summary.top_risks[]`, and evidence JSON agree on derived fields for the same `path_id`.
- Empty-state markdown includes explicit reasons and coverage confidence when no high-risk governable paths exist.
- Public/customer-redacted output preserves the same derived posture while redacting selected fields.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: [semver:patch] Fixed Agent Action BOM and report projection consistency so empty-state, risk-tier, control-state, credential, and production-target fields agree across buyer-facing artifacts.
Semver marker override: [semver:patch]
Contract/API impact: Preserves existing v1 fields and may add optional projection/empty-state metadata to report and BOM schemas.
Versioning/migration impact: No migration required if fields are additive; older consumers can ignore new metadata.
Architecture constraints: Preserve Risk as the owner of projection semantics and Reporting as a serializer/renderer. Do not let report markdown recalculate risk independently.
ADR required: yes
TDD first failing test(s): `TestAgentActionBOMDoesNotRenderPositiveEmptyStateForStandingCredential`, `TestReportArtifactsShareActionPathProjection`, `TestCustomerRedactedProjectionPreservesControlState`
Cost/perf impact: low; projection should be O(number of action paths).
Chaos/failure hypothesis: If scan quality, proof status, or inventory fields are partial, the projection emits explicit degraded reasons and does not return a false clean empty state.

### Story 1.2: Evidence Confidence Lanes

Priority: P0

Tasks:

- Add a deterministic confidence lane enum with `confirmed_action_path`, `likely_action_path`, `semantic_review_candidate`, and `context_only`.
- Classify confidence lanes from evidence type and linkage strength: executable workflow plus credential plus permission/target is confirmed; workflow/action without complete authority is likely; prompt/instruction semantics without execution linkage is semantic review; supporting metadata is context-only.
- Add lane fields and reason codes to `risk.ActionPath`, Agent Action BOM items, risk report action paths, report summary action paths, and control backlog items where useful.
- Ensure buyer-facing report sections rank and phrase semantic review candidates differently from confirmed executable paths.
- Ensure confidence lanes interact with `control_state`, `risk_zone`, `review_burden`, `risk_tier`, and `action_path_to_control_first` without suppressing valid high-risk likely paths.
- Add appendix/debug handling for context-only findings so they are not dropped from evidence trails.
- Update schemas and docs with lane definitions and examples.
- Update `CHANGELOG.md` with the confidence-lane behavior.

Repo paths:

- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/risk/govern_first_model.go`
- `core/report/agent_action_bom.go`
- `core/report/build.go`
- `core/report/types.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `docs/commands/scan.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk -run 'Test.*ConfidenceLane|Test.*GovernFirst|Test.*BuyerProjection' -count=1`
- `go test ./core/report ./core/aggregate/controlbacklog -run 'Test.*ConfidenceLane|Test.*AgentActionBOM|Test.*ControlBacklog' -count=1`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add table tests for workflow+credential+permission confirmed paths, workflow-only likely paths, AGENTS.md/prompt semantic candidates, and documentation/context-only findings.
- Add ranking tests proving confirmed/likely mutable or credentialed paths outrank generic semantic findings.
- Add report markdown tests proving semantic candidates use review wording, not confirmed-action wording.
- Add schema tests for confidence lane enums and omitted-field compatibility.

Matrix wiring:

- Fast lane: `core/risk`, `core/report`, and `core/aggregate/controlbacklog` lane tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 5.1 scenario must include all four lanes.
- Cross-platform lane: no platform-specific assumptions.
- Risk lane: `make test-hardening` for ambiguous evidence fail-closed or downgrade behavior.
- Release/UAT lane: not required unless public CLI examples change.

Acceptance criteria:

- Semantic prompt, AGENTS.md, and Jenkinsfile review signals appear as review candidates unless execution linkage proves an action path.
- Confirmed executable paths retain full buyer-facing priority and proof-gap language.
- Context-only findings remain available in evidence refs or appendix surfaces but do not inflate top actionable counts.
- Docs include the lane taxonomy and static-analysis limits.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added evidence confidence lanes so report and BOM output distinguish confirmed action paths from likely paths, semantic review candidates, and context-only evidence.
Semver marker override: [semver:minor]
Contract/API impact: Adds optional confidence-lane fields and enums to report, risk, BOM, and backlog schemas.
Versioning/migration impact: Additive v1 fields only; older artifacts without lanes should normalize to an explicit compatibility fallback during report generation.
Architecture constraints: Confidence classification belongs in Risk/Aggregation projection, not markdown rendering. Detection emits evidence; Risk classifies lane.
ADR required: yes
TDD first failing test(s): `TestConfidenceLaneConfirmedWorkflowCredentialPermission`, `TestSemanticInstructionFindingIsReviewCandidate`, `TestConfidenceLaneAffectsGovernFirstRanking`
Cost/perf impact: low.
Chaos/failure hypothesis: If evidence linkage is incomplete or contradictory, the lane downgrades and emits reason codes rather than presenting a confirmed path.

### Story 2.1: Normalized Credential Authority Model

Priority: P0

Tasks:

- Add a `CredentialAuthority` or equivalent normalized structure for action paths and inventory privilege-map entries with first-class fields for `credential_present`, `credential_referenced_by_workflow`, `credential_usable_by_path`, `credential_kind`, `access_type`, `standing_access`, `likely_jit`, `rotation_evidence_status`, and `credential_source`.
- Preserve existing `CredentialProvenance` compatibility fields while using the new authority model for ranking, BOM display, report summary, control graph credential nodes, and remediation.
- Distinguish workflow secret reference, durable standing credential, OIDC/workload identity, delegated OAuth, inherited human credential, GitHub workflow token, JIT evidence, and unknown durable secret references without exposing secret values.
- Add rotation evidence states such as `present`, `missing`, `not_applicable`, `unknown`, and `stale` with reason codes.
- Update workflow, non-human identity, secrets, MCP, and package-script evidence adapters only where needed to populate the normalized authority model from existing evidence keys.
- Ensure `credential_access` remains true only when a path can use or plausibly inherit the credential, while mere context references can remain lower-confidence or context-only.
- Add redaction behavior for credential subjects, sources, and evidence locations.
- Update schemas, docs, and changelog.

Repo paths:

- `core/aggregate/inventory/privileges.go`
- `core/aggregate/inventory/inventory.go`
- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/risk/govern_first_model.go`
- `core/aggregate/attackpath/graph.go`
- `core/report/agent_action_bom.go`
- `core/report/build.go`
- `core/report/types.go`
- `core/detect/ciagent/detector.go`
- `core/detect/secrets/detector.go`
- `core/detect/nonhumanidentity/detector.go`
- `core/detect/mcp/detector.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/control-path-graph.schema.json`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/aggregate/inventory ./core/risk ./core/report -run 'Test.*Credential|Test.*Authority|Test.*Standing|Test.*Rotation' -count=1`
- `go test ./core/detect/ciagent ./core/detect/secrets ./core/detect/nonhumanidentity ./core/detect/mcp -run 'Test.*Credential|Test.*Secret|Test.*WorkflowToken' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add tests for workflow-referenced PAT-like secrets, GitHub workflow token posture, cloud admin keys, OIDC workload identity, delegated OAuth, inherited human credentials, JIT evidence, and unknown durable references.
- Add tests proving `credential_referenced_by_workflow` can be true while `credential_usable_by_path` is false when execution linkage is missing.
- Add tests for rotation evidence present/missing/stale/not-applicable states.
- Add no-secret serialization tests across scan JSON, inventory, risk report, BOM, evidence JSON, markdown, and redacted profiles.
- Add ranking tests proving standing usable credentials boost govern-first priority.

Matrix wiring:

- Fast lane: credential authority package tests and detector evidence tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 5.1 scenario must include release/build workflows with standing credential references and OIDC/JIT contrasts.
- Cross-platform lane: path and evidence-location normalization must pass Windows smoke.
- Risk lane: `make test-hardening` required for no-secret output and fail-closed redaction.
- Release/UAT lane: not required unless CLI examples change.

Acceptance criteria:

- BOM/evidence JSON distinguishes credential presence, workflow reference, path usability, kind, access type, source, rotation evidence, standing access, and likely JIT status for the same path.
- A release workflow with a standing credential reference outranks a generic AI tool inventory item.
- A semantic credential mention without execution linkage is not promoted to a confirmed credential-usable action path.
- Redacted share profiles hide credential subjects and local evidence locations while preserving joinable authority state.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added normalized credential authority fields for report, BOM, inventory, and risk outputs without exposing secret values.
Semver marker override: [semver:minor]
Contract/API impact: Adds public JSON fields and schema definitions for credential authority while preserving existing credential provenance fields.
Versioning/migration impact: Additive v1 fields; old states should backfill authority from existing provenance where possible.
Architecture constraints: Detection emits references and evidence; Aggregation normalizes authority; Risk ranks authority; Reporting serializes and redacts.
ADR required: yes
TDD first failing test(s): `TestCredentialAuthoritySeparatesReferenceFromUsability`, `TestStandingReleaseCredentialRanksControlFirst`, `TestCredentialAuthorityRedactionOmitsSubject`
Cost/perf impact: low.
Chaos/failure hypothesis: If credential evidence is partial, Wrkr marks unknown/missing rotation or lower usability rather than assuming safe or confirmed authority.

### Story 2.2: Purpose And Versioned Config Metadata

Priority: P1

Tasks:

- Add `purpose`, `purpose_source`, and `purpose_confidence` to inventory tools/agents, privilege-map entries, action paths, BOM items, registry entries, and control-path graph nodes where applicable.
- Derive purpose from workflow names, job names, MCP server names/descriptions, package scripts, agent instructions, repo metadata, owner metadata, and optional `wrkr:purpose` annotations.
- Add deterministic precedence rules for purpose sources and confidence, including conflict handling when multiple sources disagree.
- Normalize `version`, `version_source`, `config_fingerprint`, and `config_source` metadata for MCP servers, CI workflows, agent configs, package-script tools, and report/BOM surfaces.
- Reuse MCP package/version extraction in `core/detect/mcp/detector.go` and extend local file hashing for workflow/config sources using deterministic canonical bytes.
- Capture workflow file hash, package-lock evidence, declared package/tool version, and config source without adding default network lookups.
- Ensure fingerprints are portable and do not include absolute checkout paths, timestamps, or secret values.
- Update schemas, report docs, detection matrix, and changelog.

Repo paths:

- `core/aggregate/inventory/inventory.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `core/report/agent_action_bom.go`
- `core/report/types.go`
- `core/aggregate/attackpath/graph.go`
- `core/detect/mcp/detector.go`
- `core/detect/ciagent/detector.go`
- `core/detect/workflowcap/analyze.go`
- `core/detect/skills/detector.go`
- `core/detect/agentcustom/detector.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/control-path-graph.schema.json`
- `docs/trust/detection-coverage-matrix.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/aggregate/inventory ./core/risk ./core/report ./core/aggregate/attackpath -run 'Test.*Purpose|Test.*Version|Test.*Fingerprint|Test.*Config' -count=1`
- `go test ./core/detect/mcp ./core/detect/ciagent ./core/detect/workflowcap ./core/detect/skills ./core/detect/agentcustom -run 'Test.*Purpose|Test.*Version|Test.*Fingerprint' -count=1`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add tests for purpose derivation from workflow/job names, MCP descriptions, package scripts, agent instructions, repo metadata, and explicit annotations.
- Add conflict tests proving purpose confidence downgrades or records conflicts deterministically.
- Add tests proving config fingerprints are byte-stable across checkout paths and line-ending differences where the parser canonicalizes content.
- Add tests for package-lock/version evidence and unknown-version fallback.
- Add schema tests for metadata fields in report, BOM, risk, inventory, and graph artifacts.

Matrix wiring:

- Fast lane: purpose/version/fingerprint unit and schema tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 5.1 scenario must show purpose and version/config metadata end to end.
- Cross-platform lane: fingerprint/path normalization on Windows smoke.
- Risk lane: `make test-hardening` for no secret material in fingerprints or metadata.
- Release/UAT lane: not required unless docs examples change.

Acceptance criteria:

- Each action path and BOM item has deterministic purpose metadata when source evidence exists, and omitted/unknown behavior when it does not.
- MCP, workflow, agent config, and package-script tools include version/config metadata where local evidence supports it.
- Config fingerprints are stable across repeated runs and do not include local absolute paths.
- Docs define purpose and version confidence levels.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added purpose and versioned config metadata to action-path, BOM, registry, and graph projections.
Semver marker override: [semver:minor]
Contract/API impact: Adds optional purpose/version/config fields to public JSON and schemas.
Versioning/migration impact: Additive v1 fields; older states render unknown/omitted values.
Architecture constraints: Detection extracts source evidence; Aggregation normalizes metadata; Risk and Report consume metadata without re-parsing raw files.
ADR required: yes
TDD first failing test(s): `TestPurposeDerivedFromWorkflowName`, `TestMCPVersionSourceFromPackageArg`, `TestConfigFingerprintIsPortable`
Cost/perf impact: medium if hashing many files; implementation must bound hashing to relevant config/workflow/package files.
Chaos/failure hypothesis: If a config cannot be parsed or hashed, Wrkr emits `config_source` and confidence/error metadata without failing unrelated scan/report paths.

### Story 2.3: Explicit Action Lineage Chain

Priority: P0

Tasks:

- Add an `action_lineage` object to action paths, Agent Action BOM items, evidence JSON, and registry entries with ordered links for repo, workflow/agent, action, credential, target, owner, approval, and proof.
- Link each lineage segment to deterministic node IDs and edge IDs from the control-path graph when present.
- Add buyer-readable labels and stable IDs for each lineage segment while preserving opaque IDs as join keys.
- Extend control-path graph nodes with purpose/version/config/lineage metadata where it belongs, without breaking graph version `1` consumers unless the implementation proposes a versioned graph bump.
- Add proof and approval lineage segments from control proof status, lifecycle/approval state, policy coverage, and Gait coverage projection where available.
- Ensure lineage redaction preserves segment order and in-artifact joinability.
- Update schemas, docs, and changelog.

Repo paths:

- `core/risk/action_paths.go`
- `core/aggregate/attackpath/graph.go`
- `core/report/agent_action_bom.go`
- `core/report/build.go`
- `core/report/types.go`
- `core/report/control_proof.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/control-path-graph.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/aggregate/attackpath ./core/risk ./core/report ./core/aggregate/controlbacklog -run 'Test.*Lineage|Test.*ControlPathGraph|Test.*ProofCoverage' -count=1`
- `go test ./core/cli -run 'TestReport.*Lineage|TestReport.*EvidenceJSON' -count=1`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add tests for complete lineage: repo -> workflow -> action -> credential -> target -> owner -> approval/proof.
- Add tests for partial lineage where credential, owner, or proof is missing, with explicit missing segment status.
- Add graph join tests proving lineage node/edge IDs resolve to control-path graph entries.
- Add redaction tests proving lineage labels redact but segment order and joins survive.
- Add schema tests for the lineage object.

Matrix wiring:

- Fast lane: control graph, action-path, report, and evidence JSON lineage tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 5.1 scenario must assert lineage chain fields in JSON and markdown/evidence output.
- Cross-platform lane: stable path labels and IDs on Windows smoke.
- Risk lane: `make test-hardening` for no-secret lineage and missing-proof behavior.
- Release/UAT lane: not required unless report examples change.

Acceptance criteria:

- Every BOM item with an action path includes deterministic lineage segments with status and evidence refs.
- Missing proof or approval appears as a lineage gap rather than disappearing from the path.
- Lineage fields remain joinable after customer/external redaction.
- The control-path graph and `action_lineage` agree on path, credential, target, and proof references.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added explicit action lineage from repo and workflow through credential, target, owner, approval, and proof in buyer-facing report artifacts.
Semver marker override: [semver:minor]
Contract/API impact: Adds `action_lineage` fields and optional graph metadata to public JSON schemas.
Versioning/migration impact: Additive v1 fields unless graph version bump is needed; graph consumers must ignore unknown fields.
Architecture constraints: Control graph remains Aggregation output; Reporting serializes graph refs and lineage labels without owning graph construction.
ADR required: yes
TDD first failing test(s): `TestActionLineageLinksGraphNodes`, `TestActionLineageShowsMissingProofSegment`, `TestRedactedLineagePreservesJoinability`
Cost/perf impact: low.
Chaos/failure hypothesis: If graph refs are missing or stale, lineage emits partial status with evidence refs and does not invent node IDs.

### Story 3.1: Mutable Endpoint Semantics

Priority: P1

Tasks:

- Add static mutable endpoint detection for OpenAPI specs, route files, MCP tool declarations, service/proto hints, and common endpoint verbs.
- Classify endpoint/action semantics as `read`, `write`, `delete`, `deploy`, `refund`, `payment`, `user_admin`, `data_export`, or `production_mutation` with confidence and evidence refs.
- Prefer structured parsing for OpenAPI JSON/YAML, route manifests, proto/service definitions, and MCP declarations. Use heuristic verb/path matching only as a fallback with lower confidence.
- Keep default behavior static-only: no live endpoint probing, no runtime traffic inspection, and no default network calls.
- Feed mutable endpoint semantics into inventory, action paths, control graph target/action nodes, Agent Action BOM reachability/lineage, registry entries, `risk_zone`, `review_burden`, and govern-first ranking.
- Ensure endpoint evidence does not expose customer identifiers, secrets, or local absolute paths.
- Add detector packages under `core/detect/openapi` and `core/detect/routes` if they do not already exist, following existing detector registry patterns.
- Update schemas, docs, detection matrix, and changelog.

Repo paths:

- `core/policy/productiontargets/builtin.go`
- `core/policy/productiontargets/targets.go`
- `core/detect/openapi`
- `core/detect/routes`
- `core/detect/mcp/detector.go`
- `core/detect/defaults/defaults.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/risk/govern_first_model.go`
- `core/aggregate/attackpath/graph.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/trust/detection-coverage-matrix.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/detect/openapi ./core/detect/routes ./core/detect/mcp ./core/detect/defaults -run 'Test.*Mutable|Test.*Endpoint|Test.*OpenAPI|Test.*Route' -count=1`
- `go test ./core/policy/productiontargets ./core/aggregate/inventory ./core/risk ./core/report -run 'Test.*Mutable|Test.*Endpoint|Test.*ProductionTarget|Test.*GovernFirst' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add OpenAPI fixtures for GET/read, POST/write, DELETE/delete, deployment, refund, payment, user-admin, and data-export endpoints.
- Add route-file fixtures for common Go, Node/Express, Next.js route, Rails, Django/FastAPI, and service/proto hints as implementation scope allows.
- Add MCP tool declaration fixtures with read-only and destructive annotations.
- Add confidence tests proving structured OpenAPI evidence outranks heuristic path/verb evidence.
- Add no-live-probe tests and no-secret serialization tests.
- Add ranking tests proving mutable production/payment/refund/admin endpoints influence govern-first priority.

Matrix wiring:

- Fast lane: detector parser, production target, risk, and report projection tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: Story 5.1 scenario includes OpenAPI/routes plus workflow credentials.
- Cross-platform lane: fixture path normalization and route globbing must pass Windows smoke.
- Risk lane: `make test-hardening` for ambiguous endpoint classification and no live probing; `make test-perf` if parser scope is broad.
- Release/UAT lane: not required unless public quickstart examples change.

Acceptance criteria:

- Static OpenAPI/routes/MCP fixtures produce mutable endpoint semantics with confidence and evidence refs.
- Mutable endpoint semantics appear in action paths, BOM, graph, registry, and report summary where linked to a tool/workflow path.
- Semantic-only endpoint hints remain lower confidence and cannot claim confirmed production mutation without linkage.
- Docs describe static-only endpoint classification and out-of-scope live runtime observation.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added static mutable endpoint semantics for action-path and report ranking across OpenAPI, routes, MCP declarations, and service hints.
Semver marker override: [semver:minor]
Contract/API impact: Adds endpoint semantics fields and detector outputs to public schemas and report artifacts.
Versioning/migration impact: Additive v1 fields; existing production target status remains compatible.
Architecture constraints: Detection parses endpoint declarations; Policy/production targets classify target categories; Risk ranks; Reporting serializes.
ADR required: yes
TDD first failing test(s): `TestOpenAPIPaymentEndpointClassifiesMutable`, `TestRouteDeleteEndpointAddsProductionMutationSignal`, `TestMutableEndpointInfluencesGovernFirstRanking`
Cost/perf impact: medium; parsers must be bounded by scan mode and file filters.
Chaos/failure hypothesis: Malformed OpenAPI or route files create parse issues/scan-quality signals and lower-confidence output, not false confirmed mutable paths.

### Story 3.2: Action Surface Registry And Govern-First Ranking Upgrade

Priority: P0

Tasks:

- Add a deterministic `action_surface_registry` artifact to report summary/evidence JSON that groups action paths by tool/server/workflow and includes owner, purpose, version/config metadata, authority, reachable actions, credentials, mutable endpoints, proof status, confidence lane, and graph refs.
- Build registry entries from inventory, action paths, BOM items, control graph refs, credential authority, purpose metadata, endpoint semantics, proof coverage, and runtime/Gait coverage where present.
- Add stable registry IDs and deterministic sorting by govern-first priority, org/repo, surface type, location, tool/server/workflow label, and path IDs.
- Upgrade govern-first ranking so standing usable credentials, release/write/deploy paths, mutable endpoints, MCP egress, production-impacting paths, missing proof, and confirmed/likely confidence lanes outrank generic tool inventory.
- Extend `control_state`, `risk_zone`, `review_burden`, `action_path_to_control_first`, and top-risk path selection with the new signals and reason codes.
- Ensure registry redaction preserves grouping and joinability.
- Update schemas, report docs, and changelog.

Repo paths:

- `core/report/build.go`
- `core/report/types.go`
- `core/report/agent_action_bom.go`
- `core/report/artifacts.go`
- `core/risk/govern_first_model.go`
- `core/risk/buyer_projection.go`
- `core/risk/action_paths.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/attackpath/graph.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/report ./core/aggregate/inventory ./core/aggregate/attackpath -run 'Test.*Registry|Test.*GovernFirst|Test.*Ranking|Test.*Mutable|Test.*Credential' -count=1`
- `go test ./core/cli -run 'TestReport.*Registry|TestReport.*DesignPartner|TestReport.*EvidenceJSON' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add registry grouping tests for MCP server, CI workflow, package script, and agent config surfaces.
- Add deterministic sorting and stable ID tests.
- Add ranking tests comparing standing release credential, mutable endpoint, MCP egress, generic write path, and dependency-only inventory.
- Add redaction tests for registry entries.
- Add evidence JSON and schema contract tests for `action_surface_registry`.

Matrix wiring:

- Fast lane: registry builder, risk ranking, report artifact, and CLI evidence JSON tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 5.1 scenario asserts registry grouping and top paths.
- Cross-platform lane: stable registry IDs and path normalization on Windows smoke.
- Risk lane: `make test-hardening` for no-secret registry output and redaction; `make test-perf` if grouping is expensive.
- Release/UAT lane: not required unless public examples change.

Acceptance criteria:

- `wrkr report --json --evidence-json` includes `action_surface_registry` when action paths exist.
- Registry entries group related paths by surface and show owner, purpose, version/config, credentials, actions, proof, and confidence lane.
- `action_path_to_control_first` selects mutable/credentialed/release/production paths ahead of generic inventory when evidence supports it.
- Redacted registry artifacts retain stable grouping and path joins.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added an action surface registry and upgraded govern-first ranking for credentialed, mutable, release, MCP egress, and production-impacting paths.
Semver marker override: [semver:minor]
Contract/API impact: Adds a public registry artifact and ranking reason fields to report/evidence schemas.
Versioning/migration impact: Additive v1 fields; older reports omit registry.
Architecture constraints: Registry is Reporting/Aggregation projection over existing facts; it must not re-run detectors or mutate saved scan state.
ADR required: yes
TDD first failing test(s): `TestActionSurfaceRegistryGroupsWorkflowPaths`, `TestGovernFirstRanksStandingReleaseCredentialAboveGenericTool`, `TestRegistryRedactionPreservesSurfaceJoin`
Cost/perf impact: low to medium depending on graph joins; keep O(paths + graph nodes + BOM items).
Chaos/failure hypothesis: If graph refs or BOM items are missing, registry emits partial coverage status and does not block report generation unless schema construction fails.

### Story 4.1: Design Partner Summary And Remediation Playbooks

Priority: P1

Tasks:

- Add `--template design-partner-summary` or `--share-profile design-partner` after choosing the smallest CLI/API surface that fits existing report patterns.
- Render the top 5-10 validated findings with plain-language fields for problem, likely explanation, threat, recommended control, confidence lane, proof gap, credential authority, mutable endpoint, owner, purpose, and lineage summary.
- Suppress noisy policy-count sections in design-partner mode while preserving machine-readable evidence JSON and deterministic artifact paths.
- Add path-specific remediation generation for standing credentials, release gates, owner confirmation, policy binding, CODEOWNERS approval, token scope restriction, proof attachment, runtime evidence rescan, endpoint review, and stale/unknown evidence.
- Route remediation through risk/report projection so BOM, registry, control backlog, and design-partner markdown agree.
- Ensure copy does not overclaim runtime control, live endpoint observation, or Gait enforcement.
- Update CLI usage, docs, schemas, examples, and changelog.

Repo paths:

- `core/report/build.go`
- `core/report/types.go`
- `core/report/render_markdown.go`
- `core/report/agent_action_bom.go`
- `core/risk/buyer_projection.go`
- `core/risk/action_paths.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/cli/report.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`
- `README.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/report ./core/aggregate/controlbacklog -run 'Test.*Remediation|Test.*DesignPartner|Test.*Playbook' -count=1`
- `go test ./core/cli -run 'TestReport.*Template|TestReport.*DesignPartner|TestReport.*Usage' -count=1`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add CLI contract tests for valid/invalid design-partner template or share profile.
- Add markdown golden tests for top 5-10 findings with problem, likely explanation, threat, and recommended control.
- Add remediation table tests for each action type and gap type.
- Add no-overclaim tests that check static-boundary wording in design-partner markdown.
- Add schema tests for any new summary fields.

Matrix wiring:

- Fast lane: report template, remediation, CLI contract, and markdown golden tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 5.1 scenario asserts design-partner markdown and evidence JSON.
- Cross-platform lane: markdown wrapping and artifact paths on Windows smoke.
- Risk lane: `make test-hardening` for invalid template/share-profile fail-closed behavior and no-secret output.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=local` if docs examples become user-facing.

Acceptance criteria:

- A design-partner report renders a concise top-path section without noisy policy bulk.
- Recommended controls are path-specific and match BOM/control backlog remediation for the same `path_id`.
- Static posture boundaries are explicit in markdown and docs.
- Invalid template/share-profile inputs fail with exit `6`.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added a buyer-ready design partner report mode with path-specific remediation playbooks for credential, release, endpoint, owner, policy, and proof gaps.
Semver marker override: [semver:minor]
Contract/API impact: Adds CLI template/share-profile behavior and optional JSON fields for design-partner summaries/remediation.
Versioning/migration impact: Additive CLI/report behavior; existing templates remain unchanged.
Architecture constraints: Reporting renders deterministic templates from Risk/Backlog remediation facts. It must not invent new findings or execute remediation.
ADR required: no
TDD first failing test(s): `TestReportDesignPartnerTemplateRendersTopValidatedFindings`, `TestRemediationForStandingReleaseCredential`, `TestDesignPartnerReportDoesNotClaimRuntimeControl`
Cost/perf impact: low.
Chaos/failure hypothesis: If top-path evidence is partial, design-partner output shows confidence/proof gaps and does not promote the path to confirmed language.

### Story 4.2: Configurable Redaction And Expanded Share Profiles

Priority: P1

Tasks:

- Add explicit redaction selectors such as `owners`, `repos`, `paths`, `credential-subjects`, `authors`, `filesystem`, `providers`, `proof-refs`, and `graph-refs`, with deterministic validation and documented defaults.
- Add share profiles after confirming final names: `internal`, `customer-redacted`, `external-redacted`, `investor-safe`, and optionally `design-partner`; preserve compatibility for existing `public`.
- Implement redaction selection through a dedicated report redaction module if the current `core/report/build.go` sanitizer should be split for maintainability.
- Apply redaction consistently to report summary, Agent Action BOM, action paths, registry entries, control graph, lineage, control backlog, evidence JSON, markdown/PDF, top findings, proof refs, runtime refs, and source privacy metadata.
- Preserve stable pseudonyms and joinability inside one artifact set.
- Add metadata describing selected fields, profile, redaction version, and policy summary.
- Ensure raw local filesystem roots and user home paths are redacted when `filesystem` or profiles requiring filesystem redaction are active.
- Update CLI usage, schemas, docs, and changelog.

Repo paths:

- `core/report/build.go`
- `core/report/redaction.go`
- `core/report/types.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/cli/report.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/control-path-graph.schema.json`
- `docs/commands/report.md`
- `README.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/report -run 'Test.*Redact|Test.*ShareProfile|Test.*Pseudonym|Test.*Lineage|Test.*Registry' -count=1`
- `go test ./core/cli -run 'TestReport.*Redact|TestReport.*ShareProfile|TestReport.*Invalid' -count=1`
- `make test-contracts`
- `make test-hardening`
- `scripts/check_docs_cli_parity.sh`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add selector parser tests for valid, duplicate, unknown, and conflicting redaction fields.
- Add profile default tests for customer/external/investor/design-partner modes.
- Add artifact-wide tests proving selected fields are redacted in summary, BOM, registry, graph, lineage, markdown, and evidence JSON.
- Add stable pseudonym tests within one artifact set and no-local-path leakage tests.
- Add schema tests for redaction metadata.

Matrix wiring:

- Fast lane: redaction module, report artifact, and CLI contract tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 5.1 scenario asserts redacted design-partner/customer artifacts.
- Cross-platform lane: filesystem path redaction on Windows and POSIX paths.
- Risk lane: `make test-hardening` required for no-secret/no-local-path output and fail-closed invalid selectors.
- Release/UAT lane: not required unless public examples change.

Acceptance criteria:

- Users can select redaction fields and share profiles via `wrkr report`.
- Redacted artifacts preserve joinability and stable pseudonyms for paths, graph refs, registry entries, and lineage segments.
- Selected sensitive fields do not appear in generated markdown, JSON, PDF text, or evidence JSON.
- Invalid selectors fail with `invalid_input` and exit `6`.

Changelog impact: required
Changelog section: Security
Draft changelog entry: [semver:minor] Added configurable report redaction selectors and expanded share profiles for safer customer, external, design-partner, and investor sharing.
Semver marker override: [semver:minor]
Contract/API impact: Adds CLI flags, share-profile enum values, redaction metadata, and artifact-wide redaction behavior.
Versioning/migration impact: Additive CLI/schema behavior; existing `internal`, `public`, and `customer-redacted` behavior must remain compatible or be explicitly documented.
Architecture constraints: Redaction belongs in Reporting serialization; it must not mutate saved scan state, inventory, proof chains, or source artifacts.
ADR required: yes
TDD first failing test(s): `TestReportRedactOwnersReposPathsCredentialSubjects`, `TestInvestorSafeProfileRedactsFilesystemAndAuthors`, `TestRedactionPreservesLineageJoinability`
Cost/perf impact: low.
Chaos/failure hypothesis: If any selected field cannot be redacted consistently, report generation fails closed rather than emitting a mixed sensitive artifact.

### Story 5.1: Purpose Credential Endpoint And Redaction Scenarios

Priority: P0

Tasks:

- Add or extend Wrkr scenario fixtures that combine MCP servers, CI workflows, OpenAPI/routes, service-token references, owner metadata, purpose annotations, versioned config, mutable endpoints, missing approval/proof, runtime/Gait sidecars where appropriate, and sensitive owner/repo/path names.
- Add expected outputs covering scan JSON, report JSON, Agent Action BOM JSON, evidence JSON, action surface registry, control-path graph, design-partner markdown, redacted artifacts, and remediation playbooks.
- Update `internal/scenarios` and `internal/acceptance` so the new scenario validates the end-to-end customer-facing output contract.
- Include fixtures for all confidence lanes: confirmed action path, likely action path, semantic review candidate, and context-only.
- Include fake credential references only; no real secret values.
- Add coverage-map entries for purpose, credential authority, version/config metadata, mutable endpoint semantics, lineage, registry, design-partner summary, and redaction.
- Keep expected artifacts byte-stable and path-portable.
- Update scenario docs and changelog.

Repo paths:

- `scenarios/wrkr`
- `internal/scenarios`
- `internal/acceptance`
- `internal/scenarios/coverage_map.json`
- `scripts/validate_scenarios.sh`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `docs/commands/scan.md`
- `CHANGELOG.md`

Run commands:

- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./internal/acceptance -run 'Test.*AgentActionBOM|Test.*DesignPartner|Test.*Registry|Test.*Redaction' -count=1`
- `make test-scenarios`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add scenario fixture repos with `.mcp.json` or tool-specific MCP configs, workflow files, OpenAPI/routes, owner metadata, and missing proof/approval evidence.
- Add expected JSON/markdown artifacts for unredacted and redacted report modes.
- Add assertions for credential authority fields, purpose metadata, version/config fingerprint, mutable endpoint semantics, confidence lane, lineage, registry grouping, ranking, remediation, and redaction.
- Add negative assertions proving no raw secret values, local absolute paths, or sensitive fixture names leak in redacted profiles.
- Add deterministic repeat-run checks for fixture output.

Matrix wiring:

- Fast lane: focused scenario contract/unit fixtures if available.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: `scripts/validate_scenarios.sh`, `make test-scenarios`, and targeted `internal/acceptance`.
- Cross-platform lane: scenario paths and redaction on Windows smoke.
- Risk lane: `make test-hardening` for no-secret/no-local-path assertions.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=local` if acceptance scorecard coverage changes.

Acceptance criteria:

- One outside-in scenario proves purpose, versioned config, credential authority, mutable endpoint semantics, lineage, registry, missing proof, and redaction in a single scan/report flow.
- Scenario expected outputs include both raw internal and redacted buyer/customer views.
- Scenario validation rejects real secret-looking values and local absolute checkout paths.
- Coverage map documents the product behavior each fixture validates.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added outside-in Wrkr scenarios for purpose, credential authority, mutable endpoints, action lineage, registry output, design-partner reports, and redaction.
Semver marker override: [semver:minor]
Contract/API impact: Adds scenario coverage and may add expected artifact fixtures for new public fields.
Versioning/migration impact: No runtime migration; scenario expected outputs become release-blocking specifications.
Architecture constraints: Scenario fixtures are specifications and must not be tailored to implementation internals. Existing expected outcomes require human review if modified.
ADR required: no
TDD first failing test(s): `TestScenarioContractsIncludesBuyerActionRegistryHardening`, `TestWrkrScenarioDesignPartnerActionRegistry`, `TestDesignPartnerRedactionScenarioNoSensitiveLeakage`
Cost/perf impact: medium for scenario runtime; keep fixtures focused and deterministic.
Chaos/failure hypothesis: If the scenario output is partial due missing optional runtime evidence, expected artifacts must show degraded confidence rather than failing open.

### Story 5.2: Documentation And Buyer Language Update

Priority: P1

Tasks:

- Update scan/report docs to explain static action registry, purpose and version metadata, credential authority, mutable endpoint semantics, confidence lanes, lineage, redaction, proof gaps, and design-partner summaries.
- Update the detection coverage matrix to include OpenAPI/routes, mutable endpoint categories, purpose/version sources, credential authority fields, confidence lanes, and redaction guarantees.
- Update README buyer language so Wrkr's value is clear while preserving the deterministic static-boundary disclaimer.
- Add sample snippets for an "agent registry + action exposure map" and a "design partner summary" using deterministic fixture-safe values.
- Update schemas documentation for new report/BOM/risk/control-graph fields.
- Ensure docs do not claim runtime enforcement, live endpoint probing, complete vulnerability assessment, or Gait control unless runtime evidence or Gait sidecars are explicitly present.
- Update `CHANGELOG.md` with documentation and public contract changes.

Repo paths:

- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `docs/trust/detection-coverage-matrix.md`
- `schemas/v1/README.md`
- `README.md`
- `product/wrkr.md`
- `product/dev_guides.md`
- `CHANGELOG.md`

Run commands:

- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/run_docs_smoke.sh`
- `make test-docs-consistency`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add or update docs consistency tests for new report flags/templates/share profiles.
- Add docs storyline checks for static-boundary language and no-overclaim phrasing.
- Add schema README checks if existing docs tests cover schema index references.
- Add link checks for new command and schema references.

Matrix wiring:

- Fast lane: docs consistency and CLI parity scripts.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 5.1 scenario docs examples must match generated fixture artifacts.
- Cross-platform lane: not required beyond existing docs smoke.
- Risk lane: not required unless docs examples affect security claims; run `make test-hardening` if no-overclaim tests live there.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=local` if README quickstart or public command examples change.

Acceptance criteria:

- Docs explain each new field group with examples and out-of-scope limits.
- README buyer language highlights action registry and exposure mapping without claiming runtime enforcement.
- Command docs match CLI help and schema behavior.
- Detection matrix lists confidence and source limitations for purpose/version/credential/endpoint/redaction surfaces.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: [semver:minor] Updated buyer-facing docs for action registry, credential authority, mutable endpoint semantics, confidence lanes, redaction, proof gaps, and design-partner reports.
Semver marker override: [semver:minor]
Contract/API impact: Documentation updates public CLI/schema behavior and buyer language.
Versioning/migration impact: No migration.
Architecture constraints: Docs must stay aligned with Wrkr's static deterministic "See" boundary and must not document Gait/Axym behavior as Wrkr behavior.
ADR required: no
TDD first failing test(s): `TestDocsReportFlagsIncludeDesignPartnerAndRedact`, `TestDocsStorylineDoesNotOverclaimRuntimeControl`, `TestSchemaReadmeListsActionSurfaceRegistry`
Cost/perf impact: low.
Chaos/failure hypothesis: If docs and CLI drift, docs parity scripts fail before release.

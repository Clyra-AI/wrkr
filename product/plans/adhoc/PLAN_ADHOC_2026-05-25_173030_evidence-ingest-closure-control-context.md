# Adhoc Plan: Evidence Ingest, Closure, And Enterprise Control Context

Date: 2026-05-25
Profile: `wrkr`
Slug: `evidence-ingest-closure-control-context`
Recommendation source: user-provided Sprint 2 recommendations covering external ownership and approval evidence ingest, evidence-source precedence, freshness and expiry, customer declarations, contradiction detection, accepted-risk governance, branch protection and deployment constraints, path-specific closure guidance, lifecycle ownership prioritization, and evidence completeness scoring.

All paths in this plan are repo-relative. User-provided absolute checkout paths have been normalized to repo-relative paths. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, scenario, or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control loop. This plan must not add Axym compliance-engine behavior, Gait runtime enforcement, scan-time LLM calls, live endpoint probing, or default network enrichment.
- External enterprise evidence is accepted only as local, deterministic, user-provided sidecars or repo-local policy/config. Wrkr must not call GitHub, Jira, ServiceNow, Backstage, cloud providers, or customer systems during scan, risk, proof, report, or ingest paths unless a future opt-in command explicitly says it is non-default.
- Sidecar evidence must be schema-validated, normalized, redacted where needed, sorted deterministically, and correlated by stable keys: repo, service, workflow, environment, path, action path ID, control path graph node, and control path graph edge.
- Canonical evidence-source precedence is locked as: verified provider/exported evidence, signed declarations, repo-local policy/config, app catalog ownership, git/review inference, then naming-convention inference.
- Precedence must not silently discard conflicts. Lower-precedence evidence remains traceable when it disagrees with the chosen value, and outputs must include deterministic conflict reason codes.
- Freshness metadata is first-class evidence metadata. Canonical fields are `source`, `observed_at`, `valid_until` or `max_age`, `issuer`, `confidence`, and freshness state `fresh`, `stale`, `expired`, or `unknown`.
- Customer declarations are declared evidence, not invisible assumptions. `wrkr-control-declarations.yaml` must be versioned, validated, redaction-aware, and contradiction-checked before influencing owners, target classes, accepted risks, exceptions, controls, or closure status.
- Accepted risk and suppression are governance queues, not deletion mechanisms. Suppressed or accepted items remain auditable through appendix, accepted-risk queue, proof/evidence refs, expiry, owner, scope, and rescan behavior.
- Branch protection, protected environments, required checks, deployment approvals, freeze windows, kill switches, and security gates are control evidence only when represented by deterministic repo-local config or provider-exported sidecars.
- Contradictions are high-value findings. A declared non-production path that references production credentials, production environments, release workflows, deployment commands, or production-target policies must route to contradiction/control-first behavior.
- Closure guidance must be path-specific. Wrkr should say which evidence would move a path toward `verified`, not repeat generic "missing approval" language.
- Lifecycle and ownership priority must be evidence-state based. Ownerless, unresolved-owner, inferred-owner, inactive-but-credentialed, and pending-lifecycle items must retain deterministic severity, SLA, closure criteria, and credential context.
- Evidence completeness scoring means "how much evidence supports this conclusion", not "how safe this path is". Low completeness must not be rendered as low risk.
- Existing API contracts remain locked: deterministic outputs, no secret extraction, no scan-data exfiltration by default, signed proof chain integrity, `--json` machine output, `--explain` rationale, `--quiet` CI-friendly operation, and exit codes `0` through `8`.
- Changelog entries are required for implementation PRs because this work changes public report JSON, schemas, CLI ingest behavior, markdown reports, evidence semantics, and governance docs.

## Current Baseline (Observed)

- `core/risk/evidence_state.go` already defines control resolution states and evidence states, derives approval/owner/proof/runtime/target/credential evidence states, decorates action paths from attribution control metadata, and keeps compatibility with existing action-path projection.
- `core/risk/evidence_language.go` centralizes buyer-facing labels for evidence states and runtime evidence absence, which is the right surface for closure and contradiction wording.
- `core/attribution/control_metadata.go` already loads `.wrkr/provenance/control-metadata.json` and `.wrkr/provenance/control-declarations.json` as coarse path-level metadata, but it does not yet model typed external source classes, freshness, issuer, confidence, precedence, branch/environment constraints, or contradiction detail.
- `core/attribution/provider_metadata.go` already loads deterministic provider provenance sidecars from `.wrkr/provenance/source-metadata.json`, `.wrkr/provenance/github-event.json`, and `.wrkr/provenance/gitlab-event.json`, and sorts candidates by source priority and time. This is a natural extension point for provider-exported control and approval metadata.
- `core/ingest/ingest.go` currently models runtime evidence bundles with evidence classes such as `policy_decision`, `approval`, `jit_credential`, `freeze_window`, `kill_switch`, `action_outcome`, and `proof_verification`; correlation statuses are `matched`, `unmatched`, `stale`, and `conflict`. It does not yet ingest ownership, app catalog, ticket approval, branch protection, deployment environment, or customer declaration evidence.
- `core/cli/ingest.go` accepts one runtime evidence input artifact and writes a managed `runtime-evidence.json` next to state. It does not yet support typed sidecar ingest, declaration validation, accepted-risk artifacts, or multi-artifact correlation summaries.
- `core/owners/owners.go` resolves ownership from CODEOWNERS, custom owner maps, service catalogs, Backstage catalogs, provider metadata, and repo fallback. It has explicit, inferred, conflicting, and missing owner states, but no freshness-aware source precedence ledger or per-source conflict reason payload.
- `core/detect/gaitpolicy/detector.go` parses Gait policy YAML and detects blocked tools. It does not yet parse branch protection, protected environments, required checks, freeze windows, kill switches, deployment constraints, or production-target declarations from policy/config.
- `core/detect/workflowcap/analyze.go` already extracts workflow capabilities, deployment environments, approval source, proof requirements, headless execution, dangerous flags, and secret access. These facts can support contradiction detection and deployment constraint evidence when paired with sidecars or policy.
- `core/aggregate/controlbacklog/controlbacklog.go` already emits evidence states, owner state, queue, remediation, closure criteria, control state, risk zone, review burden, and graph refs. It does not yet expose accepted-risk queues, lifecycle control queues, typed closure requirements, suppression visibility, contradiction classes, or completeness scores.
- `core/aggregate/scanquality/scanquality.go` already emits compact coverage and absence claims. It does not yet calculate per-path completeness across discovery, authority, blast radius, control, runtime evidence, and proof.
- `core/aggregate/inventory/inventory.go` and neighboring inventory packages already carry credential authority, governance controls, path context, trust depth, mutable endpoint semantics, and lifecycle-adjacent inventory data. These are required inputs for lifecycle queue and completeness scoring.
- `core/report/agent_action_bom.go`, `core/report/control_proof.go`, `core/report/render_markdown.go`, and `core/report/gait_coverage.go` already render action-path BOM, proof coverage, markdown, runtime policy, graph refs, evidence refs, and compact scan coverage. They need typed closure guidance, accepted-risk visibility, lifecycle queue, contradictions, and completeness fields.
- Schemas under `schemas/v1` already cover Agent Action BOM, report summary, risk report, findings, evidence bundle, policy configs, proof outputs, inventory, and export artifacts. There are no dedicated v1 schemas yet for external evidence sidecars, control declarations, accepted risk/suppression, branch/deployment constraints, or completeness scoring.

## Exit Criteria

- External ownership, approval, app catalog, ticket approval, branch protection, deployment environment, policy record, customer owner map, and control constraint sidecars are schema-backed, deterministically loaded, redacted where needed, and correlated to repos, services, workflows, environments, paths, action paths, graph nodes, and graph edges.
- Evidence-source precedence is implemented once and consumed by owners, ingest, control backlog, buyer projection, and reports. Disagreements emit stable conflict reason codes and preserve lower-precedence evidence refs.
- Evidence freshness metadata appears on declared/imported evidence, control backlog items, Agent Action BOM items, report summaries where useful, evidence bundle outputs, and relevant schemas. Stale or expired evidence cannot be rendered as verified without a reason.
- `wrkr-control-declarations.yaml` is a versioned, validated, documented customer declaration artifact for owner mappings, target classes, accepted internal tooling, approved exceptions, non-prod declarations, control evidence links, and expiry dates.
- Invalid, stale, expired, contradicted, or unsupported declaration input fails closed with deterministic error class and exit code: invalid input as `6`, schema/policy violations as `3`, and unsafe output behavior as `8`.
- Contradictions such as non-prod declarations with production secrets, production environment names, deployment commands, release workflows, production-target policies, or standing credentials route into high-value findings, control backlog rows, Agent Action BOM items, markdown, and closure guidance.
- Accepted-risk and suppression records require reason, owner, expiry, scope, evidence state, rescan behavior, and visibility behavior. They move items to accepted-risk or appendix views and never silently remove evidence from JSON, markdown, proof, or export surfaces.
- Branch protections, protected environments, deployment approvals, required checks, security gates, freeze windows, and kill switches are first-class evidence classes in risk/control projection, reports, and evidence bundle outputs.
- Every governable path has deterministic closure requirements that name the specific evidence needed to move state toward `verified`, such as owner assignment, approval attachment, policy reference, provider export, JIT credential proof, deployment constraint, or declared internal tooling acceptance.
- Lifecycle ownership control queue promotes ownerless, unresolved-owner, inferred-owner, inactive-but-credentialed, pending-lifecycle, and revoked-but-active paths with severity, owner evidence state, credential status, recommended action, SLA, and closure criteria.
- Per-path evidence completeness scoring exists for discovery, authority, blast radius, control, runtime evidence, and proof. Reports distinguish "safe" from "insufficient evidence" and tests prevent low completeness from being rendered as low risk.
- Scenario, contract, hardening, chaos, schema, docs parity, and v1 acceptance lanes cover the new public contracts and fail-closed behavior.

## Public API and Contract Map

- CLI contracts:
  - Preserve existing exit codes: `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, and `8` unsafe operation blocked.
  - Extend `wrkr ingest --json` with deterministic local-file inputs for typed evidence bundles only. Candidate flags should be additive, such as `--type`, repeated `--input`, or `--declarations`, and must keep existing runtime evidence behavior compatible.
  - Extend `wrkr scan --json` only with additive declaration/provider metadata loading. Any new flags must be local-path based, fail closed on invalid input, and avoid default network access.
  - Extend `wrkr report --json`, `wrkr report --md`, and `wrkr export --json` with additive accepted-risk, closure guidance, lifecycle queue, contradiction, freshness, branch/deployment constraint, and completeness fields.
- JSON and schema contracts:
  - New sidecar schemas should live under `schemas/v1`, with likely paths such as `schemas/v1/evidence/external-control-evidence.schema.json`, `schemas/v1/evidence/control-declarations.schema.json`, `schemas/v1/evidence/accepted-risk.schema.json`, and branch/deployment constraint definitions either colocated under `schemas/v1/evidence` or `schemas/v1/policy`.
  - Additive shared evidence metadata fields include `source`, `source_type`, `source_precedence`, `issuer`, `observed_at`, `valid_until`, `max_age`, `confidence`, `freshness_state`, `evidence_state`, `evidence_refs`, `redaction`, and `conflict_reasons`.
  - Additive output fields include `precedence_decision`, `source_conflicts`, `freshness_state`, `freshness_reasons`, `accepted_risk`, `suppression`, `closure_requirements`, `lifecycle_queue`, `constraint_evidence`, `contradiction_state`, `contradiction_reasons`, and `evidence_completeness`.
  - Compatibility aliases from existing evidence-state work may remain in v1, but new source-of-truth fields must drive aliases rather than parallel logic.
- Detection and ingest contracts:
  - Structured parsers are required for JSON/YAML/TOML. YAML that affects proof/evidence contracts should remain compatible with `gopkg.in/yaml.v3`.
  - Sidecars are data imports, not remote adapters. Provider evidence is "verified" only when a signed/exported provider artifact or proof-linked sidecar supports that state.
  - Evidence correlation must not extract raw secrets. Credential references remain presence/context signals only.
- Risk and aggregation contracts:
  - `core/risk` owns contradiction, precedence projection, control/evidence state consistency, and completeness semantics.
  - `core/aggregate/controlbacklog` owns queueing, accepted-risk visibility, lifecycle control queue, closure requirements, and item-level presentation fields.
  - `core/owners` owns owner-specific source resolution and conflict detail, but should consume common precedence/freshness helpers instead of forking rules.
- Proof and evidence output contracts:
  - Proof record types stay consistent with Wrkr and `Clyra-AI/proof` primitives: `scan_finding`, `risk_assessment`, `approval`, and `lifecycle_transition`.
  - Evidence bundles should include imported evidence metadata and freshness/closure summaries without breaking chain verification.
  - Signed or provider-exported artifacts must be represented by refs/digests and no private raw payloads in redacted exports.
- Documentation contracts:
  - Docs must explain sidecar formats, declarations, precedence, freshness, contradictions, accepted-risk behavior, closure criteria, lifecycle queues, and completeness scoring with examples based on profile commands: `wrkr scan --json`, `wrkr regress run --baseline <baseline-path> --json`, and `wrkr score --json`.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/ingest.md`
  - `docs/commands/report.md`
  - `docs/commands/export.md`
  - `docs/commands/evidence.md`
  - `docs/trust/contracts-and-schemas.md`
  - `docs/trust/detection-coverage-matrix.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Scenario and contract docs impacted:
  - `internal/scenarios/coverage_map.json`
  - scenario fixtures under `scenarios/wrkr/**`
  - CLI/report/schema acceptance tests under `internal/acceptance`
  - contract tests under `testinfra/contracts`
- OSS trust baseline:
  - Example sidecars must use fake orgs, fake repos, fake owners, fake tickets, fake URLs, fake services, and fake provider exports.
  - No generated customer reports, local scan outputs, runtime evidence bundles, proof chains, credentials, private provider exports, or transient state files should be committed outside deterministic fixtures.
  - Docs must clearly say Wrkr consumes local evidence exports; it does not default to querying provider APIs or customer systems.
  - Redacted exports must preserve audit usefulness while removing customer-specific owners, tickets, URLs, service names, or repo names when an anonymized/share profile requests it.
- Docs must answer:
  - How to prepare external evidence sidecars.
  - How source precedence is applied when CODEOWNERS, teams, app catalog, provider exports, tickets, and customer maps disagree.
  - How freshness state affects verified, declared, inferred, unknown, and contradictory evidence.
  - How accepted-risk and suppression differ from deleting or hiding findings.
  - What concrete evidence closes each common governance gap.
  - How completeness scoring differs from risk scoring.

## Recommendation Traceability

| Recommendation / Finding | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| 11. External ownership and approval evidence ingest | P0 | Stories 1.1, 1.2 | Repo-local files are not the only valid ownership or approval source. | Add typed sidecar schemas and deterministic correlation across repo, service, workflow, environment, path, and graph nodes. | Enterprise evidence can become auditable Wrkr input without network exfiltration. |
| 12. Evidence source precedence rules | P0 | Story 2.1 | Multiple sources may disagree. | Implement a shared precedence resolver with conflict reasons and refs. | Stable, explainable outcomes instead of source-order accidents. |
| 13. Evidence freshness and expiry | P0 | Story 2.2 | Owner maps, approvals, exceptions, and snapshots become stale. | Track source, observed time, validity, issuer, confidence, and freshness state. | Customers can tell verified evidence from expired declarations. |
| 14. Customer declaration governance | P0 | Story 2.3 | Declarations should be visible evidence, not hidden assumptions. | Add `wrkr-control-declarations.yaml`, validation, redaction, contradiction checks, and docs. | Customer context becomes portable and reviewable. |
| 15. Contradiction detection | P0 | Story 2.4 | Contradictions are high-value enterprise findings. | Compare declarations, metadata, target class, credentials, environments, workflow permissions, deployments, and production policies. | Buyers see the places where evidence disagrees, not just missing fields. |
| 16. Accepted risk / suppression workflow | P1 | Story 3.1 | Customers need audit-safe suppression. | Require reason, owner, expiry, scope, evidence state, rescan, and visibility. | Suppression reduces noise without erasing audit context. |
| 17. Branch protection and deployment constraint evidence | P0 | Story 1.3 | Control is not just a workflow saying approval exists. | Model protections, environments, checks, gates, freeze windows, and kill switches as evidence classes. | Reports can distinguish declared approvals from enforced delivery constraints. |
| 18. Path-specific closure evidence guidance | P1 | Story 4.1 | Customers need closure criteria, not repetitive gap language. | Generate closure requirements by path type, evidence state, target, and contradiction. | Operators know the next artifact needed to close each item. |
| 19. Lifecycle and ownership prioritization | P1 | Story 3.2 | Ownership risk must be evidence-state based. | Add lifecycle queue with severity, owner evidence state, credential status, action, SLA, and closure. | Ownerless and stale-lifecycle paths are prioritized cleanly. |
| 20. Evidence completeness scoring | P1 | Story 4.2 | Customers need to distinguish safe from not enough evidence. | Score discovery, authority, blast radius, control, runtime evidence, and proof per path. | Buyer reports become more honest and less binary. |

## Test Matrix Wiring

- Fast lane:
  - Focused unit tests for sidecar schema normalization, precedence decisions, freshness math, declaration validation, contradiction classification, accepted-risk scope matching, lifecycle queue construction, closure requirement generation, and completeness score calculation.
  - Candidate command: `go test ./core/ingest ./core/owners ./core/attribution ./core/risk ./core/aggregate/controlbacklog ./core/aggregate/scanquality ./core/report ./core/config -count=1`.
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane:
  - Windows smoke must cover path normalization for sidecars, declaration loading, branch/environment evidence, accepted-risk scopes, markdown rendering, JSON schema validation, and deterministic sorting without POSIX-only assumptions.
- Risk lane:
  - `make test-hardening` for fail-closed invalid sidecars, expired evidence, contradictions, redaction, unsafe artifact paths, and no-secret serialization.
  - `make test-chaos` for partial provider exports, unreadable declaration files, mixed fresh/stale sources, conflict storms, parse failures, and corrupt accepted-risk records.
  - `make test-perf` if path-level correlation or completeness scoring materially changes scan/report runtime.
- Release/UAT lane:
  - `make test-release-smoke`
  - `scripts/run_v1_acceptance.sh --mode=release` when schemas, docs examples, or report examples change.
- Gating rule:
  - Wave 1 must land before declarations, precedence, suppression, lifecycle, or completeness stories depend on external sidecars.
  - Wave 2 must land before reports can call external evidence verified or contradictory.
  - Wave 3 must land before accepted-risk and lifecycle queues affect primary/appendix visibility.
  - Wave 4 must land before markdown or exports claim path closure guidance or completeness scores.
  - Wave 5 docs and contract updates must ship before any release notes advertise Sprint 2 enterprise-control context.

## Minimum-Now Sequence

- Wave 1 - External evidence foundation:
  - Story 1.1 adds schemas and normalized data model for external control evidence sidecars.
  - Story 1.2 wires ownership, approval, app catalog, ticket, and policy evidence into ingest, attribution, owners, and graph/path correlation.
  - Story 1.3 models branch protection and deployment constraints as first-class evidence.
- Wave 2 - Governance semantics:
  - Story 2.1 implements source precedence and conflict reasons.
  - Story 2.2 implements freshness and expiry state.
  - Story 2.3 implements customer declaration governance.
  - Story 2.4 implements contradiction detection.
- Wave 3 - Queues and visibility:
  - Story 3.1 implements accepted-risk and suppression governance.
  - Story 3.2 implements lifecycle and ownership control queue.
- Wave 4 - Closure and completeness:
  - Story 4.1 implements path-specific closure evidence guidance.
  - Story 4.2 implements evidence completeness scoring.
- Wave 5 - Contracts, scenarios, and docs:
  - Story 5.1 updates schemas, docs, scenarios, changelog, and release-facing examples across the full Sprint 2 surface.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No default network calls to GitHub, Jira, ServiceNow, Backstage, cloud providers, CI providers, or customer systems.
- No live endpoint probing or runtime enforcement.
- No Axym product logic, Gait runtime control, or compliance-engine behavior in Wrkr.
- No extraction or serialization of raw secret values.
- No removal of existing v1 JSON fields without an explicit versioned migration.
- No hidden suppression, deletion, or reclassification of findings without retained audit evidence.

## Epic 1: External Evidence Foundation

Objective: give Wrkr a deterministic, schema-backed way to load enterprise evidence that lives outside repo-local AI tool files while preserving local-first privacy and stable output contracts.
Traceability: Recommendations 11 and 17.

### Story 1.1: Define External Control Evidence Sidecar Schemas And Canonical Model

Priority: P0
Recommendation coverage: 11, 17

Tasks:
- Define a canonical external control evidence model for ownership, approvals, provider exports, app catalog ownership, ticket approvals, branch protection, deployment environment, required checks, security gates, freeze windows, kill switches, policy records, and customer owner maps.
- Add JSON schemas under `schemas/v1` for typed sidecars and shared evidence metadata, including source identity, issuer, observed time, validity, confidence, refs, redaction hints, and correlation keys.
- Add Go structs and normalizers in `core/ingest` for sidecar records, preserving existing runtime evidence bundle compatibility.
- Add deterministic record ID generation and stable sort order by source precedence key, repo, service, workflow, environment, path, evidence class, observed time, and record ID.
- Add schema fixtures with fake provider exports and fake customer data only.

Repo paths:
- `core/ingest/ingest.go`
- `core/evidence/evidence.go`
- `schemas/v1/evidence/evidence-bundle.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/README.md`
- `testinfra/contracts`
- `internal/acceptance`

Run commands:
- `go test ./core/ingest ./core/evidence -count=1`
- `go test ./testinfra/contracts -count=1`
- `make test-contracts`

Test requirements:
- Add failing schema validation tests for every sidecar type before implementation.
- Add byte-stability tests proving identical sidecars normalize to identical JSON and record ordering.
- Add negative tests for unsupported schema version, invalid timestamp, invalid validity window, missing source, missing correlation key, duplicate record IDs, and raw-secret-looking payload rejection.
- Add fixtures that verify redaction hints survive normalization without preserving private raw values.

Matrix wiring:
- Fast lane: focused Go unit tests for `core/ingest` normalizers and schema helpers.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: schema fixture acceptance for representative sidecars.
- Cross-platform lane: path separator and case handling for sidecar paths.
- Risk lane: `make test-hardening` for invalid, unsafe, or secret-bearing sidecars.

Acceptance criteria:
- A typed external sidecar with deterministic fake data validates against schemas and normalizes to stable JSON.
- Existing runtime evidence bundles continue to load, normalize, save, and correlate unchanged.
- Invalid sidecars return deterministic schema or invalid-input errors without partial writes.
- No schema or fixture contains real provider/customer data.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added schema-backed external control evidence sidecars for local ownership, approval, provider, branch, deployment, and policy evidence.
Semver marker override: [semver:minor]
Contract/API impact: Adds public v1 sidecar schemas and additive evidence metadata fields while preserving existing runtime evidence input.
Versioning/migration impact: New schemas start at v1; existing runtime evidence remains valid with no migration.
Architecture constraints: Keep parsing and normalization in `core/ingest`; do not let report or risk code parse raw sidecar files directly.
ADR required: no
TDD first failing test(s): `TestExternalEvidenceSidecarSchemaValidation`, `TestExternalEvidenceNormalizeStableOrder`, and `TestExternalEvidenceRejectsSecretLikeValues`.
Cost/perf impact: medium, because additional sidecar normalization can affect scan/report startup when many records are present.
Chaos/failure hypothesis: Corrupt or partially unreadable sidecar input fails closed with deterministic error output and leaves existing managed artifacts unchanged.

### Story 1.2: Correlate Ownership, Approval, Catalog, Ticket, And Policy Evidence To Paths And Graph Nodes

Priority: P0
Recommendation coverage: 11

Tasks:
- Extend ingest correlation to map sidecar records onto repo, service, workflow, environment, path, action path ID, control path graph node ID, and control path graph edge ID.
- Extend `core/attribution/provider_metadata.go` and `core/attribution/control_metadata.go` to expose normalized external control evidence without bypassing `core/ingest` validation.
- Extend `core/owners/owners.go` so GitHub teams, app catalogs, Backstage ownership, customer maps, and provider metadata participate in owner resolution through the shared source ledger.
- Propagate correlated evidence refs into `core/risk.ActionPath`, control backlog items, Agent Action BOM items, and evidence bundle outputs.
- Add deterministic unmatched evidence summaries for sidecar records that cannot be correlated.

Repo paths:
- `core/ingest/ingest.go`
- `core/attribution/provider_metadata.go`
- `core/attribution/control_metadata.go`
- `core/owners/owners.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/evidence/evidence.go`
- `schemas/v1`

Run commands:
- `go test ./core/ingest ./core/attribution ./core/owners ./core/risk ./core/aggregate/controlbacklog ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`

Test requirements:
- Add correlation tests for repo-only, service, workflow, environment, path, action path ID, graph node, and graph edge matches.
- Add owner resolution tests that show provider/team evidence beats lower-precedence inference only through the shared precedence rules added in Wave 2.
- Add unmatched record tests that preserve evidence in summaries without attaching it to the wrong path.
- Add scenario fixtures covering GitHub team export, Backstage/app catalog export, Jira approval, ServiceNow approval, and customer owner map records.

Matrix wiring:
- Fast lane: focused correlation and owners tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario fixtures for multi-source external evidence.
- Cross-platform lane: path matching for Windows separators and case-insensitive repository names where configured.
- Risk lane: `make test-hardening` for ambiguous graph/path matches and no-secret serialization.

Acceptance criteria:
- External ownership and approval evidence can be loaded, normalized, correlated, and surfaced in JSON outputs without network access.
- Ambiguous or unmatched records remain auditable and do not mutate owner/control state.
- Owner resolution includes source, source type, confidence, evidence refs, and conflict details.
- Evidence refs propagate consistently to control backlog, Agent Action BOM, report summary, and evidence bundle outputs.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added deterministic correlation for external ownership, approval, app catalog, ticket, policy, and provider evidence.
Semver marker override: [semver:minor]
Contract/API impact: Adds external evidence correlation fields to JSON reports and evidence outputs.
Versioning/migration impact: Additive v1 output fields; old outputs remain readable.
Architecture constraints: Source parsing stays in ingest/attribution/owners; risk consumes normalized evidence and does not read sidecar files.
ADR required: no
TDD first failing test(s): `TestExternalEvidenceCorrelatesByPathAndGraphNode`, `TestExternalEvidenceUnmatchedRecordsRemainAuditable`, and `TestOwnerResolutionUsesExternalEvidenceRefs`.
Cost/perf impact: medium, due to path and graph correlation indexes.
Chaos/failure hypothesis: A sidecar with mixed valid, stale, and unmatched records produces deterministic partial correlation and clear unmatched reasons without panics or random ordering.

### Story 1.3: Model Branch Protection And Deployment Constraint Evidence

Priority: P0
Recommendation coverage: 17

Tasks:
- Add evidence classes and schemas for branch protections, protected environments, deployment approvals, required checks, security gates, freeze windows, and kill switches.
- Extend `core/detect/gaitpolicy` to parse repo-local Gait policy/config declarations for deployment constraints and production-target controls using structured YAML parsing.
- Extend workflow capability analysis inputs so workflow environment names, permissions, required approval hints, and deployment commands can be compared to imported branch/environment constraints.
- Project constraint evidence into risk, control backlog, Agent Action BOM, Gait coverage report, and evidence bundle outputs.
- Ensure constraint evidence can upgrade control state only when freshness and precedence rules allow it.

Repo paths:
- `core/detect/gaitpolicy/detector.go`
- `core/detect/workflowcap/analyze.go`
- `core/attribution/provider_metadata.go`
- `core/risk/buyer_projection.go`
- `core/report/gait_coverage.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/evidence/evidence.go`
- `schemas/v1/policy`
- `schemas/v1/evidence`

Run commands:
- `go test ./core/detect/gaitpolicy ./core/detect/workflowcap ./core/risk ./core/report ./core/aggregate/controlbacklog ./core/evidence -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- Add parser tests for branch protection, environment approval, required checks, freeze window, kill switch, and security gate declarations.
- Add correlation tests between workflow deployment environments and provider-exported protected environment records.
- Add contradiction tests for workflow deploy commands that target production without matching branch/environment constraints.
- Add schema tests for provider export and repo-local policy representations.

Matrix wiring:
- Fast lane: focused parser and projection tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenarios for protected and unprotected production deployment paths.
- Cross-platform lane: workflow path and policy path handling.
- Risk lane: `make test-hardening` and `make test-chaos` for stale provider exports, partial constraints, and conflicting branch/environment data.

Acceptance criteria:
- Branch protection and deployment constraints are visible as first-class evidence classes.
- Protected environment approvals and required checks influence control evidence only when correlated to the relevant path/workflow/environment.
- Stale or contradictory constraint evidence routes to evidence-required or contradictory states rather than verified control.
- Markdown and JSON distinguish declared workflow approval from externally verified branch/environment constraints.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added branch protection, protected environment, deployment approval, required check, freeze window, and kill switch evidence for control reports.
Semver marker override: [semver:minor]
Contract/API impact: Adds new evidence classes and additive report fields for branch/deployment constraint evidence.
Versioning/migration impact: Additive schema and JSON fields; no removal of current workflow capability fields.
Architecture constraints: Detection parses repo-local policy; provider exports enter through ingest; risk consumes normalized constraints.
ADR required: no
TDD first failing test(s): `TestGaitPolicyLoadsDeploymentConstraints`, `TestWorkflowDeploymentConstraintCorrelation`, and `TestStaleDeploymentConstraintDoesNotVerifyControl`.
Cost/perf impact: low to medium, depending on policy fixture size and correlation volume.
Chaos/failure hypothesis: If provider-exported branch protection is incomplete or stale, Wrkr must preserve evidence refs and route the path to evidence-required rather than safe language.

## Epic 2: Governance Semantics

Objective: make imported and declared evidence explainable, time-bound, and contradiction-aware so enterprise context improves accuracy without becoming unverifiable assumption.
Traceability: Recommendations 12, 13, 14, and 15.

### Story 2.1: Implement Evidence Source Precedence And Conflict Reasons

Priority: P0
Recommendation coverage: 12

Tasks:
- Add a shared precedence resolver for evidence sources with the locked order: verified provider/exported evidence, signed declarations, repo-local policy/config, app catalog ownership, git/review inference, naming-convention inference.
- Represent precedence decisions with selected value, selected source, selected evidence refs, rejected/conflicting candidates, and stable reason codes.
- Refactor `core/owners` and control metadata merge logic to use precedence instead of first-non-empty merge behavior where evidence sources can disagree.
- Propagate conflict details into risk projection, control backlog, Agent Action BOM, report summary, and schemas.
- Add deterministic sorting for conflicts so output is byte-stable.

Repo paths:
- `core/owners/owners.go`
- `core/ingest/ingest.go`
- `core/attribution/control_metadata.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/risk/buyer_projection.go`
- `core/report/agent_action_bom.go`
- `schemas/v1`

Run commands:
- `go test ./core/owners ./core/ingest ./core/attribution ./core/risk ./core/aggregate/controlbacklog ./core/report -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- Add precedence table tests for every source pair and tie-break case.
- Add conflict reason tests for owner conflicts, approval conflicts, target class conflicts, policy conflicts, and branch/environment constraint conflicts.
- Add regression tests proving deterministic order independent of sidecar file ordering.
- Add schema tests for conflict output fields.

Matrix wiring:
- Fast lane: precedence resolver and owners tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario with CODEOWNERS, GitHub team export, Backstage owner, ticket owner, and repo fallback disagreement.
- Cross-platform lane: deterministic sorting and path normalization.
- Risk lane: `make test-hardening` for fail-closed ambiguous high-risk conflicts.

Acceptance criteria:
- Multiple conflicting owner/control sources produce one deterministic selected value plus explicit conflict reasons.
- Lower-precedence sources are not lost from evidence refs.
- Conflict state can route a path to contradictory evidence where appropriate.
- No package keeps a private ad hoc precedence order for ownership or control evidence.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed evidence resolution to use deterministic source precedence with conflict reasons across ownership and control outputs.
Semver marker override: [semver:minor]
Contract/API impact: Adds conflict and precedence fields; may change selected owners/control states where higher-authority evidence exists.
Versioning/migration impact: Additive fields with behavior change documented in v1 schema/docs.
Architecture constraints: Shared precedence helper must be consumed by owners, ingest, attribution, and risk without cyclic imports.
ADR required: no
TDD first failing test(s): `TestEvidencePrecedenceVerifiedProviderBeatsCodeowners`, `TestEvidencePrecedencePreservesConflicts`, and `TestEvidencePrecedenceStableOrder`.
Cost/perf impact: low.
Chaos/failure hypothesis: If every evidence source disagrees, Wrkr emits deterministic contradiction detail and avoids safe-by-default or silent fallback behavior.

### Story 2.2: Add Evidence Freshness And Expiry State

Priority: P0
Recommendation coverage: 13

Tasks:
- Add freshness metadata fields to imported and declared evidence: `source`, `observed_at`, `valid_until`, `max_age`, `issuer`, `confidence`, and `freshness_state`.
- Implement freshness evaluation with deterministic clock injection for tests and generated-at based report behavior.
- Propagate freshness state into ownership resolution, control metadata, runtime/provider evidence summaries, control backlog, Agent Action BOM, control proof report, and schemas.
- Add report language for fresh, stale, expired, and unknown evidence that does not overclaim expired controls.
- Ensure expired evidence cannot produce `verified` closure without an explicit accepted-risk or declaration reason that remains visible.

Repo paths:
- `core/ingest/ingest.go`
- `core/evidence/evidence.go`
- `core/owners/owners.go`
- `core/report/control_proof.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/risk/evidence_state.go`
- `schemas/v1`

Run commands:
- `go test ./core/ingest ./core/evidence ./core/owners ./core/report ./core/aggregate/controlbacklog ./core/risk -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- Add deterministic clock tests for fresh, stale, expired, and unknown freshness states.
- Add max-age and valid-until precedence tests, including invalid combinations.
- Add projection tests proving expired provider evidence lowers evidence confidence and routes to evidence-required.
- Add schema tests for freshness metadata and docs examples.

Matrix wiring:
- Fast lane: freshness unit tests with injected time.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario with fresh provider approval, expired ticket approval, stale owner map, and unknown Backstage timestamp.
- Cross-platform lane: RFC3339 parsing and file path behavior.
- Risk lane: `make test-hardening` and `make test-chaos` for impossible dates, invalid max-age, and time-bound contradictions.

Acceptance criteria:
- Freshness state is deterministic for the same generated-at time and input artifacts.
- Expired evidence is visible and cannot silently verify a control.
- Stale evidence produces closure guidance to refresh or replace the evidence.
- JSON schemas and docs define timestamp, validity, issuer, confidence, and freshness semantics.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added freshness and expiry metadata for imported and declared evidence across reports, backlog, and evidence bundles.
Semver marker override: [semver:minor]
Contract/API impact: Adds freshness fields to public JSON outputs and sidecar schemas.
Versioning/migration impact: Missing freshness on older sidecars maps to `unknown`; no old records are rejected solely for absence unless schema version opts in.
Architecture constraints: Freshness evaluation must be deterministic and avoid direct `time.Now()` in projection paths except through existing generated-at inputs.
ADR required: no
TDD first failing test(s): `TestFreshnessStateFromValidityWindow`, `TestExpiredEvidenceCannotVerifyControl`, and `TestFreshnessStableWithGeneratedAt`.
Cost/perf impact: low.
Chaos/failure hypothesis: Sidecars with impossible or contradictory validity windows fail closed with schema/policy errors and do not partially update managed evidence.

### Story 2.3: Add Versioned Customer Declaration Governance

Priority: P0
Recommendation coverage: 14

Tasks:
- Add deterministic loading and validation for `wrkr-control-declarations.yaml` and optional `.wrkr/control-declarations.yaml`.
- Support owner mappings, target classes, accepted internal tooling, approved exceptions, non-prod declarations, control evidence links, evidence refs, expiry dates, redaction hints, and issuer metadata.
- Add `core/config` integration so declaration loading is explicit, deterministic, and scoped to the selected scan root.
- Wire declarations into ingest, owners, attribution control metadata, scan command output, risk projection, and control backlog.
- Add contradiction preflight that reports declaration issues before they can verify controls.

Repo paths:
- `core/config/config.go`
- `core/owners/owners.go`
- `core/ingest/ingest.go`
- `core/cli/scan.go`
- `core/attribution/control_metadata.go`
- `core/risk/buyer_projection.go`
- `schemas/v1/evidence`
- `docs/commands/scan.md`
- `docs/commands/ingest.md`

Run commands:
- `go test ./core/config ./core/owners ./core/ingest ./core/cli ./core/attribution ./core/risk -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- Add parser tests for minimal and full declarations.
- Add validation tests for missing owner, invalid target class, invalid expiry, unsupported evidence ref, invalid redaction mode, duplicate scopes, and unsafe paths.
- Add scan contract tests for declaration load success/failure and JSON output.
- Add scenarios for declared internal tooling, approved exception, non-prod declaration, and expired declaration.

Matrix wiring:
- Fast lane: config/declaration parser and scan command tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario fixtures and v1 acceptance with declaration sidecars.
- Cross-platform lane: declaration path lookup and glob scope behavior.
- Risk lane: `make test-hardening` and `make test-chaos` for invalid, unreadable, expired, and contradictory declarations.

Acceptance criteria:
- `wrkr-control-declarations.yaml` is validated, normalized, and represented as declared evidence.
- Declaration data can influence owner/target/exception/control state only through precedence, freshness, and contradiction checks.
- Invalid declarations fail closed with deterministic exit code and JSON error envelope.
- Redacted outputs preserve declaration reason codes and refs without exposing private values.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added versioned customer control declarations for owner mappings, target classes, accepted tooling, exceptions, non-prod declarations, and evidence links.
Semver marker override: [semver:minor]
Contract/API impact: Adds a public declaration artifact and scan/report JSON fields.
Versioning/migration impact: Declaration schema starts at v1 and is optional; invalid provided declarations fail closed.
Architecture constraints: Loading belongs in config/ingest/scan boundaries; risk consumes normalized declaration evidence and reasons.
ADR required: yes
TDD first failing test(s): `TestControlDeclarationsLoadFromRoot`, `TestInvalidControlDeclarationFailsClosed`, and `TestDeclarationDoesNotBypassContradictionCheck`.
Cost/perf impact: low.
Chaos/failure hypothesis: A declaration file that is unreadable, partially malformed, or contradictory produces a deterministic failure or contradiction finding without corrupting saved state.

### Story 2.4: Detect Contradictory Evidence Across Declarations, Targets, Credentials, Workflows, And Policies

Priority: P0
Recommendation coverage: 15

Tasks:
- Add contradiction rules for declared non-production paths that reference production secrets, production environment names, deployment commands, release workflow permissions, production-target policies, standing credentials, or protected deployment constraints.
- Compare customer declarations, repo metadata, target classification, credential references, environment names, workflow permissions, deployment commands, branch/deployment constraints, and production-target policies.
- Emit contradiction state, reason codes, evidence refs, impacted target class, and recommended closure action in risk projection, control backlog, Agent Action BOM, markdown, and evidence bundle outputs.
- Ensure contradiction findings are ranked and visible as enterprise control findings.
- Add report wording through centralized language helpers.

Repo paths:
- `core/risk/buyer_projection.go`
- `core/risk/evidence_state.go`
- `core/risk/action_paths.go`
- `core/risk/action_path_type.go`
- `core/risk/target_class.go`
- `core/risk/evidence_language.go`
- `core/risk/action_paths_test.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/detect/workflowcap/analyze.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`

Run commands:
- `go test ./core/risk ./core/aggregate/controlbacklog ./core/detect/workflowcap ./core/report -count=1`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- Add failing risk tests for non-prod declaration plus production secret reference, production environment, deploy command, release permission, standing credential, and production-target policy.
- Add control backlog tests for contradiction queue, severity, closure criteria, and evidence refs.
- Add markdown/report QA tests to block soft or ambiguous contradiction wording.
- Add scenario fixture for contradictory declaration versus workflow/credential evidence.

Matrix wiring:
- Fast lane: focused contradiction classification and report wording tests.
- Core CI lane: `make test-fast`.
- Acceptance lane: contradiction scenario and v1 report acceptance.
- Cross-platform lane: environment/path matching consistency.
- Risk lane: `make test-hardening` and `make test-chaos` for contradictory, partial, stale, and unsupported evidence.

Acceptance criteria:
- Contradictory evidence routes paths to `contradictory` evidence state and control-first visibility where risk-bearing.
- Contradiction reasons are stable, ranked, and evidence-ref backed.
- Markdown and JSON explain the contradiction without claiming raw secret values.
- Contradictions cannot be downgraded by lower-precedence or expired evidence.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added contradiction detection for customer declarations, production targets, credentials, workflows, deployment constraints, and policy evidence.
Semver marker override: [semver:minor]
Contract/API impact: Adds contradiction fields, reason codes, and report/backlog behavior.
Versioning/migration impact: Additive fields with ranking behavior change for contradictory paths.
Architecture constraints: Contradiction rules belong in risk projection; detectors should emit facts, not buyer-facing contradiction decisions.
ADR required: no
TDD first failing test(s): `TestNonProdDeclarationContradictedByProductionSecret`, `TestContradictionRanksControlFirst`, and `TestContradictionMarkdownIsEvidenceScoped`.
Cost/perf impact: low to medium, depending on rule count.
Chaos/failure hypothesis: If evidence is partially missing, Wrkr emits evidence-required or unknown states instead of fabricating contradictions.

## Epic 3: Queues And Visibility

Objective: make enterprise governance workflows auditable by routing accepted risk, suppression, lifecycle, and ownership issues into explicit queues instead of hiding or flattening them.
Traceability: Recommendations 16 and 19.

### Story 3.1: Add Governance-Grade Accepted Risk And Suppression Workflow

Priority: P1
Recommendation coverage: 16

Tasks:
- Add accepted-risk and suppression records with required reason, owner, expiry, scope, evidence state, rescan behavior, visibility behavior, issuer, and evidence refs.
- Add deterministic scope matching for repo, path, service, workflow, environment, action path ID, target class, finding type, and graph node/edge refs.
- Update control backlog to include accepted-risk queue, appendix visibility, suppression metadata, and rescan behavior rather than deleting matched items.
- Update report, export, evidence bundle, and Agent Action BOM outputs to show accepted-risk and suppressed items according to visibility behavior.
- Add expired accepted-risk behavior that re-promotes items into primary queues with reason codes.

Repo paths:
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/cli/report.go`
- `core/cli/export.go`
- `core/evidence/evidence.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `schemas/v1`

Run commands:
- `go test ./core/aggregate/controlbacklog ./core/cli ./core/evidence ./core/report -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-scenarios`

Test requirements:
- Add accepted-risk matching tests for each supported scope dimension.
- Add expiry tests proving expired accepted risks reappear in primary/action queues.
- Add report/export tests proving suppressed items move to appendix or accepted-risk queue rather than disappearing.
- Add schema tests requiring reason, owner, expiry, scope, evidence state, rescan behavior, and visibility behavior.

Matrix wiring:
- Fast lane: scope matching and queue tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: accepted-risk and suppression scenario fixtures.
- Cross-platform lane: path scope and glob behavior.
- Risk lane: `make test-hardening` and `make test-chaos` for expired, malformed, or overbroad suppression.

Acceptance criteria:
- Accepted-risk records cannot be created or consumed without reason, owner, expiry, scope, evidence state, and visibility behavior.
- Suppressed items remain present in auditable JSON or appendix outputs according to policy.
- Expired accepted-risk records no longer suppress primary visibility.
- Redacted exports preserve the existence and governance reason without leaking private ticket or owner details.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added accepted-risk and suppression governance with expiry, ownership, scope, evidence state, rescan behavior, and appendix visibility.
Semver marker override: [semver:minor]
Contract/API impact: Adds accepted-risk/suppression schemas and output fields; report visibility behavior changes for suppressed items.
Versioning/migration impact: Additive fields; existing reports remain valid but new behavior must be documented for suppression consumers.
Architecture constraints: Suppression matching lives in aggregation/report paths and must not remove findings from source, detection, proof, or evidence state.
ADR required: no
TDD first failing test(s): `TestAcceptedRiskRequiresGovernanceFields`, `TestSuppressedItemsMoveToAppendix`, and `TestExpiredAcceptedRiskRepromotesItem`.
Cost/perf impact: low.
Chaos/failure hypothesis: An overbroad or malformed suppression is rejected or downgraded to non-applied evidence with clear reason, never silently applied.

### Story 3.2: Add Lifecycle And Ownership Control Queue

Priority: P1
Recommendation coverage: 19

Tasks:
- Build a lifecycle control queue for ownerless, unresolved-owner, inferred-owner, inactive-but-credentialed, pending-lifecycle, deprecated-but-active, revoked-but-active, and stale-approval items.
- Include severity, owner evidence state, credential status, lifecycle status, recommended action, SLA, closure criteria, evidence refs, and source conflicts.
- Promote lifecycle queue data into control backlog, inventory aggregate, Agent Action BOM, markdown, and report summary.
- Ensure credential-bearing lifecycle gaps rank above clean inventory hygiene.
- Add deterministic ordering by severity, credential status, evidence state, repo, path, and stable ID.

Repo paths:
- `core/owners/owners.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/aggregate/inventory/inventory.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/risk/buyer_projection.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`

Run commands:
- `go test ./core/owners ./core/aggregate/controlbacklog ./core/aggregate/inventory ./core/report ./core/risk -count=1`
- `make test-scenarios`
- `make test-contracts`

Test requirements:
- Add lifecycle queue tests for ownerless, unresolved, inferred, inactive credentialed, pending, deprecated active, and revoked active paths.
- Add severity ordering tests proving credential-bearing and production-target lifecycle gaps outrank inventory-only items.
- Add report tests for lifecycle queue markdown and JSON summary counts.
- Add schema tests for lifecycle queue fields.

Matrix wiring:
- Fast lane: lifecycle queue and sorting tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario with lifecycle and ownership states across credentialed and non-credentialed paths.
- Cross-platform lane: stable sorting and path normalization.
- Risk lane: `make test-hardening` for owner conflict and lifecycle conflict behavior.

Acceptance criteria:
- Lifecycle queue items include severity, owner evidence state, credential status, action, SLA, and closure criteria.
- Inactive or revoked paths with credential access cannot be hidden as inventory hygiene.
- Owner evidence state drives lifecycle recommendations instead of raw owner string presence.
- Queue counts and items are visible in JSON and markdown outputs.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added lifecycle and ownership control queues for ownerless, inferred-owner, stale-lifecycle, and credential-bearing governance gaps.
Semver marker override: [semver:minor]
Contract/API impact: Adds lifecycle queue fields to backlog, report, inventory, and Agent Action BOM outputs.
Versioning/migration impact: Additive output fields with ranking behavior change for lifecycle gaps.
Architecture constraints: Ownership resolution stays in owners; queue policy belongs in aggregation/risk; report renders normalized queue data.
ADR required: no
TDD first failing test(s): `TestLifecycleQueuePromotesInactiveCredentialedPath`, `TestLifecycleQueueUsesOwnerEvidenceState`, and `TestLifecycleQueueStableSeverityOrder`.
Cost/perf impact: low.
Chaos/failure hypothesis: Conflicting lifecycle and owner evidence produces a lifecycle queue item with conflict reasons rather than dropping or duplicating the path.

## Epic 4: Closure And Completeness

Objective: turn evidence-state output into operator-ready closure requirements and a per-path explanation of how complete the available evidence is.
Traceability: Recommendations 18 and 20.

### Story 4.1: Generate Path-Specific Closure Evidence Guidance

Priority: P1
Recommendation coverage: 18

Tasks:
- Add a closure requirement model with requirement type, current evidence state, required evidence, acceptable source classes, freshness requirement, examples, and closure refs.
- Generate path-specific closure requirements such as assign owner, attach approval, attach policy reference, provide provider export, prove JIT credential, prove deployment constraint, refresh expired evidence, resolve contradiction, or accept as declared internal tooling.
- Surface closure guidance in control backlog, Agent Action BOM, control proof report, markdown, and export JSON.
- Replace repetitive generic gap language with centralized evidence-language helpers.
- Add deterministic sorting by severity, requirement type, evidence state, and path ID.

Repo paths:
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/control_proof.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/cli/export.go`
- `core/risk/evidence_language.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`

Run commands:
- `go test ./core/aggregate/controlbacklog ./core/report ./core/cli ./core/risk -count=1`
- `make test-contracts`
- `make test-scenarios`

Test requirements:
- Add closure requirement tests for owner unknown, approval unknown, proof unknown, runtime not collected, expired evidence, contradiction, deployment constraint missing, and accepted internal tooling.
- Add markdown snapshot tests proving closure text is path-specific and evidence-scoped.
- Add export tests for machine-readable closure requirements.
- Add schema tests for closure requirement fields.

Matrix wiring:
- Fast lane: closure helper and report rendering tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: report acceptance scenarios with closure guidance.
- Cross-platform lane: markdown/export deterministic output.
- Risk lane: `make test-hardening` for contradiction closure and expired evidence closure.

Acceptance criteria:
- Each governable path has zero or more machine-readable closure requirements.
- Closure text names the needed evidence instead of repeating generic missing-control language.
- Contradictions and expired evidence produce specific closure actions.
- Markdown, JSON, and export output agree on closure requirement IDs and text.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added path-specific closure evidence guidance across control backlog, Agent Action BOM, markdown reports, and exports.
Semver marker override: [semver:minor]
Contract/API impact: Adds closure requirement arrays and wording changes in reports/exports.
Versioning/migration impact: Additive fields; docs must explain replacement of generic gap language.
Architecture constraints: Closure derivation should consume projected evidence states and not reparse detector facts in report renderers.
ADR required: no
TDD first failing test(s): `TestClosureRequirementsForUnknownOwnerAndApproval`, `TestClosureRequirementsForExpiredEvidence`, and `TestClosureGuidanceMarkdownMatchesJSON`.
Cost/perf impact: low.
Chaos/failure hypothesis: If path context is incomplete, closure guidance falls back to evidence-required actions with scoped reasons rather than unsafe prescriptive advice.

### Story 4.2: Add Per-Path Evidence Completeness Scoring

Priority: P1
Recommendation coverage: 20

Tasks:
- Define per-path completeness axes: discovery, authority, blast radius, control, runtime evidence, and proof.
- Score each axis from required evidence, present evidence, parser coverage, runtime match status, proof sufficiency, evidence states, freshness, contradictions, and unsupported surfaces.
- Add total completeness score, axis scores, evidence gaps, unsupported surfaces, freshness penalties, contradiction penalties, and explanation reasons to action paths, control backlog, Agent Action BOM, and report summary where appropriate.
- Ensure completeness scoring is separate from risk scoring and cannot downgrade high-risk paths by itself.
- Add buyer-facing wording that distinguishes "low risk" from "insufficient evidence".

Repo paths:
- `core/aggregate/scanquality/scanquality.go`
- `core/risk/buyer_projection.go`
- `core/risk/evidence_state.go`
- `core/report/agent_action_bom.go`
- `core/evidence/evidence.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`

Run commands:
- `go test ./core/aggregate/scanquality ./core/risk ./core/report ./core/evidence -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- Add scoring tests for complete evidence, missing owner, stale approval, unsupported detector surface, no runtime evidence collected, proof mismatch, and contradictory declarations.
- Add tests proving low completeness does not reduce risk tier or hide control-first paths.
- Add report tests for buyer-safe completeness labels.
- Add schema tests for axis scores and reasons.

Matrix wiring:
- Fast lane: completeness scoring unit tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenarios showing high risk with low completeness and low risk with high completeness.
- Cross-platform lane: deterministic score ordering and JSON formatting.
- Risk lane: `make test-hardening` and `make test-chaos` for reduced scan coverage, parser failures, stale evidence, and contradictions.

Acceptance criteria:
- Every Agent Action BOM path has completeness scores and reasons for each required axis.
- Report summaries include aggregate completeness without implying low evidence means safety.
- Unsupported or reduced coverage lowers completeness and adds closure guidance.
- Completeness scores are byte-stable for the same input and generated-at time.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added per-path evidence completeness scoring for discovery, authority, blast radius, control, runtime evidence, and proof sufficiency.
Semver marker override: [semver:minor]
Contract/API impact: Adds completeness score fields and report summary aggregates.
Versioning/migration impact: Additive schema fields; docs must separate completeness from risk scoring.
Architecture constraints: Completeness combines scanquality, risk, evidence, and report facts through normalized inputs; it must not make live checks or mutate risk score.
ADR required: no
TDD first failing test(s): `TestEvidenceCompletenessAxes`, `TestLowCompletenessDoesNotDowngradeRisk`, and `TestCompletenessAccountsForReducedCoverage`.
Cost/perf impact: medium, because every path receives axis-level scoring and explanations.
Chaos/failure hypothesis: Under reduced coverage or parser failures, completeness degrades with explicit reasons while risk posture remains conservative.

## Epic 5: Contracts, Scenarios, And Documentation

Objective: make Sprint 2 behavior release-ready by aligning docs, schema contracts, examples, scenarios, changelog, and acceptance gates.
Traceability: Recommendations 11 through 20.

### Story 5.1: Ship Schema, Scenario, Docs, And Changelog Parity For Sprint 2

Priority: P0
Recommendation coverage: 11, 12, 13, 14, 15, 16, 17, 18, 19, 20

Tasks:
- Update v1 schemas and schema README for external evidence, declarations, accepted risk, closure requirements, lifecycle queue, branch/deployment constraints, freshness, conflicts, contradictions, and completeness scoring.
- Add end-to-end scenarios that cover a clean verified external control path, conflicting owner sources, expired approval, contradictory non-prod declaration, accepted-risk appendix behavior, lifecycle owner queue, branch protection evidence, and completeness scoring.
- Update command docs for scan, ingest, report, export, and evidence bundle flows.
- Update trust docs for local sidecar evidence, no default provider queries, precedence, freshness, redaction, and evidence completeness.
- Add changelog entries with semver markers and operator-facing descriptions.
- Add docs parity checks for new flags, examples, schema paths, and report language.

Repo paths:
- `schemas/v1`
- `docs/commands/scan.md`
- `docs/commands/ingest.md`
- `docs/commands/report.md`
- `docs/commands/export.md`
- `docs/commands/evidence.md`
- `docs/trust/contracts-and-schemas.md`
- `docs/trust/detection-coverage-matrix.md`
- `internal/scenarios/coverage_map.json`
- `scenarios/wrkr`
- `internal/acceptance`
- `CHANGELOG.md`

Run commands:
- `make test-contracts`
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- Add docs-vs-CLI parity tests for any new scan/ingest/report/export flags.
- Add scenario coverage map entries for each Sprint 2 recommendation.
- Add schema example validation for every new sidecar and output field family.
- Add report QA tests for wording around verified, declared, stale, expired, suppressed, accepted, contradictory, and incomplete evidence.

Matrix wiring:
- Fast lane: docs parity snippets and schema validation tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenarios, docs smoke, and v1 acceptance.
- Cross-platform lane: docs examples that use local paths must be portable.
- Risk lane: `make test-hardening` for unsafe examples, redaction, and no-secret fixtures.

Acceptance criteria:
- All new public fields, sidecars, flags, queues, and report terms are documented with deterministic examples.
- Every Sprint 2 recommendation maps to at least one scenario or contract test.
- Changelog contains operator-facing entries in valid sections with semver signal.
- Docs and examples do not imply default provider queries or enterprise-wide absence claims.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added documentation, schemas, scenarios, and acceptance coverage for Sprint 2 enterprise evidence ingest and control context.
Semver marker override: [semver:minor]
Contract/API impact: Documents and validates all new public schemas, JSON fields, CLI examples, and report terms.
Versioning/migration impact: v1 additive schema expansion with docs for compatibility aliases and new fields.
Architecture constraints: Docs must match executable behavior and profile commands; scenarios must exercise source, detection, aggregation, risk, proof/evidence, and report boundaries without collapsing them.
ADR required: no
TDD first failing test(s): `TestSprint2ScenarioCoverageMap`, `TestSprint2SchemaExamplesValidate`, and `TestSprint2DocsCLIParity`.
Cost/perf impact: low.
Chaos/failure hypothesis: If docs or schema examples drift from command behavior, docs parity and scenario validation fail before release.

## Definition of Done

- Generated implementation PRs follow TDD: failing tests first, minimal implementation, refactor with tests green.
- Every story's listed repo paths are either touched or explicitly deferred in the PR description with rationale.
- `make lint-fast`, `make test-fast`, and `make test-contracts` pass for every implementation PR.
- Risk-bearing stories run their listed hardening, chaos, scenario, and acceptance lanes.
- JSON outputs are deterministic and schema-validated.
- No raw secrets, customer records, generated reports, transient evidence bundles, or private provider exports are committed outside fake fixtures.
- Public docs, schema README, command examples, and changelog are updated in the same PR as externally visible behavior.
- New sidecars and declarations are local-file based, fail closed on invalid input, and never trigger default network calls.
- Evidence state, source precedence, freshness, contradiction, accepted-risk, lifecycle queue, closure guidance, and completeness semantics are consistent across control backlog, Agent Action BOM, report summary, markdown, export, and evidence bundle outputs.
- Implementation handoff command: `Use $plan-implement with plan_path: product/plans/adhoc/PLAN_ADHOC_2026-05-25_173030_evidence-ingest-closure-control-context.md`

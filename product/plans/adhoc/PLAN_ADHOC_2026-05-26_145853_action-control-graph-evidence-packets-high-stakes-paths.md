# Adhoc Plan: Action-Control Graph, Evidence Packets, And High-Stakes Paths

Date: 2026-05-26
Profile: `wrkr`
Slug: `action-control-graph-evidence-packets-high-stakes-paths`
Recommendation source: user-provided Sprint 3 recommendations covering Agentic SDLC risk tiers, agent team and workflow chain modeling, Control Path Graph V2, provider-neutral PR/MR provenance, Agentic SDLC evidence packets, recent AI-assisted PR review, high-stakes path presets, production-data context, cloud role and deployment authority, SaaS token scope detection, risk classification validation, autonomy-tier control recommendations, delegation readiness, intent-to-outcome lineage, draft action contracts, governed before/after views, and the default one-workflow Agent Action BOM experience.

All paths in this plan are repo-relative. User-provided absolute checkout paths have been normalized to repo-relative paths. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, scenario, or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control loop. This plan must not add Axym compliance-engine behavior, Gait runtime enforcement, scan-time LLM calls, live endpoint probing, or default network enrichment.
- Sprint 3 is contract-first. Additive v1 JSON fields, schemas, fixtures, docs, and report rendering must land before reports claim new autonomy, workflow-chain, evidence-packet, or high-stakes control semantics.
- The default buyer-facing artifact is a focused Agent Action BOM for one workflow/action path. Broad scanner findings, graph internals, scan quality, proof diagnostics, and detector details must be appendix/evidence surfaces by default.
- Autonomy tiers are separate from severity. `tier_0_safe_metadata`, `tier_1_low_risk_internal`, `tier_2_app_code_owner_review`, `tier_3_sensitive_code_or_infra`, and `tier_4_prod_privileged_or_customer_impacting` describe what can be delegated, not just how bad a finding is.
- Delegation readiness is separate from risk tier and severity. `safe_to_delegate`, `review_required`, `approval_required`, `proof_required`, `ready_for_control`, `blocked`, and `blocked_by_contradiction` are buyer action states.
- Recommended controls are explicit outcomes, not prose-only remediation. Allowed values are `allow`, `owner_review`, `security_review`, `approval_required`, `jit_credential_required`, `proof_required`, `block_standing_credential`, and `block`.
- Control Path Graph V2 is additive over the existing graph contract. Preserve existing graph IDs and v1 compatibility while adding node and edge kinds for intent, task, human identity, agent team, PR/MR, approval identity, policy identity, asset identity, evidence identity, and deployment path.
- Agent team and workflow chain artifacts must be deterministic, grouped by stable repo, PR/MR, workflow, task/source, tool, credential, owner, approval, target, and evidence keys.
- Provider provenance remains local-file based. Wrkr may ingest provider-exported sidecars, but it must not query GitHub, GitLab, Jira, ServiceNow, cloud providers, CI providers, observability tools, or SaaS APIs during scan, risk, proof, report, or ingest paths by default.
- Evidence packets are typed Wrkr artifacts. They may include redacted or digest-only diff and proof references, but must not serialize raw secret values, private provider payloads, or customer-sensitive data outside the selected share profile.
- High-stakes path classification is deterministic and structured where possible. Prefer parsed workflow, Terraform, CloudFormation, Kubernetes, OpenAPI, route, dependency, and provider sidecar data over regex-only matching.
- Production-data and mutable-endpoint findings must be rendered with agent, workflow, credential, owner, deployment, action, path, target, and evidence context so they do not read like generic AppSec findings.
- Risk classification validation must fail closed for contradictory high-risk inputs. A "low risk" label on sensitive files, broad credentials, deployment paths, or production/customer-impacting targets cannot remain clean without owner review, approval, proof, or contradiction state.
- Draft action contracts are report artifacts, not enforcement policy. They recommend the shape that Gait or a customer control should adopt later without implementing Gait behavior in Wrkr.
- Changelog entries are required for implementation PRs because this work changes public report JSON, schemas, CLI/report behavior, markdown presentation, evidence semantics, detector outputs, and user-facing docs.

## Current Baseline (Observed)

- `core/risk/action_paths.go` already builds action paths from inventory privilege maps, decorates evidence states, links attack paths, projects buyer-facing fields, carries credential authority, target class, action class, closure requirements, evidence completeness, and action lineage.
- `core/risk/buyer_projection.go` already derives confidence lanes, evidence states, target classes, contradictions, inventory risk, control priority, risk tier, control state, risk zone, and review burden. It does not yet model Agentic SDLC autonomy tiers, delegation readiness, tier-specific control outcomes, risk classification validation, action contracts, or governed before/after paths.
- `core/risk/action_lineage.go` currently renders a path lineage through repo, workflow, agent, action, credential, target, owner, approval, and proof segments based on control-path graph refs. It does not yet model intent, task/request, human requester, agent session, PR/MR, workflow run, deployment, policy verdict, control, or outcome as first-class lineage nodes.
- `core/aggregate/attackpath/graph.go` already has a simple attack graph and a richer `ControlPathGraph` surface referenced by reports. The current `schemas/v1/control-path-graph.schema.json` node enum is limited to `control_path`, `agent`, `execution_identity`, `credential`, `tool`, `workflow`, `repo`, `governance_control`, `target`, and `action_capability`.
- `core/aggregate/controlbacklog/controlbacklog.go` already emits control-first queues, review queues, accepted-risk queues, lifecycle queues, governance dispositions, closure requirements, evidence completeness, credential authority, standing privilege, policy coverage, and graph refs. It does not yet expose autonomy-tier recommended controls, delegation readiness, draft action contracts, or governed before/after paths.
- `core/report/agent_action_bom.go` already builds Agent Action BOM summary/items with control resolution, evidence states, contradictions, runtime evidence refs, proof refs, reachability, graph refs, closure requirements, evidence completeness, introduced-by attribution, and action lineage. It is still a broad item list rather than a default single-workflow buyer experience.
- `core/report/render_markdown.go` already renders report markdown across risk/control surfaces. It needs a constrained first-page path map, authority, target, control resolution, evidence state, readiness, proof state, and recommended governed path before appendix material.
- `core/attribution/provider_metadata.go` loads deterministic `.wrkr/provenance/source-metadata.json`, GitHub event, and GitLab event sidecars with PR/MR number, commit SHA, author, timestamp, provider URL, and changed files. It does not yet model reviewers, approvals, check suites, required checks, branch protections, deployments, merge method, or environment gates.
- `core/risk/introduced_by.go` only decorates action paths with the current attribution result. It needs a provider-neutral provenance model before action paths can answer who produced, reviewed, checked, approved, deployed, and merged a change.
- `core/ingest/ingest.go` already supports `runtime` and `external_control` record kinds, evidence classes for policy decisions, approvals, JIT credentials, freeze windows, kill switches, action outcomes, proof verification, owner assignment, policy records, branch protection, protected environments, deployment approvals, required checks, and security gates. It does not yet define a typed Agentic SDLC evidence packet.
- `core/evidence/evidence.go` already includes Agent Action BOM and proof/report artifacts in evidence bundles. It needs evidence-packet inclusion, redaction behavior, and missing-evidence summaries for consequential AI-assisted SDLC changes.
- `core/detect/workflowcap/analyze.go`, `core/aggregate/inventory/privileges.go`, and `core/aggregate/privilegebudget/budget.go` already provide workflow capabilities, production target status, credential provenance, credential authority, standing privilege, mutable endpoint semantics, deployment/write classification, and matched production targets. These are the natural inputs for high-stakes presets, autonomy tiers, and readiness.
- `core/risk/mutable_endpoint.go`, `core/detect/routes/detector.go`, and `core/detect/openapi/detector.go` already surface route/API and mutable-endpoint semantics. They need nearest agent/workflow/credential/action context in report projection.
- `schemas/v1/agent-action-bom.schema.json`, `schemas/v1/risk/risk-report.schema.json`, and `schemas/v1/report/report-summary.schema.json` already include many additive report fields with permissive item compatibility, but they do not yet enumerate autonomy tiers, delegation readiness, recommended control outcomes, action contracts, evidence packets, workflow chain artifacts, or the primary focused BOM view.

## Exit Criteria

- Every action path and Agent Action BOM item has a deterministic Agentic SDLC autonomy tier with reason codes derived from file sensitivity, path type, target class, action class, workflow permission, credential authority, deploy/write capability, evidence states, and contradiction state.
- Every action path and BOM item has a separate `delegation_readiness_state`, recommended control outcome, and rationale. Contradictions always route to `blocked_by_contradiction` or an equivalent fail-closed recommended control.
- Agent team/workflow chain artifacts exist and are grouped by repo, PR/MR, workflow, task/source, tool, credential, owner, approval, target, evidence, and outcome. IDs are byte-stable across repeated runs.
- Control Path Graph V2 can render `intent/task -> human -> agent team -> tool -> credential -> repo -> PR/MR -> CI/CD -> approval -> deploy path -> affected asset -> evidence` without breaking existing v1 graph consumers.
- Provider-neutral PR/MR provenance sidecars cover metadata, changed files, authors, reviewers, approvals, required checks, check results, security scans, deployments, merge method, branch protection, and environment gates.
- Agentic SDLC evidence packets are typed, schema-backed, locally ingested, redaction-aware, proof-linked, and available in report/evidence artifacts for consequential AI-assisted changes.
- A recent AI-assisted PR/MR review workflow accepts explicit PR/MR IDs or local provider metadata sidecars and ranks AI-assisted or automation-assisted delivery paths without default network access.
- High-stakes path presets classify release automation, CI/CD, MCP/tool configs, IaC, auth/identity code, payment flows, regulated/customer-facing workflows, dependency publishing, credential-bearing automation, external egress, and mutable endpoints.
- Production-data and mutable-endpoint findings render nearest workflow, tool, credential authority, owner, route/API evidence, deployment evidence, action class, path type, target class, proof state, and missing evidence.
- Cloud role and deployment authority parsing links workflow credentials to Terraform IAM, CloudFormation IAM, Kubernetes RBAC, GitHub OIDC trust, Azure federated credentials, GCP workload identity, deployment commands, service connections, environment names, and production assets.
- SaaS token and service-token detection classifies token family, target system, likely scope, standing/JIT provenance, action classes, blast radius, and evidence location without extracting secret values.
- Risk classification validation detects mismatches such as low-risk labels on sensitive paths, missing owner review, missing security checks on workflow edits, missing proof on deploy paths, and broad credentials used in supposedly low-risk work.
- Draft `recommended_action_contract` appears for each control-first path with allowed action, required authority, review, approval, proof, allowed autonomy level, validation step, default posture, delegation readiness, evidence states, outcome evidence state, and readiness state.
- High-risk paths include `today_path` and `recommended_governed_path` in JSON and markdown.
- The default Agent Action BOM experience leads with one workflow/action path and answers: what can change, what authority it uses, which controls cover it, what proof exists, what is unresolved, whether it can run alone, and what should change.
- Scenario, contract, schema, hardening, chaos, performance, docs parity, and v1 acceptance lanes cover all new public contracts and fail-closed behavior.

## Public API and Contract Map

- CLI contracts:
  - Preserve exit codes: `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, and `8` unsafe operation blocked.
  - Extend `wrkr report --json` and `wrkr report --md` with additive Agent Action BOM fields for autonomy tier, delegation readiness, recommended control, recommended action contract, today path, governed path, workflow chain, evidence packet refs, and focused view metadata.
  - Add a focused reporting mode such as `wrkr report --agent-action-bom --focus-path <path_id>` or a `workflow-bom` equivalent only after existing report flag patterns are inspected. The mode must accept local state/report inputs only and must fail with exit `6` for unknown path IDs.
  - Extend `wrkr ingest --json` with local typed evidence-packet inputs while preserving existing runtime evidence behavior.
  - Add a recent PR/MR review mode only as local sidecar ingestion or explicit IDs resolved from already provided metadata. No provider API calls are allowed by default.
- JSON and schema contracts:
  - Extend `schemas/v1/agent-action-bom.schema.json`, `schemas/v1/risk/risk-report.schema.json`, `schemas/v1/report/report-summary.schema.json`, and `schemas/v1/control-path-graph.schema.json` additively.
  - Add schemas for workflow chain or agent team path artifacts, PR/MR provenance sidecars, Agentic SDLC evidence packets, recommended action contracts, and governed path views under `schemas/v1`.
  - Canonical enums include autonomy tiers, delegation readiness states, recommended control outcomes, action contract readiness states, workflow chain node/edge kinds, and evidence packet result/missing-evidence states.
  - Existing `risk_tier`, `control_state`, `review_burden`, and `control_priority` fields remain valid and must not be repurposed to mean autonomy or delegation readiness.
- Detection and aggregation contracts:
  - Structured parsing is required for JSON/YAML/TOML/IaC/provider sidecars. Regex-only detection is acceptable only as a bounded fallback for unstructured command text with reason codes and confidence.
  - `core/detect` owns detectors and parsed facts. `core/aggregate` owns rollups, privileges, workflow chains, and graph construction. `core/risk` owns tier, readiness, validation, and control recommendation semantics. `core/report` owns presentation and artifact shaping.
  - No detector may extract raw secret values. Secret and token detectors classify family/scope/provenance from safe context only.
- Proof and evidence output contracts:
  - Evidence packets reference proof records and proof chain data by refs/digests. They do not replace `scan_finding`, `risk_assessment`, `approval`, or lifecycle/transition proof records.
  - Evidence bundle exports include evidence-packet summaries and missing-evidence status while preserving redaction/share-profile behavior.
  - Graph/evidence refs remain stable and deterministic across repeated runs with the same input.
- Documentation contracts:
  - Docs must explain the single-workflow BOM first, then appendices. They must not position broad scanner output as the primary buyer workflow.
  - Docs must include local sidecar examples for PR/MR provenance and evidence packets using fake organizations, repos, users, tickets, checks, deployments, and assets.
  - Public examples must use profile command anchors: `wrkr scan --json`, `wrkr regress run --baseline <baseline-path> --json`, and `wrkr score --json` where machine-readable evidence examples are needed.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/report.md`
  - `docs/commands/ingest.md`
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
  - Example PR/MR sidecars, evidence packets, workflow chains, and action contracts must use fake orgs, repos, users, reviewers, service accounts, cloud roles, environments, tickets, check names, deployment IDs, URLs, and assets.
  - Do not commit generated customer reports, local scan outputs, runtime evidence bundles, proof chains, private provider exports, credentials, or transient state files outside deterministic fixtures.
  - Redacted exports must preserve actionability while removing customer-specific owner, ticket, URL, service, repo, deployment, and asset names for external share profiles.
  - Docs must state that Wrkr consumes local exports and sidecars by default; it does not query provider APIs or customer systems in the scan/report path.
- Docs must answer:
  - How to read one focused workflow BOM.
  - How autonomy tiers differ from severity and risk tier.
  - How delegation readiness differs from recommended control.
  - How to prepare PR/MR provenance and evidence packet sidecars.
  - How high-stakes path presets are classified.
  - How production-data findings become agent/workflow/action findings.
  - How a draft action contract can be used by customers without treating it as runtime enforcement.

## Recommendation Traceability

| Recommendation / Finding | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| 21. Agentic SDLC Risk Tiers | P0 | Story 1.1 | Wrkr must answer what can safely run alone. | Add deterministic autonomy-tier projection separate from severity. | Buyers get delegation boundaries instead of raw risk labels. |
| 22. Agent Team / Workflow Chain Model | P0 | Story 2.1 | Specialized workflows operate the SDLC, not isolated tools. | Add workflow chain artifacts grouped by repo, PR/MR, workflow, tool, credential, owner, approval, target, and evidence. | Reports show delegated delivery paths end to end. |
| 23. SDLC Action-Control Graph V2 | P0 | Story 2.2 | The graph is the core Clyra object. | Extend graph node/edge kinds through intent, human, agent team, PR/MR, approval, deploy path, asset, and evidence. | Graph output can support buyer BOMs and downstream controls. |
| 24. PR / Review / Checks Provenance | P0 | Story 3.1 | Buyers need who made, reviewed, checked, deployed, and merged a change. | Add provider-neutral PR/MR provenance sidecars. | AI-assisted changes become auditable without provider API calls. |
| 25. Agentic SDLC Evidence Packet | P0 | Story 3.2 | Consequential AI-assisted changes need one defensible audit packet. | Add typed evidence-packet ingest/report/evidence contracts. | Release review and incident review have a portable packet. |
| 26. Recent AI-Assisted PR Review Workflow | P1 | Story 3.3 | "Review 10 recent AI-assisted PRs" is a concrete buyer ask. | Join provider metadata, changed files, AI evidence, credentials, checks, approvals, controls, proof, and runtime evidence. | Wrkr can rank bounded recent delivery paths quickly. |
| 27. High-Stakes Path Presets | P0 | Story 4.1 | The wedge is production, credentials, releases, data, and regulated systems. | Add deterministic classifiers and filters for high-stakes surfaces. | Reports prioritize the paths buyers actually care about. |
| 28. Production-Data Finding Context | P0 | Story 4.2 | Generic AppSec findings miss agent/workflow authority. | Attach nearest workflow, credential, owner, route/API, deployment, action, path, and target context. | Production-data findings become governable action paths. |
| 29. Cloud Role And Deployment Authority | P0 | Story 4.3 | Repo permissions do not answer production impact. | Parse IAM, RBAC, workload identity, OIDC, deployment commands, service connections, and production policies. | Wrkr can connect workflow credentials to production authority. |
| 30. SaaS Scope And Service Token Detection | P1 | Story 4.4 | Agent teams touch planning, deploy, observe, notify, and operate systems. | Classify SaaS token family, target system, likely scope, standing/JIT provenance, action class, and blast radius. | Non-code authority becomes visible without secret extraction. |
| 31. Risk Classification Validation | P0 | Story 1.4 | "Low risk" claims can be wrong. | Compare claimed/inferred classification against files, actions, credentials, targets, review, checks, and proof. | Wrkr flags unsafe delegation claims deterministically. |
| 32. Control Recommendations By Autonomy Tier | P0 | Story 1.2 | Wrkr should enable autonomy, not only detect risk. | Map tier and evidence to recommended controls. | Buyers get clear allow/review/approve/proof/block outcomes. |
| 33. Delegation Readiness Model | P0 | Story 1.2 | The key buyer question is whether the workflow can run mostly alone. | Add readiness states separate from severity. | Reports answer delegate/review/approve/prove/block directly. |
| 34. Intent To Outcome Lineage | P1 | Story 2.3 | Clyra's story is delegated action from request to outcome and proof. | Extend lineage with optional intent/task/session/outcome nodes. | Auditors and operators can trace request to result. |
| 35. Draft Action Contract Generation | P1 | Story 1.3 | Buyers need the control shape they should adopt. | Generate `recommended_action_contract` for control-first paths. | The BOM becomes a bridge from discovery to control design. |
| 36. Before / After Governed Path View | P1 | Story 1.3 | Buyers need the transition from discovered risk to governable path. | Render `today_path` and `recommended_governed_path` side by side. | Remediation becomes concrete and easy to explain. |
| 36A. Primary Workflow BOM Experience Constraint | P0 | Story 5.1 | The first artifact must be simple, fast, and unmistakable. | Make one-workflow BOM the default presentation contract. | Wrkr avoids drifting into noisy scanner output. |
| 36B. One-Page Workflow BOM View | P0 | Story 5.2 | The first product experience should make one workflow impossible to misread. | Add focus-path rendering and appendix split. | A buyer can understand one action path on one page. |

## Test Matrix Wiring

- Fast lane:
  - Focused unit tests for autonomy tier derivation, delegation readiness, recommended controls, action contract generation, governed path projection, workflow-chain IDs, graph node/edge additions, PR/MR provenance normalization, evidence-packet validation, high-stakes classifiers, cloud authority parsing, SaaS token classification, production-data context joins, and focused BOM rendering.
  - Candidate command: `go test ./core/risk ./core/aggregate/controlbacklog ./core/aggregate/attackpath ./core/aggregate/agentresolver ./core/attribution ./core/ingest ./core/evidence ./core/report ./core/detect/workflowcap ./core/detect/secrets ./core/detect/nonhumanidentity ./core/detect/routes ./core/detect/openapi -count=1`.
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
  - Windows smoke must cover path normalization, PR/MR sidecar loading, evidence-packet loading, graph sorting, focused BOM rendering, schema validation, cloud/IaC fixture parsing, and deterministic line endings.
- Risk lane:
  - `make test-hardening` for invalid sidecars, malformed evidence packets, unknown path IDs, unsafe output paths, missing proof on deploy paths, low-risk contradictions, and no-secret serialization.
  - `make test-chaos` for partial provider exports, conflicting approvals/checks/deployments, stale evidence packets, corrupted provenance, ambiguous cloud roles, and mixed fresh/stale workflow evidence.
  - `make test-perf` when workflow-chain grouping, graph expansion, IaC parsing, or recent PR review changes report runtime materially.
- Release/UAT lane:
  - `make test-release-smoke`
  - `scripts/run_v1_acceptance.sh --mode=release` when schemas, docs examples, report examples, or evidence bundle artifacts change.
- Gating rule:
  - Wave 1 must land before any report claims delegation readiness, autonomy safety, or control recommendations.
  - Wave 2 must land before evidence packets or focused BOMs reference workflow-chain or graph V2 fields.
  - Wave 3 must land before recent PR/MR review can rank delivery paths.
  - Wave 4 must land before autonomy tiers classify production, cloud, SaaS, or mutable endpoint authority.
  - Wave 5 must land before the default buyer experience changes.
  - Wave 6 docs, scenarios, schemas, and changelog must ship before release notes advertise Sprint 3 behavior.

## Minimum-Now Sequence

- Wave 1 - Autonomy and control projection:
  - Story 1.1 adds Agentic SDLC autonomy tiers.
  - Story 1.2 adds delegation readiness and recommended controls.
  - Story 1.3 adds draft action contracts and governed before/after views.
  - Story 1.4 adds risk classification validation.
- Wave 2 - Workflow graph and lineage:
  - Story 2.1 adds workflow chain / agent team path artifacts.
  - Story 2.2 extends Control Path Graph V2.
  - Story 2.3 extends intent-to-outcome lineage.
- Wave 3 - Provenance and evidence packets:
  - Story 3.1 adds PR/MR provenance sidecars.
  - Story 3.2 adds Agentic SDLC evidence packets.
  - Story 3.3 adds recent AI-assisted PR/MR review.
- Wave 4 - High-stakes authority:
  - Story 4.1 adds high-stakes path presets.
  - Story 4.2 ties production-data findings to agent/action context.
  - Story 4.3 links cloud role and deployment authority.
  - Story 4.4 classifies SaaS scope and service tokens.
- Wave 5 - Buyer BOM experience:
  - Story 5.1 makes the one-workflow Agent Action BOM the default buyer presentation.
  - Story 5.2 adds focus-path one-page rendering and appendix split.
- Wave 6 - Contracts, scenarios, and docs:
  - Story 6.1 updates schemas, scenarios, docs, changelog, and release-facing examples across the Sprint 3 surface.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No default network calls to GitHub, GitLab, Jira, ServiceNow, Backstage, cloud providers, CI providers, observability tools, ticketing systems, or customer SaaS systems.
- No live endpoint probing, runtime enforcement, or Gait policy execution.
- No Axym product logic or compliance-engine behavior in Wrkr.
- No extraction or serialization of raw secret values.
- No removal of existing v1 JSON fields without an explicit versioned migration.
- No broad UI or hosted service work.
- No automatically opening remediation PRs as part of the recent PR/MR review workflow.

## Epic 1: Autonomy And Control Projection

Objective: turn existing action-path risk facts into deterministic delegation, review, approval, proof, and control outcomes.
Traceability: Recommendations 21, 31, 32, 33, 35, and 36.

### Story 1.1: Add Agentic SDLC Autonomy Tiers

Priority: P0
Recommendation coverage: 21

Tasks:
- Add canonical autonomy-tier constants and validation for `tier_0_safe_metadata`, `tier_1_low_risk_internal`, `tier_2_app_code_owner_review`, `tier_3_sensitive_code_or_infra`, and `tier_4_prod_privileged_or_customer_impacting`.
- Derive tier from file sensitivity, path type, target class, action class, workflow permission, credential authority, deploy/write capability, evidence states, and contradiction state.
- Add tier reason codes and evidence refs to `risk.ActionPath`, Agent Action BOM items, control backlog items, risk report action paths, and report summary rollups.
- Ensure contradiction state and verified production/customer-impacting authority can only promote a tier, never demote it.
- Add stable sorting and summarization by tier for report and export consumers.

Repo paths:
- `core/risk/buyer_projection.go`
- `core/risk/action_paths.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/report/report-summary.schema.json`

Run commands:
- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report -count=1`
- `make test-contracts`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- Unit tests for each tier, promotion reason, tie-breaker, contradiction promotion, and low-evidence behavior.
- Golden/schema tests for action path JSON, Agent Action BOM JSON, markdown labels, and report summary rollups.
- Determinism tests that repeat the same fixture and assert byte-stable tier and reason-code output.

Matrix wiring:
- Fast lane: focused `core/risk`, `controlbacklog`, and `report` tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: v1 local acceptance with at least one scenario per tier.
- Cross-platform lane: Windows smoke for path sensitivity and stable ordering.
- Risk lane: `make test-hardening` for contradiction and fail-closed tier promotion.

Acceptance criteria:
- Every projected action path has an autonomy tier and sorted reason codes.
- Tier output is additive in v1 schemas and does not replace `risk_tier`.
- Tier derivation never lowers severity, control state, or control priority.
- Markdown labels explain tier meaning without hiding evidence gaps.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added Agentic SDLC autonomy tiers to action paths, control backlog items, Agent Action BOM output, and report summaries.
Semver marker override: [semver:minor]
Contract/API impact: Additive JSON/schema fields and markdown labels for autonomy tier and reason codes.
Versioning/migration impact: Existing reports remain valid; new fields are optional in v1 consumers until regenerated.
Architecture constraints: Risk owns tier derivation; aggregation and report layers consume projected fields only.
ADR required: no
TDD first failing test(s): Add failing tier fixture tests in `core/risk` and schema golden tests before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Ambiguous contradictory evidence promotes to the highest applicable tier instead of producing a clean low-tier result.

### Story 1.2: Add Delegation Readiness And Recommended Controls

Priority: P0
Recommendation coverage: 32, 33

Tasks:
- Add `delegation_readiness_state` with values `safe_to_delegate`, `review_required`, `approval_required`, `proof_required`, `ready_for_control`, `blocked`, and `blocked_by_contradiction`.
- Add `recommended_control` with values `allow`, `owner_review`, `security_review`, `approval_required`, `jit_credential_required`, `proof_required`, `block_standing_credential`, and `block`.
- Derive readiness and recommended control from autonomy tier, path type, target class, credential authority, control resolution, evidence confidence, runtime/proof status, contradiction state, owner state, approval state, and policy coverage.
- Keep readiness separate from severity, risk tier, review burden, and control state; expose all four when present.
- Add summary counts by readiness and recommended control to risk report, Agent Action BOM, control backlog, export, and markdown.

Repo paths:
- `core/risk/buyer_projection.go`
- `core/risk/govern_first.go`
- `core/risk/action_paths.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/cli/export.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/risk/risk-report.schema.json`

Run commands:
- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- Table tests for readiness/control mapping across all tiers and evidence states.
- Regression tests proving low severity can still require proof or approval when evidence is missing.
- Contract tests for enums, summary counts, JSON, markdown, and export fields.

Matrix wiring:
- Fast lane: focused readiness/control unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixtures for delegate/review/approve/prove/block outcomes.
- Cross-platform lane: deterministic sorting and JSON output smoke.
- Risk lane: hardening tests for contradiction, missing proof, stale runtime evidence, and standing credential blocks.

Acceptance criteria:
- Every control-first or governable action path has a readiness state and recommended control.
- Contradictions route to `blocked_by_contradiction` and `block` or stricter equivalent.
- Standing credentials on tier 4 paths recommend `block_standing_credential` unless verified JIT/approval/proof evidence changes the outcome.
- JSON, markdown, and export surfaces use the same enum values.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added delegation readiness states and autonomy-tier control recommendations for Agent Action BOM and control backlog outputs.
Semver marker override: [semver:minor]
Contract/API impact: Additive public enums and summary fields in report/export schemas.
Versioning/migration impact: No existing enum values are removed; downstream consumers can ignore new fields until upgraded.
Architecture constraints: Readiness derivation stays in `core/risk`; control backlog may queue and render but not fork semantics.
ADR required: no
TDD first failing test(s): Add readiness matrix tests for all recommended-control outcomes before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Missing evidence cannot be interpreted as `safe_to_delegate`; it routes to review, approval, proof, or block.

### Story 1.3: Generate Draft Action Contracts And Governed Before/After Views

Priority: P1
Recommendation coverage: 35, 36

Tasks:
- Add `recommended_action_contract` for each control-first action path with path summary, allowed action, required authority, required review, required approval, required proof, allowed autonomy level, validation step, default posture, delegation readiness, evidence states, outcome evidence state, and readiness state.
- Add action contract readiness states `draft`, `needs_owner`, `needs_approval_evidence`, `ready_for_report_only`, `ready_for_control`, and `blocked_by_contradiction`.
- Derive `today_path` from the discovered action path and `recommended_governed_path` from autonomy tier, credential authority, target class, control resolution, unresolved evidence, and draft action contract.
- Render before/after governed paths in JSON and markdown for high-risk and control-first paths.
- Keep action contracts report-only and explicitly not runtime enforcement.

Repo paths:
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/risk/buyer_projection.go`
- `core/report/render_markdown.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/risk/risk-report.schema.json`

Run commands:
- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report -count=1`
- `make test-contracts`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- Unit tests for action-contract derivation by tier, credential authority, proof state, owner state, and contradiction state.
- Markdown golden tests for today/recommended governed path rendering.
- Schema tests for action contract and governed path shapes.

Matrix wiring:
- Fast lane: focused action-contract and markdown tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario with a deploy-capable path moving from standing credential to JIT/proof/approval contract.
- Cross-platform lane: stable markdown/JSON line ending smoke.
- Risk lane: hardening test that contradicted paths cannot be marked `ready_for_control`.

Acceptance criteria:
- Control-first BOM items include action contracts and before/after path views.
- Contract readiness is deterministic and separate from delegation readiness.
- Markdown side-by-side view is concise enough to support the one-page BOM.
- Contradicted paths render a blocked contract with closure evidence requirements.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added draft recommended action contracts and governed before/after path views for control-first action paths.
Semver marker override: [semver:minor]
Contract/API impact: Additive Agent Action BOM and risk report fields for action contracts and governed path views.
Versioning/migration impact: Existing BOM items remain valid; new contract fields are optional.
Architecture constraints: Risk derives contract inputs; report formats the contract; no runtime enforcement is introduced.
ADR required: no
TDD first failing test(s): Add contract-readiness fixture tests and markdown golden tests before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: If required evidence is missing or contradictory, generated contracts stay draft/blocked and never claim control readiness.

### Story 1.4: Validate Claimed Risk Classification Against Actual Authority

Priority: P0
Recommendation coverage: 31

Tasks:
- Add risk classification validation comparing declared or inferred low-risk labels against sensitive files, action classes, credentials, targets, checks, owner review, approvals, and proof.
- Detect low-risk labels on CI/CD, release, IaC, auth/identity, payment, regulated/customer-facing, MCP/tool config, dependency publishing, mutable endpoint, and credential-bearing paths.
- Add stable validation reason codes such as `classification:low_risk_sensitive_path`, `classification:missing_owner_review`, `classification:missing_security_check`, `classification:missing_deploy_proof`, and `classification:broad_credential_low_risk`.
- Feed validation outcomes into autonomy tier promotion, readiness, recommended control, control backlog queues, Agent Action BOM, and markdown.
- Add closure requirements explaining which evidence would make the classification defensible.

Repo paths:
- `core/risk/buyer_projection.go`
- `core/risk/govern_first.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/risk/introduced_by.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/risk/risk-report.schema.json`

Run commands:
- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report -count=1`
- `make test-hardening`
- `make test-contracts`

Test requirements:
- Unit tests for each mismatch class and promotion behavior.
- Scenario tests where "low risk" stays valid only for safe metadata/internal paths with adequate evidence.
- Hardening tests for fail-closed contradictions and missing security check on workflow edits.

Matrix wiring:
- Fast lane: focused classification validation tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixture with low-risk claim on deploy path and another valid low-risk path.
- Cross-platform lane: path sensitivity and ordering smoke.
- Risk lane: `make test-hardening` and `make test-chaos` for conflicting labels and partial provenance.

Acceptance criteria:
- Invalid low-risk claims are visible in JSON and markdown with reason codes.
- Validation can promote autonomy tier/readiness but never silently demotes a path.
- Missing owner review, checks, proof, or broad credentials produce actionable closure requirements.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Added validation that flags unsafe low-risk classifications when files, actions, credentials, targets, review, checks, or proof contradict the claim.
Semver marker override: [semver:minor]
Contract/API impact: Additive validation fields and reason codes in risk/BOM outputs.
Versioning/migration impact: Existing fields remain; consumers should treat new validation failures as stronger governance signals.
Architecture constraints: Validation belongs in `core/risk`; attribution supplies provenance facts without owning risk semantics.
ADR required: no
TDD first failing test(s): Add failing low-risk contradiction fixtures before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Partial provenance cannot make a sensitive low-risk claim safe; it yields missing-evidence validation output.

## Epic 2: Workflow Chain, Graph V2, And Intent Lineage

Objective: model delegated SDLC work as a chain from intent and human request through agent team, tools, credentials, PR/MR, CI/CD, approval, deployment, asset, evidence, and outcome.
Traceability: Recommendations 22, 23, and 34.

### Story 2.1: Add Agent Team / Workflow Chain Artifact

Priority: P0
Recommendation coverage: 22

Tasks:
- Add deterministic `workflow_chain` or `agent_team_path` structs grouped by repo, PR/MR, workflow, task/source, tool, credential, owner, approval, target, evidence, and outcome.
- Build chain IDs from normalized stable keys and preserve refs to action path IDs, graph node IDs, graph edge IDs, proof refs, evidence refs, source finding keys, and introduced-by provenance.
- Correlate existing agent resolver output, action paths, action lineage, privilege inventory, control backlog, runtime/external evidence, and provider metadata.
- Add chain summary counts by workflow, repo, autonomy tier, readiness state, recommended control, target class, and evidence completeness.
- Expose chain refs on Agent Action BOM items and risk report action paths.

Repo paths:
- `core/aggregate/agentresolver/resolver.go`
- `core/risk/action_paths.go`
- `core/risk/action_lineage.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/attackpath/graph.go`
- `schemas/v1/control-path-graph.schema.json`
- `schemas/v1/agent-action-bom.schema.json`

Run commands:
- `go test ./core/aggregate/agentresolver ./core/aggregate/attackpath ./core/risk ./core/report -count=1`
- `make test-contracts`
- `scripts/validate_scenarios.sh`

Test requirements:
- Unit tests for chain grouping, ID stability, duplicate collapse, stable sorting, missing optional metadata, and graph/BOM refs.
- Scenario tests with one human-requested PR, one headless CI workflow, and one multi-tool agent team path.
- Schema tests for chain artifact shape and BOM refs.

Matrix wiring:
- Fast lane: focused chain grouping and ID tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixtures for workflow chain output.
- Cross-platform lane: path normalization and stable hash smoke.
- Risk lane: chaos test for missing PR metadata or partial runtime evidence.

Acceptance criteria:
- Workflow chains are deterministic and grouped by stable keys.
- Missing optional task/PR/outcome data produces explicit unknown states, not unstable IDs.
- BOM and graph refs can navigate from action path to workflow chain.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added workflow chain artifacts that group delegated SDLC paths by repo, PR/MR, workflow, tool, credential, owner, approval, target, evidence, and outcome.
Semver marker override: [semver:minor]
Contract/API impact: Additive JSON/schema artifact and refs from BOM/risk outputs.
Versioning/migration impact: New artifact is optional when chain inputs are absent.
Architecture constraints: Aggregation owns grouping; risk/report consume chain refs.
ADR required: yes
TDD first failing test(s): Add workflow-chain grouping fixtures before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Partial or conflicting chain metadata yields explicit unknown/conflict states while preserving deterministic IDs.

### Story 2.2: Extend SDLC Control Path Graph V2

Priority: P0
Recommendation coverage: 23

Tasks:
- Add graph node kinds for intent, task, human identity, agent team, PR/MR, approval identity, policy identity, asset identity, evidence identity, deployment path, CI/CD run, workflow run, and outcome.
- Add edge kinds for request-to-human, human-delegates-task, task-executed-by-agent-team, agent-team-uses-tool, tool-uses-credential, credential-authorizes-workflow, workflow-changes-repo, repo-produces-pr, pr-runs-checks, checks-gate-approval, approval-authorizes-deploy, deploy-affects-asset, and evidence-proves-outcome.
- Preserve existing node/edge kinds and graph refs for backward compatibility.
- Update graph summary rollups by node kind, edge kind, autonomy tier, readiness state, and evidence state.
- Add schema, contract tests, and deterministic graph golden fixtures.

Repo paths:
- `core/aggregate/attackpath/graph.go`
- `core/risk/action_lineage.go`
- `core/risk/risk.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/control-path-graph.schema.json`
- `testinfra/contracts`

Run commands:
- `go test ./core/aggregate/attackpath ./core/risk -count=1`
- `make test-contracts`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- Graph builder tests for every new node/edge kind and deterministic edge ordering.
- Schema compatibility tests proving existing graph fixtures still validate.
- Golden tests for V2 graph fixture with intent/task/human/PR/deploy/evidence path.

Matrix wiring:
- Fast lane: graph builder unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: v1 acceptance fixture with graph V2 fields.
- Cross-platform lane: stable graph IDs on Windows path separators.
- Risk lane: hardening test for malformed refs and duplicate nodes.

Acceptance criteria:
- Graph V2 can represent the full Sprint 3 SDLC action-control chain.
- Existing graph consumers are not broken by additive fields.
- Graph refs remain stable and are available to BOM, action lineage, evidence packets, and risk report.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added Control Path Graph V2 nodes and edges for delegated SDLC intent, human, agent team, PR/MR, approval, deployment, asset, evidence, and outcome paths.
Semver marker override: [semver:minor]
Contract/API impact: Additive graph schema enum values, summary fields, and refs.
Versioning/migration impact: Existing graph version remains compatible unless implementation chooses an explicit additive graph contract marker.
Architecture constraints: Aggregation constructs graph; risk lineage decorates paths from graph refs only.
ADR required: yes
TDD first failing test(s): Add graph V2 schema and golden fixture tests before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Missing or duplicate graph refs do not panic and render explicit missing/conflict refs.

### Story 2.3: Extend Intent-To-Outcome Lineage

Priority: P1
Recommendation coverage: 34

Tasks:
- Extend `action_lineage` with optional intent, task/request, human, agent/session, PR/MR, workflow/run, credential, target/action, approval/control, deployment, outcome, and proof/evidence segments.
- Populate lineage from PR/MR sidecars, coding-agent session ingest, provider metadata, CI/CD run metadata, runtime evidence, proof refs, deployment/publish outcomes, and graph V2 refs.
- Keep lineage segments optional with explicit `missing`, `unknown`, `present`, `verified`, `declared`, `inferred`, or `contradictory` statuses.
- Add evidence refs and graph node/edge refs for every lineage segment.
- Render concise lineage in focused BOM and detailed lineage in appendix JSON/markdown.

Repo paths:
- `core/risk/action_lineage.go`
- `core/risk/introduced_by.go`
- `core/attribution/provider_metadata.go`
- `core/ingest/ingest.go`
- `core/aggregate/attackpath/graph.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/control-path-graph.schema.json`
- `schemas/v1/agent-action-bom.schema.json`

Run commands:
- `go test ./core/risk ./core/attribution ./core/ingest ./core/aggregate/attackpath ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`

Test requirements:
- Segment construction tests for full, partial, and missing lineage.
- Contract tests for lineage schema and refs.
- Scenario tests proving request-to-outcome path renders without default network access.

Matrix wiring:
- Fast lane: lineage unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario with PR/MR, workflow run, approval, deployment, and proof refs.
- Cross-platform lane: stable segment IDs and path normalization.
- Risk lane: chaos test for partial provider metadata and conflicting outcome evidence.

Acceptance criteria:
- Existing repo/workflow/agent/action lineage remains available.
- New segments are additive and deterministic.
- Focused BOM uses concise lineage while appendix retains full refs.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added intent-to-outcome action lineage segments for delegated SDLC workflows.
Semver marker override: [semver:minor]
Contract/API impact: Additive lineage segment kinds and refs in BOM/risk schemas.
Versioning/migration impact: Consumers that only know older segments can ignore new kinds.
Architecture constraints: Lineage decorates from graph/evidence/provenance; it must not parse raw source directly.
ADR required: no
TDD first failing test(s): Add lineage segment golden tests before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Missing task/session/outcome evidence yields explicit unknown segments, not silently omitted safety claims.

## Epic 3: Provenance, Evidence Packets, And Recent PR Review

Objective: make consequential AI-assisted SDLC changes auditable through local provider metadata and typed evidence packets.
Traceability: Recommendations 24, 25, and 26.

### Story 3.1: Expand Provider-Neutral PR/MR Provenance

Priority: P0
Recommendation coverage: 24

Tasks:
- Extend attribution sidecar contracts for PR/MR metadata, changed files, authors, reviewers, approvals, required checks, check results, security scan results, deployments, merge method, branch protections, and environment gates.
- Normalize GitHub, GitLab, and generic provider shapes into provider-neutral structs.
- Correlate provenance to action paths by changed files, workflow paths, code paths, PR/MR IDs, commit SHA, branch/environment, and graph refs.
- Expose provenance on `introduced_by`, action lineage, workflow chain, evidence packets, Agent Action BOM, report artifacts, and CLI artifacts.
- Add deterministic conflict handling for disagreeing reviewers, check states, approvals, deployments, or branch protection evidence.

Repo paths:
- `core/attribution/provider_metadata.go`
- `core/risk/introduced_by.go`
- `core/report/build.go`
- `core/cli/report_artifacts.go`
- `core/report/agent_action_bom.go`
- `schemas/v1`
- `testinfra/contracts`

Run commands:
- `go test ./core/attribution ./core/risk ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- Parser/normalizer tests for GitHub, GitLab, and generic PR/MR sidecars.
- Correlation tests for changed files, workflow edits, branch/environment gates, check results, and deployments.
- Contract tests for provenance schema and redacted export behavior.

Matrix wiring:
- Fast lane: provider metadata unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario with AI-assisted PR/MR provenance and required checks.
- Cross-platform lane: changed-file path normalization smoke.
- Risk lane: hardening/chaos for malformed sidecars, conflicting approvals, and missing required checks.

Acceptance criteria:
- PR/MR provenance answers who authored, reviewed, approved, checked, deployed, and merged a change when local sidecars provide the data.
- Missing or conflicting provider data is explicit in JSON and markdown.
- No provider API calls are introduced.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added provider-neutral PR/MR provenance sidecars for changed files, reviewers, approvals, checks, deployments, merge metadata, branch protection, and environment gates.
Semver marker override: [semver:minor]
Contract/API impact: Additive provenance schemas and introduced-by fields.
Versioning/migration impact: Existing simple source metadata remains valid; new sidecars are optional.
Architecture constraints: Attribution owns provider normalization; risk/report consume normalized provenance only.
ADR required: no
TDD first failing test(s): Add provider sidecar parser and correlation tests before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Corrupted or contradictory provenance fails closed with explicit conflict/missing evidence status.

### Story 3.2: Add Agentic SDLC Evidence Packets

Priority: P0
Recommendation coverage: 25

Tasks:
- Define typed evidence packet schema and Go model for consequential AI-assisted SDLC changes.
- Include task, owner, agent identity, tool calls, code diff refs or digests, files touched, autonomy tier, permissions, credentials, tests, reviewers, approvals, deployment path, policy verdict, exceptions, result, proof refs, and missing-evidence status.
- Ingest packet sidecars through local files, normalize and validate deterministically, and redact according to share profile.
- Correlate packets to action paths, workflow chains, graph refs, PR/MR provenance, runtime evidence, control backlog, proof coverage, and Agent Action BOM items.
- Emit packet summaries and refs through report artifacts and evidence bundles.

Repo paths:
- `core/ingest/ingest.go`
- `core/evidence/evidence.go`
- `core/report/control_proof.go`
- `core/report/agent_action_bom.go`
- `core/cli/report_artifacts.go`
- `schemas/v1`
- `testinfra/contracts`

Run commands:
- `go test ./core/ingest ./core/evidence ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-hardening`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- Schema and normalization tests for complete, partial, stale, invalid, and redacted evidence packets.
- Correlation tests linking packets to path IDs, PR/MR IDs, workflow IDs, proof refs, and graph refs.
- Hardening tests that raw secret-like values and unsafe paths are not serialized.

Matrix wiring:
- Fast lane: evidence packet unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario with evidence packet included in report/evidence bundle.
- Cross-platform lane: local file path normalization and artifact write smoke.
- Risk lane: hardening/chaos for malformed packets, stale packets, redaction, and unsafe output paths.

Acceptance criteria:
- Evidence packets are schema-backed and can be ingested from local files.
- Missing evidence is explicit and does not block packet emission unless schema/security constraints fail.
- Evidence bundle exports include packet summaries/refs without leaking raw secrets or private payloads.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added typed Agentic SDLC evidence packets for consequential AI-assisted changes, including proof refs and missing-evidence status.
Semver marker override: [semver:minor]
Contract/API impact: New v1 evidence packet schema and additive report/evidence refs.
Versioning/migration impact: Existing runtime evidence bundles remain compatible.
Architecture constraints: Ingest validates/normalizes packets; evidence/report layers emit summaries and refs.
ADR required: no
TDD first failing test(s): Add packet schema and redaction fixture tests before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Partial or stale packets remain auditable as incomplete evidence and cannot mark a path verified.

### Story 3.3: Add Recent AI-Assisted PR/MR Review Workflow

Priority: P1
Recommendation coverage: 26

Tasks:
- Add a named local workflow that reviews a bounded set of recent PRs/MRs or a date range from explicit IDs or provider metadata sidecars.
- Join PR/MR metadata, changed files, workflow/config changes, AI/session evidence, MCP/tool/framework signals, credentials, checks, approvals, deployments, controls, proof records, runtime evidence, and evidence packets.
- Rank AI-assisted or automation-assisted delivery paths by autonomy tier, delegation readiness, recommended control, high-stakes target, evidence completeness, and contradiction state.
- Render focused workflow BOMs for the top paths and appendix details for raw findings, scan quality, graph refs, proof refs, and detector diagnostics.
- Fail with exit `6` for invalid ID/date inputs and avoid provider network calls by default.

Repo paths:
- `core/attribution/provider_metadata.go`
- `core/risk/introduced_by.go`
- `core/risk/action_lineage.go`
- `core/report/agent_action_bom.go`
- `core/cli/report_artifacts.go`
- `core/report/templates/templates.go`
- `schemas/v1`
- `docs/commands/report.md`

Run commands:
- `go test ./core/attribution ./core/risk ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-scenarios`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- CLI/input tests for explicit IDs, date ranges, missing metadata, and invalid inputs.
- Ranking tests for AI-assisted PRs with checks, approvals, deployments, credentials, and proof refs.
- Scenario tests for "review 10 recent AI-assisted PRs" using local sidecars only.

Matrix wiring:
- Fast lane: input parsing, ranking, and report unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: local scenario for bounded recent PR/MR review.
- Cross-platform lane: date parsing and path normalization smoke.
- Risk lane: hardening test for invalid ranges, too-large bounded sets, and missing provenance.

Acceptance criteria:
- The workflow ranks bounded recent AI/automation-assisted delivery paths without network calls.
- Invalid or unsupported inputs use deterministic error classes and exit codes.
- Output links each ranked path to focused BOM, provenance, graph, proof, evidence packet, and missing evidence.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a local recent PR/MR review workflow for ranking bounded AI-assisted or automation-assisted delivery paths from provider metadata sidecars.
Semver marker override: [semver:minor]
Contract/API impact: Additive CLI/report mode and JSON fields for recent PR/MR review.
Versioning/migration impact: Existing report behavior remains available; focused review is opt-in until default BOM behavior is updated.
Architecture constraints: Report/CLI orchestrates local data; attribution/risk provide normalized facts.
ADR required: no
TDD first failing test(s): Add CLI and ranking tests for bounded PR/MR review before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Partial provider metadata ranks with lower completeness and cannot claim approval/proof that is not present.

## Epic 4: High-Stakes Authority And Production Context

Objective: prioritize paths where agents or workflows can affect production, customer data, credentials, releases, cloud resources, SaaS systems, or regulated flows.
Traceability: Recommendations 27, 28, 29, and 30.

### Story 4.1: Add High-Stakes Path Presets

Priority: P0
Recommendation coverage: 27

Tasks:
- Add deterministic classifiers and filters for release automation, production paths, credential-bearing automation, IaC, identity/auth code, package publishing, payment flows, regulated/customer-facing workflows, external egress, MCP/tool configs, and mutable endpoints.
- Feed high-stakes presets into autonomy tier, delegation readiness, risk validation, control backlog priority, and Agent Action BOM ordering.
- Add high-stakes preset reason codes and evidence refs from workflowcap, mutable endpoint, action path, buyer projection, and control backlog sources.
- Ensure presets are explainable and avoid noisy bulk output by emphasizing top actionable paths.
- Add docs and schema enum definitions for preset names and classification reasons.

Repo paths:
- `core/detect/workflowcap/analyze.go`
- `core/risk/mutable_endpoint.go`
- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/risk/risk-report.schema.json`

Run commands:
- `go test ./core/detect/workflowcap ./core/risk ./core/aggregate/controlbacklog -count=1`
- `make test-contracts`
- `make test-scenarios`

Test requirements:
- Unit tests for each preset and reason code.
- Scenario tests for release, IaC, auth, payment, external egress, package publish, and MCP/tool config paths.
- Regression tests preventing generic low-priority rendering for high-stakes paths.

Matrix wiring:
- Fast lane: classifier unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: high-stakes scenario fixtures.
- Cross-platform lane: path and workflow command normalization smoke.
- Risk lane: hardening tests for ambiguous high-stakes indicators and fail-closed classification.

Acceptance criteria:
- High-stakes presets are visible in JSON and markdown with evidence refs.
- Presets affect prioritization without suppressing raw evidence.
- Sensitive but incomplete paths route to review/proof rather than safe delegation.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added high-stakes path presets for CI/CD, release automation, MCP/tool configs, IaC, auth, payments, regulated workflows, dependency publishing, credentials, egress, and mutable endpoints.
Semver marker override: [semver:minor]
Contract/API impact: Additive preset fields/enums in action path and BOM schemas.
Versioning/migration impact: Existing risk fields remain; high-stakes fields refine prioritization.
Architecture constraints: Detection produces facts; risk owns preset-to-control projection.
ADR required: no
TDD first failing test(s): Add high-stakes classifier fixtures before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Ambiguous high-stakes evidence is marked review/proof required rather than safe.

### Story 4.2: Tie Production-Data Findings To Agent/Workflow Context

Priority: P0
Recommendation coverage: 28

Tasks:
- Join mutable-endpoint, route, OpenAPI, workflow, tool, credential authority, owner, deployment, action class, path type, target class, proof, and evidence state facts.
- Render nearest workflow/tool/credential/owner context for production-data and mutable-endpoint findings in Agent Action BOM and markdown.
- Add target/action context reason codes and refs to action paths and control backlog items.
- Ensure generic route/API findings are promoted to agent/workflow/action findings only when there is a deterministic correlation.
- Add appendix details for route/API evidence and detector diagnostics.

Repo paths:
- `core/risk/mutable_endpoint.go`
- `core/risk/action_paths.go`
- `core/detect/routes/detector.go`
- `core/detect/openapi/detector.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `schemas/v1/agent-action-bom.schema.json`

Run commands:
- `go test ./core/risk ./core/detect/routes ./core/detect/openapi ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`

Test requirements:
- Unit tests for route/API to action-path correlation.
- Scenario tests for production mutation, payment/refund, user admin, data export, and read-only endpoints.
- Markdown golden tests proving production-data findings render with agent/workflow/credential context.

Matrix wiring:
- Fast lane: correlation and rendering tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: production-data scenario fixture.
- Cross-platform lane: path normalization and route ordering smoke.
- Risk lane: hardening tests for false joins and incomplete route evidence.

Acceptance criteria:
- Production-data findings include workflow, tool, credential authority, owner, deployment, action, path, target, and evidence context when deterministically available.
- Uncorrelated route/API findings stay in appendix/supporting context rather than pretending to be governed paths.
- Output distinguishes read-only from mutable/customer-impacting semantics.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Improved production-data and mutable-endpoint findings with agent, workflow, credential, owner, deployment, action, target, and evidence context.
Semver marker override: [semver:minor]
Contract/API impact: Additive context fields and refs in BOM/report outputs.
Versioning/migration impact: Existing mutable endpoint fields remain valid.
Architecture constraints: Detection owns route/API parsing; risk/report own correlation and presentation.
ADR required: no
TDD first failing test(s): Add route/API correlation and markdown golden tests before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Weak correlations remain appendix-only and cannot inflate or sanitize action-path claims.

### Story 4.3: Link Cloud Role And Deployment Authority

Priority: P0
Recommendation coverage: 29

Tasks:
- Parse Terraform IAM, CloudFormation IAM, Kubernetes RBAC, GitHub OIDC trust, Azure federated credentials, GCP workload identity, deployment commands, service connections, environment names, and production-target policies.
- Link workflow credentials and action paths to cloud roles, deployment targets, Kubernetes permissions, Terraform/IaC resources, and production assets.
- Add authority reason codes for admin/write/read-only, production target, environment gate, service connection, workload identity, standing credential, and JIT/workload credential.
- Feed cloud/deployment authority into autonomy tier, delegation readiness, recommended control, high-stakes presets, graph V2, workflow chains, and evidence packets.
- Add fixtures with fake cloud/account/project/cluster/role/resource names only.

Repo paths:
- `core/detect/nonhumanidentity/detector.go`
- `core/detect/secrets/detector.go`
- `core/detect/workflowcap/analyze.go`
- `core/aggregate/inventory/privileges.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/attackpath/graph.go`
- `schemas/v1/inventory/inventory.schema.json`
- `schemas/v1/control-path-graph.schema.json`

Run commands:
- `go test ./core/detect/nonhumanidentity ./core/detect/secrets ./core/detect/workflowcap ./core/aggregate/inventory ./core/aggregate/privilegebudget ./core/aggregate/attackpath -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-perf`

Test requirements:
- Structured parser tests for Terraform, CloudFormation, Kubernetes RBAC, OIDC trust, Azure federation, and GCP workload identity fixtures.
- Correlation tests linking workflow credentials to deployment authority.
- Hardening tests for no secret extraction, malformed IaC, and ambiguous role scope.

Matrix wiring:
- Fast lane: detector/parser/correlation tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: cloud deployment authority scenario fixture.
- Cross-platform lane: fixture path and YAML/JSON parsing smoke.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf`.

Acceptance criteria:
- Workflow credentials can be linked to cloud/deployment authority when structured evidence exists.
- Ambiguous authority is explicit and routes to review/proof rather than safe delegation.
- Raw secrets are never extracted or persisted.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Added cloud role and deployment authority correlation for workflow credentials, IaC resources, Kubernetes permissions, workload identity, service connections, and production assets.
Semver marker override: [semver:minor]
Contract/API impact: Additive inventory, graph, risk, and BOM authority fields.
Versioning/migration impact: Existing credential authority fields remain and are enriched by new evidence.
Architecture constraints: Detection parses structured sources; aggregation correlates authority; risk projects control implications.
ADR required: yes
TDD first failing test(s): Add structured cloud/IaC/RBAC fixtures and no-secret tests before implementation.
Cost/perf impact: high
Chaos/failure hypothesis: Malformed or partial IaC produces dependency/evidence gaps without unsafe role claims.

### Story 4.4: Detect SaaS Scope And Service Tokens

Priority: P1
Recommendation coverage: 30

Tasks:
- Detect SDLC SaaS token families and likely scopes across planning, routing, review, deploy, observe, notify, and operate systems without extracting secret values.
- Classify token family, target system, likely scope, standing/JIT provenance, action classes, blast radius, owner/evidence location, and confidence.
- Feed SaaS authority into credential provenance, credential authority, action paths, workflow chains, high-stakes presets, autonomy tiers, and recommended controls.
- Add safe fixtures for systems such as issue tracking, source control, CI/CD, package registries, observability, incident response, notification, secrets manager, and deployment platforms.
- Add redaction and share-profile tests for SaaS names, URLs, owners, and token refs.

Repo paths:
- `core/detect/secrets/detector.go`
- `core/detect/nonhumanidentity/detector.go`
- `core/detect/dependency/detector.go`
- `core/detect/workflowcap/analyze.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `schemas/v1/inventory/inventory.schema.json`
- `schemas/v1/agent-action-bom.schema.json`

Run commands:
- `go test ./core/detect/secrets ./core/detect/nonhumanidentity ./core/detect/dependency ./core/detect/workflowcap ./core/aggregate/inventory ./core/risk -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- Detector tests for token family and likely scope from safe context.
- No-secret tests proving values are not extracted, logged, or serialized.
- Scenario tests for SaaS deploy token, observability token, package publish token, and notification token.

Matrix wiring:
- Fast lane: SaaS classifier unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: SaaS token authority scenario fixture.
- Cross-platform lane: env/config path normalization smoke.
- Risk lane: hardening tests for secret scrubbing and ambiguous scope.

Acceptance criteria:
- SaaS service-token authority appears in credential provenance and action-path context without secret values.
- Likely scope is reason-coded and confidence-labeled.
- Ambiguous broad SaaS authority influences readiness/control outcomes.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Added SaaS service-token family and likely-scope classification for SDLC systems without extracting secret values.
Semver marker override: [semver:minor]
Contract/API impact: Additive credential provenance, inventory, risk, and BOM fields.
Versioning/migration impact: Existing secret-presence findings remain; new fields enrich context.
Architecture constraints: Detection classifies safe context only; aggregation/risk derive authority and controls.
ADR required: no
TDD first failing test(s): Add no-secret SaaS token fixtures before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Unknown token family/scope remains unknown and cannot produce a false low-risk delegation state.

## Epic 5: Primary Workflow BOM Experience

Objective: make the first buyer-facing report a one-workflow action-control artifact instead of a broad scanner dump.
Traceability: Recommendations 36A and 36B.

### Story 5.1: Make Single-Workflow Agent Action BOM The Default Buyer Presentation

Priority: P0
Recommendation coverage: 36A

Tasks:
- Define the default Agent Action BOM presentation contract around one workflow/action path: path map, authority, target, control resolution, evidence state, delegation readiness, proof state, and recommended governed path.
- Keep raw findings, scan quality, graph refs, proof refs, detector diagnostics, and broad item lists in appendix/evidence JSON by default.
- Add summary metadata that identifies the selected primary path, selection reason, autonomy tier, readiness state, recommended control, evidence completeness, and appendix refs.
- Update markdown rendering so the first page always leads with the selected workflow/action path.
- Preserve machine-readable full BOM items for existing consumers.

Repo paths:
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/templates/templates.go`
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`

Run commands:
- `go test ./core/report ./core/cli -count=1`
- `make test-contracts`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make test-focused-docs`

Test requirements:
- Markdown golden tests proving the first page starts with the primary workflow path.
- JSON/schema tests for primary path metadata and appendix refs.
- Docs parity tests for report command behavior and examples.

Matrix wiring:
- Fast lane: report rendering and CLI unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: v1 acceptance fixture for default BOM presentation.
- Cross-platform lane: markdown rendering and artifact path smoke.
- Risk lane: hardening test for empty/no-focused-path states.

Acceptance criteria:
- Default buyer BOM leads with one selected path, not raw scanner sections.
- Appendix sections retain full auditability and machine-readable details.
- Existing full JSON item list remains available.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed the default Agent Action BOM presentation to lead with one workflow/action path and move raw findings, graph refs, proof refs, scan quality, and detector diagnostics to appendices.
Semver marker override: [semver:minor]
Contract/API impact: Additive primary-view metadata and markdown presentation change.
Versioning/migration impact: Existing JSON items remain; markdown order changes intentionally.
Architecture constraints: Report owns presentation; risk/aggregation own facts.
ADR required: no
TDD first failing test(s): Add first-page BOM golden tests before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: When no eligible primary path exists, output uses explicit empty-state/coverage-reduced language and keeps appendices available.

### Story 5.2: Add One-Page Focused Workflow BOM View

Priority: P0
Recommendation coverage: 36B

Tasks:
- Add focused rendering such as `--focus-path <path_id>` or equivalent workflow BOM mode after matching existing CLI patterns.
- Limit the primary page to path map `AI/tool -> repo/PR -> workflow -> credential -> action -> target`, evidence labels, delegation readiness, control resolution, unresolved evidence, recommended control, and before/after governed path.
- Move scan quality, raw findings, graph refs, proof details, and detector diagnostics to appendix JSON/Markdown sections.
- Add deterministic path ID validation and clear errors for missing, ambiguous, or context-only paths.
- Add one-page markdown/PDF-ready layout constraints in templates without adding a hosted UI.

Repo paths:
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/templates/templates.go`
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`

Run commands:
- `go test ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-focused-docs`

Test requirements:
- CLI contract tests for valid focus path, missing path, ambiguous path, and context-only path handling.
- Markdown golden tests for the one-page path map and appendix split.
- Scenario test for focused workflow BOM from recent PR review and from regular report output.

Matrix wiring:
- Fast lane: CLI/report focus-path tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: focused BOM scenario fixture.
- Cross-platform lane: stable artifact paths and markdown rendering.
- Risk lane: hardening tests for unsafe output paths and invalid path IDs.

Acceptance criteria:
- Focused BOM output fits the primary workflow page contract.
- Unknown path IDs fail deterministically with invalid-input behavior.
- Appendix output remains complete and linkable from the primary page.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a focused one-page Agent Action BOM view for a single workflow/action path with appendix details for raw findings, graph refs, proof details, and detector diagnostics.
Semver marker override: [semver:minor]
Contract/API impact: Additive CLI/report mode and focused BOM schema fields.
Versioning/migration impact: Existing report command behavior remains available with additive focus mode.
Architecture constraints: CLI validates selection; report renders; no new hosted service or UI runtime.
ADR required: no
TDD first failing test(s): Add focus-path CLI and markdown golden tests before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Invalid focus selection cannot produce a misleading partial report.

## Epic 6: Contracts, Scenarios, Docs, And Release Readiness

Objective: lock Sprint 3 behavior into public schemas, executable scenarios, docs, changelog, and release validation lanes.
Traceability: All Sprint 3 recommendations.

### Story 6.1: Update Schemas, Scenarios, Docs, Changelog, And Acceptance Coverage

Priority: P0
Recommendation coverage: 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 36A, 36B

Tasks:
- Update all touched v1 schemas with autonomy tier, readiness, recommended control, workflow chain, graph V2, PR/MR provenance, evidence packet, high-stakes presets, production context, cloud/SaaS authority, validation, action contract, governed path, and focused BOM fields.
- Add deterministic schema fixtures and contract tests for old and new report shapes.
- Add scenarios for each major Sprint 3 path: safe metadata, low-risk internal, owner-review app code, sensitive infra/auth, production/customer-impacting deploy, evidence packet, recent PR/MR review, high-stakes cloud authority, SaaS token, contradiction, and focused BOM.
- Update docs and examples for report, ingest, export, evidence, contracts/schemas, and detection coverage.
- Update changelog with operator-facing entries and semver marker guidance.
- Add docs parity checks for CLI flags, JSON shape, examples, and markdown first-page story.

Repo paths:
- `schemas/v1`
- `testinfra/contracts`
- `internal/acceptance`
- `internal/scenarios/coverage_map.json`
- `scenarios/wrkr`
- `README.md`
- `docs/commands/report.md`
- `docs/commands/ingest.md`
- `docs/commands/export.md`
- `docs/commands/evidence.md`
- `docs/trust/contracts-and-schemas.md`
- `docs/trust/detection-coverage-matrix.md`
- `schemas/v1/README.md`
- `CHANGELOG.md`

Run commands:
- `make lint-fast`
- `make test-fast`
- `make test-contracts`
- `scripts/validate_scenarios.sh`
- `make test-scenarios`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make test-focused-docs`
- `make prepush-full`

Test requirements:
- Contract tests for every new schema and compatibility fixture.
- Scenario tests mapped in `internal/scenarios/coverage_map.json`.
- Docs-vs-CLI parity tests for new flags, examples, and report behavior.
- Release acceptance run before advertising Sprint 3 behavior.

Matrix wiring:
- Fast lane: schema/docs focused tests and targeted unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario validation, scenario tests, and local v1 acceptance.
- Cross-platform lane: Windows smoke for schemas, fixtures, report artifacts, and path normalization.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf` when implementation touches authority parsing or graph scale.
- Release/UAT lane: `make test-release-smoke` and `scripts/run_v1_acceptance.sh --mode=release`.

Acceptance criteria:
- Every Sprint 3 public contract has a schema and deterministic fixture.
- Every recommendation maps to at least one scenario or contract test.
- Docs explain local-first sidecars, no-default-network behavior, focused BOM, evidence packets, autonomy tiers, readiness, recommended controls, action contracts, and high-stakes authority.
- Changelog entries are present before release.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Documented Sprint 3 Agent Action BOM, workflow-chain, evidence-packet, autonomy-tier, high-stakes authority, and focused report contracts with schema and scenario coverage.
Semver marker override: [semver:minor]
Contract/API impact: Broad additive v1 schema, scenario, docs, and CLI/report contract updates.
Versioning/migration impact: No field removals; additive fields require schema consumers to tolerate new enums and objects.
Architecture constraints: Docs and schemas must match executable behavior in the same PRs.
ADR required: no
TDD first failing test(s): Add schema/fixture/docs parity failures before implementation PRs update behavior.
Cost/perf impact: low
Chaos/failure hypothesis: Contract drift is caught by docs, schema, scenario, and acceptance lanes before release.

## Definition of Done

- All Sprint 3 recommendation rows in the traceability table map to shipped stories, tests, schemas, docs, and changelog entries.
- New fields are additive, schema-backed, documented, and deterministic.
- No scan/risk/proof/report path calls an LLM or defaults to network access.
- No raw secret values are extracted, logged, serialized, or committed in fixtures.
- Autonomy tier, delegation readiness, recommended control, action contract readiness, and risk tier remain distinct concepts in code, JSON, markdown, and docs.
- Control Path Graph V2 and workflow chains preserve stable IDs and refs across repeated runs.
- Evidence packets, PR/MR provenance, and recent PR/MR review use local sidecars by default and fail closed on invalid inputs.
- Focused Agent Action BOM output leads with one workflow/action path and moves broad diagnostics to appendices.
- Required local gates for implementation PRs are green: `make lint-fast`, `make test-fast`, `make test-contracts`, scenario validation, local v1 acceptance, and focused docs checks.
- Risk-bearing implementation PRs also run hardening, chaos, performance, or `make prepush-full` lanes as specified by story matrix wiring.

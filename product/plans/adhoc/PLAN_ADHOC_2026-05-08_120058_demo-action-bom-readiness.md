# Adhoc Plan: Demo Action BOM Readiness

Date: 2026-05-08
Profile: `wrkr`
Slug: `demo-action-bom-readiness`
Recommendation source: user-provided demo-readiness recommendations covering PR provenance, buyer-facing control state, skill/instruction action semantics, risk zones and review burden, CI credential precision, Gait coverage projection, and an outside-in 5-minute demo acceptance scenario.

All paths in this plan are repo-relative. This is a planning artifact only; it does not implement runtime, schema, scenario, or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product. These stories must not implement Gait enforcement, Axym compliance logic, or any scan-time LLM path.
- Default scan, risk, proof, and report behavior must remain local-first and deterministic. Provider or PR enrichment can use already-materialized CI/source metadata by default; live provider API calls must be explicit, bounded, auditable, and fail closed or degrade with clear quality signals.
- Secret values must never be extracted. Credential precision means classifying secret references, token names, workflow permission posture, and provenance, not serializing secret material.
- Schema and JSON changes are additive v1 contract changes unless a story explicitly introduces a versioned migration. Existing `introduced_by`, credential provenance, policy coverage, runtime evidence, and action path fields must stay backward-compatible.
- Buyer-facing fields must be deterministic projections from existing evidence and new static signals, not prose generated from model output.
- Action path and Agent Action BOM output should answer the demo questions directly: who/what introduced the path, what it can do, what credential or control gap makes it risky, whether it should be approved, blocked, evidenced, or inventoried, and whether Gait coverage exists.
- Risk ranking remains focused on top actionable paths. New semantic signals must reduce ambiguity without creating noisy bulk findings.
- Scenario fixtures are spec artifacts. The 5-minute demo scenario must exercise scan, report, BOM JSON, BOM markdown, schemas, and docs in one outside-in lane.
- Changelog entries are required because the work changes public report/BOM JSON, schemas, docs, risk semantics, and scenario coverage.

## Current Baseline (Observed)

- The requested code surfaces exist in this repo, including `core/attribution/attribution.go`, `core/risk/introduced_by.go`, `core/risk/action_paths.go`, `core/report/agent_action_bom.go`, `core/detect/ciagent/detector.go`, `core/detect/workflowcap/analyze.go`, `core/detect/skills/detector.go`, `core/ingest/ingest.go`, and `core/cli/report.go`.
- `attribution.Result` and report/BOM schemas already expose optional `introduced_by` fields such as `pr_number` and `provider_url`, but the recommendation source states normal scan/report attribution is not reliably populated with PR-level context.
- Agent Action BOM and report docs already describe action path fields for action classes, standing privilege, credential provenance, policy coverage, runtime evidence status/classes, proof coverage, and local git attribution.
- `control_state`, `risk_zone`, and `review_burden` are not named as explicit report/BOM/action path fields in the current searched code and schema surfaces.
- Runtime evidence ingest already normalizes classes such as `policy_decision`, `approval`, `jit_credential`, `freeze_window`, `kill_switch`, `action_outcome`, and `proof_verification`; BOM output currently summarizes status/classes/refs rather than projecting a compact per-control coverage table.
- Credential provenance schemas already include several high-value kinds such as `github_pat`, `github_app_key`, `deploy_key`, `cloud_admin_key`, `cloud_access_key`, `jit_credential`, and `unknown_durable`; workflow detectors still need more direct workflow secret/env reference extraction and same-path attachment.
- Existing scenario and acceptance tests include Agent Action BOM and action path anchors, but the requested exact 5-minute demo path needs a dedicated fixture or extension proving PR/workflow, headless AI agent, broad PAT/cloud admin references, skill instructions, MCP config, owner/approval/proof gaps, Gait evidence, JSON output, and markdown output together.

## Exit Criteria

- Agent Action BOM JSON and markdown show PR-level provenance when deterministic provider metadata is available: `pr_number`, `provider_url`, `commit_sha`, author, timestamp, and changed file.
- Local-only scans remain deterministic and useful when provider metadata is unavailable, with stable fallback attribution and explicit provenance quality/reason fields where needed.
- Each action path and BOM item carries a deterministic `control_state` value: `safe_by_default`, `approval_required`, `block_recommended`, `evidence_required`, or `inventory_only`.
- Each action path and BOM item carries a deterministic `risk_zone` value from the demo taxonomy: `coding_help`, `repo_write`, `credential_bearing`, `ci_cd`, `iac`, `release`, `production_data`, or `external_egress`.
- Each action path and BOM item carries `review_burden` and review burden reasons derived from write/deploy/release frequency signals when present, and from owner, approval, proof, and backlog signals when frequency is unavailable.
- Skill and agent instruction scanning emits deterministic semantic action hints for deploy/release, cloud/database, secret handling, MCP/tool binding, package/script execution, approval bypass, destructive commands, ownership/review gaps, and proof requirements.
- GitHub workflow and CI detections classify broad PATs, cloud admin keys, GitHub App keys, deploy keys, generic durable secrets, and GitHub workflow tokens by reference name and workflow permission posture without extracting secret values.
- Gait coverage is projected per action path as present/missing/stale/conflict/not-applicable for policy decision, approval, JIT credential, freeze window, kill switch, action outcome, and proof verification, without implementing enforcement.
- A deterministic acceptance scenario proves the 5-minute demo path end to end across `wrkr scan`, `wrkr report`, Agent Action BOM JSON, Agent Action BOM markdown, schemas, and docs.

## Public API and Contract Map

- Scan/report/BOM JSON contracts:
  - `summary.action_paths[]`, top-level `action_paths[]`, risk report action path projections, and Agent Action BOM `items[]` gain additive fields for `control_state`, `risk_zone`, `review_burden`, and reasons/evidence refs where needed.
  - Existing `introduced_by` fields remain optional and gain reliable population from local git, CI event payloads, source acquisition metadata, and explicit provider enrichment when configured.
  - Runtime coverage fields stay additive and must not mutate saved scan findings.
- Schema contracts:
  - Update `schemas/v1/agent-action-bom.schema.json`, `schemas/v1/report/report-summary.schema.json`, `schemas/v1/risk/risk-report.schema.json`, and relevant inventory/export schemas when new fields are serialized.
  - Keep enum additions backward-compatible and document omitted-field behavior for older sidecars and reports.
- CLI contracts:
  - `wrkr scan --json`, `wrkr report --json`, and report/BOM markdown remain deterministic for the same inputs, except explicit timestamp/version fields.
  - If a new explicit provenance enrichment flag is required, it must be documented with network/privacy behavior and must not alter default zero-egress behavior.
  - Exit codes remain unchanged: provider metadata absence is a quality/degradation signal, not a runtime failure, unless the user explicitly requested provider enrichment and it fails closed.
- Proof/evidence contracts:
  - Proof record types remain consistent with existing Wrkr and `Clyra-AI/proof` primitives.
  - Runtime evidence coverage is report projection only; Gait remains the control/enforcement product.
- Docs contracts:
  - `docs/commands/report.md` and related command docs must show how to read `control_state`, `risk_zone`, `review_burden`, PR provenance, credential provenance, and Gait coverage.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `docs/commands/report.md`
  - `docs/commands/scan.md` if scan provenance inputs or flags change
  - `docs/commands/ingest.md` for runtime evidence/Gait sidecar coverage
  - `docs/examples/security-team.md`
  - `docs/examples/operator-playbooks.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- OSS trust baseline must remain aligned:
  - No new default telemetry, provider calls, or scan-data exfiltration.
  - No generated binaries, transient reports, or demo output artifacts committed outside fixture expectations.
  - Fixture secrets must be references only, never real values.
- Docs must answer:
  - Which PR or workflow introduced this risky path?
  - Is this path safe by default, approval-required, evidence-required, inventory-only, or block-recommended?
  - What risk zone is it in, and why is the review burden high or low?
  - Which credential reference is driving the posture?
  - Which Gait controls are present or missing without implying Wrkr enforces them?

## Recommendation Traceability

| Recommendation / Finding | Priority | Planned Coverage |
|---|---:|---|
| Populate `introduced_by` with PR-level context when available | P0 | Story 1.1 |
| Add explicit buyer-facing `control_state` | P0 | Story 2.2 |
| Deepen skill and instruction scanning into semantic action hints | P0 | Story 2.1 |
| Add explicit `risk_zone` and `review_burden` fields | P1 | Story 2.3 |
| Improve workflow credential classification for broad PAT/cloud admin demo | P0 | Story 1.2 |
| Show Gait coverage per BOM path without implementing Gait | P1 | Story 3.1 |
| Add outside-in deterministic 5-minute demo acceptance scenario | P0 | Story 4.1 |

## Test Matrix Wiring

- Fast lane:
  - Focused package tests for attribution, workflow credential classification, skill semantic extraction, action path derivation, BOM build/render, and ingest correlation.
  - Candidate commands: `go test ./core/attribution ./core/risk ./core/report -count=1`, `go test ./core/detect/ciagent ./core/detect/workflowcap ./core/detect/skills ./core/detect/promptchannel ./core/detect/agentframework -count=1`, and `go test ./core/ingest ./core/evidence ./core/cli -run 'Test.*RuntimeEvidence|Test.*AgentActionBOM|Test.*Report' -count=1`.
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `go test ./internal/acceptance -run 'Test.*AgentActionBOM|Test.*Demo' -count=1`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
- Cross-platform lane:
  - Windows smoke for CLI JSON/markdown rendering, path normalization, and fixture path behavior.
  - Provider metadata tests must avoid shell-specific assumptions and live network calls.
- Risk lane:
  - `make test-hardening` for fail-closed provider enrichment, unsafe path handling, and no-secret serialization.
  - `make test-chaos` for provider metadata unavailable/stale/conflict states and runtime evidence sidecar failures.
  - `make test-perf` when semantic scanning or workflow parsing materially changes scan/report runtime.
- Release/UAT lane:
  - `scripts/run_v1_acceptance.sh --mode=local`
  - Release UAT only if docs or examples add new copy-paste public commands.
- Gating rule:
  - Story completion requires focused tests plus the lane marked for that story. Final implementation requires `make prepush-full`, `make test-contracts`, scenario validation, and the 5-minute demo acceptance scenario green.

## Minimum-Now Sequence

- Wave 1 - Demo evidence foundation:
  - Story 1.1 wires PR/provider provenance into existing `introduced_by` contracts.
  - Story 1.2 classifies workflow credential references and attaches them to the same CI action path.
- Wave 2 - Action semantics and buyer projection:
  - Story 2.1 extracts deterministic skill/instruction action semantics.
  - Story 2.2 derives explicit `control_state`.
  - Story 2.3 derives `risk_zone` and `review_burden`.
- Wave 3 - Control-loop coverage:
  - Story 3.1 projects Gait coverage from runtime evidence sidecars without implementing enforcement.
- Wave 4 - Outside-in proof:
  - Story 4.1 adds the 5-minute demo fixture, acceptance tests, and docs synchronization.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No Axym or Gait product feature implementation in Wrkr.
- No scan-time LLM calls, model-generated risk explanations, telemetry upload, or default live provider lookup.
- No extraction, hashing, or persistence of secret values.
- No removal or incompatible renaming of existing report/BOM/action path fields.
- No branch-protection, CI, schema, proof verification, or exit-code bypass.
- No broad report redesign beyond the fields and markdown sections needed for the requested demo narrative.

## Definition of Done

- Every story starts with failing tests or fixture assertions for the requested behavior.
- New fields are additive, schema-validated, documented, and present in JSON and markdown where applicable.
- Default local scans remain deterministic and private with stable output when provider metadata and runtime evidence are absent.
- Provider/CI provenance is populated when deterministic metadata is available and reports clear quality when unavailable.
- Credential classification operates on references and permission posture only, with tests proving no secret values are serialized.
- Control state, risk zone, review burden, and Gait coverage have stable derivation precedence and reason codes.
- The outside-in scenario proves the demo answers in one path: PR/workflow, headless AI agent, credential, action classes, owner/approval/proof gaps, Gait coverage, BOM JSON, BOM markdown, and docs parity.
- `CHANGELOG.md` includes operator-facing entries under the correct sections.

## Stories

### Story 1.1: PR-Level Provenance Attribution

Priority: P0

Tasks:

- Extend provenance resolution in `core/attribution/attribution.go` and `core/risk/introduced_by.go` so `introduced_by` can be populated from local git history, CI event payloads, source acquisition metadata, branch/ref names, and explicit provider enrichment when configured.
- Keep local-only fallback deterministic: if no PR metadata exists, preserve stable commit/blame attribution and emit a clear provenance source/quality reason rather than fabricating a PR.
- Add provider adapters or helper functions for GitHub and GitLab metadata behind existing source/provider boundaries, with bounded calls only when the user already opted into hosted acquisition or an explicit provenance enrichment setting.
- Wire PR-level attribution through `core/cli/scan.go`, report summary build paths, `core/risk/action_paths.go`, and `core/report/agent_action_bom.go`.
- Ensure fields include `pr_number`, `provider_url`, `commit_sha`, author, timestamp, and changed file, with deterministic ordering and stable omitted-field behavior.
- Update schemas under `schemas/v1` only where serialized surfaces are missing or too permissive for the new contract.
- Update report docs and changelog with the provenance behavior and privacy boundary.

Repo paths:

- `core/attribution/attribution.go`
- `core/risk/introduced_by.go`
- `core/risk/action_paths.go`
- `core/cli/scan.go`
- `core/report/build.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `docs/commands/scan.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/attribution ./core/risk ./core/report -run 'Test.*IntroducedBy|Test.*Provenance' -count=1`
- `go test ./core/cli -run 'TestScan.*Provenance|TestReport.*IntroducedBy' -count=1`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add failing unit tests for PR metadata from GitHub event payload, GitLab merge request metadata, hosted source metadata, and local git fallback.
- Add contract tests proving `introduced_by` provider fields serialize in BOM/report JSON and remain omitted when unavailable.
- Add deterministic ordering tests for multiple candidate PRs or changed files.
- Add failure/degradation tests for provider metadata unavailable, stale, and explicitly requested but unreachable.

Matrix wiring:

- Fast lane: focused attribution, risk, report, and CLI tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: covered by Story 4.1 scenario.
- Cross-platform lane: path normalization and local git fallback must pass on Windows smoke.
- Risk lane: `make test-hardening` if live provider enrichment or new filesystem metadata reads are added.
- Release/UAT lane: not required unless public command examples change.

Acceptance criteria:

- A fixture with deterministic PR metadata renders `introduced_by.pr_number`, `introduced_by.provider_url`, `commit_sha`, author, timestamp, and changed file in BOM/report JSON.
- A local-only fixture without provider metadata produces stable commit attribution and no nondeterministic PR fields.
- Missing provider metadata is visible as quality/degradation context, not a false runtime failure.
- Docs explain default privacy behavior and explicit enrichment behavior.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added deterministic PR-level provenance projection for Agent Action BOM and report action paths when provider or CI metadata is available.
Semver marker override: [semver:minor]
Contract/API impact: Adds optional report/BOM/action path fields and provenance quality semantics; existing fields remain compatible.
Versioning/migration impact: No migration required; older reports omit the new metadata.
Architecture constraints: Preserve Source, Risk, and Compliance/reporting boundaries; provider lookups must stay outside deterministic default scan behavior unless explicitly configured.
ADR required: yes
TDD first failing test(s): `TestIntroducedByIncludesGitHubPRFromEventPayload`, `TestIntroducedByFallsBackToLocalGitWithoutProviderMetadata`, `TestAgentActionBOMIntroducedByProviderFields`
Cost/perf impact: medium when explicit provider enrichment is enabled; low for local metadata paths.
Chaos/failure hypothesis: If provider metadata is unavailable or conflicts with local commit attribution, Wrkr reports deterministic fallback quality and does not invent PR context.

### Story 1.2: Workflow Credential Precision For CI Action Paths

Priority: P0

Tasks:

- Extend `core/detect/ciagent/detector.go` and `core/detect/workflowcap/analyze.go` to extract workflow secret names, env refs, `with` inputs, permission blocks, and `${{ secrets.NAME }}` references from structured workflow YAML.
- Classify common references such as `GH_PAT`, `GITHUB_TOKEN`, `PROD_DEPLOY_PAT`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `GCP_SERVICE_ACCOUNT`, `GOOGLE_APPLICATION_CREDENTIALS`, GitHub App private keys, deploy keys, and generic durable secrets.
- Distinguish ephemeral workflow tokens from broad PATs using workflow `permissions`, action context, and write/deploy/release reachability.
- Attach credential provenance to the same CI action path that carries headless Claude/Codex/Copilot execution, not to a detached generic secret finding.
- Keep `core/detect/secrets/detector.go` aligned so static secret-reference detection and workflow credential classification share stable reason codes without exposing values.
- Update `core/aggregate/privilegebudget/budget.go`, `core/aggregate/inventory/privileges.go`, and `core/risk/action_paths.go` so credential kind/access type influence standing privilege, control state, and risk zone derivation.
- Update schema enums if new additive credential kinds such as `github_workflow_token` are needed.

Repo paths:

- `core/detect/ciagent/detector.go`
- `core/detect/workflowcap/analyze.go`
- `core/detect/secrets/detector.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `schemas/v1/inventory/inventory.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `CHANGELOG.md`

Run commands:

- `go test ./core/detect/ciagent ./core/detect/workflowcap ./core/detect/secrets -run 'Test.*Credential|Test.*Secret|Test.*PAT|Test.*Cloud' -count=1`
- `go test ./core/aggregate/privilegebudget ./core/aggregate/inventory ./core/risk -run 'Test.*Credential|Test.*StandingPrivilege|Test.*ActionPath' -count=1`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add fixture workflows for headless AI agent plus broad PAT, GitHub workflow token with write permissions, cloud admin key refs, GitHub App private key, deploy key, and generic durable secret.
- Prove classification uses names and permission posture only, never secret values.
- Prove credential provenance attaches to the CI action path that owns the workflow agent invocation.
- Add schema/contract tests for any new credential enum values.

Matrix wiring:

- Fast lane: focused detector, inventory, privilege budget, and action path tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 4.1 consumes the same fixture shape.
- Cross-platform lane: not path-sensitive beyond normal fixture handling.
- Risk lane: `make test-hardening` for no-secret serialization and fail-closed parse errors.
- Release/UAT lane: not required.

Acceptance criteria:

- CI workflows with `claude -p`, Codex full-auto, or Copilot coding agent and broad credential refs render the credential on the same BOM/action path.
- `GITHUB_TOKEN` classification reflects permission posture and is not mislabeled as a durable PAT by name alone.
- Cloud admin and deploy key references increase standing privilege/control recommendations deterministically.
- Fixture reports contain credential kind, access type, standing access, evidence basis, and classification reasons.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added precise CI credential-reference classification for headless agent action paths, including broad PAT, workflow token, cloud admin, GitHub App, deploy key, and durable secret references.
Semver marker override: [semver:minor]
Contract/API impact: May add credential enum values and reason codes in inventory, risk, report, and BOM JSON.
Versioning/migration impact: No migration required; older scans omit new credential classifications.
Architecture constraints: Detection owns workflow parsing, Aggregation owns credential rollups, and Risk owns control/action path amplification.
ADR required: no
TDD first failing test(s): `TestCIAgentClassifiesBroadPATOnSameActionPath`, `TestWorkflowCapabilityClassifiesCloudAdminSecretRefs`, `TestCredentialReferencesDoNotSerializeSecretValues`
Cost/perf impact: low.
Chaos/failure hypothesis: Malformed workflow YAML yields deterministic parse errors and does not create false credential access.

### Story 2.1: Skill And Agent Instruction Action Semantics

Priority: P0

Tasks:

- Extend skill and instruction scanners beyond `allowed-tools` so they emit deterministic semantic action hints for deploy/release, cloud/database, secret handling, MCP/tool binding, package/script execution, approval bypass, destructive commands, ownership/review gaps, and proof requirements.
- Use structured parsing for YAML/TOML/frontmatter when available; use a bounded, versioned keyword dictionary only for unstructured markdown instructions.
- Update `core/detect/skills/detector.go`, `core/detect/promptchannel/patterns.go`, and `core/detect/agentframework/source.go` to produce stable evidence keys, action reasons, and source locations.
- Feed semantic action hints into `core/aggregate/inventory/privileges.go` so action classes and credential/production reachability can reflect skill and instruction semantics.
- Update `core/risk/action_paths.go` so semantic signals participate in path inclusion, class derivation, risk zones, review burden, and control state without bypassing existing evidence boundaries.
- Add proof requirement detection as a signal only; do not create proof records from skill prose.
- Update docs with examples and limitations for semantic instruction scanning.

Repo paths:

- `core/detect/skills/detector.go`
- `core/detect/promptchannel/patterns.go`
- `core/detect/agentframework/source.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/inventory/inventory.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/detect/skills ./core/detect/promptchannel ./core/detect/agentframework -run 'Test.*ActionSemantic|Test.*Instruction|Test.*Skill' -count=1`
- `go test ./core/aggregate/inventory ./core/risk ./core/report -run 'Test.*ActionClass|Test.*ActionPath|Test.*AgentActionBOM' -count=1`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add fixtures for deploy/release instructions, cloud/database commands, package scripts, MCP bindings, destructive language, approval bypass language, missing owner/review language, and proof-required language.
- Prove bounded keyword semantics are deterministic and avoid matching secrets or arbitrary long prose into noisy findings.
- Prove structured skill metadata takes precedence over unstructured prose when both are present.
- Prove semantic signals affect action classes and BOM output through inventory/risk boundaries.

Matrix wiring:

- Fast lane: focused detector, inventory, risk, and report tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: Story 4.1 fixture includes skill/instruction semantic coverage.
- Cross-platform lane: fixture path behavior must remain stable.
- Risk lane: `make test-hardening` for unsafe skill paths and no-secret extraction; `make test-perf` if dictionary scanning changes scan budgets.
- Release/UAT lane: not required.

Acceptance criteria:

- Skill and agent instruction fixtures produce stable action hints with file/range evidence.
- Deploy/release/cloud/database/destructive/approval-bypass hints are visible in inventory, action paths, and BOM output.
- Proof-required language contributes to evidence/control gaps without fabricating proof coverage.
- Existing allowed-tools behavior remains compatible.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added deterministic semantic action hints for skills and agent instructions so deploy, release, cloud, database, MCP, package execution, approval bypass, and proof requirement signals flow into action paths and BOM output.
Semver marker override: [semver:minor]
Contract/API impact: Adds action semantic reason codes and possibly inventory/report schema fields.
Versioning/migration impact: No migration required; older scans lack semantic hint fields.
Architecture constraints: Detection extracts signals, Aggregation rolls privileges up, Risk derives path impact, and Report renders the result.
ADR required: no
TDD first failing test(s): `TestSkillDetectorExtractsDeployAndCloudActionSemantics`, `TestInstructionPatternsDetectApprovalBypassWithoutSecretExtraction`, `TestActionPathsIncludeSkillSemanticSignals`
Cost/perf impact: medium if broad markdown scanning is expanded; keep bounded and benchmark if needed.
Chaos/failure hypothesis: Ambiguous prose should degrade to low-confidence semantic hints or no hint, not high-risk false positives.

### Story 2.2: Explicit Control State Projection

Priority: P0

Tasks:

- Add `control_state` derivation to `core/risk/govern_first_model.go` and `core/risk/action_paths.go` with deterministic precedence and reason codes.
- Use the requested enum: `safe_by_default`, `approval_required`, `block_recommended`, `evidence_required`, and `inventory_only`.
- Derive state from action classes, credential provenance, standing privilege, production/write/deploy reachability, approval gap, policy coverage, proof coverage, runtime evidence, and semantic instruction signals.
- Recommended precedence: `block_recommended` for high-blast-radius standing privilege or destructive production/deploy paths without sufficient control coverage; `approval_required` for write/deploy/release paths missing approval/owner review; `evidence_required` for controlled paths missing proof or runtime coverage; `safe_by_default` for low-risk governed paths; `inventory_only` for visibility-only paths.
- Wire `control_state` into control backlog queues in `core/aggregate/controlbacklog/controlbacklog.go`, score/report build paths, Agent Action BOM JSON, and markdown rendering.
- Render `control_state` prominently in `core/report/agent_action_bom.go` and `core/report/render_markdown.go` without hiding existing `recommended_action`, `control_priority`, or policy/proof details.
- Update schemas and docs.

Repo paths:

- `core/risk/govern_first_model.go`
- `core/risk/action_paths.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/build.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report -run 'Test.*ControlState|Test.*GovernFirst|Test.*AgentActionBOM' -count=1`
- `go test ./core/cli -run 'TestReport.*ControlState|TestScan.*ActionPath' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add table-driven tests for all control states and precedence conflicts.
- Add report/BOM schema tests proving JSON contains `control_state` where expected.
- Add markdown render tests proving the state appears near the top of each BOM item.
- Add backlog tests proving queues align with `block_recommended`, `approval_required`, `evidence_required`, and lower-priority states.

Matrix wiring:

- Fast lane: focused risk, backlog, report, and CLI tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: `make test-scenarios` plus Story 4.1.
- Cross-platform lane: markdown and JSON rendering must pass on Windows smoke.
- Risk lane: `make test-hardening` and `make test-chaos` for ambiguous high-risk paths and missing runtime/proof evidence.
- Release/UAT lane: not required unless docs examples become copy-paste UAT commands.

Acceptance criteria:

- BOM/report JSON includes `control_state` for every action path/BOM item included in the govern-first path model.
- The same fixture produces byte-stable control states across repeat runs.
- Markdown BOM makes the buyer answer visible without requiring users to infer it from lower-level fields.
- Control backlog queue assignment remains deterministic and explainable.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added buyer-facing control state projection for action paths and Agent Action BOM items, distinguishing safe-by-default, approval-required, evidence-required, block-recommended, and inventory-only paths.
Semver marker override: [semver:minor]
Contract/API impact: Adds public JSON/schema fields and markdown output semantics.
Versioning/migration impact: No migration required; older reports omit `control_state`.
Architecture constraints: Risk owns derivation, Aggregation owns queue rollup, Report owns rendering, and Proof/evidence contracts are read-only inputs.
ADR required: yes
TDD first failing test(s): `TestControlStatePrecedenceBlockBeatsApproval`, `TestControlStateEvidenceRequiredForMissingProof`, `TestAgentActionBOMRendersControlState`
Cost/perf impact: low.
Chaos/failure hypothesis: When evidence is missing or conflicting, high-risk ambiguous paths must prefer approval/block/evidence states over safe states.

### Story 2.3: Risk Zones And Review Burden

Priority: P1

Tasks:

- Add `risk_zone` derivation in `core/risk/action_paths.go` with stable enum values: `coding_help`, `repo_write`, `credential_bearing`, `ci_cd`, `iac`, `release`, `production_data`, and `external_egress`.
- Add `review_burden` and `review_burden_reasons` to action paths and Agent Action BOM items. Use a small stable enum such as `low`, `medium`, `high`, and `critical`.
- Derive review burden from PR/write/deploy/release frequency signals when present, and from missing owner, missing approval, missing proof, standing privilege, runtime coverage gaps, and generated backlog volume when frequency signals are absent.
- Update `core/score/score.go` and report build paths so risk zone and review burden influence explanation/ranking without destabilizing existing score contracts.
- Render risk zone and review burden in Agent Action BOM JSON/markdown and summary counts where useful.
- Update schemas and docs with enum definitions and derivation notes.

Repo paths:

- `core/risk/action_paths.go`
- `core/score/score.go`
- `core/report/build.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/score ./core/report -run 'Test.*RiskZone|Test.*ReviewBurden|Test.*ActionPath' -count=1`
- `go test ./core/cli -run 'TestReport.*RiskZone|TestReport.*ReviewBurden' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add table-driven derivation tests for each risk zone and review burden level.
- Add precedence tests for paths matching multiple zones, such as release plus credential-bearing plus production data.
- Add deterministic tests for missing frequency signals so absence is handled predictably.
- Add schema and markdown tests for report/BOM rendering.

Matrix wiring:

- Fast lane: focused risk, score, report, and CLI tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: `make test-scenarios` and Story 4.1.
- Cross-platform lane: JSON/markdown render tests on Windows smoke.
- Risk lane: `make test-hardening` for fail-closed zone precedence; `make test-perf` only if scoring/report runtime changes materially.
- Release/UAT lane: not required.

Acceptance criteria:

- Every action path/BOM item has an explicit risk zone and review burden when enough evidence exists, and deterministic omitted/unknown behavior when it does not.
- High-volume or missing-control paths show higher review burden with stable reasons.
- Low-risk coding help remains distinguishable from auth/secrets/IaC/prod/release paths.
- Risk zone and review burden appear in demo BOM markdown and JSON.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added explicit risk zones and review burden projections to action paths and Agent Action BOM output.
Semver marker override: [semver:minor]
Contract/API impact: Adds public JSON/schema fields and report semantics.
Versioning/migration impact: No migration required; older reports omit zone/burden fields.
Architecture constraints: Risk owns classification, Score may consume the classification, Report renders it, and schemas define the public contract.
ADR required: no
TDD first failing test(s): `TestRiskZoneClassifiesReleaseCredentialProductionPath`, `TestReviewBurdenIncreasesForMissingOwnerApprovalAndProof`, `TestBOMRendersRiskZoneAndReviewBurden`
Cost/perf impact: low.
Chaos/failure hypothesis: Conflicting path signals choose the highest-impact zone deterministically and include reasons instead of hiding ambiguity.

### Story 3.1: Gait Coverage Projection In Wrkr Output

Priority: P1

Tasks:

- Normalize runtime evidence into path-level Gait coverage fields for policy decision, approval, JIT credential, freeze window, kill switch, action outcome, and proof verification.
- Keep this as coverage projection only. Wrkr must not block, approve, grant credentials, freeze, kill, or enforce actions.
- Extend `core/ingest/ingest.go` and `core/evidence/evidence.go` only as needed to preserve normalized evidence class, refs, status, freshness, and conflict reasons.
- Update `core/report/agent_action_bom.go` and `core/report/render_markdown.go` to render compact present/missing/stale/conflict/not-applicable coverage per BOM path.
- Update `core/cli/report.go` and docs so report users can point at an evidence sidecar and understand missing vs present Gait coverage.
- Add schema fields for coverage objects and evidence refs where needed.

Repo paths:

- `core/ingest/ingest.go`
- `core/evidence/evidence.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/cli/report.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/ingest.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/ingest ./core/evidence ./core/report ./core/cli -run 'Test.*RuntimeEvidence|Test.*GaitCoverage|Test.*AgentActionBOM' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`
- `make test-chaos`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add runtime evidence sidecar fixtures for each coverage class and for missing, stale, conflict, and unmatched states.
- Prove Gait coverage correlates by `path_id`, `agent_id`, workflow location, policy ref, and graph refs without mutating saved scan findings.
- Prove markdown renders missing vs present coverage compactly.
- Prove no wording implies Wrkr performed enforcement.

Matrix wiring:

- Fast lane: focused ingest, evidence, report, and CLI tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: `make test-scenarios` plus Story 4.1 sidecar fixture.
- Cross-platform lane: sidecar path handling and markdown rendering on Windows smoke.
- Risk lane: `make test-hardening` and `make test-chaos` for stale/conflicting/unreadable sidecars.
- Release/UAT lane: not required unless public command examples change.

Acceptance criteria:

- BOM JSON exposes per-path Gait coverage for the requested seven control classes.
- BOM markdown shows missing vs present coverage without implying enforcement.
- Unavailable or stale evidence produces deterministic status and reason codes.
- Existing runtime evidence class summaries remain compatible.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added path-level Gait coverage projection in Agent Action BOM output for policy decisions, approvals, JIT credentials, freeze windows, kill switches, action outcomes, and proof verification.
Semver marker override: [semver:minor]
Contract/API impact: Adds public BOM/report coverage fields and markdown semantics.
Versioning/migration impact: No migration required; older reports omit per-control coverage objects.
Architecture constraints: Ingest normalizes evidence, Evidence owns evidence helpers, Report projects coverage, and Gait enforcement remains out of scope.
ADR required: yes
TDD first failing test(s): `TestRuntimeEvidenceProjectsGaitCoverageByPath`, `TestAgentActionBOMRendersMissingAndPresentGaitCoverage`, `TestGaitCoverageDoesNotMutateScanFindings`
Cost/perf impact: low.
Chaos/failure hypothesis: Missing, stale, or conflicting sidecars produce explicit coverage status and do not mark controls present.

### Story 4.1: Outside-In Demo Acceptance Scenario

Priority: P0

Tasks:

- Create a deterministic scenario fixture for the exact 5-minute demo path: GitHub Action running Claude/Codex-style headless AI, broad PAT/cloud key secret refs, write/deploy/package commands, MCP config, agent instructions, skills, ownership gaps, approval gaps, proof gaps, and optional Gait runtime evidence sidecar.
- Include deterministic PR/workflow provenance metadata so the fixture can answer "which PR or workflow introduced this path?"
- Assert `wrkr scan`, `wrkr report`, Agent Action BOM JSON, and Agent Action BOM markdown include PR provenance, AI agent identity, credential provenance, semantic action classes, control state, risk zone, review burden, owner/approval/proof gaps, and Gait coverage.
- Update scenario coverage maps and acceptance tests so this path is required for release-readiness gates.
- Update `docs/commands/report.md` with a compact example of the demo answers, using fixture-safe fake values only.
- Ensure all fixture secrets are references, not values, and no generated runtime report artifacts are committed outside expected fixture outputs.

Repo paths:

- `internal/acceptance/agent_action_bom_acceptance_test.go`
- `internal/acceptance/v1_acceptance_test.go`
- `internal/scenarios/agent_action_bom_demo_scenario_test.go`
- `internal/scenarios/coverage_map.json`
- `internal/scenarios/contracts_test.go`
- `core/cli/scan.go`
- `core/cli/report.go`
- `docs/commands/report.md`
- `scenarios/wrkr/`
- `CHANGELOG.md`

Run commands:

- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -run 'Test.*AgentActionBOM.*Demo|TestScenarioContracts' -count=1 -tags=scenario`
- `go test ./internal/acceptance -run 'Test.*AgentActionBOM|Test.*Demo' -count=1`
- `make test-scenarios`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`
- `make prepush-full`

Test requirements:

- Add fixture assertions for required JSON fields and markdown substrings without relying on nondeterministic timestamps.
- Add schema validation for BOM/report output from the fixture.
- Add no-secret assertions proving fake secret refs are not serialized as values.
- Add scenario coverage-map entries linking the demo path to provenance, credentials, action semantics, control state, risk zone, review burden, and Gait coverage.

Matrix wiring:

- Fast lane: focused scenario/acceptance tests for the demo fixture.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: `scripts/validate_scenarios.sh`, `make test-scenarios`, and `go test ./internal/acceptance -run 'Test.*AgentActionBOM|Test.*Demo' -count=1`.
- Cross-platform lane: fixture path and markdown rendering covered by Windows smoke.
- Risk lane: `make test-hardening` for no-secret fixture/report behavior and `make test-chaos` if sidecar failure handling is exercised.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=local` after the full demo path lands.

Acceptance criteria:

- One deterministic fixture answers all demo questions in JSON and markdown.
- Scenario validation fails if any required demo field disappears.
- Docs and scenario assertions stay in sync with the schema contract.
- The final implementation handoff can run one command sequence to prove demo readiness before release.

Changelog impact: required
Changelog section: Added
Draft changelog entry: [semver:minor] Added an outside-in Agent Action BOM demo scenario covering PR provenance, headless CI agent credentials, action semantics, control state, risk zone, review burden, and Gait coverage.
Semver marker override: [semver:minor]
Contract/API impact: Locks the demo JSON/markdown fields as scenario-backed public behavior.
Versioning/migration impact: No migration required; adds fixture coverage and docs.
Architecture constraints: Scenario fixtures remain deterministic spec artifacts; CLI/report assertions must use public surfaces rather than private implementation details.
ADR required: no
TDD first failing test(s): `TestAgentActionBOMDemoScenarioAnswersProvenanceCredentialControlAndCoverage`, `TestAgentActionBOMDemoMarkdownContainsBuyerAnswers`, `TestScenarioContractsIncludeDemoActionBOMCoverage`
Cost/perf impact: medium in acceptance lane; keep fixture minimal enough for regular scenario runs.
Chaos/failure hypothesis: If runtime evidence sidecar is absent, stale, or conflicting, the demo still renders the path and marks Gait coverage missing/stale/conflict deterministically.

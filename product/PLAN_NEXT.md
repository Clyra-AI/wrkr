# PLAN WRKR_RESIDUAL_HARDENING: Claim Governance, Instance Identity, and Supported Source Coverage

Date: 2026-03-15
Source of truth: user-provided recommended work items from 2026-03-15, `product/dev_guides.md`, `product/architecture_guides.md`, `product/wrkr.md`, and the observed repository baseline from this planning run
Scope: Wrkr repository only. Planning artifact only. Residual hardening, claim-boundary tightening, and targeted coverage expansion for supported source-level agent detection, instance-scoped privilege identity, first-class security visibility, and production-target-backed production-write claims.

## Global Decisions (Locked)

- Preserve Wrkr's deterministic, offline-first, fail-closed posture. No LLM calls, no live runtime probing, and no default scan-data exfiltration are allowed in scan, risk, regress, proof, or report paths.
- Preserve the required architecture boundaries:
  - Source
  - Detection
  - Aggregation
  - Identity
  - Risk
  - Proof emission
  - Compliance mapping and evidence output
- Keep public detection claims scoped to supported framework-native source parsing plus conservative custom scaffolds unless Wave 4 explicitly lands broader bespoke internal/custom source detection.
- Treat `agent_instance_id` as the canonical consumer key for `agent_privilege_map` rows and downstream instance-scoped evidence. Keep `agent_id` for compatibility and rollup correlation only.
- Treat `security_visibility_status` plus `reference_basis` as the only machine-readable basis for the claim "unknown to security." Do not use `approval_classification=unknown` as a proxy.
- Treat `production_write` as a guarded subset of `write_capable`. Public and report wording must default to `write_capable` unless production targets are explicitly configured and valid.
- Keep all contract changes additive. No schema major bump, no exit-code changes, and no compatibility-breaking field removals are allowed in this plan.
- Follow TDD first. All behavior changes must start with failing tests, then implementation, then refactor.
- Any story touching architecture boundaries, report semantics, proof context, regress semantics, or fail-closed behavior must run `make prepush-full`.

## Current Baseline (Observed)

- `git status --short` was clean before generating this plan.
- `core/detect/agentframework/source.go` already contains framework-specific Python and JS/TS source profiles for LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex, and MCP-client patterns.
- The supported framework detector packages already include source-only repo tests:
  - `core/detect/agentlangchain/detector_test.go`
  - `core/detect/agentcrewai/detector_test.go`
  - `core/detect/agentopenai/detector_test.go`
  - `core/detect/agentautogen/detector_test.go`
  - `core/detect/agentllamaindex/detector_test.go`
  - `core/detect/agentmcpclient/detector_test.go`
- `core/detect/agentframework/detector_test.go` already includes deterministic same-file multi-agent source coverage.
- `scenarios/wrkr/agent-source-frameworks/repos/source-only-agents` already exists and can be reused for higher-level release-gate coverage.
- `core/detect/agentcustom` remains conservative custom scaffolding detection from declarations, not broad bespoke internal/custom source parsing.
- `inventory.agents[*]` and `agent_privilege_map[*]` already expose additive `agent_instance_id`, `symbol`, `location_range`, and `security_visibility_status` fields in code and docs.
- `core/proofmap/proofmap.go`, `core/report/build.go`, `core/report/campaign.go`, `core/export/appendix/export.go`, `core/cli/root_test.go`, and `docs/commands/scan.md` already reflect much of the instance-scoped and security-visibility model.
- `core/report/report_test.go` already guards the `write_capable` fallback when production targets are not configured.
- `internal/e2e/campaign/campaign_e2e_test.go` already checks additive `unknown_to_security_*` campaign metrics.
- Residual risk is now mostly regression and claim drift:
  - downstream compatibility surfaces such as `core/regress/regress.go` still center `agent_id` and `tool_id`, so instance identity can still be weakened later unless explicitly guarded
  - public copy still needs tighter scoping so supported framework-native parsing is not mistaken for broad bespoke custom-source detection
  - "unknown to security" and `production_write` wording must stay basis-aware as examples, templates, and downstream exports evolve

## Exit Criteria

1. Supported framework source-only repos continue to produce correct deterministic agent inventory with stable ordering.
2. Same-file multi-agent fixtures continue to emit distinct agent instances across `inventory.agents`, `agent_privilege_map`, report, proof, appendix export, evidence, and regress flows.
3. No downstream consumer treats `agent_id` as the canonical privilege-row identity when `agent_instance_id` is available.
4. Every external "unknown to security" claim maps back to `security_visibility_status` plus `reference_basis`.
5. No report, proof, evidence, docs, or examples use `approval_classification=unknown` as a proxy for "unknown to security."
6. Public and report output never imply `production_write` without configured and valid production targets.
7. README, command docs, examples, and trust docs stay aligned with the implemented runtime claim boundary in the same rollout.
8. Optional broader bespoke internal/custom source detection is either implemented with deterministic tests and updated copy or explicitly deferred with public wording kept scoped to supported frameworks plus conservative custom scaffolds.

## Public API and Contract Map

Stable/public surfaces touched in this plan:

- `wrkr scan --json`
- `wrkr report --json`
- `wrkr report --report-md`
- `wrkr campaign aggregate --json`
- `wrkr regress init --baseline <path> --json`
- `wrkr regress run --baseline <path> --state <path> --json`
- `wrkr evidence --json`
- appendix export artifacts under `core/export/appendix`
- public docs and examples:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/regress.md`
  - `docs/commands/report.md`
  - `docs/commands/campaign.md`
  - `docs/commands/evidence.md`
  - `docs/examples/security-team.md`
  - `docs/examples/production-targets.v1.yaml`
  - `docs/trust/detection-coverage-matrix.md`

Stable fields and semantics that must remain compatible:

- `inventory.agents[*].agent_instance_id`
- `inventory.agents[*].symbol`
- `inventory.agents[*].location`
- `inventory.agents[*].location_range`
- `inventory.agents[*].security_visibility_status`
- `inventory.tools[*].approval_classification`
- `inventory.tools[*].security_visibility_status`
- `inventory.security_visibility_summary.reference_basis`
- `inventory.security_visibility_summary.unknown_to_security_write_capable_agents`
- `agent_privilege_map[*].agent_instance_id`
- `agent_privilege_map[*].agent_id`
- `agent_privilege_map[*].tool_id`
- `agent_privilege_map[*].production_write`
- `privilege_budget.production_write`

Internal surfaces expected to change or be audited:

- `core/detect/agentframework/*`
- `core/detect/defaults/*`
- `core/detect/agentcustom/*`
- `core/aggregate/inventory/*`
- `core/aggregate/privilegebudget/*`
- `core/proofmap/*`
- `core/report/*`
- `core/regress/*`
- `core/export/appendix/*`
- `core/cli/*`
- `internal/e2e/*`
- `internal/scenarios/*`
- `testinfra/contracts/*`
- `testinfra/hygiene/*`

Shim and deprecation policy:

- `agent_id` remains available for compatibility and lifecycle correlation, but new joins and row identity rules must use `agent_instance_id`.
- `tool_id` remains available for tool correlation and legacy compatibility, not as the identity anchor for instance-scoped privilege rows.
- `approval_classification=unknown` remains an approval-policy state only.
- `production_write` remains machine-readable, but public/report wording must downgrade to `write_capable` when targets are missing, invalid, or not appropriate for the workflow.

Schema and versioning policy:

- No schema major bump is planned.
- Contract changes must be additive only.
- If regress payloads or appendix/report outputs need explicit `agent_instance_id` or `reference_basis` fields, add them without removing legacy fields.
- Compatibility tests must continue to accept legacy baselines where instance identity is equivalent.

Machine-readable error expectations:

- Exit-code contract remains unchanged: `0/1/2/3/4/5/6/7/8`.
- Missing or invalid production targets in strict mode continue to fail closed with exit `6`.
- Missing or inapplicable reference basis must suppress or downgrade "unknown to security" wording rather than invent a count or change the exit code.
- Source parse errors must remain deterministic and isolated so one malformed source file does not suppress unrelated detections.

## Docs and OSS Readiness Baseline

README first-screen contract:

- `README.md` must continue to tell the truth about what Wrkr can detect right now.
- Supported framework-native source parsing is a valid claim.
- Broad bespoke internal/custom source parsing is not a valid claim unless Wave 4 lands.
- `write_capable` is a default-safe claim.
- `production_write` is a configured-workflow claim only.
- "Unknown to security" must always point back to the explicit visibility model and reference basis.

Integration-first docs flow:

1. `README.md`
2. `docs/commands/scan.md`
3. `docs/commands/regress.md`
4. `docs/commands/report.md`
5. `docs/commands/campaign.md`
6. `docs/commands/evidence.md`
7. `docs/examples/security-team.md`
8. `docs/examples/production-targets.v1.yaml`
9. `docs/trust/detection-coverage-matrix.md`

Lifecycle path model:

- `.wrkr/last-scan.json` remains the canonical saved scan state.
- `.wrkr/inventory-baseline.json` remains a compatible raw snapshot baseline input.
- `.wrkr/wrkr-regress-baseline.json` remains the canonical regress baseline artifact.
- `.wrkr/proof-chain.json` remains the canonical proof-chain path.
- Production target policy remains an explicit user-supplied file path.

Docs source-of-truth for this plan:

- runtime and CLI contracts: `docs/commands/*.md`
- operator and security workflows: `docs/examples/*.md`
- public landing copy: `README.md`
- detection-scope trust narrative: `docs/trust/detection-coverage-matrix.md`

OSS readiness baseline:

- Existing OSS trust files remain the baseline:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `.github/ISSUE_TEMPLATE/*`
  - `.github/pull_request_template.md`
- No new OSS trust files are required for this plan.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Keep supported framework source parsers release-gated with source-only fixtures | The current claim is credible only if it cannot silently regress | Preserve implemented framework coverage | Stable discovery credibility | W3-S01 |
| R2 | Keep same-file multi-agent source fixtures distinct and stable | The strongest supported-framework claim depends on instance-level precision | Preserve deterministic instance inventory | Trustworthy path discovery | W2-S02, W3-S01 |
| R3 | Keep public detection copy scoped to supported frameworks unless broader custom-source detection ships | Current repo supports conservative custom scaffolds, not broad bespoke custom source parsing | Tighten public claim boundary | Avoid over-claiming and trust erosion | W3-S02, W4-S01 |
| R4 | Treat `agent_instance_id` as the canonical downstream privilege-row key everywhere | Tool-level joins can collapse distinct same-file agents | Harden contract correctness | Instance-accurate proof and regress behavior | W2-S01 |
| R5 | Keep end-to-end tests proving same-file identities survive scan, proof, export, report, and regress flows | Future refactors can reintroduce tool-scoped joins | Protect implemented behavior | Durable downstream correctness | W2-S02 |
| R6 | Keep "unknown to security" tied to `security_visibility_status` and `reference_basis` | Approval semantics are not the same as security visibility | Make claim semantics first-class | Truthful posture reporting | W1-S01 |
| R7 | Suppress or downgrade "unknown to security" when reference basis is unavailable or inappropriate | Unsupported workflows should not fabricate the claim | Fail-closed claim governance | Lower false-confidence risk | W1-S01 |
| R8 | Keep `production_write` claims backed by valid production targets and default public wording to `write_capable` | Capability is broader than environment-backed production access | Harden claim discipline | Safer public/report posture messaging | W1-S02 |

## Test Matrix Wiring

Fast lane:

- `make lint-fast`
- targeted `go test` package runs with `-count=1`

Core CI lane:

- `make prepush`
- `make test-contracts`
- `make test-docs-consistency`

Acceptance lane:

- `make test-scenarios`
- `go test ./internal/e2e/regress -count=1`
- `go test ./internal/e2e/campaign -count=1`
- machine-readable command checks:
  - `wrkr scan --path <fixture-root> --json`
  - `wrkr regress init --baseline <scan-state-path> --json`
  - `wrkr regress run --baseline <baseline-path> --state <state-path> --json`
  - `wrkr report --json`
  - `wrkr campaign aggregate --input-glob '<glob>' --json`

Cross-platform lane:

- `go test ./core/cli -count=1`
- required CI coverage for `windows-smoke`

Risk lane:

- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-perf` when source-parsing breadth or hot-path cost changes materially
- `make test-agent-benchmarks` when detector breadth or parse volume changes materially

Merge and release gating rule:

- Waves 1 and 2 are merge-blocking P0 work and must not merge without green fast lane, core CI lane, acceptance lane, cross-platform lane, and any required risk-lane checks.
- Wave 3 is merge-blocking for any release that publicly claims supported framework-native source parsing.
- Wave 4 is optional and cannot merge with broader public copy unless its own detector, benchmark, docs, and precision gates are green in the same PR.

## Epic W1: Claim-Boundary Hardening

Objective: Make external claims basis-aware and fail-closed for security visibility and production-write language before further expansion work.

### Story W1-S01: Make security visibility the only basis for "unknown to security"

Priority: P0
Tasks:
- Audit `core/aggregate/inventory/inventory.go`, `core/regress/regress.go`, `core/report/campaign.go`, `core/report/build.go`, and `core/proofmap/proofmap.go` so every external "unknown to security" claim derives from `security_visibility_status` plus `reference_basis`.
- Add suppress-or-downgrade behavior for workflows where `reference_basis` is absent or not appropriate for the claim.
- Keep approval semantics separate from visibility semantics in scan, report, proof, regress, evidence, and campaign outputs.
- Update `docs/commands/scan.md`, `docs/commands/evidence.md`, `docs/commands/report.md`, `docs/commands/campaign.md`, and `docs/examples/security-team.md` to state the contract explicitly.
Repo paths:
- `core/aggregate/inventory/inventory.go`
- `core/regress/regress.go`
- `core/report/campaign.go`
- `core/report/build.go`
- `core/proofmap/proofmap.go`
- `docs/commands/scan.md`
- `docs/commands/evidence.md`
- `docs/commands/report.md`
- `docs/commands/campaign.md`
- `docs/examples/security-team.md`
Run commands:
- `go test ./core/aggregate/inventory ./core/regress ./core/report ./core/proofmap ./core/cli -count=1`
- `go test ./internal/e2e/campaign -count=1`
- `make test-contracts`
- `make test-docs-consistency`
- `make prepush-full`
Test requirements:
- schema and artifact compatibility tests for any additive visibility fields
- CLI `--json` stability tests for scan, report, campaign, and regress outputs
- deterministic downgrade tests when `reference_basis` is absent or not valid for the workflow
- docs consistency and README first-screen checks for touched claim language
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Cross-platform lane
- Risk lane
Acceptance criteria:
- No output or docs surface uses `approval_classification=unknown` as a proxy for "unknown to security."
- When a workflow lacks a usable `reference_basis`, Wrkr suppresses or downgrades the claim instead of fabricating `unknown_to_security` wording.
- Machine-readable payloads continue to expose explicit visibility status and reference basis without exit-code changes.
Contract/API impact:
- Additive only. Existing approval fields remain unchanged; visibility-driven claims become the only allowed basis for external wording.
Versioning/migration impact:
- No schema major bump. Any new regress or proof fields are additive and legacy-compatible.
Architecture constraints:
- Keep visibility derivation inside aggregation, regress, report, and proof layers rather than spreading claim logic into docs-only code paths.
- Preserve deterministic ordering and fail-closed wording when basis data is unavailable.
- Do not leak raw source details directly into report/proof logic beyond existing normalized inventory context.
ADR required: yes
TDD first failing test(s):
- add a failing regress test covering missing `reference_basis` downgrade behavior
- add a failing report test ensuring approval-unknown does not render as security-unknown
- add a failing proofmap test ensuring visibility context only appears when basis is explicit
- extend `core/cli/campaign_test.go` with a failing basis-aware wording assertion
Cost/perf impact: low
Chaos/failure hypothesis:
- If a saved state or workflow lacks valid reference-basis context, Wrkr must degrade to neutral visibility wording while keeping deterministic machine-readable output and unchanged exit codes.

### Story W1-S02: Keep `production_write` claims gated by valid production targets

Priority: P0
Tasks:
- Audit `core/cli/scan.go`, `core/report/build.go`, `core/report/report_test.go`, `README.md`, `docs/commands/scan.md`, `docs/examples/production-targets.v1.yaml`, and `docs/examples/security-team.md` for wording that could imply `production_write` without configured targets.
- Keep default user-facing and public/report language at `write_capable` unless `--production-targets` is configured and valid.
- Preserve non-strict graceful degradation and strict fail-closed behavior for invalid production-target files.
- Add regression tests for missing, invalid, and configured target workflows in CLI and report surfaces.
Repo paths:
- `core/cli/scan.go`
- `core/report/build.go`
- `core/report/report_test.go`
- `README.md`
- `docs/commands/scan.md`
- `docs/examples/production-targets.v1.yaml`
- `docs/examples/security-team.md`
Run commands:
- `go test ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-docs-consistency`
- `make prepush-full`
Test requirements:
- CLI `--json` stability tests for strict and non-strict production-target workflows
- exit-code contract tests for invalid strict mode
- markdown/report wording tests proving fallback to `write_capable`
- docs storyline smoke for examples and README copy
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Cross-platform lane
- Risk lane
Acceptance criteria:
- Public and report output never imply `production_write` when targets are missing, invalid, or not configured.
- Default workflow language stays at `write_capable` unless valid production-target configuration is present.
- Strict-mode exit `6` and non-strict warning behavior remain unchanged.
Contract/API impact:
- No new machine-readable contract is required; this story hardens wording and usage of the existing `production_write` budget contract.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep policy loading and degradation behavior in the CLI and reporting layers explicit and deterministic.
- Preserve symmetric semantics between configured and not-configured production-target states.
- Do not let docs or templates outrun machine-readable truth.
ADR required: no
TDD first failing test(s):
- extend `TestBuildSummaryUsesWriteCapableFallbackWhenProductionTargetsNotConfigured`
- extend `TestScanProductionTargetsMissingNonStrictEmitsWarningAndNullCount`
- add a failing public-report wording test for invalid production targets
Cost/perf impact: low
Chaos/failure hypothesis:
- Invalid production-target configuration must never escalate public claims; it must either fail closed in strict mode or degrade explicitly in non-strict mode.

## Epic W2: Instance-Scoped Privilege Contract Hardening

Objective: Ensure `agent_instance_id` survives as the canonical identity across downstream consumers and same-file multi-agent flows.

### Story W2-S01: Make `agent_instance_id` the canonical downstream privilege-row key

Priority: P0
Tasks:
- Audit `core/aggregate/privilegebudget/budget.go`, `core/aggregate/inventory/privileges.go`, `core/aggregate/inventory/inventory.go`, `core/proofmap/proofmap.go`, `core/export/appendix/export.go`, `core/regress/regress.go`, and `core/report/build.go` for joins or summaries that can still collapse onto `tool_id` or `agent_id`.
- Add additive `agent_instance_id` handling to downstream payloads where compatibility structs still expose only `agent_id` and `tool_id`.
- Keep `agent_id` for compatibility while documenting that it is no longer the row identity.
- Preserve deterministic sorting by org, framework, location, range, and instance identity.
Repo paths:
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/inventory/privileges.go`
- `core/aggregate/inventory/inventory.go`
- `core/proofmap/proofmap.go`
- `core/export/appendix/export.go`
- `core/regress/regress.go`
- `core/report/build.go`
- `docs/commands/scan.md`
- `docs/commands/regress.md`
- `docs/commands/report.md`
Run commands:
- `go test ./core/aggregate/privilegebudget ./core/aggregate/inventory ./core/proofmap ./core/export/appendix ./core/regress ./core/report ./core/cli -count=1`
- `go test ./internal/e2e/regress -count=1`
- `make test-contracts`
- `make test-docs-consistency`
- `make prepush-full`
Test requirements:
- additive schema and compatibility tests for any new regress or report fields
- CLI `--json` stability tests for scan and regress
- legacy-baseline compatibility tests
- deterministic sort-order checks for same-file multi-agent payloads
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Cross-platform lane
- Risk lane
Acceptance criteria:
- No downstream privilege-row consumer uses `agent_id` as the canonical identity when `agent_instance_id` is present.
- Same-file multi-agent rows remain distinct in scan, report, proof, export, and regress outputs.
- Legacy baselines remain compatible for equivalent instance identity.
Contract/API impact:
- Additive `agent_instance_id` propagation may be added to regress and related downstream outputs; legacy fields stay intact.
Versioning/migration impact:
- No schema major bump. Existing consumers may continue using `agent_id`, but docs must direct new consumers to `agent_instance_id`.
Architecture constraints:
- Keep instance identity resolution centralized in aggregation and identity helpers.
- Avoid boundary leakage from proof/report back into raw-source parsing.
- Preserve deterministic ordering and explicit side-effect semantics.
ADR required: yes
TDD first failing test(s):
- extend `TestBuildCreatesSeparateInstanceScopedEntriesForAgentsInSameFile`
- extend `TestMapFindingsKeepsSameFileAgentsDistinctByInstanceIdentity`
- extend `TestCompareFlagsAdditionalInstanceBeyondLegacyBaseline`
- add a failing CLI contract test for regress payload instance identity
Cost/perf impact: low
Chaos/failure hypothesis:
- If one consumer receives partial symbol or range metadata, Wrkr must still preserve distinct instance IDs when available and must not silently collapse rows back to tool scope.

### Story W2-S02: Keep same-file multi-agent identity distinct end to end

Priority: P0
Tasks:
- Extend scan, proof, appendix export, report, campaign, and regress tests so a same-file multi-agent fixture proves distinct rows survive every downstream transformation.
- Reuse `scenarios/wrkr/agent-source-frameworks` or add a focused scenario fixture that keeps two agents in one file with different privilege posture.
- Assert stable ordering, stable row counts, and byte-stable serialized artifacts across reruns.
Repo paths:
- `core/cli/scan_agent_context_test.go`
- `core/proofmap/proofmap_test.go`
- `core/export/appendix/export_test.go`
- `core/report/report_test.go`
- `core/regress/regress_test.go`
- `internal/e2e/regress/regress_e2e_test.go`
- `internal/e2e/campaign/campaign_e2e_test.go`
- `scenarios/wrkr/agent-source-frameworks`
- `testinfra/contracts`
Run commands:
- `go test ./core/cli ./core/proofmap ./core/export/appendix ./core/report ./core/regress -count=1`
- `go test ./internal/e2e/regress ./internal/e2e/campaign -count=1`
- `make test-scenarios`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- scenario acceptance coverage for same-file multi-agent repositories
- contract and golden updates for scan, export, and regress payloads
- repeat-run determinism checks for serialized outputs
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Cross-platform lane
- Risk lane
Acceptance criteria:
- The same fixture produces distinct instance-scoped rows across scan, report, proof, appendix export, and regress flows.
- Ordering remains deterministic across reruns.
- Evidence and export artifacts remain byte-stable unless intentionally updated.
Contract/API impact:
- No new contract beyond W2-S01; this story seals the behavior with regression coverage.
Versioning/migration impact:
- None beyond additive coverage updates.
Architecture constraints:
- Keep orchestration thin and reuse normalized inventory context rather than bespoke per-consumer identity reconstruction.
- Preserve cancellation and timeout behavior for CLI flows while adding end-to-end assertions.
ADR required: no
TDD first failing test(s):
- extend `TestScanPayload_SourceOnlyMultiAgentFileProducesSeparatePrivilegeRows`
- extend `TestBuildWithOptionsDeterministicAndAnonymized`
- extend `TestE2ERegressRunAcceptsLegacyBaselineForEquivalentInstanceIdentity` with same-file multi-agent expectations
- add a failing report summary test for dual same-file agents
Cost/perf impact: low
Chaos/failure hypothesis:
- Under repeated export, proof-map, and regress roundtrips, same-file multi-agent identity must stay distinct and byte-stable rather than collapsing or reordering.

## Epic W3: Supported Framework Source-Detection Guardrails

Objective: Keep the existing supported framework source-detection claim release-gated, precise, and clearly scoped.

### Story W3-S01: Release-gate supported framework source parsers with source-only and precision fixtures

Priority: P1
Tasks:
- Audit `core/detect/agentframework/source.go` and `core/detect/defaults/defaults.go` to keep supported framework profiles deterministic and explicitly registered.
- Keep or expand per-framework source-only tests for LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex, and MCP-client patterns.
- Strengthen precision fixtures around tool bindings, auth surfaces, deployment artifacts, and same-file multi-agent cases.
- Reuse `scenarios/wrkr/agent-source-frameworks` as the acceptance fixture for release gating.
Repo paths:
- `core/detect/agentframework/source.go`
- `core/detect/defaults/defaults.go`
- `core/detect/agentframework/detector_test.go`
- `core/detect/agentlangchain/detector_test.go`
- `core/detect/agentcrewai/detector_test.go`
- `core/detect/agentopenai/detector_test.go`
- `core/detect/agentautogen/detector_test.go`
- `core/detect/agentllamaindex/detector_test.go`
- `core/detect/agentmcpclient/detector_test.go`
- `scenarios/wrkr/agent-source-frameworks`
Run commands:
- `go test ./core/detect/... -count=1`
- `make test-scenarios`
- `make test-agent-benchmarks`
- `make prepush-full`
Test requirements:
- parser and detector unit tests with source-only fixtures
- deterministic multi-agent ordering tests
- scenario acceptance checks for source-only repos
- benchmark checks when parser breadth or file-walk cost changes materially
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Risk lane
Acceptance criteria:
- Supported framework source-only repos continue to produce correct agent inventory with stable ordering.
- Same-file multi-agent source fixtures continue to emit distinct agent instances.
- Parse errors remain deterministic and isolated from unrelated detections.
Contract/API impact:
- No public schema change is required; this story protects implemented behavior.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep detection logic isolated in detection packages.
- Prefer explainable parsing and deterministic evidence over broad heuristic matching.
- Maintain bounded file walking, deterministic ordering, and no hidden network dependencies.
ADR required: no
TDD first failing test(s):
- extend `TestDetectMany_SourceOnlyMultiAgentFileYieldsStableSeparateDetections`
- extend each `*Detector_SourceOnlyRepo` test with deterministic ordering and precision assertions
- add a failing scenario assertion for the shared source-only fixture
Cost/perf impact: low
Chaos/failure hypothesis:
- A malformed file or partial import pattern in one supported framework must not suppress unrelated supported detections or destabilize ordering.

### Story W3-S02: Keep public detection copy scoped to supported frameworks

Priority: P1
Tasks:
- Audit `README.md`, `docs/trust/detection-coverage-matrix.md`, and `docs/commands/scan.md` so supported framework-native source parsing and conservative custom scaffolds are described separately.
- Add docs consistency or storyline checks that fail if public copy implies bespoke internal/custom source detection without corresponding runtime support.
- If Wave 4 is deferred, state that public scope remains supported frameworks plus conservative custom scaffolds.
Repo paths:
- `README.md`
- `docs/trust/detection-coverage-matrix.md`
- `docs/commands/scan.md`
- `testinfra/hygiene`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `make prepush`
Test requirements:
- docs consistency checks
- README first-screen checks
- integration-before-internals storyline smoke for touched flows
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
Acceptance criteria:
- Public copy never implies broad bespoke internal/custom source detection unless Wave 4 lands in the same rollout.
- Detection docs clearly distinguish supported framework-native source parsing from conservative custom scaffolding support.
Contract/API impact:
- Docs-only clarification of existing runtime scope.
Versioning/migration impact:
- None.
Architecture constraints:
- Docs remain an executable contract and must track runtime truth in the same PR.
ADR required: no
TDD first failing test(s):
- add a failing docs-consistency check for unsupported broader custom-source wording
- add a failing README first-screen assertion for scoped detection copy
Cost/perf impact: low
Chaos/failure hypothesis:
- If docs drift ahead of runtime support, docs consistency gates must fail before merge.

## Epic W4: Optional Bespoke Custom-Source Expansion

Objective: Provide a conditional path for broader bespoke internal/custom source detection only if product messaging is intentionally expanded.

### Story W4-S01: Optionally add deterministic bespoke internal/custom source detection

Priority: P2
Tasks:
- Make an explicit product decision before implementation: broaden the public claim beyond supported frameworks plus conservative custom scaffolds, or defer.
- If approved, design an isolated deterministic detector path for bespoke internal/custom agent source patterns with conservative confidence and explainable evidence.
- Add strong negative fixtures so ambiguous internal patterns fail closed to no finding instead of broad false positives.
- Update `README.md` and `docs/trust/detection-coverage-matrix.md` in the same PR only if the detector ships and tests are green.
Repo paths:
- `core/detect/agentframework/source.go`
- `core/detect/defaults/defaults.go`
- `core/detect/agentcustom/detector.go`
- `core/detect/agentcustom/detector_test.go`
- `scenarios/wrkr/agent-source-frameworks`
- `README.md`
- `docs/trust/detection-coverage-matrix.md`
- `testinfra/benchmarks/agents`
Run commands:
- `go test ./core/detect/... -count=1`
- `make test-scenarios`
- `make test-agent-benchmarks`
- `make test-perf`
- `make prepush-full`
Test requirements:
- positive and negative detector fixtures for bespoke internal/custom source patterns
- determinism and precision tests that protect supported framework coverage
- benchmark and performance checks for expanded parsing scope
- docs consistency checks if public copy changes
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Risk lane
Acceptance criteria:
- If executed, broader custom/internal source detection is deterministic, precision-tested, and documented in the same rollout.
- If not executed, public messaging remains scoped and no broader claim appears.
- Supported framework coverage does not regress.
Contract/API impact:
- Any new custom-source findings must be additive and explainable; no existing supported-framework contract may be weakened.
Versioning/migration impact:
- None unless a new additive finding type or evidence key is introduced, in which case compatibility tests must be updated in the same PR.
Architecture constraints:
- Keep bespoke custom-source logic isolated behind a dedicated detector seam or tightly scoped extension point.
- Preserve thin orchestration, bounded parsing, deterministic ordering, and extension points that reduce enterprise fork pressure.
- Do not let risk or report layers parse raw source directly.
ADR required: yes
TDD first failing test(s):
- add failing positive and negative custom-source detector fixtures
- add a failing benchmark threshold test if parser breadth grows materially
- add a failing docs-scope test that only passes when runtime support exists
Cost/perf impact: medium
Chaos/failure hypothesis:
- Ambiguous bespoke internal source patterns must fail closed to no finding rather than creating noisy false-positive agent inventory.
Dependencies:
- Execute only after Waves 1 through 3 are complete and only with explicit product approval to broaden the claim.

## Minimum-Now Sequence

Wave 1:

- W1-S01
- W1-S02

Why first:

- Claim-boundary hardening is the safest first move because public and report language must not outrun the runtime basis already in the repo.

Wave 2:

- W2-S01
- W2-S02

Why second:

- Instance-scoped downstream identity is contract and evidence correctness work. It must be locked before any further narrative about "unknown paths" or same-file agent discovery is amplified.

Wave 3:

- W3-S01
- W3-S02

Why third:

- Once claim boundaries and instance identity are hardened, supported source parsing can be safely release-gated and publicly scoped without ambiguity.

Wave 4:

- W4-S01

Why optional:

- This wave is only valuable if product positioning intentionally broadens beyond supported frameworks plus conservative custom scaffolds. It is not required for the safe residual-hardening release.

## Explicit Non-Goals

- No live runtime interception, probing, or telemetry collection.
- No LLM-backed detection or scoring.
- No major schema, exit-code, or lifecycle-model redesign.
- No dashboard, UI, or hosted control-plane work.
- No expansion of public custom-source claims unless Wave 4 is explicitly approved and implemented.
- No vulnerability-scanner scope expansion beyond existing Wrkr boundaries.

## Definition of Done

- Every recommendation in this planning run maps to at least one story in this plan.
- P0 claim-boundary and identity waves ship with docs, tests, and machine-readable contract checks in the same PRs.
- Supported framework source parsing remains release-gated by source-only and same-file multi-agent fixtures.
- `agent_instance_id` remains the canonical privilege-row key across downstream consumers.
- "Unknown to security" is always tied to `security_visibility_status` plus `reference_basis`.
- `production_write` is never implied without valid production-target configuration.
- Required lanes are green for each merged story, including `make prepush-full` for architecture, report, regress, proof, or failure-semantics changes.

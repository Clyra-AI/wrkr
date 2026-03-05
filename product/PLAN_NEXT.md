# PLAN AGENT_PHASE_1_5: Deterministic Tools + Agents Inventory

Date: 2026-03-05  
Source of truth: user-provided recommended items (20), `product/dev_guides.md`, `product/architecture_guides.md`, `product/wrkr.md`, `AGENTS.md`  
Scope: Wrkr repository only. Planning artifact only; no implementation in this document.

## Global Decisions (Locked)

- Preserve Wrkr deterministic/offline-first/fail-closed contracts on scan, risk, proof, policy, and evidence paths.
- Keep architecture boundaries explicit and testable: Source -> Detection -> Aggregation -> Identity -> Risk -> Proof emission -> Compliance.
- Ship additive-first API/schema changes only in this plan; do not remove or rename existing scan JSON top-level keys.
- Keep `inventory.tools` and existing top-level scan JSON keys stable; add `inventory.agents` as additive output.
- Preserve existing lifecycle identity contract (`agent_id`) while adding deterministic instance-level identity to prevent collisions.
- Keep exit code taxonomy stable (`0..8`) and keep `--json` machine-readable output stable for automation.
- Promote top-5 framework detector coverage to Wave 2 gate (LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex) per execution model.
- Treat policy rule IDs as contract surface; add compatibility for `WRKR-A###` without regressing `WRKR-###` consumers.
- Require `make prepush-full` for architecture/risk/boundary stories and `make test-hardening` + `make test-chaos` for reliability/fault stories.
- Enforce same-input -> same-output determinism for findings, inventory entities, risk ranking, proof records, and evidence artifacts.

## Current Baseline (Observed)

- `core/aggregate/inventory/inventory.go` and `schemas/v1/inventory/inventory.schema.json` currently model `tools` but not first-class `agents` inventory.
- `core/cli/scan.go` emits stable top-level keys (`findings`, `ranked_findings`, `top_findings`, `inventory`, `privilege_budget`, `agent_privilege_map`, etc.) and those keys are contract-sensitive.
- Identity today is derived by `ToolID(tool_type, location)` + `AgentID(tool_id, org)` in `core/identity/identity.go`; this is coarse for multiple agent definitions in one file.
- `core/model/identity_bearing.go` excludes only `policy_check`, `policy_violation`, and `parse_error`; correlation/helper finding types can still pollute identity/inventory.
- Default detectors (`core/detect/defaults/defaults.go`) do not include LangChain, CrewAI, OpenAI Agents SDK, AutoGen, or LlamaIndex detectors.
- There is no dedicated relationship resolver package for agent->tool/data/auth links and no dedicated deployment correlator package for agent->deploy artifact links.
- Privilege map entries are tool-centric (`core/aggregate/inventory/privileges.go`, `core/aggregate/privilegebudget/budget.go`) and do not yet model agent framework/bindings/deployment posture.
- Finding contract (`core/model/finding.go`, `schemas/v1/findings/finding.schema.json`) has single `location` string but no optional line-range metadata.
- Policy rule-pack schema currently enforces `^WRKR-[0-9]{3}$` only (`schemas/v1/policy/rule-pack.schema.json`).
- Built-in policy kinds (`core/policy/eval/eval.go`, `core/policy/rules/builtin.yaml`) do not include WRKR-A001..A010 agent rule semantics.
- Risk and attack-path models (`core/risk/risk.go`, `core/risk/classify/classify.go`, `core/aggregate/attackpath/graph.go`) are not yet agent-relationship amplified.
- Proof/evidence mapping (`core/proofmap/proofmap.go`, `core/evidence/evidence.go`) uses current finding/risk fields and needs additive agent-context portability fields.

## Exit Criteria

1. `inventory.agents` is emitted deterministically while `inventory.tools` and scan top-level JSON contract keys remain backward compatible.
2. Deterministic agent-instance identity prevents same-file collisions and remains backward compatible with existing `agent_id` lifecycle flows.
3. Top-5 framework detectors in Wave 2 meet precision gate (`>=95%`) with deterministic ordering.
4. Agent relationship resolver outputs stable tool/data/auth bindings with deterministic evidence keys.
5. Deployment correlator outputs deterministic deployment posture and matched artifact evidence.
6. Agent-centric privilege map entries include framework/bindings/deployment/approval posture and are deterministically sorted.
7. Agent definition location ranges are optional/additive and do not break existing finding/inventory consumers.
8. Correlation-only findings are excluded from identity and inventory entity creation.
9. Policy ID compatibility accepts `WRKR-A###` (and aliases where configured) without regressing existing policy/profile/contract tests.
10. WRKR-A001..A010 policy checks are deterministic with stable remediation and test fixtures.
11. Waves 3 and 4 deliver expanded detector coverage, recall harness, risk amplification, attack-path edges, proof portability, compliance mapping, and docs parity.
12. All required matrix lanes pass, including `make prepush-full`, scenario/contract suites, and docs checks, with no scan JSON or exit-code regressions.

## Public API and Contract Map

Stable/public surfaces:
- CLI output contracts: `wrkr scan --json`, `wrkr report --json`, `wrkr evidence --json`, `wrkr regress --json`.
- Exit code taxonomy: `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, `8` unsafe operation blocked.
- Scan top-level JSON keys in `core/cli/scan.go` payload.
- Inventory schema v1 fields already consumed externally (`tools`, `summary`, `privilege_budget`, `agent_privilege_map`).
- Policy rule IDs and profile evaluation semantics.

Internal surfaces:
- New detector packages for agent frameworks.
- New resolver/correlator packages under aggregation layer.
- Internal identity derivation helpers for instance IDs.
- Internal scoring/correlation heuristics and evidence key extraction helpers.

Shim/deprecation path:
- Keep current `agent_id` flows intact; add additive instance ID field(s) and helper APIs.
- Accept both `WRKR-###` and `WRKR-A###` IDs via loader/schema compatibility layer.
- If aliasing is enabled, preserve canonical emitted rule IDs deterministically and document alias normalization.

Schema/versioning policy:
- Keep schema family on `v1`; all new fields in this plan are additive and optional unless empty-array deterministic defaults are contract-required.
- No removal/rename of existing required keys in v1.
- Any future breaking change requires explicit versioned schema (`v2`) and migration notes.

Machine-readable error expectations:
- Preserve existing error envelope format and exit code mapping for scan/policy/evidence paths.
- New agent-policy validation errors map to existing stable error classes (`invalid_input` or `policy_schema_violation`) with deterministic reason text.
- Do not introduce ad-hoc or detector-specific exit codes.

## Docs and OSS Readiness Baseline

README first-screen contract:
- Keep concise first-screen coverage of what Wrkr does, who it is for, and deterministic quickstart.
- Update first-screen copy to explicitly describe “tools + agents” inventory scope and non-goals.

Integration-first docs flow:
- `docs/commands/scan.md` must show integration-safe JSON examples and exit-code semantics before internals.
- Examples must remain copy-pasteable and deterministic.

Lifecycle path model:
- Keep lifecycle model centered on `discovered`, `under_review`, `approved`, `active`, `deprecated`, `revoked`.
- Document how instance identity and relationship/deployment context affect lifecycle evidence without changing state machine semantics.

Docs source-of-truth:
- Command contracts: `docs/commands/*`.
- Architecture boundaries: `docs/architecture.md` + `product/architecture_guides.md`.
- Product scope/boundaries: `product/wrkr.md`.

OSS trust baseline:
- Baseline files exist (`CONTRIBUTING.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`).
- This plan updates behavior/docs, not maintainer policy; if maintainer expectations change, document explicitly in same PR.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Add `inventory.agents` additive contract | Dual inventory dimensions without breakage | Contract-safe model expansion | Better auditor/operator visibility with no consumer break | W1-S01 |
| R2 | Deterministic agent-instance identity | Avoid collisions in multi-agent files | Identity precision hardening | Stable lifecycle and drift signals | W1-S02 |
| R3 | Add top 3 framework detectors | Highest-signal phase 1.5 coverage | Precision-first detection expansion | Fast adoption leverage with high trust | W1-S06 |
| R4 | Build relationship resolver | Core value path for privilege narratives | Cross-surface deterministic correlation | Actionable blast-radius mapping | W1-S07 |
| R5 | Build deployment correlator | Runtime posture depends on deploy path | Deployment-aware agent posture | Higher signal for true production risk | W1-S08 |
| R6 | Extend privilege map agent-centric | Required for actionable risk stories | Agent-layer privilege budgeting | Better prioritization and remediation | W1-S10 |
| R7 | Add location ranges | Need exact agent definition location | Evidence precision and traceability | Faster triage, stronger audit portability | W1-S03 |
| R8 | Block correlation pollution | Prevent false identities/lifecycle drift | Canonical-entity hygiene | Lower noise and fewer false entities | W1-S04 |
| R9 | Policy ID compatibility (`WRKR-A###`) | New namespace currently schema-invalid | Policy contract compatibility | Enables agent rules without breaking profiles | W1-S05 |
| R10 | Implement WRKR-A001..A010 checks | Auditor-facing deterministic outcomes | Agent policy enforcement | Immediate governance value for buyers | W1-S11 |
| R11 | Expand coverage (AutoGen/LlamaIndex/MCP-client patterns) | Raise recall after precision baseline | Controlled coverage expansion | Better recall while preserving credibility | W1-S09, W2-S12 |
| R12 | Conservative custom-agent detector | Capture custom agents with low FP | Confidence-gated heuristic detection | Coverage moat without trust erosion | W2-S13 |
| R13 | Risk amplification factors | Tool-only scoring underestimates agent risk | Agent-aware risk math | Better ranking quality for high blast radius | W2-S16 |
| R14 | Attack-path edges for agents | Improve explainability and remediation order | Graph-model enrichment | Stronger executive/auditor narratives | W2-S17 |
| R15 | Proof record agent context portability | Keep richer context in verifiable evidence | Proof contract additive extension | Portable audit bundles with richer semantics | W2-S18 |
| R16 | Compliance mappings for agent findings | Convert findings to control evidence | Compliance-value expansion | Faster control coverage demonstration | W2-S19 |
| R17 | Scenario + contract packs | Prevent regressions deterministically | Outside-in validation expansion | Durable release confidence | W2-S15 |
| R18 | Precision/recall benchmark harness | Enforce precision-over-recall strategy | Measured quality gating | Sustained detector trust over time | W2-S14 |
| R19 | Docs/CLI narrative updates | Keep user/auditor expectations aligned | Contract documentation parity | Lower support friction and adoption friction | W2-S20 |
| R20 | Four PR waves with strict gates | Minimize blast radius and focus review | Controlled rollout governance | Safer integration and faster approvals | W2-S21 |

## Test Matrix Wiring

Fast lane:
- `make lint-fast`
- `make test-fast`

Core CI lane:
- `make prepush`
- `make test-contracts`
- targeted package tests for touched paths (`go test ./core/... -count=1`)

Acceptance lane:
- `make test-scenarios`
- `scripts/run_v1_acceptance.sh --mode=local`

Cross-platform lane:
- `windows-smoke` required check
- path-handling and JSON envelope contract tests on Linux/macOS/Windows runners

Risk lane:
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-perf` for performance-sensitive stories

Merge/release gating rule:
- Wave 1 PRs cannot merge unless Fast + Core CI + Acceptance + Cross-platform + required Risk lanes are green.
- Wave 2 cannot start until Wave 1 contract gates are green.
- Wave 3 cannot start until Wave 2 contract gates are green and baseline precision fixture set is locked.
- Wave 4 cannot start until Wave 3 contract gates are green and benchmark/scenario thresholds are locked.
- No merge allowed with scan JSON contract diffs or exit-code regressions unless explicitly versioned and approved.

## Epic W1-E1 (Wave 1): Contract-Safe Data Model and Identity Foundation

Objective: add agent-first inventory and identity primitives without breaking existing scan, schema, lifecycle, or policy contracts.

### Story W1-S01: Add first-class `inventory.agents` contract (additive only)
Priority: P0
Tasks:
- Add `agents` model to `core/aggregate/inventory` with deterministic sorting by org/framework/instance ID/location.
- Keep `inventory.tools` unchanged and preserve current scan top-level JSON keys.
- Update inventory schema with additive `agents` object contract and deterministic empty array behavior.
- Update scan/export/state contract tests to assert additive-only behavior.
Repo paths:
- `core/aggregate/inventory/inventory.go`
- `schemas/v1/inventory/inventory.schema.json`
- `core/cli/scan.go`
- `core/export/inventory/export.go`
- `core/aggregate/inventory/inventory_test.go`
- `testinfra/contracts/*`
Run commands:
- `go test ./core/aggregate/inventory ./core/cli ./core/export/inventory -count=1`
- `make test-contracts`
- `go run ./cmd/wrkr scan --path scenarios/wrkr/policy-check/repos --json --quiet`
- `make prepush-full`
Test requirements:
- Schema validation tests for new `inventory.agents` field.
- Golden fixture updates for scan JSON payload with additive keys only.
- Compatibility tests proving `inventory.tools` and existing top-level scan keys are unchanged.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- `inventory.agents` is always present and deterministically ordered.
- Existing contract tests remain green without consumer-facing key removals/renames.
- Repeated scans on same input produce byte-stable agent inventory ordering.
Contract/API impact:
- Additive scan/inventory API expansion only; no breaking top-level key change.
Versioning/migration impact:
- Schema remains `v1`; additive optional field with deterministic default `[]`.
Architecture constraints:
- Aggregation layer builds agent inventory; CLI remains orchestration only.
- Preserve thin orchestration with explicit side-effect boundaries.
- Keep extension points for additional agent frameworks without cross-layer leakage.
ADR required: yes
TDD first failing test(s):
- `TestInventoryBuild_EmitsAgentsAdditiveOnly`
- `TestScanJSONContract_PreservesTopLevelKeysWithAgents`
Cost/perf impact: low
Chaos/failure hypothesis:
- If agent extraction fails for one repo, scan still emits deterministic inventory with explicit parse errors and no contract break.
Dependencies:
- none

### Story W1-S02: Introduce deterministic agent-instance identity (collision-safe)
Priority: P0
Tasks:
- Add instance identity derivation key: framework + file + symbol/name + range.
- Preserve current `agent_id` flow and add backward-compatible mapping from prior tool-based IDs.
- Update observed-tool and lifecycle reconciliation paths to store/use instance-level identity while retaining current lifecycle state semantics.
Repo paths:
- `core/identity/identity.go`
- `core/cli/scan_helpers.go`
- `core/lifecycle/lifecycle.go`
- `core/identity/identity_test.go`
- `core/lifecycle/lifecycle_test.go`
Run commands:
- `go test ./core/identity ./core/cli ./core/lifecycle -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Deterministic identity tests for two agent definitions in same file.
- Compatibility tests for existing `agent_id` lookup/manifest behavior.
- Repeat-run byte-stability tests for instance identity generation.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Two agent definitions in one file produce stable distinct instance IDs across repeated scans.
- Existing lifecycle flows continue to resolve prior identities deterministically.
Contract/API impact:
- Additive identity surface (`agent_instance_id` or equivalent) while preserving existing `agent_id` semantics.
Versioning/migration impact:
- No schema major bump; if manifest fields change, apply additive migration with compatibility reads.
Architecture constraints:
- Identity derivation stays in identity boundary package.
- Lifecycle package consumes identity outputs; no direct detector coupling.
- Preserve symmetric API semantics (`derive` vs `derive+validate`) for future extension.
ADR required: yes
TDD first failing test(s):
- `TestAgentInstanceID_TwoDefinitionsSameFile_AreDistinct`
- `TestAgentIDBackwardCompatibility_ToolIDFlowStillResolves`
Cost/perf impact: low
Chaos/failure hypothesis:
- Under partial metadata (missing symbol/range), fallback identity remains deterministic and non-colliding within file scope.
Dependencies:
- W1-S01

### Story W1-S03: Add optional location ranges for agent definitions
Priority: P0
Tasks:
- Extend finding model with optional line range metadata for agent detections.
- Extend finding and inventory schemas with additive optional range fields.
- Wire detectors/resolver outputs to populate path + line ranges when available.
Repo paths:
- `core/model/finding.go`
- `schemas/v1/findings/finding.schema.json`
- `schemas/v1/inventory/inventory.schema.json`
- `core/aggregate/inventory/inventory.go`
- `core/model/finding_test.go`
Run commands:
- `go test ./core/model ./core/aggregate/inventory -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Schema tests validating optional range fields.
- Golden fixtures for findings/inventory with and without ranges.
- Compatibility tests ensuring old payloads remain valid.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Agent records include path + line range where parser provides range.
- Older consumers and existing fixtures remain valid with absent range fields.
Contract/API impact:
- Additive finding/inventory contract field extension.
Versioning/migration impact:
- No schema version bump; optional fields only.
Architecture constraints:
- Parsing boundaries own range extraction; aggregation passes through normalized metadata.
- No regex-only extraction where structured parse metadata is available.
ADR required: yes
TDD first failing test(s):
- `TestFindingSchema_AllowsOptionalLocationRange`
- `TestInventoryAgents_IncludeRangeWhenAvailable`
Cost/perf impact: low
Chaos/failure hypothesis:
- If range extraction fails, detector emits deterministic finding without range and no runtime failure.
Dependencies:
- W1-S01, W1-S02

### Story W1-S04: Prevent identity/inventory pollution from correlation-only findings
Priority: P0
Tasks:
- Add explicit identity-bearing/inventory-bearing gating for canonical detector findings.
- Exclude helper/correlation findings from lifecycle identity creation and inventory entity materialization.
- Add deterministic allowlist/denylist tests for finding types.
Repo paths:
- `core/model/identity_bearing.go`
- `core/aggregate/inventory/inventory.go`
- `core/model/identity_bearing_test.go`
- `core/cli/scan_observed_tools_test.go`
Run commands:
- `go test ./core/model ./core/aggregate/inventory ./core/cli -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Deterministic identity-bearing classification fixtures.
- Lifecycle/inventory tests proving correlation-only findings do not create entities.
- Reason-code stability assertions for excluded finding categories.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Only canonical detections participate in lifecycle + inventory entity creation.
- Helper/correlation findings remain available for evidence/risk context only.
Contract/API impact:
- Internal entity-creation contract tightened; external scan payload still includes helper findings.
Versioning/migration impact:
- No version bump.
Architecture constraints:
- Domain classification centralized in model boundary; avoid duplicate filters across layers.
- Keep orchestration thin and deterministic.
ADR required: yes
TDD first failing test(s):
- `TestIdentityBearing_ExcludesCorrelationOnlyFindings`
- `TestObservedTools_IgnoresCorrelationFindings`
Cost/perf impact: low
Chaos/failure hypothesis:
- Mixed finding streams cannot generate fake lifecycle transitions.
Dependencies:
- W1-S02

### Story W1-S05: Add policy ID compatibility for agent namespace (`WRKR-A###`)
Priority: P0
Tasks:
- Extend rule-pack schema to accept `WRKR-A###` IDs (and alias mapping rules where needed).
- Update policy loader and profile evaluator to normalize ID comparison deterministically.
- Add compatibility tests for mixed rule packs and profile thresholds.
Repo paths:
- `schemas/v1/policy/rule-pack.schema.json`
- `core/policy/loader.go`
- `core/policy/profileeval/eval.go`
- `core/policy/policy_test.go`
- `core/policy/profileeval/eval_test.go`
Run commands:
- `go test ./core/policy/... -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Schema validation for both `WRKR-###` and `WRKR-A###` IDs.
- Deterministic profile evaluation tests with mixed namespaces.
- Contract tests for stable rule ID serialization and rationale ordering.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Agent rule IDs are accepted in schema/loader/profile flows.
- Existing policy/profile contract tests remain stable.
Contract/API impact:
- Policy ID namespace expansion with backward compatibility.
Versioning/migration impact:
- Additive schema regex broadening; no major version bump.
Architecture constraints:
- Keep rule normalization in policy boundary; no CLI special-casing.
- Maintain policy-as-code deterministic semantics.
ADR required: yes
TDD first failing test(s):
- `TestRulePackSchema_AcceptsWRKRAIDs`
- `TestProfileEval_NormalizesRuleAliasesDeterministically`
Cost/perf impact: low
Chaos/failure hypothesis:
- Unknown rule ID formats fail closed with deterministic validation error class.
Dependencies:
- none

## Epic W1-E2 (Wave 2): Core Agent Detection, Relationship Resolution, and Deployment Correlation

Objective: deliver deterministic high-signal detection plus relationship/deployment context to support agent-centric risk narratives.

### Story W1-S06: Implement top-3 framework detectors (LangChain, CrewAI, OpenAI Agents SDK)
Priority: P0
Tasks:
- Add detector packages with typed parsing/AST-first extraction and deterministic finding ordering.
- Add framework-specific fixtures for positive/negative and parse-error cases.
- Register detectors in default registry and ensure deterministic detector order.
Repo paths:
- `core/detect/agentlangchain/*`
- `core/detect/agentcrewai/*`
- `core/detect/agentopenai/*`
- `core/detect/defaults/defaults.go`
- `core/detect/defaults/defaults_test.go`
Run commands:
- `go test ./core/detect/... -count=1`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- Precision-focused fixture tests with structured parsing.
- Deterministic output ordering tests.
- Parse error contract tests for malformed framework files.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Top 3 framework detectors emit deterministic findings with `>=95%` precision on labeled fixtures.
- Output ordering is stable across repeated runs.
Contract/API impact:
- New finding types added; existing finding fields and ordering contract preserved.
Versioning/migration impact:
- Additive finding-type growth only.
Architecture constraints:
- Detection boundary only; no direct risk/policy coupling in detector code.
- Prefer typed decoders/AST over regex-only extraction.
- Preserve cancellation/timeout propagation from scan context.
ADR required: yes
TDD first failing test(s):
- `TestLangChainDetector_PrecisionFixtures`
- `TestCrewAIDetector_DeterministicOrdering`
- `TestOpenAIAgentsDetector_ParseErrors`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Malformed framework files produce deterministic parse_error findings without aborting whole scan.
Dependencies:
- W1-S03

### Story W1-S07: Build agent relationship resolver (agent -> tools/data/auth bindings)
Priority: P0
Tasks:
- Create resolver package in aggregation layer to link agent defs to tool registrations, data sources, and auth references.
- Emit stable evidence keys for each binding edge.
- Integrate resolver output into scan orchestration and inventory agent records.
Repo paths:
- `core/aggregate/agentresolver/*`
- `core/cli/scan.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/agentresolver/*_test.go`
Run commands:
- `go test ./core/aggregate/... ./core/cli -count=1`
- `make test-scenarios`
- `make prepush-full`
- `make test-chaos`
Test requirements:
- Relationship graph unit tests for tool/data/auth edge extraction.
- Deterministic evidence key tests.
- Integration tests proving stable resolver output inside scan JSON.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Agent records include deterministic bound tools, data sources, and auth surfaces.
- Evidence keys are stable and sorted.
Contract/API impact:
- Additive agent relationship fields in inventory and finding evidence.
Versioning/migration impact:
- No schema major bump; additive fields only.
Architecture constraints:
- Resolver lives in aggregation boundary and consumes normalized findings.
- No direct filesystem crawling from resolver once detector outputs exist.
- Extension points for additional binding categories.
ADR required: yes
TDD first failing test(s):
- `TestAgentResolver_BindsToolsDataAuthDeterministically`
- `TestScanPayload_IncludesAgentBindings`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Partial binding extraction keeps deterministic partial output and marks missing links explicitly.
Dependencies:
- W1-S06

### Story W1-S08: Build deployment correlator (agent -> deploy artifacts/pipeline)
Priority: P0
Tasks:
- Add deployment correlator package linking agent code to Docker/K8s/serverless/CI artifacts.
- Integrate compiled-action and CI findings as correlation signals.
- Emit deterministic deployment status and matched artifact evidence on agent records.
Repo paths:
- `core/aggregate/agentdeploy/*`
- `core/detect/compiledaction/detector.go`
- `core/cli/scan.go`
- `core/aggregate/agentdeploy/*_test.go`
Run commands:
- `go test ./core/aggregate/... ./core/detect/compiledaction ./core/cli -count=1`
- `make test-scenarios`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- Deterministic correlator tests for Docker/K8s/serverless/CI matchers.
- Fail-closed tests for ambiguous artifact matching.
- Scenario tests with deployment/no-deployment splits.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Agent records include deterministic deployment status and matched artifact evidence.
- Ambiguous correlation paths are explicit and deterministic.
Contract/API impact:
- Additive deployment-context fields for agents.
Versioning/migration impact:
- No version bump.
Architecture constraints:
- Correlator resides in aggregation boundary; detectors remain extraction-focused.
- Explicit side-effect semantics in correlator API naming (`resolve` vs `correlate`).
ADR required: yes
TDD first failing test(s):
- `TestAgentDeploymentCorrelator_MatchesArtifactsDeterministically`
- `TestAgentDeploymentCorrelator_AmbiguousPathFailClosed`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Missing/partial deploy manifests do not create false deployed=true assertions.
Dependencies:
- W1-S06

### Story W1-S09: Reach Wave 2 top-5 framework detector gate (AutoGen + LlamaIndex baseline)
Priority: P0
Tasks:
- Add high-confidence AutoGen and LlamaIndex baseline detectors to complete top-5 wave gate.
- Keep strict confidence thresholds and deterministic ordering.
- Defer broader MCP-client pattern expansion to Wave 3.
Repo paths:
- `core/detect/agentautogen/*`
- `core/detect/agentllamaindex/*`
- `core/detect/defaults/defaults.go`
- `core/detect/defaults/defaults_test.go`
Run commands:
- `go test ./core/detect/... -count=1`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- Precision fixtures for AutoGen/LlamaIndex detectors.
- Deterministic registration and output ordering tests.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Wave 2 detector set includes 5 frameworks with `>=95%` precision on baseline corpus.
- No regression in top-3 framework detector precision.
Contract/API impact:
- Additive finding types only.
Versioning/migration impact:
- None.
Architecture constraints:
- Maintain detector isolation and typed parse preference.
- Keep cancellation propagation and bounded file traversal.
ADR required: no
TDD first failing test(s):
- `TestAutoGenDetector_PrecisionBaseline`
- `TestLlamaIndexDetector_PrecisionBaseline`
Cost/perf impact: medium
Chaos/failure hypothesis:
- New detectors degrade gracefully on unsupported versions and emit deterministic parse_error findings.
Dependencies:
- W1-S06

## Epic W1-E3 (Wave 2): Agent-Centric Privilege and Core Policy Enforcement

Objective: ship auditor-usable policy outcomes and privilege narratives for agent-centric blast radius.

### Story W1-S10: Extend privilege map to agent-centric tree entries
Priority: P0
Tasks:
- Expand privilege map entries with framework, bound tools/APIs/data, deployment context, and approval posture.
- Update privilege budget aggregation to include agent-layer deterministic rollups.
- Ensure deterministic sorting for tree entries and summarized counts.
Repo paths:
- `core/aggregate/inventory/privileges.go`
- `core/aggregate/privilegebudget/budget.go`
- `schemas/v1/inventory/inventory.schema.json`
- `core/aggregate/privilegebudget/budget_test.go`
Run commands:
- `go test ./core/aggregate/inventory ./core/aggregate/privilegebudget -count=1`
- `make test-contracts`
- `go run ./cmd/wrkr scan --path scenarios/wrkr/attack-path-correlation/repos --json --quiet`
- `make prepush-full`
Test requirements:
- Schema tests for additive privilege-map fields.
- Deterministic sorting tests for agent-layer entries.
- Budget rollup regression tests for old tool-only cases.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Scan JSON includes agent-layer privilege entries with deterministic ordering.
- Existing privilege budget fields remain stable.
Contract/API impact:
- Additive inventory privilege fields with stable existing keys.
Versioning/migration impact:
- v1 additive schema update only.
Architecture constraints:
- Privilege aggregation remains in aggregation boundary; policy/risk consume normalized output.
- Avoid direct detector coupling in budget logic.
ADR required: yes
TDD first failing test(s):
- `TestPrivilegeMap_IncludesAgentLayerBindings`
- `TestPrivilegeBudget_DeterministicAgentSorting`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Missing relationship/deployment context yields explicit unknown fields, not silent drop or false assumptions.
Dependencies:
- W1-S07, W1-S08

### Story W1-S11: Implement WRKR-A001..A010 policy checks in existing framework
Priority: P0
Tasks:
- Add WRKR-A001..A010 rules to builtin rule pack with deterministic remediation text.
- Extend policy evaluator with new rule kinds (approval gaps, prod write, secrets, exfil, delegation, dynamic discovery, kill switch, data classification, auto-deploy gate).
- Add deterministic allow/fail fixtures and profile compatibility tests.
Repo paths:
- `core/policy/rules/builtin.yaml`
- `core/policy/eval/eval.go`
- `core/policy/eval/eval_test.go`
- `core/policy/profileeval/eval_test.go`
Run commands:
- `go test ./core/policy/... -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`
- `make test-hardening`
Test requirements:
- Deterministic policy pass/fail fixture tests for all A001..A010 rules.
- Reason-code and remediation-text stability checks.
- Fail-closed undecidable-path tests.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Each WRKR-A rule has deterministic pass/fail behavior and remediation text.
- Profile and contract test suites remain stable.
Contract/API impact:
- Additive policy rule IDs/kinds and policy findings.
Versioning/migration impact:
- No schema major bump; rule-pack content expands.
Architecture constraints:
- Policy logic remains in policy boundary, consuming normalized findings/context.
- Keep policy-as-code semantics deterministic and auditable.
ADR required: yes
TDD first failing test(s):
- `TestPolicyEval_WRKRA001_NoApprovalFails`
- `TestPolicyEval_WRKRA010_AutoDeployWithoutHumanGateFails`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Missing optional context causes deterministic conservative fail/unknown behavior (never silent pass).
Dependencies:
- W1-S05, W1-S07, W1-S08, W1-S10

## Epic W2-E4 (Wave 3): Coverage Expansion and Quality Gates

Objective: raise recall and confidence with controlled detector expansion and measurable quality thresholds.

### Story W2-S12: Expand detector coverage (MCP-client patterns + deeper AutoGen/LlamaIndex)
Priority: P1
Tasks:
- Add MCP-client agent pattern detector package.
- Expand AutoGen/LlamaIndex detector signatures beyond Wave 2 baseline while preserving precision.
- Track recall trend to `>=70%` benchmark with precision `>=95%` preserved.
Repo paths:
- `core/detect/agentmcpclient/*`
- `core/detect/agentautogen/*`
- `core/detect/agentllamaindex/*`
- `core/detect/defaults/defaults.go`
Run commands:
- `go test ./core/detect/... -count=1`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- Expanded fixture corpus across true-positive/false-positive sets.
- Deterministic ordering and parse-error behavior tests.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Recall trend reaches `>=70%` benchmark with precision `>=95%` maintained.
- Detector outputs remain deterministic and sorted.
Contract/API impact:
- Additive finding type expansion only.
Versioning/migration impact:
- None.
Architecture constraints:
- Detection logic remains isolated from risk/policy outputs.
- Prefer typed parsing and bounded work.
ADR required: no
TDD first failing test(s):
- `TestMCPClientDetector_FixtureCoverage`
- `TestDetectorExpansion_PrecisionRecallThresholds`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Unsupported MCP-client formats emit parse errors deterministically without scan abort.
Dependencies:
- W1-S06, W1-S09

### Story W2-S13: Add conservative custom-agent scaffolding detector
Priority: P1
Tasks:
- Implement custom detector requiring multiple strong co-occurring signals before emitting findings.
- Add confidence gates and explain evidence for each triggered detection.
- Keep detector off broad heuristics to minimize false positives.
Repo paths:
- `core/detect/agentcustom/*`
- `core/detect/defaults/defaults.go`
- `core/detect/agentcustom/*_test.go`
Run commands:
- `go test ./core/detect/agentcustom ./core/detect/defaults -count=1`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- Low-FP fixture tests with strict confidence thresholds.
- Deterministic evidence key tests for co-occurrence signals.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Detector only fires when configured confidence gate is met.
- Fixture results show low false-positive rate and deterministic ordering.
Contract/API impact:
- Additive finding type only.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep heuristic logic encapsulated in detector package with explicit thresholds.
- Maintain explainable, auditable evidence output.
ADR required: no
TDD first failing test(s):
- `TestCustomAgentDetector_RequiresStrongSignalCooccurrence`
- `TestCustomAgentDetector_LowFalsePositiveFixtures`
Cost/perf impact: low
Chaos/failure hypothesis:
- Sparse signal repos never produce synthetic custom-agent findings.
Dependencies:
- W1-S06

### Story W2-S14: Add precision/recall benchmark harness with release gates
Priority: P1
Tasks:
- Build labeled benchmark corpus and deterministic evaluation command.
- Add CI threshold checks that fail precision <95% or recall regression over budget.
- Expose benchmark reports as CI artifacts for release review.
Repo paths:
- `testinfra/benchmarks/agents/*`
- `scripts/run_agent_benchmarks.sh`
- `Makefile`
- `.github/workflows/*`
Run commands:
- `make test-fast`
- `make test-contracts`
- `scripts/run_agent_benchmarks.sh --json`
- `make prepush-full`
Test requirements:
- Deterministic benchmark runner tests.
- CI gate tests for threshold enforcement and regression budgets.
- Artifact schema checks for benchmark JSON output.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- CI fails on precision <95%.
- CI fails on recall regression beyond approved budget.
- Benchmark output is deterministic across repeated runs.
Contract/API impact:
- New internal benchmark command/artifact; no user-facing exit-code contract change.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep benchmark harness isolated from runtime scan path.
- Deterministic fixture corpus and evaluation semantics only.
ADR required: yes
TDD first failing test(s):
- `TestAgentBenchmarkHarness_FailsPrecisionBelowThreshold`
- `TestAgentBenchmarkHarness_FailsRecallRegressionBudget`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Missing benchmark labels fail closed in CI with deterministic error output.
Dependencies:
- W1-S06, W1-S09

### Story W2-S15: Add scenario + contract test packs for agent detection/correlation/policy
Priority: P1
Tasks:
- Add new scenarios for framework detection, relationship/deployment links, and policy outcomes.
- Add contract tests for schema/output stability and deterministic artifact diffs.
- Extend internal scenario coverage map and acceptance scorecard wiring.
Repo paths:
- `scenarios/wrkr/*`
- `internal/scenarios/*`
- `testinfra/contracts/*`
- `internal/scenarios/coverage_map.json`
Run commands:
- `make test-scenarios`
- `make test-contracts`
- `scripts/validate_scenarios.sh`
- `scripts/run_v1_acceptance.sh --mode=local`
Test requirements:
- Scenario acceptance packs covering detector/correlation/deployment/policy.
- Schema/golden stability tests.
- Deterministic output ordering checks.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform
Acceptance criteria:
- New scenario ACs pass.
- Existing contract suites do not regress.
- Coverage map includes new FR/AC mappings for agent stories.
Contract/API impact:
- No API change; contract guardrails expanded.
Versioning/migration impact:
- None.
Architecture constraints:
- Scenario tests remain outside-in and deterministic.
- Avoid product logic duplication in test harness.
ADR required: no
TDD first failing test(s):
- `TestScenario_AgentRelationshipCorrelation`
- `TestScenario_AgentPolicyOutcomes`
Cost/perf impact: low
Chaos/failure hypothesis:
- Scenario fixture corruption is detected deterministically by scenario contract checks.
Dependencies:
- W1-S06, W1-S07, W1-S08, W1-S11

## Epic W2-E5 (Wave 4): Risk, Attack Path, Proof, and Compliance Hardening

Objective: integrate agent context into ranking, narratives, proof portability, and compliance coverage.

### Story W2-S16: Extend risk scoring with agent-specific amplification factors
Priority: P1
Tasks:
- Add scoring factors for deployment scope, production write, delegation, dynamic tool discovery, missing approval, missing kill-switch.
- Keep deterministic scoring math and explain reasons list order.
- Update risk classification helpers for new agent-context evidence.
Repo paths:
- `core/risk/risk.go`
- `core/risk/classify/classify.go`
- `core/risk/risk_test.go`
- `core/risk/classify/classify_test.go`
Run commands:
- `go test ./core/risk/... -count=1`
- `make test-contracts`
- `make test-perf`
- `make prepush-full`
Test requirements:
- Deterministic ranking tests for amplified agent exposures.
- Explainability tests for stable reason strings.
- Performance regression checks on scoring path.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- High-blast agent exposures are consistently elevated in ranked findings.
- Repeat runs produce byte-stable ranked ordering and reasons.
Contract/API impact:
- Additive risk reason fields and potential score shifts; schema shape unchanged.
Versioning/migration impact:
- No schema version bump; documented ranking behavior change.
Architecture constraints:
- Scoring logic remains within risk boundary; no detector-level score mutation.
- Keep bounded work and deterministic sorting tie-breakers.
ADR required: yes
TDD first failing test(s):
- `TestRiskScore_AgentAmplificationElevatesHighBlastExposure`
- `TestRiskReasons_DeterministicOrderingWithAgentFactors`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Missing optional agent context falls back deterministically to conservative baseline score.
Dependencies:
- W1-S07, W1-S08, W1-S10, W1-S11

### Story W2-S17: Extend attack-path modeling with agent relationship edges
Priority: P1
Tasks:
- Add graph nodes/edges for agent->tool->data/secret/deploy chains.
- Keep stable node/edge IDs and deterministic graph ordering.
- Update attack path scoring inputs to include new edge rationales.
Repo paths:
- `core/aggregate/attackpath/graph.go`
- `core/aggregate/attackpath/graph_test.go`
- `core/risk/attackpath/score.go`
- `core/risk/attackpath/score_test.go`
Run commands:
- `go test ./core/aggregate/attackpath ./core/risk/attackpath -count=1`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- Deterministic node/edge ID tests.
- Scenario tests for agent-linked chain outputs.
- Regression tests for existing non-agent attack-path behavior.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Attack-path outputs include agent-linked chains with stable IDs.
- Existing attack-path contracts remain valid.
Contract/API impact:
- Additive graph semantics and rationale fields.
Versioning/migration impact:
- No schema major bump.
Architecture constraints:
- Graph building remains in aggregation boundary; scoring remains in risk boundary.
- Preserve explicit dataflow and avoid circular dependencies.
ADR required: yes
TDD first failing test(s):
- `TestAttackGraph_IncludesAgentToolDataDeployEdges`
- `TestAttackPathNodeEdgeIDs_AreDeterministic`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Missing relation edges do not cause panics or unstable empty-node graphs.
Dependencies:
- W1-S07, W1-S08

### Story W2-S18: Extend proof records for agent evidence portability
Priority: P1
Tasks:
- Add additive agent fields to mapped `scan_finding` and `risk_assessment` events.
- Keep proof record type contracts unchanged.
- Update evidence bundle outputs and verification tests for enriched fields.
Repo paths:
- `core/proofmap/proofmap.go`
- `core/evidence/evidence.go`
- `core/proofmap/proofmap_test.go`
- `core/evidence/evidence_test.go`
Run commands:
- `go test ./core/proofmap ./core/evidence -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- Proof mapping tests for additive agent fields.
- Bundle sign/verify determinism tests.
- Compatibility tests for existing proof consumers.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Evidence bundles contain agent context and remain verifiable end-to-end.
- Proof record types and chain integrity contracts remain stable.
Contract/API impact:
- Additive event fields in existing proof record types.
Versioning/migration impact:
- No proof type rename; additive contract only.
Architecture constraints:
- Proof mapping remains translation-only; no policy/scoring logic introduced.
- Preserve canonical ordering for mapped metadata/event fields.
ADR required: yes
TDD first failing test(s):
- `TestProofMap_ScanFindingIncludesAgentContextAdditively`
- `TestEvidenceBundle_VerifiesWithAgentContextFields`
Cost/perf impact: low
Chaos/failure hypothesis:
- Unknown agent fields in older snapshots are ignored deterministically, not treated as verification failures.
Dependencies:
- W1-S01, W1-S02, W1-S07, W1-S08

### Story W2-S19: Add compliance mappings for new agent findings
Priority: P1
Tasks:
- Add WRKR-A mapping entries for EU AI Act, SOC 2, and PCI in Wrkr compliance mapping surfaces.
- Coordinate additive mapping updates with `Clyra-AI/proof` framework/control definitions.
- Add deterministic coverage tests for `wrkr evidence --frameworks ... --json`.
Repo paths:
- `core/compliance/*`
- `core/proofmap/*`
- `core/evidence/*`
- `testinfra/contracts/*`
- `external dependency: Clyra-AI/proof framework YAML mappings`
Run commands:
- `go test ./core/compliance ./core/proofmap ./core/evidence -count=1`
- `go run ./cmd/wrkr evidence --state .wrkr/state.json --frameworks eu_ai_act,soc2,pci_dss --json`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Compliance mapping tests for WRKR-A001..A010 to listed controls.
- Deterministic coverage percentage and gaps output tests.
- Cross-repo compatibility checks for proof framework IDs.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- `wrkr evidence --frameworks ...` includes deterministic control coverage for agent findings.
- Mapping results remain stable across repeated runs.
Contract/API impact:
- Additive compliance evidence coverage for agent rule IDs.
Versioning/migration impact:
- No breaking contract in Wrkr; proof mapping additions coordinated as additive change.
Architecture constraints:
- Compliance logic stays in compliance/proofmap boundaries.
- Keep external contract dependency explicit and version-pinned.
ADR required: yes
TDD first failing test(s):
- `TestComplianceMapping_WRKRAControlsCovered`
- `TestEvidenceFrameworkCoverage_DeterministicForAgentFindings`
Cost/perf impact: low
Chaos/failure hypothesis:
- Missing external mapping dependency fails closed with deterministic dependency/classification error.
Dependencies:
- W1-S11, W2-S18

## Epic W2-E6 (Wave 4): Documentation, OSS Readiness, and Program Gating

Objective: align external contracts/docs with new behavior and enforce four-wave delivery gates.

### Story W2-S20: Update docs and CLI narratives for tools + agents scope/boundaries
Priority: P1
Tasks:
- Update scan, architecture, and detection coverage docs for “tools + agents” model.
- Add explicit non-goals and See/Prove/Control product boundary text.
- Ensure docs-contract parity checks remain green.
Repo paths:
- `docs/commands/scan.md`
- `docs/architecture.md`
- `docs/trust/detection-coverage-matrix.md`
- `product/wrkr.md`
- `README.md` (if first-screen contract needs adjustment)
Run commands:
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
- `make prepush`
Test requirements:
- Docs consistency checks.
- README first-screen and integration-before-internals flow checks.
- Command/flag/exit-code parity checks for touched docs.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform
Acceptance criteria:
- Externally visible behavior is fully documented with accurate scope and boundaries.
- Docs checks pass with no CLI parity drift.
Contract/API impact:
- Documentation-only contract clarification; no runtime API changes.
Versioning/migration impact:
- None.
Architecture constraints:
- Docs must reflect actual architecture boundaries and failure semantics.
ADR required: no
TDD first failing test(s):
- `TestDocsCLIParity_ScanAgentsInventoryNarrative`
- `TestDocsConsistency_ToolsAgentsBoundary`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not runtime risk-bearing; docs gates fail deterministically on drift.
Dependencies:
- W1-S01 through W2-S19 (as relevant)

### Story W2-S21: Enforce four-PR-wave execution model with strict gates
Priority: P0
Tasks:
- Define wave-specific PR templates/checklists and CI gate criteria.
- Enforce Wave sequencing gates (Wave 1 foundation -> Wave 2 core detection/policy -> Wave 3 expansion/quality -> Wave 4 hardening/docs) before downstream merges.
- Add release gate checks for `make prepush-full`, scenario/contract suites, and scan JSON/exit-code diff checks.
Repo paths:
- `.github/workflows/*`
- `.github/required-checks.json`
- `scripts/check_branch_protection_contract.sh`
- `testinfra/contracts/*`
- `docs/trust/*`
Run commands:
- `make prepush-full`
- `make test-contracts`
- `make test-scenarios`
- `scripts/run_v1_acceptance.sh --mode=local`
- `go run ./cmd/wrkr scan --path scenarios/wrkr/scan-diff-no-noise/input/local-repos --json --quiet`
Test requirements:
- Gate enforcement tests for required checks and branch-protection contract.
- Scan JSON/exit-code regression tests across wave boundaries.
- CI workflow contract tests for new required lanes.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Wave sequencing is enforced by CI contract checks.
- No merge occurs with scan JSON/exit-code regressions.
- Program gate docs and checks are auditable.
Contract/API impact:
- Governance and CI contract tightening; runtime contract unchanged.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep gating logic in CI/testinfra boundaries, not runtime command paths.
- Preserve deterministic local reproducibility of all merge gates.
ADR required: yes
TDD first failing test(s):
- `TestRequiredChecks_EnforceWaveSequence1To2To3To4`
- `TestScanContract_NoJSONOrExitRegressionAcrossWaves`
Cost/perf impact: low
Chaos/failure hypothesis:
- Misconfigured CI gates fail closed (block merge) rather than allowing partial wave progression.
Dependencies:
- W1-S01 through W1-S11

## Minimum-Now Sequence

1. Wave 1 foundation contracts and identity:
   W1-S01 -> W1-S02 -> W1-S03 -> W1-S04 -> W1-S05.
2. Wave 1 gate checkpoint:
   run full matrix and lock contract baselines before any Wave 2 story starts.
3. Wave 2 detection/correlation core:
   W1-S06 -> W1-S07 -> W1-S08 -> W1-S09.
4. Wave 2 core policy and privilege:
   W1-S10 -> W1-S11.
5. Wave 2 gate checkpoint:
   run full matrix and lock detector precision baselines before any Wave 3 story starts.
6. Wave 3 coverage and quality:
   W2-S12 -> W2-S13 -> W2-S14 -> W2-S15.
7. Wave 3 gate checkpoint:
   run benchmark/scenario/contract suites and lock thresholds before any Wave 4 story starts.
8. Wave 4 risk/proof/compliance:
   W2-S16 -> W2-S17 -> W2-S18 -> W2-S19.
9. Wave 4 docs and governance closure:
   W2-S20 -> W2-S21.

## Explicit Non-Goals

- Do not detect whether agents are currently running in production runtime.
- Do not infer runtime behavior/actions from execution telemetry.
- Do not implement runtime gating/blocking or kill-switch enforcement controls in Wrkr runtime.
- Do not infer intent/capability beyond deterministic declared/configured artifacts.
- Do not add LLM inference into detection, risk, policy, or proof paths.
- Do not implement Axym or Gait product logic in this repository beyond existing interoperability contracts.

## Definition of Done

- All recommendations map to execution-ready stories with concrete tasks, paths, commands, tests, matrix lanes, and acceptance criteria.
- Wave 1 through Wave 4 ordering is dependency-aware and enforced by CI/program gates.
- All contract-sensitive stories include explicit contract/API and versioning/migration impacts.
- All risk-bearing stories include chaos/failure hypotheses and risk-lane commands.
- Determinism requirements are validated by contract/scenario/benchmark suites where applicable.
- Docs and CLI narratives are updated for externally visible behavior changes in the same PR wave.
- Final merge gate for completed implementation work requires green `make prepush-full`, contract/scenario suites, and docs parity checks with no scan JSON/exit-code regressions.

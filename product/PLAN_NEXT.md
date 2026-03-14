# PLAN WRKR_UNKNOWN_WRITE_CAPABLE_PATHS: Native Detection, Instance Identity, Security Visibility, and Claim Governance

Date: 2026-03-14  
Source of truth: user-provided recommended work items dated 2026-03-14, `product/dev_guides.md`, `product/architecture_guides.md`, `AGENTS.md`, and the observed repo/runtime/docs baseline from this planning run  
Scope: Wrkr repository only. Planning artifact only. Four-wave plan. Wave 1 closes source-level detection gaps. Wave 2 makes privilege reporting instance-accurate. Wave 3 adds a first-class `unknown_to_security` model. Wave 4 hardens `production_write` claim governance and aligns public/report workflows.

## Global Decisions (Locked)

- Preserve Wrkr's deterministic, offline-first, fail-closed posture. No LLM calls, no live runtime probing, no network dependency in default scan/risk/proof paths, and no default scan-data exfiltration are allowed.
- Preserve architecture boundaries:
  - Source
  - Detection
  - Aggregation
  - Identity
  - Risk
  - Proof emission
  - Compliance mapping/evidence output
- Native source detection is required for LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex, and MCP-client patterns in Python plus JS/TS. Structured parsing is mandatory; regex-only detection is not acceptable for framework source.
- Declaration-file support under `.wrkr/agents/*` remains supported. Source-level detection is additive and must not reduce declaration coverage or precision.
- Same file with multiple agents must emit separate deterministic agent instances ordered by `org`, `framework`, `file`, `symbol`, `start_line`, `end_line`.
- `agent_privilege_map` becomes agent-instance anchored. `tool_id` remains for correlation, but it is no longer the identity anchor for privilege reporting.
- Add a first-class additive field named `security_visibility_status` with values `approved`, `known_unapproved`, and `unknown_to_security`. Do not overload `approval_classification`.
- `approval_classification` and `approval_summary` remain intact for approval-policy semantics. The new visibility model is separate and additive.
- Agent-instance outputs are the source of truth for the claim "unknown write-capable AI paths". Tool-level rows may roll up visibility for inventory summaries, but all write-capable unknown counts must be derived from agent-instance rows.
- Tool-level rollup precedence for `security_visibility_status` is:
  - `unknown_to_security`
  - `known_unapproved`
  - `approved`
- `production_write` remains a guarded subset of `write_capable`. Public/report workflows must default to `write_capable` unless `--production-targets` is configured and valid.
- No public schema major bump or exit-code change is allowed in this plan. Contract changes must be additive, documented, and covered by compatibility tests.
- README/docs/report copy may not promise source-level detection, instance-scoped privilege identity, or `production_write` claims unless the corresponding runtime behavior is implemented and covered by tests in the same wave.
- `make prepush-full` is required for stories that alter architecture, risk, report claims, proof context, or failure semantics.

## Current Baseline (Observed)

- `git status --short` was clean before generating this plan.
- `core/detect/defaults/defaults.go` already registers framework detectors for LangChain, CrewAI, OpenAI, AutoGen, LlamaIndex, MCP-client, and custom agents.
- Those framework detectors currently delegate to `core/detect/agentframework/detector.go`, which only parses declaration files (`json`, `yaml`, `toml`) and does not parse framework source code.
- Existing agent framework tests in `core/detect/agentframework/*_test.go` validate declaration parsing, parse-error isolation, and deterministic multi-format behavior, but not Python or JS/TS source discovery.
- `core/aggregate/inventory/inventory.go` already emits `inventory.agents[*].agent_instance_id` and deterministically sorts agent rows by `org/framework/instance/location`.
- `inventory.agents[*]` currently lacks an explicit `symbol` or `name` field even though instance identity already depends on symbol/range metadata when present.
- `core/aggregate/privilegebudget/budget.go` still builds `agent_privilege_map` by iterating `inventory.tools` and joining agent context by `AgentID` and tool-scoped fallback keys, which can collapse instance-level rows back onto tool identity.
- `core/aggregate/inventory/privileges.go` does not yet expose `agent_instance_id` on `agent_privilege_map` entries.
- `core/regress/regress.go` already supports instance-aware baseline matching in parts of the flow, but the user-facing privilege/report/export surfaces are not consistently instance-anchored end to end.
- `core/report/build.go`, `core/report/campaign.go`, `core/export/appendix/export.go`, and `core/proofmap/proofmap.go` currently surface `approval_classification`, `unknown_tools`, and `production_write` data, but there is no explicit machine-readable concept for "security did not know this path existed before this scan/reference state".
- `README.md` and `docs/trust/detection-coverage-matrix.md` already say Wrkr has native structured parsing for supported agent frameworks and deterministic instance-scoped privilege mapping, which is ahead of the current runtime implementation.
- `README.md` also includes a public org-scan example with `production_write: true`, while the safe meaning of that claim depends on configured production targets.
- `docs/commands/scan.md` documents `approval_classification` as `approved|unapproved|unknown`, but there is no corresponding `unknown_to_security` contract today.
- `production_write` engine support already exists:
  - `PrivilegeBudget.ProductionWrite` carries `configured`, `status`, and `count`
  - `scan` supports `--production-targets` and `--production-targets-strict`
  - `campaign` already suppresses `production_write_tools` when not configured
- Existing test and enforcement surfaces are strong and should be reused:
  - detector unit tests under `core/detect/*`
  - inventory, privilege-budget, regress, report, proofmap, and CLI contract tests
  - `internal/e2e/regress`
  - `internal/e2e/campaign`
  - scenario fixtures under `scenarios/wrkr/*`
  - `make prepush`, `make prepush-full`, `make test-hardening`, `make test-chaos`, `make test-perf`, `make test-agent-benchmarks`, `make test-docs-consistency`
- Required PR checks declared in `.github/required-checks.json` remain:
  - `fast-lane`
  - `scan-contract`
  - `wave-sequence`
  - `windows-smoke`

## Exit Criteria

1. Repositories with real LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex, or MCP-client source and no `.wrkr/agents/*` declarations still produce correct deterministic agent inventory.
2. Multi-agent files emit separate stable agent instances with explicit `agent_instance_id`, `symbol`, and `location_range` in machine-readable outputs.
3. `agent_privilege_map` is keyed and sorted by agent instance identity, not tool identity, while tool inventory rows remain unchanged for tool-level inventory use cases.
4. Attack-path, proof, appendix export, report, and regress flows preserve distinct identities for multiple agents in the same file.
5. Machine-readable outputs can truthfully report `unknown_to_security` separately from `approval_classification`, and the status is derived deterministically from approved/manifests plus prior reference state plus current scan inventory.
6. Wrkr can emit a deterministic machine-readable count for `unknown_to_security` write-capable agent paths when a reference state is available.
7. Public/report/evidence outputs never imply `production_write` posture unless production targets are configured and valid.
8. Default public/report wording uses `write_capable` unless `--production-targets` is explicitly supplied.
9. README, command docs, examples, and detection-coverage docs align with the implemented behavior in the same rollout.
10. All story-level tests, matrix wiring, and required PR checks pass with no contract regressions.

## Public API and Contract Map

Stable/public surfaces touched in this plan:

- `wrkr scan --json`
  - `inventory.agents[*]`
  - `inventory.tools[*]`
  - `inventory.approval_summary`
  - `inventory.privilege_budget`
  - `agent_privilege_map[*]`
  - optional `report`
- `wrkr regress init --baseline <scan-state-path> --json`
- `wrkr regress run --baseline <baseline-path-or-scan-state-path> --state <state-path> --json`
- `wrkr report --json`
- `wrkr campaign aggregate --json`
- evidence bundle JSON/markdown outputs emitted from `wrkr evidence`
- appendix and inventory export artifacts under `core/export/*`
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
  - `docs/compliance/eu_ai_act_audit_readiness.md`

Internal surfaces expected to change:

- `core/detect/agentframework/*`
- `core/detect/agentlangchain/*`
- `core/detect/agentcrewai/*`
- `core/detect/agentopenai/*`
- `core/detect/agentautogen/*`
- `core/detect/agentllamaindex/*`
- `core/detect/agentmcpclient/*`
- `core/detect/defaults/*`
- `core/aggregate/inventory/*`
- `core/aggregate/privilegebudget/*`
- `core/cli/scan.go`
- `core/regress/*`
- `core/report/*`
- `core/proofmap/*`
- `core/evidence/*`
- `core/export/appendix/*`
- `core/risk/*` when attack-path identity propagation needs additive context
- `core/identity/*` only if helper expansion is required without changing current ID semantics
- `testinfra/contracts/*`
- `internal/e2e/*`
- `internal/scenarios/*`
- `scenarios/wrkr/*`

Shim/deprecation path:

- `agent_privilege_map[*].tool_id` remains present for tool-inventory correlation during v1, but it is explicitly not the identity anchor for privilege rows after this rollout.
- `agent_privilege_map[*].agent_id` remains present and continues to be the org-scoped canonical identity envelope. New consumers must key privilege rows on `agent_instance_id`.
- `approval_classification=unknown` remains valid for approval-policy uncertainty. It must not be interpreted as `unknown_to_security`.
- Existing declaration-file detection remains supported after source parsers land; declaration paths are not deprecated in this plan.
- `production_write` remains in the machine-readable budget object, but public/report claims must downgrade to `write_capable` when targets are absent or invalid.

Schema/versioning policy:

- No schema major bump is planned.
- All contract changes are additive only.
- Preferred additive fields introduced by this plan:
  - `inventory.agents[*].symbol`
  - `inventory.agents[*].security_visibility_status`
  - `inventory.tools[*].security_visibility_status`
  - `agent_privilege_map[*].agent_instance_id`
  - `agent_privilege_map[*].symbol`
  - `agent_privilege_map[*].location`
  - `agent_privilege_map[*].location_range`
  - `agent_privilege_map[*].security_visibility_status`
  - `inventory.security_visibility_summary`
  - `campaign.metrics.unknown_to_security_tools`
  - `campaign.metrics.unknown_to_security_agents`
  - `campaign.metrics.unknown_to_security_write_capable_agents`
  - additive report/proof/evidence summary fields for security visibility and reference basis
- Existing fields remain stable:
  - `approval_classification`
  - `approval_summary`
  - `write_capable`
  - `production_write.status`
  - `production_write.count`
- If appendix export adds `agent_instance_id` columns, the new columns must be additive and documented without removing current columns.

Machine-readable error expectations:

- No exit-code changes are allowed.
- Source parser failures must remain deterministic and either emit additive parse findings or deterministic partial-result warnings; they must not suppress unrelated detector output.
- Invalid `--production-targets` with `--production-targets-strict` continues to fail closed with `invalid_input` and exit `6`.
- Invalid or missing `--production-targets` in non-strict mode continues to succeed with status/warning output, but no public/report workflow may upgrade wording to `production_write`.
- Security-visibility derivation must always declare the reference basis used. If the basis is unavailable for a workflow that wants to claim `unknown_to_security`, the workflow must downgrade/suppress the claim rather than fabricate a count.

## Docs and OSS Readiness Baseline

README first-screen contract:

- `README.md` currently claims native structured parsing for supported agent frameworks and shows a `production_write: true` example.
- This plan treats `README.md` as executable contract. Runtime and docs must land together so those claims become truthful or are downgraded in the same rollout.
- The default first-screen posture message after this plan is:
  - `write_capable` is always claimable
  - `production_write` is claimable only with configured production targets
  - `unknown_to_security` is claimable only from the explicit visibility model with declared reference basis

Integration-first docs flow:

1. `README.md` remains the landing surface.
2. `docs/commands/scan.md` remains the canonical scan contract.
3. `docs/commands/regress.md` remains the canonical baseline/reference workflow contract.
4. `docs/commands/report.md`, `docs/commands/campaign.md`, and `docs/commands/evidence.md` remain the canonical report/evidence/public-output contracts.
5. `docs/examples/security-team.md` remains the canonical security workflow.
6. `docs/examples/production-targets.v1.yaml` remains the canonical production-target example.
7. `docs/trust/detection-coverage-matrix.md` remains the canonical detection-scope explainer.

Lifecycle path model:

- `.wrkr/last-scan.json` remains the canonical scan state snapshot.
- `.wrkr/inventory-baseline.json` remains the compatible raw scan-snapshot baseline path.
- `.wrkr/wrkr-regress-baseline.json` remains the canonical regress baseline artifact.
- `.wrkr/proof-chain.json` remains the canonical proof-chain path.
- production target policy remains an explicit user-supplied path, for example `./docs/examples/production-targets.v1.yaml`.

Docs source-of-truth for this plan:

- runtime contracts: `docs/commands/*.md`
- operator/security workflows: `docs/examples/*.md`
- landing message: `README.md`
- detection trust narrative: `docs/trust/detection-coverage-matrix.md`
- compliance workflow references: `docs/compliance/eu_ai_act_audit_readiness.md`

OSS readiness baseline:

- Existing OSS trust files are already present and remain mandatory:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `.github/ISSUE_TEMPLATE/*`
  - `.github/pull_request_template.md`
- No new OSS trust files are required for this plan, but public wording changes must keep support and governance expectations aligned with current docs.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Add native source parsers for Python and JS/TS agent code across LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex, and MCP-client patterns | Current coverage is strongest on declaration files, not direct framework source | Broaden deterministic discovery coverage | Higher confidence discovery in real repos without `.wrkr/agents/*` | W1-S01 |
| R2 | Detect agent instances from imports, constructors, registrations, tool bindings, and entrypoints | Framework source needs instance-aware extraction, not declaration-only detection | Move from config-first to source-aware posture discovery | Fewer false negatives and more accurate path inventory | W1-S01 |
| R3 | Build `agent_privilege_map` from `inventory.agents` keyed by `agent_instance_id` | Tool identity still collapses multiple instances | Make privilege reporting match real execution units | Instance-accurate risk and proof surfaces | W2-S01 |
| R4 | Preserve distinct agent identities through attack-path, proof, appendix export, and regress flows | A single collapsed identity breaks downstream evidence and drift logic | Propagate instance identity through the full pipeline | Trustworthy evidence and stable regression behavior | W2-S02 |
| R5 | Introduce a first-class `unknown_to_security` concept separate from `approval_classification=unknown` | Current unknown approval is too weak for the claim | Add explicit security-visibility semantics | Truthful machine-readable "security did not know this existed" reporting | W3-S01 |
| R6 | Surface the visibility model in inventory summary, report/campaign metrics, proof context, and evidence bundle summaries | The claim must exist in every decision/report surface that matters | Make visibility status operational, not hidden | Better executive/security reporting and proof portability | W3-S02 |
| R7 | Treat `production_write` as a guarded claim requiring `--production-targets`, while `write_capable` stays always available | The current engine exists, but public/report claim safety depends on target config | Separate capability from environment-backed production claim | Safer public messaging and lower trust risk | W4-S01, W4-S02 |

## Test Matrix Wiring

Fast lane:

- `make lint-fast`
- targeted `go test` for changed detection, aggregation, report, regress, proofmap, and CLI packages with `-count=1`

Core CI lane:

- `make prepush`
- `make test-contracts`
- `make test-docs-consistency`

Acceptance lane:

- `go test ./internal/scenarios -run '^TestScenarioContracts$' -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./internal/e2e/regress -count=1`
- `go test ./internal/e2e/campaign -count=1`
- machine-readable command runs such as:
  - `wrkr scan --path <scenario> --json`
  - `wrkr regress init --baseline <scan-state-path> --json`
  - `wrkr regress run --baseline <baseline-path-or-scan-state-path> --state <state-path> --json`
  - `wrkr campaign aggregate --input-glob '<glob>' --json`

Cross-platform lane:

- `windows-smoke`
- existing Go matrix behavior on Ubuntu/macOS/Windows for CLI contract stories

Risk lane:

- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-perf` for detection/aggregation hot paths
- `make test-agent-benchmarks` for source-parser and agent-resolution performance regression checks

Merge/release gating rule:

- Required PR checks remain `fast-lane`, `scan-contract`, `wave-sequence`, and `windows-smoke`.
- Any story touching runtime contracts, proof context, regress logic, or report/public claims must also show green `make prepush-full`.
- Any story adding or changing detection hot paths must also show green `make test-perf` and `make test-agent-benchmarks`.
- Any story changing docs or examples must show green `make test-docs-consistency`.
- No story may merge with unresolved drift between runtime behavior and README/command/example wording.

## Epic W1-E1: Native Source-Level Agent Detection

Objective: make Wrkr detect supported agent frameworks directly from deterministic Python and JS/TS source without relying on `.wrkr/agents/*` declarations, while keeping declaration coverage and precision intact.

### Story W1-S01: Add deterministic source parsers and normalized agent emission for supported frameworks
Priority: P0
Tasks:
- Extend `core/detect/agentframework` so framework detectors can parse structured source surfaces in addition to declaration files.
- Implement deterministic Python and JS/TS parsing for LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex, and MCP-client patterns using imports, constructors, registrations, tool bindings, and entrypoint signals.
- Normalize source-derived agents to the existing agent payload shape and add explicit additive fields for `symbol` and `location_range` where source metadata exists.
- Preserve declaration-file support and deterministic deduplication when both declaration and source surfaces exist for the same agent.
- Add source-only scenario fixtures with no `.wrkr/agents/*` files and expected outputs for each supported framework plus a mixed multi-agent file case.
- Update the detection coverage matrix so docs clearly separate declaration-backed coverage from source-backed coverage.
Repo paths:
- `core/detect/agentframework/detector.go`
- `core/detect/agentframework/*.go` (new source-parser helpers)
- `core/detect/agentlangchain/*`
- `core/detect/agentcrewai/*`
- `core/detect/agentopenai/*`
- `core/detect/agentautogen/*`
- `core/detect/agentllamaindex/*`
- `core/detect/agentmcpclient/*`
- `core/detect/defaults/defaults.go`
- `core/aggregate/inventory/inventory.go`
- `core/cli/scan.go`
- `core/detect/agentframework/detector_test.go`
- `core/detect/agentlangchain/detector_test.go`
- `core/detect/agentcrewai/detector_test.go`
- `core/detect/agentopenai/detector_test.go`
- `core/detect/agentautogen/detector_test.go`
- `core/detect/agentllamaindex/detector_test.go`
- `core/detect/agentmcpclient/detector_test.go`
- `core/cli/scan_agent_context_test.go`
- `docs/trust/detection-coverage-matrix.md`
- `scenarios/wrkr/agent-source-frameworks/*` (new)
- `internal/scenarios/coverage_map.json`
Run commands:
- `go test ./core/detect/agentframework ./core/detect/agentlangchain ./core/detect/agentcrewai ./core/detect/agentopenai ./core/detect/agentautogen ./core/detect/agentllamaindex ./core/detect/agentmcpclient -count=1`
- `go test ./core/aggregate/inventory ./core/cli -count=1`
- `wrkr scan --path ./scenarios/wrkr/agent-source-frameworks/repos --json`
- `make test-perf`
- `make test-agent-benchmarks`
- `make prepush-full`
Test requirements:
- parser unit tests for Python and JS/TS source extraction
- deterministic multi-agent same-file ordering tests
- declaration/source coexistence and deduplication tests
- scenario/golden tests for source-only repos with no declaration files
- compatibility tests proving existing declaration fixtures still pass unchanged
- performance budget and benchmark checks for the new parser path
- docs consistency update for the coverage matrix
Matrix wiring:
- Fast lane: targeted detector, inventory, and CLI tests
- Core CI lane: `make prepush`
- Acceptance lane: scenario contract tests plus `wrkr scan --path ./scenarios/wrkr/agent-source-frameworks/repos --json`
- Cross-platform lane: `windows-smoke`
- Risk lane: `make prepush-full`, `make test-perf`, `make test-agent-benchmarks`
Acceptance criteria:
- A repo containing supported framework source and no declaration files produces the expected agent inventory.
- A single file with multiple agents yields separate deterministic detections with stable instance ordering.
- Source-derived agents emit `framework`, `file`, `symbol`, `location_range`, bound tools, auth surfaces, and deployment hints when those signals exist.
- Existing declaration-only fixtures retain current precision and deterministic ordering.
- `docs/trust/detection-coverage-matrix.md` truthfully describes the new coverage and remaining deterministic limits.
Contract/API impact:
- Additive `inventory.agents[*].symbol` and continued additive `location_range` usage where metadata exists.
- Additive source-derived evidence keys on `findings[*]` and agent context.
Versioning/migration impact:
- Additive only; no schema major bump.
- Existing consumers must continue to accept declaration-only agents with missing `symbol`/`location_range`.
Architecture constraints:
- Keep parsing inside the detection layer with thin orchestration and focused helpers for language parsing/normalization.
- No source execution, no network lookups, and no runtime imports are allowed.
- Ordering must be deterministic across files, frameworks, and source languages.
- Keep extension points explicit so new frameworks can plug in without collapsing detector boundaries.
ADR required: yes
TDD first failing test(s):
- `core/detect/agentframework/detector_test.go` source-only framework cases
- `core/cli/scan_agent_context_test.go` source-derived agent context case
- new scenario contract for `scenarios/wrkr/agent-source-frameworks`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Malformed or partially supported source files must emit deterministic parse-error or partial-result signals without suppressing unrelated detections or reordering stable findings.

## Epic W2-E2: Instance-Scoped Agent Privilege Identity

Objective: make privilege, export, proof, and regress flows use agent-instance identity as the canonical reporting anchor so multiple agents in the same file remain distinct throughout the pipeline.

### Story W2-S01: Re-key `agent_privilege_map` on `inventory.agents` and `agent_instance_id`
Priority: P0
Tasks:
- Add required additive field `agent_instance_id` to `AgentPrivilegeMapEntry`.
- Build `agent_privilege_map` by iterating `inventory.agents` and joining tool-level permission signals plus deployment/binding/auth context onto the matching agent instance row.
- Add additive agent context fields needed for debugging/report joins: `symbol`, `location`, and `location_range`.
- Preserve tool-level rows for `inventory.tools`, but stop using tool identity as the primary privilege-row dedupe key.
- Update scan JSON contract tests and appendix/export surfaces that currently assume tool-scoped privilege identity.
Repo paths:
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/inventory/privileges.go`
- `core/cli/scan.go`
- `core/aggregate/privilegebudget/budget_test.go`
- `core/aggregate/inventory/inventory_test.go`
- `core/cli/root_test.go`
- `testinfra/contracts/story1_contracts_test.go`
- `testinfra/contracts/story15_contracts_test.go`
- `core/export/appendix/export.go`
- `core/export/inventory/export_test.go`
Run commands:
- `go test ./core/aggregate/inventory ./core/aggregate/privilegebudget ./core/export/... ./core/cli -count=1`
- `wrkr scan --path ./scenarios/wrkr/agent-source-frameworks/repos --json`
- `make prepush-full`
Test requirements:
- additive schema/contract tests for `agent_privilege_map[*].agent_instance_id`
- deterministic same-file multi-agent privilege-row tests
- CLI `--json` stability tests
- appendix/export snapshot compatibility tests
- compatibility tests proving tool inventory remains stable while privilege identity becomes instance-scoped
Matrix wiring:
- Fast lane: targeted aggregation, export, and CLI tests
- Core CI lane: `make prepush`
- Acceptance lane: `wrkr scan --path ./scenarios/wrkr/agent-source-frameworks/repos --json`
- Cross-platform lane: `windows-smoke`
- Risk lane: `make prepush-full`
Acceptance criteria:
- Two agents in one file produce two stable `agent_privilege_map` rows with distinct `agent_instance_id` values.
- Each privilege row carries joined write/exec/credential/deployment/binding context for that specific agent instance.
- `tool_id` remains available for correlation, but row identity is clearly agent-instance based.
- Existing tool inventory outputs remain stable for tool-level consumers.
Contract/API impact:
- Additive `agent_privilege_map[*].agent_instance_id`, `symbol`, `location`, and `location_range`.
- `agent_privilege_map[*].tool_id` is retained but documented as correlation-only for privilege reporting.
Versioning/migration impact:
- Additive only; no schema major bump.
- Existing consumers may continue reading `agent_id`, but new consumers must switch to `agent_instance_id` as the privilege-row key.
Architecture constraints:
- Keep aggregation logic focused in aggregation packages; do not push privilege-join logic into report or CLI layers.
- Preserve explicit side-effect semantics and deterministic ordering.
- Avoid hidden fallback behavior that silently collapses instance rows when instance metadata exists.
ADR required: yes
TDD first failing test(s):
- `core/aggregate/privilegebudget/budget_test.go` same-file multi-agent privilege-row case
- `core/cli/root_test.go` scan payload expectations for `agent_instance_id`
Cost/perf impact: low
Chaos/failure hypothesis:
- Missing legacy metadata or mixed old/new agent IDs must degrade via explicit compatibility fallback without collapsing distinct current instance rows or duplicating privilege counts.

### Story W2-S02: Preserve instance identity through regress, proof, appendix export, and attack-path/report joins
Priority: P0
Tasks:
- Update regress baseline/build/compare logic so multi-agent same-file cases remain distinct through init/run flows while preserving legacy baseline compatibility.
- Add `agent_instance_id` propagation to proof-map records and relationships wherever agent context exists.
- Update appendix privilege exports and any report/attack-path joins that still rely on tool identity so downstream artifacts preserve agent-instance separation.
- Add deterministic end-to-end fixtures for scan -> proof/evidence -> regress with two agents in one file.
Repo paths:
- `core/regress/regress.go`
- `core/proofmap/proofmap.go`
- `core/export/appendix/export.go`
- `core/report/build.go`
- `core/risk/risk.go`
- `core/regress/regress_test.go`
- `core/proofmap/proofmap_test.go`
- `core/report/report_test.go`
- `internal/e2e/regress/regress_e2e_test.go`
- `scenarios/wrkr/agent-relationship-correlation/*`
- `scenarios/wrkr/attack-path-correlation/*`
- `internal/scenarios/coverage_map.json`
Run commands:
- `go test ./core/regress ./core/proofmap ./core/export/appendix ./core/report ./core/risk -count=1`
- `go test ./internal/e2e/regress -count=1`
- `wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json`
- `wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json --json`
- `make prepush-full`
Test requirements:
- regress compatibility/migration tests for legacy tool-scoped baselines
- proof relationship tests with additive `agent_instance_id`
- appendix export contract tests for new identity columns/fields
- attack-path/report deterministic join tests for multiple agents in one file
- end-to-end regress tests proving two instances survive the full flow
Matrix wiring:
- Fast lane: targeted regress, proofmap, report, and export tests
- Core CI lane: `make prepush`
- Acceptance lane: `go test ./internal/e2e/regress -count=1` plus regress JSON command runs
- Cross-platform lane: `windows-smoke`
- Risk lane: `make prepush-full`
Acceptance criteria:
- Regress init/run preserves distinct identities for multiple agents in one file.
- Proof records and relationships include additive instance context when available.
- Appendix privilege exports preserve instance-separated rows.
- Attack-path/report joins do not collapse multiple same-file agents back to a single tool-scoped identity.
Contract/API impact:
- Additive `agent_instance_id` in proof/export/report surfaces where agent context is already exposed.
- Legacy baseline compatibility remains documented and covered by tests.
Versioning/migration impact:
- Additive only.
- Pre-instance baselines continue to reconcile to equivalent current identities with deterministic documented behavior.
Architecture constraints:
- Keep proof/report/export layers as consumers of aggregation identity, not owners of identity derivation.
- Preserve symmetric semantics between baseline init and compare flows.
- Keep fallback behavior explicit and testable.
ADR required: yes
TDD first failing test(s):
- `core/regress/regress_test.go` same-file multi-agent drift preservation case
- `core/proofmap/proofmap_test.go` additive instance context propagation case
- `internal/e2e/regress/regress_e2e_test.go` end-to-end multi-agent baseline case
Cost/perf impact: low
Chaos/failure hypothesis:
- Legacy baselines plus new multi-instance scans must not cause duplicate drift reasons, proof fan-out explosions, or report/export row instability.

## Epic W3-E3: First-Class `unknown_to_security` Model

Objective: add an explicit machine-readable security-visibility model that is separate from approval classification and is usable in inventory, regress, report, proof, and evidence workflows.

### Story W3-S01: Add `security_visibility_status` and deterministic visibility summary to inventory and regress flows
Priority: P0
Tasks:
- Introduce additive field `security_visibility_status` on agent rows, tool rows, and privilege rows with values `approved`, `known_unapproved`, and `unknown_to_security`.
- Add additive `inventory.security_visibility_summary` with separate agent/tool counts and an explicit `unknown_to_security_write_capable_agents` count.
- Add additive summary provenance such as `reference_basis` and optional `reference_path` so consumers know whether visibility came from approved manifests only, prior scan state, or regress baseline.
- Derive row-level visibility from approved/manifests plus prior reference state plus current scan inventory, while preserving current `approval_classification` logic untouched.
- Define tool-level rollup precedence from underlying agent-instance rows.
- Ensure regress and scan flows can recompute the same visibility outcome deterministically from the same declared reference inputs.
Repo paths:
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/inventory/privileges.go`
- `core/regress/regress.go`
- `core/cli/scan.go`
- `core/aggregate/inventory/inventory_test.go`
- `core/regress/regress_test.go`
- `core/cli/root_test.go`
- `docs/commands/scan.md`
- `docs/commands/regress.md`
- `scenarios/wrkr/security-visibility-baseline/*` (new)
- `internal/scenarios/coverage_map.json`
Run commands:
- `go test ./core/aggregate/inventory ./core/regress ./core/cli -count=1`
- `wrkr scan --path ./scenarios/wrkr/security-visibility-baseline/repos --json`
- `wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json`
- `wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json --json`
- `make prepush-full`
Test requirements:
- additive schema tests for new visibility fields and summary objects
- deterministic visibility derivation tests for approved, known_unapproved, and unknown_to_security cases
- compatibility tests proving `approval_classification` and `approval_summary` remain unchanged
- regress baseline/reference provenance tests
- CLI `--json` stability tests
- fail-closed tests for missing or malformed explicit reference inputs used by visibility derivation
Matrix wiring:
- Fast lane: targeted inventory, regress, and CLI tests
- Core CI lane: `make prepush`
- Acceptance lane: scenario contract tests plus scan/regress JSON command runs
- Cross-platform lane: `windows-smoke`
- Risk lane: `make prepush-full`
Acceptance criteria:
- `security_visibility_status` is emitted separately from `approval_classification`.
- Inventory summary exposes deterministic counts for `approved`, `known_unapproved`, and `unknown_to_security`.
- Wrkr can emit a deterministic machine-readable count for unknown-to-security write-capable agent paths from the same reference inputs.
- Tool-level visibility rollups are derived from agent-instance rows with documented precedence.
- No existing `approval_classification` consumer is forced to migrate to the new field.
Contract/API impact:
- Additive `security_visibility_status` row fields and `inventory.security_visibility_summary`.
- Additive provenance fields declaring the visibility reference basis.
Versioning/migration impact:
- Additive only.
- Existing consumers may ignore the new visibility fields and continue using `approval_classification`.
Architecture constraints:
- Keep visibility derivation in aggregation/regress logic, not in docs/report-only layers.
- Fail closed or downgrade claims when the required reference basis cannot be established.
- Keep the derivation deterministic and auditable from explicit inputs.
ADR required: yes
TDD first failing test(s):
- `core/aggregate/inventory/inventory_test.go` visibility-status derivation cases
- `core/regress/regress_test.go` visibility reference-basis case
- `core/cli/root_test.go` scan payload visibility summary case
Cost/perf impact: low
Chaos/failure hypothesis:
- Ambiguous or missing reference basis must never silently classify rows as `known_unapproved`; outputs must either derive a deterministic basis or explicitly downgrade/suppress the claim.

### Story W3-S02: Surface `unknown_to_security` through report, campaign, proof, evidence, and appendix outputs
Priority: P1
Tasks:
- Extend campaign metrics, report summary data, proof-map metadata, evidence bundle summaries, and appendix exports to include explicit security-visibility counts and context.
- Ensure report/public phrasing for "unknown write-capable AI paths" is backed by the new visibility summary and declared reference basis.
- Add additive proof metadata/event context for `security_visibility_status` and visibility reference basis where agent context exists.
- Update security-team and evidence docs so operators know where the new counts come from and how to interpret them.
Repo paths:
- `core/report/campaign.go`
- `core/report/build.go`
- `core/proofmap/proofmap.go`
- `core/evidence/evidence.go`
- `core/export/appendix/export.go`
- `core/report/campaign_test.go`
- `core/report/report_test.go`
- `core/proofmap/proofmap_test.go`
- `core/evidence/evidence_test.go`
- `internal/e2e/campaign/campaign_e2e_test.go`
- `docs/commands/campaign.md`
- `docs/commands/evidence.md`
- `docs/examples/security-team.md`
Run commands:
- `go test ./core/report ./core/proofmap ./core/evidence ./core/export/appendix -count=1`
- `go test ./internal/e2e/campaign -count=1`
- `wrkr campaign aggregate --input-glob './.tmp/campaign/*.json' --json`
- `make prepush-full`
Test requirements:
- campaign/report/proof/evidence additive schema and golden tests
- compatibility tests for existing approval and production-write metrics
- proof relationship and metadata coverage tests
- evidence bundle summary tests
- campaign e2e tests for visibility metrics
- docs consistency checks for updated campaign/evidence/security-team docs
Matrix wiring:
- Fast lane: targeted report, proofmap, evidence, export, and campaign tests
- Core CI lane: `make prepush`
- Acceptance lane: `go test ./internal/e2e/campaign -count=1` plus campaign JSON aggregation runs
- Cross-platform lane: `windows-smoke`
- Risk lane: `make prepush-full`
Acceptance criteria:
- Campaign/report/evidence outputs include explicit visibility counts and declared reference basis.
- Proof records carry additive security-visibility context when agent context is available.
- Evidence summaries can support the phrase "X unknown-to-security write-capable AI paths" without relying on `approval_classification=unknown`.
- Existing approval and production-write metrics remain stable and documented.
Contract/API impact:
- Additive visibility metrics on report/campaign/evidence/proof surfaces.
- Additive appendix export columns/fields for visibility status and instance identity as needed.
Versioning/migration impact:
- Additive only.
- Existing campaign/report consumers continue to work without visibility-field awareness.
Architecture constraints:
- Report/evidence/proof layers consume visibility data from inventory/regress outputs; they do not re-derive it independently.
- Keep portable evidence and proof-chain integrity intact.
- Preserve deterministic ordering and byte stability for generated artifacts.
ADR required: yes
TDD first failing test(s):
- `core/report/campaign_test.go` visibility-metric case
- `core/proofmap/proofmap_test.go` visibility-context case
- `core/evidence/evidence_test.go` evidence summary visibility case
Cost/perf impact: low
Chaos/failure hypothesis:
- Campaign aggregation over mixed input artifacts must never synthesize unknown-to-security counts when reference-basis metadata is missing or incompatible.

## Epic W4-E4: Production-Target-Backed `production_write` Claim Governance

Objective: ensure Wrkr only makes `production_write` claims when production targets are explicitly configured, while keeping `write_capable` as the always-available capability signal.

### Story W4-S01: Guard `production_write` claims in scan/report/public/campaign workflows
Priority: P1
Tasks:
- Centralize claim-governance logic that inspects `PrivilegeBudget.ProductionWrite.Status` before report/public/campaign wording is rendered.
- Keep the machine-readable `production_write` budget object intact, but ensure numeric or headline `production_write` claims appear only when targets are configured and valid.
- Downgrade default wording to `write_capable` when targets are not configured or invalid, and keep explicit status/warnings visible.
- Add report/public/campaign contract tests for configured, not configured, and invalid production-target states.
Repo paths:
- `core/cli/scan.go`
- `core/report/build.go`
- `core/report/campaign.go`
- `core/cli/root_test.go`
- `core/cli/campaign_test.go`
- `core/cli/report_contract_test.go`
- `core/report/report_test.go`
- `core/report/campaign_test.go`
- `docs/commands/report.md`
- `docs/commands/campaign.md`
Run commands:
- `go test ./core/cli ./core/report -count=1`
- `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --report-md --report-template public --json`
- `wrkr campaign aggregate --input-glob './.tmp/campaign/*.json' --json`
- `make prepush-full`
Test requirements:
- CLI/report/public template behavior tests
- `--json` stability tests
- campaign markdown/JSON guard tests
- deterministic configured/not_configured/invalid status fixture coverage
- machine-readable warning/claim downgrade tests
Matrix wiring:
- Fast lane: targeted CLI and report tests
- Core CI lane: `make prepush`
- Acceptance lane: scan/report/campaign JSON command runs
- Cross-platform lane: `windows-smoke`
- Risk lane: `make prepush-full`
Acceptance criteria:
- Public/report output never implies `production_write` without configured production targets.
- Default output wording is `write_capable` unless `--production-targets` is supplied and valid.
- Machine-readable `production_write` status remains available for automation even when public wording is downgraded.
- Invalid target configuration never upgrades claim wording.
Contract/API impact:
- No exit-code change.
- Possible additive report summary metadata documenting claim-governance state.
Versioning/migration impact:
- No breaking contract changes; wording and additive metadata only.
Architecture constraints:
- Keep claim-governance logic in report/CLI policy helpers, not scattered across templates.
- Preserve deterministic wording selection for identical inputs.
- Do not infer production targets from repo content; the path must remain explicit and opt-in.
ADR required: no
TDD first failing test(s):
- `core/report/report_test.go` public report without production targets
- `core/cli/root_test.go` scan report payload downgrade case
- `core/cli/campaign_test.go` campaign summary guard case
Cost/perf impact: low
Chaos/failure hypothesis:
- Mixed configured and unconfigured scan artifacts must never surface an aggregate `production_write` claim unless every required input is explicitly configured.

### Story W4-S02: Document the production-target workflow and public claim rules
Priority: P1
Tasks:
- Update README and command/example docs so `write_capable` is the default message and `production_write` is clearly presented as an explicit opt-in production-target workflow.
- Refresh `docs/examples/production-targets.v1.yaml` so the example remains the canonical onboarding artifact for security teams.
- Update security-team and compliance docs to explain when `production_write` is safe to state and when only `write_capable` is safe.
- Ensure docs consistency checks enforce the same wording across README, command docs, and examples.
Repo paths:
- `README.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/commands/campaign.md`
- `docs/commands/evidence.md`
- `docs/examples/production-targets.v1.yaml`
- `docs/examples/security-team.md`
- `docs/compliance/eu_ai_act_audit_readiness.md`
- `docs/trust/detection-coverage-matrix.md`
- `testinfra/hygiene/*` if README/docs contract assertions need updates
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `go test ./testinfra/... -count=1`
Test requirements:
- docs consistency checks
- storyline/smoke checks for updated workflow copy
- README first-screen contract checks for claim wording
- docs source-of-truth mapping checks for touched command/example docs
- maintainer/support expectation checks if public wording materially changes user guidance
Matrix wiring:
- Fast lane: targeted `go test ./testinfra/... -count=1`
- Core CI lane: `make test-docs-consistency`
- Acceptance lane: `make test-docs-storyline`
- Cross-platform lane: none beyond existing required checks
- Risk lane: not required unless runtime behavior changes in the same PR
Acceptance criteria:
- README and command docs use `write_capable` as the default public message.
- Production-target workflow is explicit and points to the canonical example file.
- Security-team/compliance docs explain that `production_write` requires configured targets.
- Docs consistency checks prevent future drift back to unsafe wording.
Contract/API impact:
- Docs-only contract alignment for public wording and workflows.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep docs aligned to implemented runtime behavior and canonical command contracts.
- Do not introduce dashboard-first or SaaS-dependent workflow language.
ADR required: no
TDD first failing test(s):
- existing docs consistency/storyline checks updated to fail on stale `production_write` default wording
Cost/perf impact: low
Chaos/failure hypothesis:
- If docs drift from runtime claim-governance behavior, docs consistency/storyline checks must fail before merge rather than allow unsafe public guidance.

## Minimum-Now Sequence

Wave 1:

- W1-S01 must land first.
- Reason: source-level agent discovery is the coverage foundation for every later claim about unknown write-capable paths.

Wave 2:

- W2-S01 then W2-S02.
- Reason: privilege, proof, regress, and attack-path/report surfaces must become instance-accurate before visibility metrics can be trusted.

Wave 3:

- W3-S01 then W3-S02.
- Reason: the explicit `unknown_to_security` model depends on instance-accurate identity and must exist in inventory/regress before report/proof/evidence consumers can surface it.

Wave 4:

- W4-S01 then W4-S02.
- Reason: public/report claim governance and docs alignment should harden the now-correct runtime behavior rather than mask incomplete implementation earlier in the sequence.

Stop conditions between waves:

- Do not start Wave 2 until source-only scenarios show stable agent instance output.
- Do not start Wave 3 until same-file multi-agent privilege rows are distinct end to end.
- Do not start Wave 4 until `unknown_to_security` counts are deterministic and surfaced machine-readably.

## Explicit Non-Goals

- No live runtime traffic inspection, live MCP probing, or runtime agent execution.
- No dashboard, hosted service, or default network dependency work.
- No package vulnerability scanning or MCP-server vulnerability assessment features.
- No change to Wrkr lifecycle-state values or exit-code meanings.
- No removal of `approval_classification`, `approval_summary`, `tool_id`, or declaration-file support in v1.
- No inference of production targets from repository content; production targets remain an explicit user-supplied policy input.
- No broad docs-site redesign or marketing rewrite beyond what is necessary to keep public/runtime claims truthful in this repo.

## Definition of Done

- Every recommendation above is mapped to implemented stories in dependency order.
- All touched public contracts are additive, documented, and covered by tests.
- `make prepush-full` passes for all runtime/proof/report/visibility stories.
- `make test-hardening`, `make test-chaos`, and `make test-perf` pass where required by the story matrix.
- `make test-agent-benchmarks` passes for source-detection changes.
- `make test-docs-consistency` passes for all docs/public wording changes.
- Scenario contracts, e2e flows, and contract tests are updated for every new public behavior.
- README, command docs, examples, and trust docs are aligned with the implemented runtime behavior.
- Required PR checks remain green: `fast-lane`, `scan-contract`, `wave-sequence`, `windows-smoke`.
- Follow-up implementation must occur on a clean branch/worktree scope with this plan file as the only planning artifact change before `adhoc-implement`.

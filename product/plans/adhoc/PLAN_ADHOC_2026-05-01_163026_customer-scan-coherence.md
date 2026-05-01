# Adhoc Plan: Customer Scan Coherence and Agent Action Readiness

Date: 2026-05-01
Profile: `wrkr`
Slug: `customer-scan-coherence`
Recommendation source: user-provided scan findings and recommendations covering Agent Action BOM buyer readiness, tolerant parsing, MCP and agent-framework depth, risk/report coherence, proof specificity, customer-safe redaction, lifecycle cleanup, and remediation quality.

All machine-local checkout paths in the recommendation source are normalized to repo-relative paths in this plan. Story repo paths below resolve from the active repository root.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control sequence. This plan improves discovery, correlation, reporting, and proof readiness only; it does not implement Gait enforcement or Axym product behavior.
- Customer-facing outputs must lead with coherent governable paths: what was scanned, which paths can read/write/deploy/reach tools, which credentials are involved, what proof or policy is missing, and how trustworthy negative results are.
- Parser failures are scan-quality diagnostics, not security findings. No parse error may become an MCP tool, control graph node, BOM item, backlog remediation, or top risk without positive detector evidence.
- Structured detector inputs are tolerant by default when parsing third-party or open schemas. Strict parsing is reserved for Wrkr-owned contracts, schemas, and policy artifacts.
- Dependency-only AI framework findings are inventory candidates until source, tool binding, credential, MCP, workflow, or runtime evidence increases confidence.
- `agent_action_bom`, `action_paths`, `attack_paths`, `control_path_graph`, `control_backlog`, proof maps, and report top risks must share stable path identifiers and prioritization semantics.
- Path-level proof sufficiency is separate from global proof-chain integrity. A valid chain head must not be reused as per-path proof coverage unless linked evidence supports that exact path.
- Scan quality, source privacy, redaction, and confidence language are first-class buyer signals. "No MCP servers found" is credible only when coverage status and miss diagnostics support that claim.
- Secret handling remains reference-only. Credential names may be classified and redacted, but raw secret values, derived secret hashes, and credential material must never be serialized.
- No LLM calls, runtime code execution, live endpoint probing, or default source upload are allowed in scan, risk, report, evidence, or proof paths.
- Output contract changes are additive unless a story explicitly versions a schema. Existing `--json`, `--explain`, `--quiet`, and exit-code semantics remain stable.
- Docs, schemas, scenarios, changelog entries, and CLI help are part of the public contract and must ship with behavior changes.

## Current Baseline (Observed)

- The repository already contains Agent Action BOM surfaces in `core/report/agent_action_bom.go`, `core/report/render_markdown.go`, `core/report/build.go`, and `schemas/v1/agent-action-bom.schema.json`, plus report/evidence artifacts in `core/report/artifacts.go`.
- Existing action-path and prioritization logic is split across `core/risk/action_paths.go`, `core/risk/govern_first.go`, `core/risk/risk.go`, `core/risk/attackpath/score.go`, and `core/aggregate/controlbacklog/controlbacklog.go`.
- Customer scan samples showed coherence gaps where dependency inventory could outrank higher-value source-level LangChain/MCP paths, high attack-path scores could coexist with low inventory-style recommendations, and top attack paths could be missing from the inspected BOM item list.
- Detector inputs currently include strict or fragile parse paths in `core/detect/parse.go`, `core/detect/dependency/detector.go`, `core/detect/webmcp/detector.go`, and framework detectors. The recommendation source reported false parse errors for normal `package.json` metadata and modern JavaScript/ESM files.
- MCP detection covers known fixed config files, but customer findings require broader candidate extraction from package scripts, workspace metadata, framework source, `.well-known` routes, command invocations, environment references, and generated miss diagnostics.
- Agent framework discovery exists under `core/detect/agentframework`, `core/detect/agentlangchain`, and dependency detectors, but buyer-facing confidence currently needs stronger distinction between generic dependency inventory and active source-level agent/tool binding.
- Credential provenance, privilege budget, and action capability semantics are spread across `core/detect/secrets`, `core/aggregate/inventory/privileges.go`, `core/aggregate/privilegebudget/budget.go`, and `core/risk/action_paths.go`, with customer scan examples showing collapsed multi-credential stories.
- Scan quality aggregation exists in `core/aggregate/scanquality/scanquality.go`, but report/BOM output needs detector health, generated-artifact suppression context, and coverage impact statuses for buyer trust.
- Lifecycle and identity gaps exist under `core/lifecycle`, `core/state`, and related CLI commands. Customer output showed reason text that can conflict with current inventory presence.
- Existing docs include `docs/commands/scan.md`, `docs/commands/report.md`, `docs/commands/mcp-list.md`, and examples, but customer-ready remediation text, redacted sharing, scan-scope accuracy, and dual exposure/governance summaries need explicit contract coverage.

## Exit Criteria

- Buyer-facing Agent Action BOM summaries lead with scan scope, governable paths, write/deploy paths, standing credential paths, reachable MCP/tools/targets, framework usage, policy/proof gaps, source privacy, positive empty states, and appendix-level detail.
- Every top attack path is represented by an Agent Action BOM item or a deterministic exclusion reason with a stable join key.
- Govern-first output, BOM control-first items, report top risks, control backlog queues, and top attack paths use one shared prioritization model.
- Reported risk dimensions are coherent: `inventory_risk`, `attack_path_score`, `control_priority`, `risk_tier`, and `recommended_action` are labeled and derived without contradictory severity/action combinations.
- Parser failures for open third-party files are reduced through tolerant parsing and modern JS/ESM fallback extraction, and remaining failures stay in scan-quality diagnostics.
- Generated or bundled JavaScript/docs/cache artifacts are suppressed or summarized as reduced coverage context instead of noisy active diagnostics.
- MCP and agent-framework detection emits normalized candidates and confidence levels for declarations, scripts, dependencies, source imports, tool bindings, reachable servers, endpoints, credentials, and workflows.
- `wrkr mcp-list` can explain why an expected MCP server was not detected for a repo, including scanned files, parsed configs, candidate scripts/packages, parse failures, generated-file suppression, and unsupported declaration types.
- Credential provenance supports multiple credentials per action path, typed evidence location, standing/JIT classification, confidence, and compatibility rollups.
- Action capability fields are internally consistent across inventory, privilege budget, action paths, BOM items, report summaries, and schemas.
- Scan quality metrics and coverage impact statuses appear in report/BOM output and make negative findings auditable.
- `--share-profile customer-redacted` produces deterministic, customer-safe report/BOM/evidence artifacts with stable pseudonyms and configurable redaction.
- Scan mode and scope are accurately represented for local path, local org mirror, remote repo, remote org, and repo-group scans.
- Lifecycle gaps, path context, tool family/instance identity, deployment status, and path-specific proof refs have deterministic semantics and regression coverage.
- Customer-facing findings include concrete remediation guidance suitable for approval, owner assignment, rotation evidence, brokered credentials, policy refs, proof refs, accepted inventory, or suppression.

## Public API and Contract Map

- `wrkr scan --json`
  - Additive scan-quality metrics may include attempted, parsed, partially parsed, skipped, suppressed, failed, and unsupported counts by detector and repo.
  - Preserve deterministic offline behavior and existing exit codes.
  - Structured parser diagnostics remain diagnostics, not findings.
- `wrkr report --json` and report templates
  - Additive report summary fields may include `operational_exposure`, `governance_readiness`, `scan_scope`, `source_privacy`, `finding_visibility`, `scan_quality`, and richer `agent_action_bom` summaries.
  - `--share-profile customer-redacted` must be deterministic, explicit, and documented.
  - Markdown rendering must preserve machine-readable JSON semantics and positive empty states.
- `agent_action_bom`
  - Additive fields may include summary sections, `path_id`, `path_context`, `deployment_status`, `confidence`, `credentials[]`, `tool_bindings[]`, `reachable_tools[]`, `reachable_servers[]`, `reachable_endpoints[]`, `exclusion_reason`, path-level proof refs, and customer-ready remediation text.
  - Item ordering must follow the shared govern-first priority model with deterministic tie-breakers.
- `action_paths`, risk reports, and attack paths
  - Additive risk dimensions may include `inventory_risk`, `attack_path_score`, `control_priority`, `risk_tier`, `recommended_action`, `deployment_status`, and `path_context`.
  - Dependency-only inventory must not outrank source-level framework/MCP paths with credentials, write/deploy capability, or tool bindings.
- `control_backlog`
  - Backlog queues become `control_first`, `review_queue`, `inventory_hygiene`, and `debug_only`, with parse diagnostics and generated-artifact noise routed away from primary remediation.
- `wrkr mcp-list`
  - Add repo filtering and miss diagnostics without requiring manual `jq`.
  - Preserve existing list output compatibility through additive fields or versioned output where needed.
- Schemas
  - Update schemas under `schemas/v1` additively where possible, including `agent-action-bom.schema.json`, `risk/risk-report.schema.json`, `report/report-summary.schema.json`, and `inventory/inventory.schema.json`.
  - Strict schema validation remains mandatory for Wrkr-owned contracts.
- Proof and evidence
  - Proof refs must be path-specific by canonical finding key, `path_id`, repo/location, or graph ref.
  - Global proof-chain metadata remains separate from per-path proof sufficiency.
- Architecture boundaries
  - Source layer owns scan scope and source privacy.
  - Detection owns parser tolerance, raw candidates, confidence evidence, and diagnostics.
  - Aggregation owns cross-detector correlation, identity instance joins, privilege maps, scan quality, and backlog queues.
  - Identity owns lifecycle, family/instance identity, owner/approval reconciliation, and state migration.
  - Risk owns prioritization, scoring, recommended action, path context, and deployment/exposure dimensions.
  - Proof emission owns proof records and chain integrity.
  - Compliance mapping/evidence output owns BOM/report/evidence rendering, redaction, proof sufficiency display, and customer remediation text.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/mcp-list.md`
  - `docs/commands/evidence.md`
  - `docs/examples/security-team.md`
  - `docs/examples/operator-playbooks.md`
  - `docs/examples/quickstart.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Docs must answer directly:
  - What exactly was scanned, in which mode, and what was excluded or suppressed?
  - Why is the Agent Action BOM the buyer-facing view, and where does appendix data live?
  - Why can a negative MCP result be trusted, or why is coverage reduced?
  - How are dependency-only AI framework findings different from active agent/tool-binding paths?
  - How do operational exposure and governance readiness differ from the compatibility posture score?
  - What should a customer do next for each finding type?
  - How does customer-redacted sharing preserve risk meaning without leaking sensitive identifiers?
- Required docs and trust gates:
  - `scripts/check_docs_cli_parity.sh`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/run_docs_smoke.sh`
  - `make test-docs-consistency`
- OSS trust baseline remains bounded to Wrkr scope. This plan does not alter support policy, licensing, vulnerability disclosure, or release distribution except where user-facing command/schema behavior changes require synchronized docs and changelog updates.

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage |
|---|---:|---|
| 1. Agent Action BOM buyer summary | P0 | Stories 4.1, 4.3 |
| 2. Tolerant structured parsing | P0 | Story 2.1 |
| 3. Package parser fix for monorepos | P0 | Story 2.1 |
| 4. Modern JS / ESM detection fallback | P0 | Story 2.2 |
| 5. Do not promote parse errors to security surfaces | P0 | Stories 2.2, 2.3 |
| 6. MCP declaration coverage expansion | P1 | Story 3.1 |
| 7. MCP miss diagnostics | P1 | Story 3.1 |
| 8. Agentic framework promotion | P1 | Story 3.2 |
| 9. LangChain-specific deep detection | P1 | Story 3.2 |
| 10. Cross-detector correlation | P1 | Story 3.3 |
| 11. Credential provenance multi-credential model | P2 | Story 5.1 |
| 12. Action capability semantics cleanup | P1 | Story 5.1 |
| 13. Backlog triage and queues | P0 | Story 1.3 |
| 14. Path-specific proof references | P1 | Stories 1.2, 5.3 |
| 15. Scan quality coverage model | P1 | Story 2.3 |
| 16. Customer-redacted share profile | P1 | Story 4.2 |
| 17. Govern-first prioritization alignment | P0 | Story 1.1 |
| 18. BOM and attack path consistency | P0 | Story 1.2 |
| 19. Risk tier and recommended action coherence | P0 | Story 1.1 |
| 20. Agent tool binding and reachability extraction | P1 | Story 3.3 |
| 21. Test fixture vs runtime path classification | P2 | Story 5.2 |
| 22. Generated artifact suppression for JS/WebMCP | P0 | Story 2.2 |
| 23. Lifecycle gap reconciliation cleanup | P2 | Story 5.2 |
| 24. Tool family vs tool instance identity | P2 | Story 5.2 |
| 25. Deployment context evidence | P2 | Story 5.3 |
| 26. Operational exposure vs governance readiness grades | P1 | Story 4.3 |
| 27. Customer-facing finding suppression policy | P0 | Story 1.3 |
| 28. Repo/org scan summary accuracy | P1 | Story 4.1 |
| 29. Detector confidence and evidence strength | P1 | Stories 3.3, 4.3 |
| 30. Customer-ready remediation text | P0 | Stories 1.3, 4.3 |

## Test Matrix Wiring

- Fast lane:
  - Focused Go unit tests for parser helpers, dependency extraction, JS fallback extraction, govern-first sorting, BOM joins, backlog queue assignment, redaction mapping, and remediation text rendering.
  - `make lint-fast`
- Core CI lane:
  - `make test-fast`
  - `make test-contracts`
  - schema validation tests for changed JSON contracts
  - report/evidence/CLI contract tests for additive fields and omission behavior
- Acceptance lane:
  - `make test-scenarios`
  - `scripts/validate_scenarios.sh`
  - scenario-tagged tests covering customer scan coherence: parser-noise fixtures, MCP miss diagnostics, LangChain source confidence, BOM/top-attack-path parity, and redacted report output.
- Cross-platform lane:
  - Keep path classification, redaction, scan-scope summaries, and generated-artifact suppression path-separator neutral.
  - Ensure Windows smoke remains stable for report/scan JSON fields, monorepo package fixtures, and local path redaction.
- Risk lane:
  - `make test-risk-lane`
  - `make test-hardening`
  - `make test-chaos` for fail-closed proof/path joins, redaction leakage prevention, parser fallback diagnostics, and output-path safety.
  - `make test-perf` for broad detector expansion, generated-file suppression, and monorepo package parsing.
- Release/UAT lane when relevant:
  - `make prepush-full`
  - `make test-release-smoke`
  - `bash scripts/test_uat_local.sh` before release promotion when public report/evidence schemas or CLI help change.
- Gating rule:
  - No story is complete until declared lanes pass, new golden outputs are byte-stable except explicit timestamp/version fields, user-facing docs and schemas agree with behavior, and no committed artifact contains developer-specific absolute checkout paths or secret values.

## Minimum-Now Sequence

- Wave 1 - Prioritization and contract coherence:
  - Story 1.1: align govern-first priority, risk tiers, and recommended actions.
  - Story 1.2: enforce BOM, attack-path, proof-ref, and graph join consistency.
  - Story 1.3: split backlog queues, finding visibility, and remediation text.
- Wave 2 - Parser and diagnostic noise control:
  - Story 2.1: make structured parsing tolerant and fix monorepo `package.json` extraction.
  - Story 2.2: add modern JS/ESM fallback extraction and generated-artifact suppression.
  - Story 2.3: emit scan-quality coverage and keep diagnostics out of security surfaces.
- Wave 3 - Agent and MCP detection depth:
  - Story 3.1: expand MCP declaration candidates and add miss diagnostics.
  - Story 3.2: promote framework dependencies and deepen LangChain/LangGraph detection.
  - Story 3.3: correlate cross-detector signals, reachability, and confidence.
- Wave 4 - Customer artifact readiness:
  - Story 4.1: harden the buyer-facing BOM summary, markdown, scan scope, and source privacy.
  - Story 4.2: add customer-redacted share profiles.
  - Story 4.3: split operational exposure from governance readiness and improve confidence/remediation language.
- Wave 5 - Governance model cleanup:
  - Story 5.1: implement multi-credential provenance and action capability semantics.
  - Story 5.2: reconcile path context, lifecycle gaps, and tool family/instance identity.
  - Story 5.3: require deployment evidence and path-specific proof refs.

## Explicit Non-Goals

- No Gait policy enforcement, runtime blocking, kill-switch execution, or policy decision execution in Wrkr.
- No Axym compliance engine behavior beyond shared proof/evidence interoperability.
- No live endpoint probing, runtime source execution, browser automation, SaaS upload, or default network enrichment.
- No LLM-generated summaries, risk scoring, remediation, parsing, or detector output.
- No raw secret extraction, secret value hashing, or credential material serialization.
- No removal or breaking rename of existing `scan`, `report`, `evidence`, `mcp-list`, `action_paths`, `control_backlog`, `control_path_graph`, or `agent_action_bom` fields without a versioned migration story.
- No broad rewrite of detector architecture when tolerant parsers, candidate signals, and aggregation joins can preserve existing boundaries.
- No customer-specific names, local filesystem roots, owner handles, proof refs, or repo paths in committed fixtures beyond deterministic synthetic scenarios.

## Definition of Done

- Customer-facing reports and BOMs explain scan scope, coverage confidence, operational exposure, governance readiness, top governable paths, proof/policy gaps, and next actions without requiring manual joins.
- Parser failures for normal third-party package metadata, modern ESM syntax, and generated bundles no longer flood primary findings or hide real MCP/framework signals.
- MCP and agent-framework findings distinguish dependency-only inventory, source-level active agent paths, tool bindings, reachable servers, credential access, and workflow/deployment context.
- Every top attack path has a BOM item or explicit exclusion reason, and proof refs are path-specific.
- Backlog queues and suppression policies keep control-first work small enough for a buyer/operator to act on while preserving appendix/debug detail.
- Redacted sharing is deterministic, stable across repeated runs for the same input, and covered by leakage tests.
- Lifecycle, identity, credential, action capability, path context, deployment status, and proof coverage semantics are internally coherent across schemas and rendered outputs.
- All changed public commands, schemas, docs, examples, and changelog entries are synchronized.
- Required fast, contract, scenario, risk, docs, and performance lanes are wired at story level and run before final implementation landing.

## Epic 1: Prioritization and Contract Coherence

Objective: make buyer-visible risk ordering, recommended actions, BOM items, attack paths, and backlog queues tell one consistent story.

### Story 1.1: Align govern-first priority, risk tiers, and recommended actions

Priority: P0
Recommendation coverage: 17, 19
Strategic direction: centralize priority derivation so action paths, BOM control-first items, report top risks, and attack paths rank by the strongest governable signal before dependency inventory.
Expected benefit: customers see high-attack-path framework/MCP paths as proof/control work instead of low-severity inventory noise.

Tasks:
- Introduce a shared priority model that ranks credential access, direct write/deploy capability, production target evidence, attack-path score, MCP/client/framework signal, tool binding, and policy/proof gaps before dependency-only inventory.
- Add labeled dimensions for `inventory_risk`, `attack_path_score`, and `control_priority` in the risk/action-path model.
- Derive `risk_tier` and `recommended_action` from the strongest governable signal, with deterministic tie-breakers by repo, location, finding key, and path ID.
- Update `action_path_to_control_first`, report top risks, BOM control-first ordering, and control backlog priority to consume the shared model.
- Add regression fixtures where a dependency-only package and a source-level LangChain/MCP path compete for top priority.
- Update schemas, docs, and changelog for additive fields and changed ranking semantics.

Repo paths:
- `core/risk/govern_first.go`
- `core/risk/action_paths.go`
- `core/risk/risk.go`
- `core/risk/attackpath/score.go`
- `core/score/score.go`
- `core/aggregate/inventory/privileges.go`
- `core/report/build.go`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*GovernFirst|Test.*ActionPath|Test.*RecommendedAction' -count=1`
- `go test ./core/score -run 'Test.*Score|Test.*Tier' -count=1`
- `go test ./core/report -run 'Test.*TopRisk|Test.*AgentActionBOM' -count=1`
- `make lint-fast`
- `make test-fast`
- `make test-contracts`
- `make test-risk-lane`

Test requirements:
- TDD fixtures proving source-level MCP/framework paths outrank dependency-only inventory when attack score, credential, write/deploy, or tool-binding evidence is stronger.
- Contract tests proving additive risk dimension fields serialize with stable names and deterministic numeric/string values.
- Regression tests preventing `score=10`, `severity=low`, and `action=inventory` contradictions for the same path unless dimensions are explicitly separated and explained.

Matrix wiring:
- Fast lane: focused `core/risk`, `core/score`, and `core/report` tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario fixture with competing dependency-only and source-level agent/MCP paths.
- Cross-platform lane: ordering tests use repo-relative paths and stable sort keys.
- Risk lane: `make test-risk-lane` and `make test-hardening` for fail-closed high-risk prioritization.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Dependency-only inventory cannot outrank source-level agent/MCP paths with stronger governable signals.
- Report top risks, BOM control-first items, attack paths, and `action_path_to_control_first` agree on the same top path order for shared fixtures.
- `risk_tier` and `recommended_action` are coherent for high attack-path scores and explain separated dimensions when needed.
- Additive schema fields and docs are synchronized.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Aligned govern-first ranking, risk tiers, and recommended actions so source-level agent and MCP paths with credentials, write/deploy reach, or high attack-path scores are prioritized ahead of dependency-only inventory.
Semver marker override: [semver:minor]
Contract/API impact: Adds labeled risk dimensions and may change ranking/order in public report and risk JSON.
Versioning/migration impact: Additive fields; downstream consumers that depend on item ordering should treat this as improved prioritization semantics.
Architecture constraints: Risk owns prioritization; report and backlog consume the shared model without recomputing private ranking rules.
ADR required: no
TDD first failing test(s): `TestGovernFirstRanksSourceMCPAboveDependencyInventory` and `TestRecommendedActionFollowsStrongestGovernableSignal`.
Cost/perf impact: low
Chaos/failure hypothesis: missing or ambiguous priority inputs degrade to review/proof gaps rather than low-risk inventory when high attack-path evidence is present.

### Story 1.2: Enforce BOM, attack-path, proof-ref, and graph join consistency

Priority: P0
Recommendation coverage: 18, 14
Strategic direction: make `path_id` and canonical finding keys the join spine across BOM items, action paths, attack paths, proof maps, and graph nodes.
Expected benefit: customers can trust the BOM as the buyer-facing artifact because every top attack path is represented or explicitly excluded.

Tasks:
- Define a canonical join contract for `path_id`, finding key, repo/location, graph refs, and proof refs across action paths, attack paths, BOM items, and control graph nodes.
- Update the BOM builder to include every top attack path or emit an explicit `exclusion_reason` with evidence basis.
- Link proof coverage by path-specific proof refs rather than reusing global proof-chain refs for unrelated paths.
- Add contract tests asserting no top attack path is orphaned from the BOM.
- Add fixture coverage for unrelated proof refs, missing path proof, and valid global proof-chain integrity with path-level proof gaps.
- Update `agent-action-bom.schema.json` and docs for additive join/exclusion/proof fields.

Repo paths:
- `core/report/agent_action_bom.go`
- `core/report/control_proof.go`
- `core/report/build.go`
- `core/aggregate/attackpath/graph.go`
- `core/risk/action_paths.go`
- `core/proofmap/proofmap.go`
- `core/evidence/evidence.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/control-path-graph.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/report -run 'Test.*AgentActionBOM|Test.*ProofCoverage|Test.*AttackPath' -count=1`
- `go test ./core/risk -run 'Test.*ActionPath' -count=1`
- `go test ./core/proofmap -run 'Test.*Path|Test.*Proof' -count=1`
- `make test-contracts`
- `make test-fast`
- `make test-hardening`

Test requirements:
- TDD contract test failing when a top attack path has no BOM item or exclusion reason.
- Proof-linkage test proving unrelated proof refs are not copied across BOM items.
- Report/evidence parity test proving BOM proof coverage and evidence proof gaps agree for the same fixture.

Matrix wiring:
- Fast lane: focused `core/report`, `core/risk`, and `core/proofmap` tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario fixture with top attack path, BOM item, graph node, and proof map linkage.
- Cross-platform lane: join keys avoid OS-specific absolute paths.
- Risk lane: `make test-hardening` for fail-closed proof-gap behavior.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Every top attack path has a corresponding BOM item or deterministic exclusion reason.
- Proof refs on BOM items are path-specific.
- Global chain integrity and path-level proof sufficiency are displayed separately.
- Schema and docs explain join and exclusion semantics.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Fixed Agent Action BOM consistency so top attack paths are represented or explicitly excluded and proof refs are linked to the specific path they support.
Semver marker override: [semver:patch]
Contract/API impact: Adds BOM join/exclusion fields and tightens proof coverage semantics without removing existing refs.
Versioning/migration impact: No migration required for consumers; stricter proof semantics may change missing-proof counts.
Architecture constraints: Report/evidence owns rendering and sufficiency display; proof emission remains the source of proof records and chain integrity.
ADR required: no
TDD first failing test(s): `TestAgentActionBOMIncludesEveryTopAttackPathOrExclusion` and `TestAgentActionBOMProofRefsArePathSpecific`.
Cost/perf impact: low
Chaos/failure hypothesis: orphaned or ambiguous joins fail into explicit exclusion/proof-gap states instead of silently omitting attack paths.

### Story 1.3: Split backlog queues, finding visibility, and remediation text

Priority: P0
Recommendation coverage: 13, 27, 30
Strategic direction: route customer-visible work into actionable queues while preserving appendix/debug data for diagnostics and audit depth.
Expected benefit: buyers see a small, prioritized set of control actions instead of thousands of equal-looking remediation rows.

Tasks:
- Add deterministic backlog queues: `control_first`, `review_queue`, `inventory_hygiene`, and `debug_only`.
- Introduce a customer-facing finding visibility policy for primary report, appendix, and debug output.
- Route parse diagnostics, generated-artifact suppressions, dependency-only inventory, and low-confidence candidates away from primary control-first output unless stronger evidence exists.
- Generate remediation text from finding type, credential provenance, policy/proof gaps, owner state, deployment status, and accepted inventory/suppression state.
- Add docs explaining queue semantics and customer-ready next actions.
- Add changelog and schema updates for additive queue and visibility fields.

Repo paths:
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/risk/govern_first.go`
- `core/report/build.go`
- `core/report/render_markdown.go`
- `core/cli/export.go`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/report.md`
- `docs/commands/scan.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/aggregate/controlbacklog -run 'Test.*Queue|Test.*Remediation|Test.*Visibility' -count=1`
- `go test ./core/report -run 'Test.*Backlog|Test.*Markdown|Test.*Remediation' -count=1`
- `make test-contracts`
- `make test-docs-consistency`
- `make test-fast`

Test requirements:
- TDD fixtures proving high-risk credential/write/deploy paths enter `control_first`.
- Fixtures proving parse errors and generated artifacts enter `debug_only` or coverage context, not primary remediation.
- Golden markdown/JSON tests for concrete remediation text.

Matrix wiring:
- Fast lane: focused backlog and report tests plus `make lint-fast`.
- Core CI lane: `make test-fast`, `make test-contracts`, and docs consistency.
- Acceptance lane: scenario with mixed high-risk paths, dependency noise, parser diagnostics, and generated suppression.
- Cross-platform lane: queue classification uses normalized paths.
- Risk lane: `make test-hardening` for fail-closed queue assignment on ambiguous high-risk evidence.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Primary report backlog is queue-labeled and small enough to identify control-first work.
- Appendix/debug data remains available for audit and troubleshooting.
- Remediation text names concrete next steps such as approve, assign owner, attach rotation evidence, require brokered credential, add policy ref, add proof ref, suppress as accepted inventory, or debug detector coverage.
- Docs and schemas describe queue and visibility semantics.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added customer-facing backlog queues, finding visibility tiers, and concrete remediation text for report and Agent Action BOM outputs.
Semver marker override: [semver:minor]
Contract/API impact: Adds queue, visibility, and remediation fields to report/backlog artifacts.
Versioning/migration impact: Additive output; consumers may adopt queues while existing backlog fields remain available.
Architecture constraints: Aggregation classifies queues; report renders customer language without changing detector findings.
ADR required: no
TDD first failing test(s): `TestControlBacklogRoutesDiagnosticsToDebugOnly` and `TestReportRemediationTextNamesConcreteNextAction`.
Cost/perf impact: low
Chaos/failure hypothesis: if queue evidence is incomplete, high-risk paths fall into review/proof queues while diagnostics remain non-security coverage output.

## Epic 2: Parser and Diagnostic Noise Control

Objective: improve detection coverage and customer trust by parsing normal third-party files tolerantly, handling modern JavaScript safely, and making diagnostics explicit.

### Story 2.1: Make structured parsing tolerant and fix monorepo package extraction

Priority: P0
Recommendation coverage: 2, 3
Strategic direction: reserve strict decoding for Wrkr-owned contracts and parse open third-party formats into tolerant structs or maps before extracting needed fields.
Expected benefit: normal metadata in `package.json`, YAML, TOML, MCP configs, and agent manifests no longer causes false parse errors or hidden dependency signals.

Tasks:
- Add tolerant JSON/YAML/TOML parser helpers in `core/detect/parse.go`, with strict helpers clearly named for Wrkr-owned contracts.
- Replace strict parsing for open detector inputs where schemas are third-party, extensible, or package-manager owned.
- Rework `package.json` extraction to read dependencies, devDependencies, optionalDependencies, peerDependencies, scripts, workspaces, packageManager, exports, and bin while ignoring unknown metadata.
- Add monorepo fixtures for Yarn PnP, workspaces, nested packages, package exports, bins, packageManager, and normal metadata such as `author` and `name`.
- Add parser-mode tests proving strict Wrkr contract parsing still rejects unknown fields when required.
- Update docs if scan-quality messages or parser diagnostics change.

Repo paths:
- `core/detect/parse.go`
- `core/detect/dependency/detector.go`
- `core/detect/dependency/detector_test.go`
- `core/detect/mcp/detector.go`
- `core/detect/agentframework/source.go`
- `core/detect/webmcp/detector.go`
- `docs/commands/scan.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect -run 'Test.*Parse|Test.*Tolerant|Test.*Strict' -count=1`
- `go test ./core/detect/dependency -run 'Test.*Package|Test.*Workspace|Test.*Monorepo' -count=1`
- `go test ./core/detect/mcp ./core/detect/webmcp ./core/detect/agentframework -count=1`
- `make lint-fast`
- `make test-fast`
- `make test-contracts`

Test requirements:
- TDD package fixtures proving unknown metadata does not fail dependency extraction.
- Fixture proving all supported package sections are extracted deterministically.
- Strict-mode regression tests for Wrkr-owned schema parsing.

Matrix wiring:
- Fast lane: focused parser and dependency tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario fixture for monorepo package discovery and reduced parse errors.
- Cross-platform lane: workspace path handling is separator-neutral.
- Risk lane: `make test-hardening` for malformed structured files and secret non-extraction.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Normal third-party metadata does not create parse errors for detector inputs.
- Dependency detection reads supported sections in monorepo packages without failing on unknown fields.
- Strict parsing remains available and enforced for Wrkr-owned contracts.
- Scan output distinguishes parse mode and diagnostics where relevant.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Fixed detector parsing for open third-party package and config formats so unknown metadata no longer blocks dependency, MCP, or framework discovery.
Semver marker override: [semver:patch]
Contract/API impact: May reduce parse diagnostics and add parser-mode diagnostic detail; no existing public fields are removed.
Versioning/migration impact: No migration required.
Architecture constraints: Detection owns tolerant parsing; contract/schema validation for Wrkr-owned artifacts remains strict.
ADR required: no
TDD first failing test(s): `TestPackageJSONIgnoresUnknownMetadataAndExtractsSections` and `TestStrictWrkrContractRejectsUnknownFields`.
Cost/perf impact: low
Chaos/failure hypothesis: malformed third-party files degrade to partial diagnostics and coverage impact without inventing findings.

### Story 2.2: Add modern JS/ESM fallback extraction and generated-artifact suppression

Priority: P0
Recommendation coverage: 4, 5, 22
Strategic direction: treat modern JS/TS/ESM parse failures as recoverable coverage events and suppress generated assets before they distract from real signals.
Expected benefit: `.mjs`, `.cjs`, top-level `await`, Yarn PnP, VitePress cache files, bundled docs assets, and generated JS do not hide WebMCP/MCP/framework signals or flood reports.

Tasks:
- Add or upgrade a JavaScript extraction path that supports modern JS/TS/ESM syntax where feasible.
- Add safe fallback extraction for import strings, package references, route declarations, MCP URLs, tool/server declarations, auth headers, and endpoint literals.
- Add generated/bundled path classifiers for VitePress cache deps, minified bundles, docs build assets, package-manager internals, vendor JS, and generated docs assets.
- Suppress generated artifacts into coverage context instead of active diagnostics unless positive high-risk evidence exists.
- Ensure WebMCP parse failures cannot create MCP tool backlog items, graph nodes, or BOM entries without positive signal evidence.
- Add docs explaining generated suppression and reduced coverage statuses.

Repo paths:
- `core/detect/webmcp/detector.go`
- `core/detect/webmcp/detector_test.go`
- `core/detect/agentframework/source.go`
- `core/aggregate/scanquality/scanquality.go`
- `core/cli/scan.go`
- `docs/commands/scan.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/webmcp -run 'Test.*ModernJS|Test.*Fallback|Test.*Generated|Test.*ParseError' -count=1`
- `go test ./core/detect/agentframework -run 'Test.*Source|Test.*Fallback' -count=1`
- `go test ./core/aggregate/scanquality -run 'Test.*Generated|Test.*Suppressed' -count=1`
- `make test-contracts`
- `make test-fast`
- `make test-perf`

Test requirements:
- TDD fixtures for `.mjs`, `.cjs`, top-level `await`, route declarations, and fallback extraction.
- Generated asset fixtures proving suppression counts are reported but not promoted to findings.
- Negative tests proving parse errors do not become MCP security surfaces.

Matrix wiring:
- Fast lane: focused WebMCP, agentframework, and scanquality tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario with modern JS source plus generated docs cache noise.
- Cross-platform lane: generated path classifiers normalize separators and case where appropriate.
- Risk lane: `make test-hardening` and `make test-perf`.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Modern JS/ESM syntax does not block safe candidate extraction when positive signals exist.
- Generated JS/docs/package-manager assets are suppressed into scan-quality context.
- Parse errors do not emit MCP tools, dependency agent surfaces, control graph nodes, BOM items, or backlog items unless positive evidence exists.
- Docs describe suppression and diagnostic behavior.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Reduced JavaScript/WebMCP parse noise by adding modern syntax fallback extraction and suppressing generated or bundled assets as coverage context instead of primary findings.
Semver marker override: [semver:patch]
Contract/API impact: Adds or refines scan-quality suppression diagnostics; reduces false positive finding surfaces.
Versioning/migration impact: No migration required.
Architecture constraints: Detection emits positive candidates and diagnostics separately; aggregation/reporting must not convert diagnostics into security findings.
ADR required: no
TDD first failing test(s): `TestWebMCPFallbackExtractsSignalsFromModernESM` and `TestWebMCPParseErrorsDoNotCreateMCPBacklogItems`.
Cost/perf impact: medium
Chaos/failure hypothesis: unsupported syntax yields partial coverage diagnostics and fallback candidates, not false security findings.

### Story 2.3: Emit scan-quality coverage and keep diagnostics out of security surfaces

Priority: P1
Recommendation coverage: 5, 15
Strategic direction: make detector health auditable by emitting coverage impact while preserving a strict boundary between diagnostics and findings.
Expected benefit: customers can tell whether negative results are complete, partial, reduced, or blocked.

Tasks:
- Add detector health metrics for attempted files, parsed files, partial parses, skipped files, suppressed files, parse failures, unsupported declarations, and coverage impact.
- Define statuses `complete`, `partial`, `reduced`, and `blocked` by detector/repo.
- Wire scan-quality summaries into report and BOM outputs where buyer trust depends on negative results.
- Add contract tests proving parse diagnostics are excluded from control graph nodes, BOM items, action paths, risk findings, and backlog remediation unless correlated with positive detector evidence.
- Add docs explaining coverage impact, suppression, and when a negative finding should be treated as low confidence.

Repo paths:
- `core/aggregate/scanquality/scanquality.go`
- `core/aggregate/scanquality/scanquality_test.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/risk/risk.go`
- `core/report/agent_action_bom.go`
- `core/report/build.go`
- `core/cli/scan.go`
- `core/cli/scan_helpers.go`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/aggregate/scanquality -run 'Test.*Coverage|Test.*Impact|Test.*Diagnostics' -count=1`
- `go test ./core/aggregate/controlbacklog -run 'Test.*Diagnostic|Test.*Parse' -count=1`
- `go test ./core/report -run 'Test.*ScanQuality|Test.*AgentActionBOM' -count=1`
- `make test-contracts`
- `make test-fast`
- `make test-hardening`

Test requirements:
- TDD coverage fixtures for complete, partial, reduced, and blocked detector states.
- Contract tests proving diagnostics remain out of security surfaces.
- Golden report/BOM output for a negative MCP result with clean versus reduced coverage.

Matrix wiring:
- Fast lane: focused scanquality, backlog, and report tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario proving "no MCP servers found" is annotated by detector coverage status.
- Cross-platform lane: coverage locations are repo-relative.
- Risk lane: `make test-hardening` for diagnostic/finding separation.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Report/BOM output exposes detector health where negative findings could otherwise mislead.
- Diagnostics are never promoted to security findings without positive evidence.
- Coverage statuses are deterministic and schema-documented.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added scan-quality coverage metrics and detector health statuses to make negative findings auditable without promoting parser diagnostics into security findings.
Semver marker override: [semver:minor]
Contract/API impact: Adds scan-quality fields to report/BOM outputs and strengthens diagnostic/finding separation.
Versioning/migration impact: Additive output only.
Architecture constraints: Scan quality is aggregation metadata; risk/report layers consume it without treating it as detector evidence.
ADR required: no
TDD first failing test(s): `TestScanQualityReportsReducedCoverageForParseFailures` and `TestDiagnosticsDoNotEnterSecuritySurfaces`.
Cost/perf impact: low
Chaos/failure hypothesis: detector failure produces explicit reduced/blocked status and coverage impact rather than silent negative confidence or false positives.

## Epic 3: Agent and MCP Detection Depth

Objective: discover and explain real MCP and agent-framework paths across configs, packages, scripts, source, credentials, workflows, and reachability signals.

### Story 3.1: Expand MCP declaration candidates and add miss diagnostics

Priority: P1
Recommendation coverage: 6, 7
Strategic direction: broaden MCP candidate extraction beyond fixed config files while making misses explainable from the CLI.
Expected benefit: "this repo has MCP servers; did Wrkr detect them?" becomes answerable through `wrkr mcp-list` without manual artifact joins.

Tasks:
- Extract MCP candidates from package scripts, package dependencies, workspace packages, known MCP server package names, command invocations, environment variable references, framework configs, `.well-known` routes, and service code literals.
- Preserve existing fixed config parsing for `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `mcp.json`, `managed-mcp.json`, Claude settings, and Codex config.
- Add candidate fields for evidence type, confidence, declaration type, transport hints, credential refs, and unsupported declaration reasons.
- Extend `wrkr mcp-list` with repo filtering and miss diagnostics: candidate files scanned, configs parsed, package/script candidates found, parse failures, generated suppressions, and unsupported declaration types.
- Update report MCP list rendering and docs.

Repo paths:
- `core/detect/mcp/detector.go`
- `core/detect/webmcp/detector.go`
- `core/detect/dependency/detector.go`
- `core/report/mcp_list.go`
- `core/cli/mcp_list.go`
- `docs/commands/mcp-list.md`
- `schemas/v1/report/report-summary.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/mcp -run 'Test.*Candidate|Test.*Package|Test.*Script|Test.*WellKnown' -count=1`
- `go test ./core/report -run 'Test.*MCPList|Test.*MCPMiss' -count=1`
- `go test ./core/cli -run 'TestMCPList.*' -count=1`
- `make test-contracts`
- `make test-fast`

Test requirements:
- TDD fixtures for package script MCP servers, workspace MCP packages, framework config declarations, and `.well-known` routes.
- CLI contract tests for repo-filtered miss diagnostics.
- Negative tests proving candidates remain candidates until confidence/evidence threshold is met.

Matrix wiring:
- Fast lane: focused MCP detector, report, and CLI tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario with expected MCP server present through package/script and source hints.
- Cross-platform lane: repo filtering and path display are separator-neutral.
- Risk lane: `make test-hardening` for unsupported and ambiguous declarations.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- MCP detection covers fixed configs plus package/script/workspace/framework/source candidates.
- `wrkr mcp-list` explains found, missed, unsupported, and reduced-coverage MCP evidence by repo.
- Low-confidence candidates do not become authoritative MCP servers without evidence basis.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Expanded MCP candidate detection and added `wrkr mcp-list` miss diagnostics for package scripts, workspace metadata, framework config, source hints, and coverage failures.
Semver marker override: [semver:minor]
Contract/API impact: Adds MCP candidate and miss-diagnostic fields plus CLI output options.
Versioning/migration impact: Additive output; existing MCP list consumers remain compatible if fields are optional.
Architecture constraints: Detection emits MCP candidates; report/CLI explain misses without probing live endpoints.
ADR required: no
TDD first failing test(s): `TestMCPDetectorFindsPackageScriptCandidate` and `TestMCPListExplainsMissedExpectedServer`.
Cost/perf impact: medium
Chaos/failure hypothesis: unsupported declarations produce miss diagnostics and coverage impact, not false servers.

### Story 3.2: Promote framework dependencies and deepen LangChain/LangGraph detection

Priority: P1
Recommendation coverage: 8, 9
Strategic direction: promote AI framework packages into framework candidates, then scan nearby source for active agent/tool evidence before raising confidence.
Expected benefit: buyer output distinguishes "LangChain is installed" from "this repo creates agents, binds tools, reads credentials, and can call targets."

Tasks:
- Promote dependencies such as LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex, Semantic Kernel, Haystack, and MCP clients into framework candidates.
- Scan nearby Python and TypeScript/JavaScript source for framework imports, agent constructors, tools, retrievers, vector stores, model providers, API key reads, memory, workflows, and entrypoints.
- Add deeper LangChain/LangGraph patterns for `create_react_agent`, `create_openai_tools_agent`, `AgentExecutor`, `ChatOpenAI`, `Watsonx`, decorators such as `tool`, retrievers, vector stores, and graph workflows.
- Attach findings to action paths and BOM only when authority or active source evidence exists; keep dependency-only findings in inventory/review.
- Add confidence levels and evidence strength for dependency-only, import-only, constructor, tool-binding, credential, and workflow evidence.

Repo paths:
- `core/detect/dependency/detector.go`
- `core/detect/dependency/detector_test.go`
- `core/detect/agentframework/source.go`
- `core/detect/agentlangchain/detector.go`
- `core/detect/agentlangchain/detector_test.go`
- `core/aggregate/agentresolver/resolver.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/dependency -run 'Test.*Framework|Test.*LangChain|Test.*Package' -count=1`
- `go test ./core/detect/agentframework ./core/detect/agentlangchain -run 'Test.*Lang|Test.*Framework|Test.*Tool|Test.*Retriever' -count=1`
- `go test ./core/aggregate/agentresolver ./core/aggregate/inventory -count=1`
- `make test-fast`
- `make test-contracts`

Test requirements:
- TDD fixtures for dependency-only framework, import-only framework, active agent constructor, tool binding, retriever/vector store, model provider, and credential ref.
- Negative tests proving dependency-only evidence does not become a high-confidence action path.
- Cross-language fixtures for Python and TypeScript/JavaScript where supported.

Matrix wiring:
- Fast lane: focused dependency/framework/langchain tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario fixture with dependency-only and active source-level LangChain paths.
- Cross-platform lane: path proximity logic avoids absolute paths.
- Risk lane: `make test-hardening` for ambiguous credential/source evidence.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Framework dependencies create candidates with confidence, not automatic high-risk paths.
- Active source evidence promotes candidates into agent/framework action paths with evidence basis.
- LangChain/LangGraph tool, retriever, provider, credential, and workflow signals surface in BOM/report output when authority exists.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added agent-framework candidate promotion and deeper LangChain/LangGraph source detection with confidence levels for dependency, import, constructor, tool, retriever, provider, and credential evidence.
Semver marker override: [semver:minor]
Contract/API impact: Adds framework candidate/confidence fields and may increase high-confidence source-level findings.
Versioning/migration impact: Additive output only.
Architecture constraints: Dependency detection creates candidates; source detectors raise confidence; aggregation/risk decide path promotion.
ADR required: no
TDD first failing test(s): `TestFrameworkDependencyCreatesCandidateNotActionPath` and `TestLangChainToolBindingPromotesFrameworkCandidate`.
Cost/perf impact: medium
Chaos/failure hypothesis: unsupported source syntax or missing nearby source leaves a low-confidence candidate and scan-quality diagnostic, not an active path.

### Story 3.3: Correlate cross-detector signals, reachability, and confidence

Priority: P1
Recommendation coverage: 10, 20, 29
Strategic direction: introduce normalized intermediate signals so dependency, source, MCP, secret, CI, workflow, and framework evidence join into coherent action paths.
Expected benefit: BOM items can answer which tools, servers, endpoints, and targets an agent can reach and how strong the evidence is.

Tasks:
- Define intermediate signals for `framework_candidate`, `mcp_server_candidate`, `package_script_invocation`, `credential_ref`, `workflow_invocation`, `tool_binding`, `reachable_tool`, `reachable_server`, `reachable_endpoint`, and `reachable_target`.
- Emit normalized tool binding and reachability signals from LangChain, LangGraph, FastMCP, MCP client, framework source, and package/script detectors.
- Correlate signals by repo, location, package/workspace, command, credential ref, path ID, and graph ref.
- Add confidence and evidence-strength language for dependency-only, source-level import, constructor, tool binding, auth header, credential ref, workflow invocation, and deployment evidence.
- Surface reachable tools/servers/endpoints/targets in BOM items and control graph nodes.
- Add tests proving cross-file correlation works without inventing joins from unrelated repositories or path contexts.

Repo paths:
- `core/aggregate/agentresolver/resolver.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `core/detect/agentframework/source.go`
- `core/detect/agentlangchain/detector.go`
- `core/detect/mcp/detector.go`
- `core/aggregate/attackpath/graph.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/control-path-graph.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/aggregate/agentresolver -run 'Test.*Signal|Test.*Correlation|Test.*Reachability' -count=1`
- `go test ./core/risk -run 'Test.*Reachable|Test.*ActionPath|Test.*Confidence' -count=1`
- `go test ./core/report -run 'Test.*Reachable|Test.*AgentActionBOM' -count=1`
- `make test-contracts`
- `make test-fast`
- `make test-scenarios`

Test requirements:
- TDD fixture where package dependency, source import, tool binding, credential ref, and workflow invocation join into one action path.
- Negative fixture where same package names in different repos do not join.
- Golden BOM/control graph output for reachable tool/server/endpoint/target fields.

Matrix wiring:
- Fast lane: focused resolver, risk, report tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario proving coherent action path from distributed detector signals.
- Cross-platform lane: joins use canonical repo-relative keys.
- Risk lane: `make test-risk-lane` and `make test-hardening`.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Cross-detector signals join into one coherent path when evidence supports it.
- BOM items show reachable tools, servers, endpoints, and targets with confidence.
- Unrelated repos/locations/packages do not over-correlate.
- Confidence language distinguishes dependency-only from source-level active evidence.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added cross-detector agent and MCP correlation signals so reports can show tool bindings, reachable servers, endpoints, targets, and evidence strength for each action path.
Semver marker override: [semver:minor]
Contract/API impact: Adds normalized signal, reachability, and confidence fields to action path, graph, and BOM artifacts.
Versioning/migration impact: Additive output only.
Architecture constraints: Detection emits normalized signals; aggregation joins them; risk/report consume joined paths.
ADR required: yes
TDD first failing test(s): `TestAgentResolverCorrelatesFrameworkMCPCredentialAndWorkflowSignals` and `TestAgentResolverDoesNotCrossJoinUnrelatedRepos`.
Cost/perf impact: medium
Chaos/failure hypothesis: incomplete join evidence yields separate candidates with explicit confidence instead of overconfident merged paths.

## Epic 4: Customer Artifact Readiness

Objective: make the first buyer view clear, shareable, privacy-safe, and actionable without hiding appendix-level evidence.

### Story 4.1: Harden the buyer-facing BOM summary, markdown, scan scope, and source privacy

Priority: P1
Recommendation coverage: 1, 28
Strategic direction: make Agent Action BOM the concise first view while preserving detailed graph/evidence as appendix data.
Expected benefit: customers immediately understand what was scanned, which agent/automation paths matter, what they can do, and what is missing.

Tasks:
- Add a compact BOM summary layer for scanned scope, scan mode, repo/org/source boundaries, governable paths, write/deploy paths, standing credential paths, MCP/tool reachability, framework usage, policy/proof gaps, source privacy, and coverage confidence.
- Render the summary in markdown for `agent-action-bom` with positive empty states when no high-risk paths are found.
- Keep detailed graph refs, evidence refs, proof refs, diagnostics, and candidate details in appendix sections or JSON fields.
- Add scan-scope accuracy fields for local path, repo group, local org mirror, remote repo, and remote org scans.
- Ensure source privacy text explains zero data exfiltration by default and any explicitly configured source acquisition behavior.
- Update docs and examples for buyer-facing BOM interpretation.

Repo paths:
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/build.go`
- `core/report/artifacts.go`
- `core/cli/report.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/report.md`
- `docs/examples/security-team.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/report -run 'Test.*AgentActionBOM|Test.*Markdown|Test.*ScanScope|Test.*EmptyState' -count=1`
- `go test ./core/cli -run 'TestReport.*AgentActionBOM|TestReport.*Markdown' -count=1`
- `make test-contracts`
- `make test-docs-consistency`
- `make test-fast`

Test requirements:
- TDD markdown golden for high-risk BOM summary.
- Positive empty-state golden for no high-risk paths with complete coverage.
- Scan-scope fixtures for local path, repo group, local mirror, remote repo, and remote org metadata.

Matrix wiring:
- Fast lane: focused report and CLI tests plus `make lint-fast`.
- Core CI lane: `make test-fast`, `make test-contracts`, and docs consistency.
- Acceptance lane: buyer-facing scenario output golden.
- Cross-platform lane: scope paths are repo-relative or redacted as configured.
- Risk lane: `make test-hardening` for privacy/source-scope claims.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- BOM markdown starts with scanned scope and top governable paths, not appendix detail.
- Positive empty states are clear and tied to coverage status.
- Scan mode and scope are accurate for local and remote acquisition modes.
- Source privacy language matches actual behavior.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a buyer-facing Agent Action BOM summary and markdown rendering with scan scope, source privacy, governable paths, reachability, proof/policy gaps, and positive empty states.
Semver marker override: [semver:minor]
Contract/API impact: Adds BOM summary and scan-scope fields; markdown output changes for the agent-action-bom template.
Versioning/migration impact: Additive JSON fields; markdown consumers should expect a new summary-first layout.
Architecture constraints: Report layer renders summaries from saved state and scan metadata; source layer owns scan scope facts.
ADR required: no
TDD first failing test(s): `TestAgentActionBOMMarkdownLeadsWithBuyerSummary` and `TestAgentActionBOMPositiveEmptyStateIncludesCoverage`.
Cost/perf impact: low
Chaos/failure hypothesis: missing scope metadata renders `unknown` with explanation rather than inventing org/repo scope.

### Story 4.2: Add deterministic customer-redacted share profiles

Priority: P1
Recommendation coverage: 16
Strategic direction: provide first-class share-safe report/BOM/evidence artifacts with stable pseudonyms and configurable redaction.
Expected benefit: design partners can share artifacts without manual redaction while preserving risk meaning.

Tasks:
- Add `--share-profile customer-redacted` to report artifact generation where supported.
- Implement stable pseudonyms for authors, owners, repo names, credential subjects, commit SHAs, local paths, proof refs, graph refs, and debug parse details.
- Add configurable redaction policies with safe defaults and deterministic salt/namespace handling.
- Ensure redaction preserves joinability within one artifact set without leaking raw identifiers.
- Add leakage tests for common sensitive fields and docs explaining what is redacted versus preserved.
- Add schema fields describing applied share profile, redaction version, and redaction policy summary.

Repo paths:
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `core/report/build.go`
- `core/report/artifacts.go`
- `core/report/render_markdown.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`
- `docs/examples/security-team.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/cli -run 'TestReport.*ShareProfile|TestReport.*Redacted' -count=1`
- `go test ./core/report -run 'Test.*Redact|Test.*ShareProfile|Test.*Pseudonym' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-docs-consistency`

Test requirements:
- TDD leakage tests for owner handles, repo names, local paths, credential subjects, commit SHAs, proof refs, and graph refs.
- Determinism tests proving repeated runs with same input and profile produce stable pseudonyms.
- Joinability tests proving redacted refs still connect BOM, graph, proof, and evidence inside the same artifact set.

Matrix wiring:
- Fast lane: focused redaction tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario producing customer-redacted report/BOM/evidence artifacts.
- Cross-platform lane: local path redaction handles Windows and POSIX paths.
- Risk lane: `make test-hardening` and `make test-chaos` for redaction leakage and malformed inputs.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- `--share-profile customer-redacted` produces deterministic redacted artifacts.
- Sensitive identifiers are absent from redacted outputs while risk meaning and intra-artifact joins remain intact.
- The applied share profile and redaction policy summary are visible in output.
- Docs explain safe sharing behavior and limits.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a `customer-redacted` share profile for report, BOM, and evidence artifacts with deterministic pseudonyms for sensitive customer identifiers.
Semver marker override: [semver:minor]
Contract/API impact: Adds a public CLI option and redaction metadata fields.
Versioning/migration impact: Additive feature; default unredacted behavior remains unchanged.
Architecture constraints: Report/evidence output owns redaction; scan state and proof records remain canonical and unmodified.
ADR required: yes
TDD first failing test(s): `TestReportCustomerRedactedRemovesSensitiveIdentifiers` and `TestCustomerRedactedPseudonymsAreStableAndJoinable`.
Cost/perf impact: low
Chaos/failure hypothesis: unknown sensitive fields default to redacted or omitted in customer profile rather than leaking raw values.

### Story 4.3: Split operational exposure from governance readiness and improve confidence/remediation language

Priority: P1
Recommendation coverage: 26, 29, 30
Strategic direction: separate what a path can operationally do from how ready governance evidence is, then express confidence and remediation in buyer language.
Expected benefit: a repo with zero write/credential/prod paths but missing governance proof does not read like the same risk as a credential-bearing MCP path.

Tasks:
- Add `operational_exposure` and `governance_readiness` summaries alongside the compatibility posture score.
- Derive operational exposure from write/deploy capability, credential access, production backing, reachable targets, runtime path context, and deployment evidence.
- Derive governance readiness from owner, approval, lifecycle, policy, proof, scan coverage, and accepted inventory state.
- Add confidence/evidence-strength labels to customer-facing findings and BOM summaries.
- Generate remediation copy from the split grade and confidence context.
- Update docs, schemas, markdown, and changelog.

Repo paths:
- `core/score/score.go`
- `core/score/model/model.go`
- `core/risk/action_paths.go`
- `core/report/build.go`
- `core/report/render_markdown.go`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/report.md`
- `docs/examples/security-team.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/score -run 'Test.*OperationalExposure|Test.*GovernanceReadiness|Test.*Posture' -count=1`
- `go test ./core/report -run 'Test.*Exposure|Test.*Readiness|Test.*Confidence|Test.*Remediation' -count=1`
- `go test ./core/risk -run 'Test.*ActionPath.*Exposure|Test.*Confidence' -count=1`
- `make test-contracts`
- `make test-fast`

Test requirements:
- TDD fixtures differentiating zero operational exposure with poor governance readiness from credential-bearing operational exposure.
- Golden markdown/JSON for confidence and remediation language.
- Regression tests preserving compatibility posture score fields.

Matrix wiring:
- Fast lane: focused score, risk, and report tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario comparing low-operational/high-governance-gap and high-operational paths.
- Cross-platform lane: no platform-specific assumptions.
- Risk lane: `make test-risk-lane` and `make test-hardening`.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Reports show separate operational exposure and governance readiness summaries.
- Confidence language differentiates dependency-only, source-level, credential-bearing, and runtime/deployment-backed evidence.
- Remediation text is concrete and consistent with the strongest issue.
- Existing posture score remains available for compatibility.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added separate operational exposure and governance readiness summaries with confidence-aware remediation language in report and Agent Action BOM outputs.
Semver marker override: [semver:minor]
Contract/API impact: Adds summary fields and customer-facing text; preserves existing posture score fields.
Versioning/migration impact: Additive output only.
Architecture constraints: Score owns grades; report owns buyer language; risk owns path-level evidence dimensions.
ADR required: no
TDD first failing test(s): `TestOperationalExposureDiffersFromGovernanceReadiness` and `TestReportRemediationUsesConfidenceAndEvidenceStrength`.
Cost/perf impact: low
Chaos/failure hypothesis: missing evidence yields `unknown` or governance gap labels rather than inflating operational exposure.

## Epic 5: Governance Model Cleanup

Objective: make credentials, capabilities, path context, lifecycle, identity instances, deployment evidence, and proof references internally consistent.

### Story 5.1: Implement multi-credential provenance and action capability semantics

Priority: P1
Recommendation coverage: 11, 12
Strategic direction: represent all credentials on a path and align action capability counters with BOM/action-class language.
Expected benefit: customer reports no longer collapse multiple credentials into `unknown_durable` or contradict write-capable counters with write action classes.

Tasks:
- Add `credentials[]` with kind, scope, standing/JIT classification, confidence, evidence location, and risk multiplier.
- Preserve a compatibility rollup field for existing consumers.
- Split action capabilities into `direct_write_capable`, `workflow_write_permission`, `pr_write`, `repo_write`, `deploy_write`, `credential_access`, and `production_write`.
- Align `write_capable`, `action_classes`, `write_path_classes`, production write, and privilege-budget counters from the same capability model.
- Add schema and report/BOM updates for multi-credential and capability fields.
- Add fixtures for workflows with GitHub token, signing key, passphrase, GitHub App refs, OIDC/JIT, static secrets, and inherited human credentials.

Repo paths:
- `core/detect/secrets/detector.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/inventory/inventory.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/secrets -run 'Test.*Credential|Test.*SecretRef' -count=1`
- `go test ./core/aggregate/privilegebudget ./core/aggregate/inventory -run 'Test.*Credential|Test.*Capability|Test.*Write' -count=1`
- `go test ./core/risk -run 'Test.*Credential|Test.*Capability|Test.*ActionClass' -count=1`
- `go test ./core/report -run 'Test.*Credential|Test.*Capability|Test.*AgentActionBOM' -count=1`
- `make test-contracts`
- `make test-fast`

Test requirements:
- TDD fixture proving multiple credentials remain distinct on one path.
- Counter consistency tests proving write-capable summaries and action classes agree.
- Secret non-extraction tests for credential refs and redaction compatibility.

Matrix wiring:
- Fast lane: focused secrets, inventory, privilege budget, risk, and report tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: workflow scenario with multiple credential refs and mixed write/deploy capability.
- Cross-platform lane: evidence locations are repo-relative.
- Risk lane: `make test-risk-lane` and `make test-hardening`.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Multiple credentials on one path are represented without collapsing provenance.
- Capability counters and action classes are consistent across inventory, budget, action paths, BOM, and report summaries.
- Raw secret values are never serialized.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added multi-credential provenance and normalized action capability fields so write, deploy, credential, and production access semantics stay consistent across inventory, risk, and BOM outputs.
Semver marker override: [semver:minor]
Contract/API impact: Adds credential array and capability fields; compatibility rollups remain.
Versioning/migration impact: Additive output with compatibility fields for existing consumers.
Architecture constraints: Detection identifies references; aggregation models provenance/capabilities; risk/report consume normalized fields.
ADR required: no
TDD first failing test(s): `TestActionPathPreservesMultipleCredentialRefs` and `TestWriteCapabilityCountersMatchActionClasses`.
Cost/perf impact: low
Chaos/failure hypothesis: unknown credential kind remains explicit with confidence and evidence location rather than collapsed or overclassified.

### Story 5.2: Reconcile path context, lifecycle gaps, and tool family/instance identity

Priority: P2
Recommendation coverage: 21, 23, 24
Strategic direction: distinguish runtime/test/docs/generated/cache paths and separate global tool families from repo/location-specific governance instances.
Expected benefit: test-only MCP clients, stale lifecycle gaps, and shared dependency identities are framed accurately instead of distorting governance priority.

Tasks:
- Add `path_context` with values for runtime source, deployable source, functional test, unit test, example, docs, generated code, package cache, and unknown, plus confidence and reasons.
- Adjust scoring/report language so test-only MCP clients are review/proof candidates while credential-bearing tests remain visible.
- Split lifecycle gaps into `missing_approval`, `owner_inferred`, `owner_unresolved`, `stale_identity`, and true `orphaned_identity`.
- Fix lifecycle messages and evidence basis so `orphaned_identity` is used only when an identity is absent from current inventory.
- Add `tool_family_id` for package/framework rollups and `tool_instance_id` for repo/location/path-specific governance.
- Tie owner, approval, proof, lifecycle, and control priority to instances rather than global package family where appropriate.

Repo paths:
- `core/risk/action_paths.go`
- `core/aggregate/inventory/privileges.go`
- `core/detect/agentframework/source.go`
- `core/aggregate/scanquality/scanquality.go`
- `core/lifecycle/gaps.go`
- `core/lifecycle/lifecycle.go`
- `core/state/state.go`
- `core/cli/identity.go`
- `core/cli/lifecycle.go`
- `core/aggregate/agentresolver/resolver.go`
- `schemas/v1/inventory/inventory.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*PathContext|Test.*Runtime|Test.*TestPath' -count=1`
- `go test ./core/lifecycle -run 'Test.*Gap|Test.*Orphan|Test.*Owner' -count=1`
- `go test ./core/state ./core/cli -run 'Test.*Identity|Test.*Lifecycle' -count=1`
- `go test ./core/aggregate/agentresolver -run 'Test.*ToolFamily|Test.*ToolInstance' -count=1`
- `make test-contracts`
- `make test-fast`

Test requirements:
- TDD fixtures for runtime source, deployable source, functional tests, unit tests, examples, docs, generated code, and package cache.
- Lifecycle fixture proving `present=true` cannot pair with true `orphaned_identity`.
- Identity fixture proving shared dependency family creates distinct tool instances by repo/location/path.

Matrix wiring:
- Fast lane: focused risk, lifecycle, state, CLI, and resolver tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario with same framework dependency across repos and test-only MCP clients.
- Cross-platform lane: path classifiers are separator-neutral and avoid absolute roots.
- Risk lane: `make test-hardening` for lifecycle/state migration and path classification ambiguity.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Path context is visible with confidence and reasons.
- Lifecycle gap reasons are internally consistent and evidence-backed.
- Tool family and tool instance identities are separate and governance attaches to instances.
- Scoring/reporting frame tests, examples, docs, generated code, and caches appropriately.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Refined path context, lifecycle gap reasons, and tool family versus tool instance identity so governance priority attaches to the correct repo/location-specific agent path.
Semver marker override: [semver:minor]
Contract/API impact: Adds identity/path-context fields and refines lifecycle reason values.
Versioning/migration impact: Existing identity consumers may need to adopt instance IDs while family rollups remain available.
Architecture constraints: Identity owns lifecycle and instance semantics; risk owns path context scoring; detection emits raw location evidence.
ADR required: yes
TDD first failing test(s): `TestLifecyclePresentIdentityIsNotOrphaned` and `TestToolFamilyAndInstanceIdsSeparateSharedDependencyFromRepoGovernance`.
Cost/perf impact: low
Chaos/failure hypothesis: ambiguous path context defaults to `unknown` with review impact rather than production/runtime overstatement.

### Story 5.3: Require deployment evidence and path-specific proof refs

Priority: P2
Recommendation coverage: 14, 25
Strategic direction: mark deployed or deploy-pipeline-associated status only when concrete evidence supports it, and attach proof to exact paths.
Expected benefit: reports do not overstate operational exposure and audit trust improves because proof refs match the path under discussion.

Tasks:
- Derive deployment status from CI workflows, Dockerfiles, Helm/Kubernetes manifests, package scripts, service entrypoints, deployment configs, runtime manifests, or production target configs.
- Emit `deployment_status` as `deployed`, `deploy_pipeline_associated`, `candidate`, `unknown`, or equivalent schema-documented values.
- Require evidence refs for deployed/deploy-pipeline-associated states; otherwise use `candidate` or `unknown`.
- Link proof records by canonical finding key, `path_id`, repo/location, or graph ref.
- Keep global proof-chain integrity separate from per-path proof sufficiency in BOM/report/evidence.
- Add tests for deployment overstatement, path-specific proof references, and compatibility with production target packs.

Repo paths:
- `core/detect/workflowcap/analyze.go`
- `core/detect/ciagent/detector.go`
- `core/policy/productiontargets/targets.go`
- `core/risk/action_paths.go`
- `core/report/agent_action_bom.go`
- `core/report/control_proof.go`
- `core/proofmap/proofmap.go`
- `core/evidence/evidence.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/workflowcap ./core/detect/ciagent -run 'Test.*Deploy|Test.*Workflow|Test.*Credential' -count=1`
- `go test ./core/policy/productiontargets -run 'Test.*Target|Test.*Deploy' -count=1`
- `go test ./core/risk -run 'Test.*Deployment|Test.*ActionPath' -count=1`
- `go test ./core/report ./core/proofmap ./core/evidence -run 'Test.*Proof|Test.*Deployment|Test.*Path' -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- TDD fixtures proving source/test paths without deployment evidence are `candidate` or `unknown`, not deployed.
- Fixtures proving CI/deploy manifests elevate deployment status with evidence refs.
- Proof tests proving path refs do not leak across unrelated findings.

Matrix wiring:
- Fast lane: focused workflowcap, ciagent, productiontargets, risk, report, proofmap, and evidence tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario with runtime source, test source, deploy pipeline, and proof records.
- Cross-platform lane: manifest and path matching are normalized.
- Risk lane: `make test-risk-lane` and `make test-hardening`.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- Deployment status is evidence-backed and not inferred from framework/source presence alone.
- Operational exposure does not inflate without deployment/write/credential/production evidence.
- Proof refs and proof coverage are path-specific.
- Global chain integrity remains separately visible.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Fixed deployment and proof semantics so agent paths require concrete deployment evidence before being marked deployed and proof refs attach to the exact path they support.
Semver marker override: [semver:patch]
Contract/API impact: Adds deployment status/evidence fields and tightens proof linkage semantics.
Versioning/migration impact: Some paths previously marked deployed may become candidate or unknown until evidence is present.
Architecture constraints: Detection/policy provide deployment evidence; risk derives exposure; report/evidence display path-specific proof sufficiency.
ADR required: no
TDD first failing test(s): `TestActionPathDeploymentStatusRequiresConcreteEvidence` and `TestProofRefsAttachOnlyToMatchingPath`.
Cost/perf impact: low
Chaos/failure hypothesis: missing or conflicting deployment evidence degrades to `candidate`/`unknown` with explanation instead of overstating production exposure.

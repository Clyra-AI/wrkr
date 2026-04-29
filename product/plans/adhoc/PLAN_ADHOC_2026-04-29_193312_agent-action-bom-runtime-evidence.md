# Adhoc Plan: Agent Action BOM Runtime Evidence

Date: 2026-04-29
Profile: `wrkr`
Slug: `agent-action-bom-runtime-evidence`
Recommendation source: user-provided recommendations for a first-class Agent Action BOM artifact, report/control graph parity, credential provenance, PAT/cloud credential classification, introduction attribution, production target packs, Gait policy coverage, runtime evidence correlation, demo fixtures, a BOM report template, normalized action classes, MCP/A2A reachability, standing privilege hardening, and end-to-end demo acceptance coverage.

All local checkout paths from the recommendation source are normalized to repo-relative paths. Story repo paths below resolve from the active checkout root.

## Global Decisions (Locked)

- Wrkr remains the See product in the See -> Prove -> Control sequence. This plan only discovers, correlates, reports, and emits proof-ready artifacts; it does not add Gait enforcement or Axym product behavior.
- `agent_action_bom` is a named, versioned, derived artifact. It must be built from existing scan state, risk/action-path state, inventory privilege maps, control-path graph state, proof references, and runtime evidence sidecars instead of becoming a second source of truth.
- Agent Action BOM v1 is canonical in `wrkr report --template agent-action-bom --json` and report evidence JSON. Scan JSON remains a raw discovery surface; any scan additions are additive parity fields only.
- All new JSON fields are additive under existing v1 contracts unless a story explicitly introduces a new versioned schema. Existing `--json`, `--explain`, `--quiet`, and exit-code contracts remain stable.
- Stable identifiers use deterministic, opaque IDs. `bom_id`, item IDs, graph refs, evidence refs, and attribution refs must be stable for the same input aside from explicit timestamp/version fields.
- No LLM calls, live code execution, or network enrichment are allowed in scan, risk, report, evidence, or proof paths. Hosted GitHub attribution remains optional and explicit; local git attribution must be deterministic from the checked-out repository history.
- Secret detection and credential classification must never extract or serialize raw secret values. Reference names, evidence keys, locations, and typed provenance are allowed.
- Gait policy coverage is discovery/correlation only. Wrkr may report coverage status and missing coverage reasons, but enforcement decisions stay in Gait/runtime evidence.
- Runtime evidence remains file-based and portable. Ingested evidence enriches report/evidence output through correlation and does not mutate static scan findings.
- Built-in production-target packs must be deterministic local classifiers with clear evidence basis and no default source upload.
- Public docs, schemas, scenarios, and changelog entries are part of the feature contract and ship in the same implementation waves as behavior changes.

## Current Baseline (Observed)

- `core/risk/action_paths.go` builds `action_paths` and `action_path_to_control_first` from `inventory.AgentPrivilegeMap`, attack-path scores, credential provenance, ownership, approval, delivery-chain, and production target signals.
- `core/aggregate/attackpath/graph.go` defines a versioned `control_path_graph` with control path, agent, execution identity, credential, tool, workflow, repo, governance control, target, and action-capability nodes.
- `core/report/types.go` exposes `action_paths`, `action_path_to_control_first`, `control_path_graph`, `runtime_evidence`, `control_backlog`, and `exposure_groups` in report summaries, but it does not expose a named `agent_action_bom` artifact.
- `core/report/artifacts.go` evidence JSON includes `control_backlog`, `control_path_graph`, `runtime_evidence`, compliance summary, proof, and next actions, but not a BOM object.
- `core/cli/scan.go` emits `action_paths` and `action_path_to_control_first` in scan JSON and builds `riskReport.ControlPathGraph`, but raw scan JSON does not currently expose top-level `control_path_graph`.
- `core/aggregate/inventory/privileges.go` has coarse `CredentialProvenance` types: `static_secret`, `workload_identity`, `inherited_human`, `oauth_delegation`, `jit`, and `unknown`. It does not yet expose buyer-facing `credential_kind`, standing/JIT access type, or PAT/cloud-admin/deploy-key classification.
- `core/aggregate/privilegebudget/budget.go` aggregates finding signals by agent, instance, repo, and location. CI secret references can still be under-correlated when the secret finding and CI action path share workflow location but not all identity keys.
- `core/ingest/ingest.go` supports runtime evidence sidecars with `path_id`, `agent_id`, `policy_ref`, `proof_ref`, `evidence_class`, and correlation status. Evidence classes are not yet normalized into the requested control-loop vocabulary.
- `docs/commands/report.md` documents existing report templates and graph/action path fields. There is no `agent-action-bom` report template or demo-ready BOM command path.
- `docs/examples/production-targets.v1.yaml` and `core/policy/productiontargets` support configured production targets, but first-time scans can still show `not_configured` when no config is supplied.
- Scenario fixtures exist under `scenarios/wrkr`, including action path and policy/correlation scenarios, but there is no single before/after fixture pack proving the full Agent Action BOM demo narrative from risky CI agent introduction through runtime remediation evidence.
- Existing changelog entries already acknowledge additive `control_path_graph` and typed credential provenance work; implementation must reconcile and extend those entries rather than duplicating conflicting release notes.

## Exit Criteria

- `agent_action_bom` is present in report JSON, report evidence JSON, and evidence bundles with a versioned schema, stable `bom_id`, deterministic summary counts, `items[]`, graph refs, evidence refs, and proof refs.
- `wrkr report --template agent-action-bom --json --evidence-json` is documented as the canonical BOM command path and returns the highest-value action-path inventory without requiring operators to join multiple fields manually.
- Scan/report graph parity is no longer confusing: raw scan JSON either exposes additive `control_path_graph` or docs explicitly route BOM generation through report output while scan remains raw discovery.
- CI secret references, broad PATs, GitHub App keys, deploy keys, cloud admin keys, workload identity/OIDC/JIT credentials, inherited human credentials, and unknown durable credentials are classified deterministically from references and evidence context without secret value extraction.
- Action paths and BOM items expose normalized `action_classes[]` and `action_reasons[]` using `read`, `write`, `deploy`, `delete`, `execute`, `egress`, and `credential_access`.
- Standing or suspected-standing privilege is driven directly by credential provenance/access type and explained in action paths, risk scoring, control backlog, review queue output, and BOM items.
- BOM items attach reachable MCP servers, MCP tools, APIs, and A2A capabilities with trust-depth metadata and evidence refs when the evidence can be joined deterministically.
- Gait policy coverage status is reported per action path and BOM item as `none`, `declared`, `matched`, `runtime_proven`, `stale`, or `conflict`, with matched policy refs and missing coverage reasons.
- Runtime evidence types for `policy_decision`, `approval`, `jit_credential`, `freeze_window`, `kill_switch`, `action_outcome`, and `proof_verification` correlate to exact BOM items.
- Optional `introduced_by` metadata is available on risky action paths and BOM items for local git scans, with hosted GitHub PR association available only when explicitly configured and deterministic.
- Built-in production-target packs identify common deploy, IaC, Kubernetes, package publishing, release automation, database migration, and customer-impacting workflows without source upload or runtime execution.
- A deterministic demo scenario fixture pack and outside-in acceptance tests prove the narrative from static discovery to BOM output to runtime evidence correlation and proof/evidence artifact generation.

## Public API and Contract Map

- CLI/report:
  - Add `agent-action-bom` to the report template enum and help text.
  - `wrkr report --template agent-action-bom --json` returns `summary.agent_action_bom` and top-level `agent_action_bom`.
  - `wrkr report --template agent-action-bom --evidence-json` writes evidence JSON led by the BOM, control graph, runtime evidence, proof refs, and handoff guidance.
- CLI/scan:
  - Keep `wrkr scan --json` compatible. Additive `control_path_graph` parity is allowed if it is built from the existing saved risk report and does not require report generation.
  - Do not add scan-side `agent_action_bom` in v1 unless the implementation can prove zero duplicate source-of-truth behavior and docs still name report/evidence as canonical.
- CLI/ingest and evidence:
  - Runtime evidence schema remains file-based and local. New evidence classes are normalized and validated without breaking existing records.
  - `wrkr evidence --json` includes BOM artifacts when a saved state has action paths and report summary generation succeeds.
- JSON/schema:
  - Add `schemas/v1/agent-action-bom.schema.json`.
  - Extend `schemas/v1/report/report-summary.schema.json`, `schemas/v1/risk/risk-report.schema.json`, and evidence bundle schemas additively.
  - Extend credential provenance schema with `credential_kind`, `access_type`, standing/JIT fields, and evidence location refs while preserving existing `type`, `scope`, `confidence`, and `risk_multiplier`.
- State/proof:
  - Saved state may carry derived BOM fields only if they are persisted as deterministic report/risk artifacts. Proof chain record types stay `scan_finding`, `risk_assessment`, `approval`, and lifecycle/decision events unless a separate proof contract story versions new record types.
  - BOM proof refs point to existing proof records and runtime evidence refs; they do not duplicate signed proof content.
- Architecture boundaries:
  - Detection classifies raw findings and reference names.
  - Aggregation builds inventory, privilege maps, reachability joins, production targets, and credential provenance.
  - Risk derives action paths, action classes, standing privilege, policy coverage, and control priority.
  - Report/evidence builds the BOM artifact and templates from saved state.
  - Ingest correlates runtime evidence to paths without mutating scan state.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/commands/ingest.md`
  - `docs/examples/security-team.md`
  - `docs/examples/operator-playbooks.md`
  - `docs/examples/production-targets.v1.yaml`
  - `docs/examples/quickstart.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Docs must answer directly:
  - What is an Agent Action BOM and which command produces it?
  - Why is `wrkr report --template agent-action-bom` canonical for BOM output?
  - How do scan `action_paths`, report `agent_action_bom`, evidence JSON, and `control_path_graph` join?
  - Which credential kinds are classified, and what secret data is never serialized?
  - How does Wrkr classify production targets when no custom target file is supplied?
  - What does each Gait policy coverage status mean?
  - Which runtime evidence classes correlate to BOM items?
  - How can a demo operator reproduce the before/after scenario and verify proof/evidence output?
- Docs parity gates:
  - `scripts/check_docs_cli_parity.sh`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/run_docs_smoke.sh`
  - `make test-docs-consistency`
  - Scenario validation through `scripts/validate_scenarios.sh`

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage |
|---|---:|---|
| 1. First-class `agent_action_bom` artifact | P0 | Stories 1.1, 1.2, 4.2 |
| 2. Scan/report control path graph parity or canonical report path | P0 | Stories 1.2, 4.2 |
| 3. CI secret-reference provenance correlation | P0 | Story 2.1 |
| 4. PAT and cloud admin credential classification | P0 | Story 2.2 |
| 5. PR/commit introduction attribution | P1 | Story 3.3 |
| 6. Production target classification pack | P1 | Story 2.4 |
| 7. Gait policy coverage mapping | P0 | Story 3.1 |
| 8. Runtime control evidence correlation | P0 | Story 3.2 |
| 9. Demo scenario fixture pack | P0 | Story 4.1 |
| 10. Agent Action BOM report template | P0 | Story 1.2 |
| 11. Action class normalization | P0 | Story 2.3 |
| 12. MCP/A2A reachability in the BOM | P1 | Story 2.5 |
| 13. Standing privilege and review queue hardening | P0 | Story 2.3 |
| 14. End-to-end demo acceptance tests | P0 | Story 4.2 |

## Test Matrix Wiring

- Fast lane: targeted Go unit tests for BOM builders, report template parsing, credential classifiers, action-class derivation, policy coverage, ingest normalization, and production target packs, plus `make lint-fast`.
- Core CI lane: `make test-fast`, `make test-contracts`, schema validation tests, report/evidence JSON contract tests, CLI help/template tests, and deterministic golden fixtures.
- Acceptance lane: `make test-scenarios`, `scripts/validate_scenarios.sh`, scenario-tagged tests for the demo fixture pack, and `scripts/run_v1_acceptance.sh --mode=local` after P0 stories land.
- Cross-platform lane: `windows-smoke` and local git attribution tests with deterministic skip behavior for unavailable git metadata or file-mode differences.
- Risk lane: `make test-risk-lane`, `make test-hardening`, `make test-chaos`, and `make test-perf` for report/evidence bundle, source-boundary, output-safety, and risk-scoring changes.
- Release/UAT lane: `make prepush-full`, `make test-release-smoke`, docs-site gates, CodeQL, and `bash scripts/test_uat_local.sh` before release candidate promotion.
- Gating rule: no story is complete until declared lanes are green, first failing tests are committed, golden outputs are byte-stable except explicit timestamp/version fields, docs/changelog/schema changes are synchronized, and no generated artifact contains developer-specific absolute checkout paths.

## Minimum-Now Sequence

- Wave 1 - Artifact contract and canonical UX:
  - Story 1.1: define and build the versioned Agent Action BOM model.
  - Story 1.2: add the Agent Action BOM report template, evidence JSON export, and graph parity docs.
- Wave 2 - Static evidence fidelity:
  - Story 2.1: correlate CI secret references into credential provenance.
  - Story 2.2: classify PAT, GitHub App, deploy key, cloud, OIDC/JIT, inherited human, and unknown durable credentials.
  - Story 2.3: normalize action classes and harden standing-privilege priority.
  - Story 2.4: add built-in production-target packs.
  - Story 2.5: attach MCP/A2A reachability to BOM items.
- Wave 3 - Control-loop correlation:
  - Story 3.1: map Gait policy coverage per action path.
  - Story 3.2: normalize and correlate runtime control evidence classes.
  - Story 3.3: add optional PR/commit introduction attribution.
- Wave 4 - Demo proof and regression lock:
  - Story 4.1: add the deterministic demo scenario fixture pack.
  - Story 4.2: add end-to-end acceptance tests and golden outputs.

## Explicit Non-Goals

- No Gait runtime enforcement, policy decision execution, or kill-switch implementation in Wrkr.
- No Axym compliance engine behavior beyond shared `Clyra-AI/proof` and evidence portability contracts.
- No LLM-generated summaries, remediation, policy matching, or risk scoring.
- No raw secret extraction, secret value hashing, or secret value serialization.
- No default network calls, hosted PR lookups, source upload, or SaaS enrichment.
- No breaking removal or renaming of existing `action_paths`, `agent_privilege_map`, `control_backlog`, `control_path_graph`, or evidence bundle fields.
- No implementation of a separate BOM database, daemon, or persistent background index.
- No broad rewrite of detector boundaries when an additive classifier or correlation pass can preserve existing contracts.

## Definition of Done

- `agent_action_bom` is generated deterministically from existing saved scan/report state and is schema-validated in report/evidence artifacts.
- `wrkr report --template agent-action-bom --json --evidence-json` is the documented demo and operator path, with actionable output for agent, repo/workflow, credential, owner, target, action class, approval status, policy coverage, proof coverage, graph refs, and control priority.
- Credential provenance and standing privilege produce clear evidence-basis fields without leaking secrets.
- Gait coverage and runtime evidence correlation attach to the exact BOM items and preserve static scan determinism.
- Production target packs improve first-run decisiveness without source upload or runtime execution.
- Demo scenarios and acceptance tests prove before/after static risk, BOM output, runtime remediation evidence, and proof/evidence artifact generation.
- Docs, schemas, command help, examples, changelog, and scenario goldens agree with executable behavior.
- Final implementation PRs include exact command output summaries, risk-lane results, and a repo-wide check showing no committed plan, fixture, doc, or schema contains developer-specific absolute checkout paths.

## Epic 1: Agent Action BOM Contract and Report UX

Objective: give buyers and operators one canonical artifact that joins action paths, privilege provenance, graph context, proof coverage, and control priority without duplicating scanner state.

### Story 1.1: Define the versioned Agent Action BOM model and builder

Priority: P0
Recommendation coverage: 1
Strategic direction: Build `agent_action_bom` as a deterministic projection over current action paths, action-path-to-control-first, inventory privilege map, control path graph, proof refs, control backlog, and runtime evidence correlation.
Expected benefit: Operators get one stable artifact that answers the demo/buyer questions without manually joining report fields.

Tasks:
- Add a `report.AgentActionBOM` model with `bom_id`, `schema_version`, `generated_at`, `summary`, `items`, `graph_refs`, `evidence_refs`, and proof/control coverage rollups.
- Add `report.BuildAgentActionBOM(summary Summary)` or an internal builder that consumes `Summary`/saved state fields and never reads raw source directly.
- Define `AgentActionBOMItem` fields for `path_id`, `agent_id`, tool, org, repo, workflow/location, owner, credential provenance, target, approval status, proof coverage, control priority, graph refs, evidence refs, and recommended next action.
- Derive `bom_id` from sorted path IDs, report schema version, target identity, and proof head hash; avoid timestamp in the ID.
- Keep item ordering identical to govern-first action-path ordering, with stable tie-breakers by repo, location, agent ID, and path ID.
- Include stable summary counts for total items, control-first items, standing privilege items, static credential items, production target items, missing approval, missing policy, missing proof, runtime-proven items, and unresolved owner items.
- Add an additive `agent_action_bom` field to `report.Summary` and `report.EvidenceBundle`.
- Add `schemas/v1/agent-action-bom.schema.json` and wire references from report summary and report evidence schemas.
- Add changelog entry under `Added`.

Repo paths:
- `core/report/types.go`
- `core/report/build.go`
- `core/report/artifacts.go`
- `core/report/report_test.go`
- `core/cli/report_contract_test.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/evidence/evidence-bundle.schema.json`
- `schemas/v1/README.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/report -run 'Test.*AgentActionBOM|Test.*Report' -count=1`
- `go test ./core/cli -run 'TestReport.*AgentActionBOM|TestReport.*Evidence' -count=1`
- `make test-contracts`
- `make lint-fast`
- `make test-fast`

Test requirements:
- TDD unit test proving a summary with two action paths emits a stable BOM ID, sorted items, summary counts, graph refs, and proof refs.
- Contract test proving `agent_action_bom` is present in report JSON and evidence JSON when action paths exist.
- Negative test proving nil/empty action paths omit or empty the BOM deterministically without runtime failure.
- Repeated-run golden test proving byte-stable JSON except explicit generated timestamps.

Matrix wiring:
- Fast lane: focused `core/report` and `core/cli` tests plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make test-fast`.
- Acceptance lane: scenario wiring begins in Story 4.2.
- Cross-platform lane: no platform-specific behavior expected.
- Risk lane: include in `make test-risk-lane` because report/evidence contracts are public security artifacts.
- Release/UAT lane: include in `make prepush-full` before release.

Acceptance criteria:
- Report summaries and report evidence JSON expose `agent_action_bom` under a schema-validated v1 contract.
- BOM items are fully derived from existing state and can be regenerated from the same saved scan without source access.
- The top BOM item matches `action_path_to_control_first.path.path_id` when a control-first path exists.
- No BOM field serializes raw source contents or secret values.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a versioned Agent Action BOM artifact in report and report evidence JSON so operators can review risky agent actions, credentials, graph refs, proof coverage, and control priority from one deterministic object.
Semver marker override: [semver:minor]
Contract/API impact: Additive report/evidence JSON and schema fields; no exit-code or existing field changes.
Versioning/migration impact: New `schema_version` for BOM v1; no migration required for existing saved scan state.
Architecture constraints: Report/evidence may project saved risk and inventory state; detection and source layers must not import report BOM types.
ADR required: no
TDD first failing test(s): `TestBuildAgentActionBOMDerivesStableItemsFromSummary` and `TestReportJSONIncludesAgentActionBOM`.
Cost/perf impact: low
Chaos/failure hypothesis: A saved state with missing graph/proof/runtime evidence still emits a valid BOM with explicit gap fields instead of failing or fabricating coverage.

### Story 1.2: Add the Agent Action BOM report template and graph parity guidance

Priority: P0
Recommendation coverage: 2, 10
Strategic direction: Make `wrkr report --template agent-action-bom` the operator and demo path for BOM generation, while removing confusion around scan/report graph surfaces.
Expected benefit: The demo has a single command path that surfaces the right artifact first, and operators understand when to use scan versus report.

Tasks:
- Add `TemplateAgentActionBOM` with CLI parsing, help text, docs, and report template resolution.
- Render Markdown/PDF sections focused on BOM summary, top path to control first, BOM items, graph summary, policy/proof gaps, standing privilege, and recommended Gait handoff.
- Emit `agent_action_bom` as top-level report JSON and nested `summary.agent_action_bom`.
- Update report evidence JSON so `--evidence-json` writes the BOM alongside control backlog, control graph, runtime evidence, compliance summary, and proof refs.
- Decide implementation-time scan parity: either add top-level `control_path_graph` to `wrkr scan --json` when already built, or explicitly document report as canonical for graph-shaped BOM output.
- Update command docs and examples to use `wrkr report --template agent-action-bom --json --evidence-json`.
- Update CLI contract tests to reject unknown template names with the existing invalid-input behavior.
- Add changelog entry under `Added`.

Repo paths:
- `core/report/types.go`
- `core/report/build.go`
- `core/report/render_markdown.go`
- `core/report/templates/`
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `core/cli/scan.go`
- `core/cli/report_contract_test.go`
- `core/cli/root_test.go`
- `docs/commands/report.md`
- `docs/commands/scan.md`
- `docs/examples/security-team.md`
- `schemas/v1/report/report-summary.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/report -run 'Test.*AgentActionBOM|Test.*Template' -count=1`
- `go test ./core/cli -run 'TestReport.*Template|TestScan.*ControlPathGraph|TestReport.*AgentActionBOM' -count=1`
- `scripts/check_docs_cli_parity.sh`
- `make test-docs-consistency`
- `make test-contracts`
- `make lint-fast`

Test requirements:
- CLI parsing test proving `agent-action-bom` is accepted for `wrkr report` and rejected elsewhere only where unsupported.
- Markdown rendering test proving BOM-specific sections lead before raw findings.
- JSON contract test proving top-level and nested BOM fields are present with `--json`.
- Docs parity test proving help text and docs include the new template.

Matrix wiring:
- Fast lane: focused CLI/report tests and docs CLI parity.
- Core CI lane: `make test-contracts`, `make test-docs-consistency`, and `make test-fast`.
- Acceptance lane: demo scenario command path in Story 4.2.
- Cross-platform lane: command parsing and JSON output are platform-neutral.
- Risk lane: report/evidence public contract runs through `make test-risk-lane`.
- Release/UAT lane: `make prepush-full` and release smoke.

Acceptance criteria:
- `wrkr report --template agent-action-bom --json` produces the BOM without requiring markdown/PDF output.
- `wrkr report --template agent-action-bom --evidence-json --evidence-json-path <path> --json` writes evidence JSON containing the BOM.
- Docs state clearly whether scan JSON contains top-level `control_path_graph` or why report is canonical for graph-shaped BOM output.
- Existing report templates keep their behavior.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added an `agent-action-bom` report template that leads with top risky agent actions, credential provenance, reachable targets, missing controls, proof status, and Gait handoff guidance.
Semver marker override: [semver:minor]
Contract/API impact: Additive report template enum, help text, docs, and JSON fields.
Versioning/migration impact: No migration; existing templates remain supported.
Architecture constraints: CLI owns template selection; report package owns rendering and derived artifacts.
ADR required: no
TDD first failing test(s): `TestReportAcceptsAgentActionBOMTemplate` and `TestAgentActionBOMTemplateLeadsWithBOMSections`.
Cost/perf impact: low
Chaos/failure hypothesis: Unsupported template input still fails closed as invalid input, while saved states without action paths produce a clear empty BOM rather than a panic.

## Epic 2: Static Evidence Fidelity and Buyer Vocabulary

Objective: make BOM items decisive by improving credential provenance, normalized action classes, standing privilege, production target defaults, and reachable MCP/A2A context.

### Story 2.1: Correlate CI secret references into action-path credential provenance

Priority: P0
Recommendation coverage: 3
Strategic direction: Merge secret-reference findings that share repo/workflow/agent-instance evidence with CI autonomy and workflow capability findings before classifying credential provenance.
Expected benefit: Risky CI agent paths show static or standing credential authority when the evidence exists, strengthening the central "standing/static authority" claim.

Tasks:
- Add failing tests where `ci_autonomy`, workflow capability, compiled action, and `secret_presence` findings share repo and workflow location but the action path currently reports `unknown` credential provenance.
- Extend signal construction in privilege-budget aggregation to merge by repo, normalized workflow file, location range, agent instance, and tool identity.
- Prefer explicit secret-detector provenance/evidence over generic workflow capability when shared location and repo match.
- Preserve deterministic sorting and conflict behavior when multiple secret refs map to one workflow.
- Add evidence-basis entries that explain the correlation without serializing secret values.
- Update action-path tests to prove correlated provenance flows into risk multipliers and BOM fields.
- Add changelog entry under `Fixed` or `Security` depending on implementation classification.

Repo paths:
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/privilegebudget/budget_test.go`
- `core/detect/secrets/detector.go`
- `core/detect/secrets/detector_test.go`
- `core/detect/ciagent/detector.go`
- `core/detect/ciagent/detector_test.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `core/risk/action_paths_test.go`
- `CHANGELOG.md`

Run commands:
- `go test ./core/aggregate/privilegebudget -run 'Test.*Credential|Test.*Secret|Test.*CI' -count=1`
- `go test ./core/detect/secrets ./core/detect/ciagent -count=1`
- `go test ./core/risk -run 'Test.*Credential|Test.*ActionPath' -count=1`
- `make test-risk-lane`
- `make test-fast`

Test requirements:
- TDD fixture with one workflow using a secret ref and headless agent invocation.
- Negative fixture proving secrets in a different repo/workflow do not bleed into the action path.
- Conflict fixture proving multiple secret refs are sorted, deduped, and evidence-based.
- Risk scoring assertion proving stronger provenance changes control priority deterministically.

Matrix wiring:
- Fast lane: focused privilege-budget, detector, and risk tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: scenario covered by Story 4.2.
- Cross-platform lane: pure parser/aggregation logic.
- Risk lane: `make test-risk-lane`, `make test-hardening`, and `make test-chaos`.
- Release/UAT lane: include in `make prepush-full`.

Acceptance criteria:
- Same-workflow CI secret references are reflected in `credential_provenance` on the associated action path and BOM item.
- Unknown provenance is retained only when no deterministic evidence joins.
- Evidence basis explains repo/workflow/agent correlation without secret values.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Correlated CI secret references into action-path credential provenance so risky headless agent workflows show static or standing credential authority when the workflow evidence supports it.
Semver marker override: [semver:patch]
Contract/API impact: Additive and more precise values in existing credential provenance fields.
Versioning/migration impact: No schema version break; existing consumers should tolerate more specific provenance/evidence basis.
Architecture constraints: Detection emits findings; aggregation owns correlation; risk/report consume normalized provenance only.
ADR required: no
TDD first failing test(s): `TestBuildPrivilegeBudgetCorrelatesWorkflowSecretReferencesToCIAgentPath`.
Cost/perf impact: low
Chaos/failure hypothesis: Ambiguous secret references across multiple workflows remain uncorrelated or low confidence instead of over-assigning authority.

### Story 2.2: Classify credential kind, access type, and JIT versus standing authority

Priority: P0
Recommendation coverage: 4
Strategic direction: Extend provenance from coarse source type into buyer-facing credential kind and access model using deterministic reference-name classifiers.
Expected benefit: Security teams can distinguish PATs, GitHub App keys, deploy keys, cloud admin keys, workload identity, delegated OAuth, JIT credentials, inherited human credentials, and unknown durable credentials.

Tasks:
- Add classifier constants for `github_pat`, `github_app_key`, `deploy_key`, `cloud_admin_key`, `cloud_access_key`, `oidc_workload_identity`, `delegated_oauth`, `jit_credential`, `inherited_human`, `static_secret`, and `unknown_durable`.
- Extend `CredentialProvenance` with `credential_kind`, `access_type`, `standing_access`, `likely_jit`, `evidence_location`, and `classification_reasons` while preserving existing fields.
- Classify only from secret reference names, workflow permission context, auth surface labels, non-human identity findings, and metadata evidence; never inspect secret values.
- Add risk multipliers for broad standing credentials and lower/no multipliers for JIT/workload identity where evidence supports it.
- Update schemas and BOM item fields to expose the new values.
- Add tests for GitHub PAT refs, GitHub App private key refs, deploy key refs, AWS/GCP/Azure admin-like refs, OIDC token permissions, manual approval/JIT evidence, and unknown durable fallbacks.
- Add changelog entry under `Added` and `Security`.

Repo paths:
- `core/aggregate/inventory/privileges.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/detect/secrets/detector.go`
- `core/detect/nonhumanidentity/detector.go`
- `core/state/state.go`
- `core/risk/action_paths.go`
- `core/report/types.go`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/inventory/inventory.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/secrets ./core/detect/nonhumanidentity -count=1`
- `go test ./core/aggregate/privilegebudget -run 'Test.*CredentialKind|Test.*PAT|Test.*Cloud|Test.*OIDC' -count=1`
- `go test ./core/risk ./core/report -run 'Test.*Credential|Test.*BOM' -count=1`
- `make test-contracts`
- `make test-risk-lane`
- `make test-fast`

Test requirements:
- Classifier table tests covering common secret reference spellings and false-positive near misses.
- Contract tests proving existing `credential_provenance.type` remains populated.
- Golden report/BOM test proving `credential_kind` and standing/JIT flags are stable.
- Negative test proving raw secret values are not serialized.

Matrix wiring:
- Fast lane: classifier and aggregation tests.
- Core CI lane: schema and contract tests plus `make test-fast`.
- Acceptance lane: demo scenario includes PAT/cloud secret refs in Story 4.2.
- Cross-platform lane: pure deterministic string classification.
- Risk lane: `make test-risk-lane`, `make test-hardening`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- BOM items and action paths distinguish credential kind, provenance type, scope, confidence, and standing/JIT access.
- Risk scoring and control priority treat broad standing credentials as higher urgency.
- Secret values never appear in findings, reports, evidence bundles, logs, or tests.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added deterministic credential-kind classification for PATs, GitHub App keys, deploy keys, cloud keys, workload identity, delegated OAuth, JIT credentials, inherited human credentials, and unknown durable secrets without exposing secret values.
Semver marker override: [semver:minor]
Contract/API impact: Additive JSON/schema fields and risk multiplier semantics.
Versioning/migration impact: Existing saved states load with missing new fields and normalize to `unknown_durable` or existing provenance type.
Architecture constraints: Secret detector marks references; aggregation owns classification; risk/report own priority/exposure presentation.
ADR required: no
TDD first failing test(s): `TestCredentialKindClassifierDoesNotRequireSecretValues`.
Cost/perf impact: low
Chaos/failure hypothesis: Conflicting credential indicators downgrade to explicit conflict/unknown durable status instead of choosing an unsafe high-confidence kind.

### Story 2.3: Normalize action classes and harden standing-privilege priority

Priority: P0
Recommendation coverage: 11, 13
Strategic direction: Preserve detailed internal permissions but derive buyer-facing action classes and direct standing-privilege reasons across risk, backlog, review queues, and BOM items.
Expected benefit: Security teams can compare agent authority consistently across CI, MCP, A2A, skills, and custom agent configurations, and static credentials become an explainable control priority.

Tasks:
- Add normalized `action_classes[]` and `action_reasons[]` to action paths, inventory privilege map entries, control backlog items where relevant, and BOM items.
- Map existing repo/PR/merge/deploy/write permissions to `write`, `deploy`, `execute`, and `credential_access`.
- Add deterministic `delete` and `egress` mapping from destructive workflow commands, package publishing, external API calls, MCP tool annotations, network URLs, and known deploy/delete verbs.
- Derive `standing_privilege` and `standing_privilege_reasons[]` directly from credential kind, access type, provenance, and evidence basis.
- Feed standing privilege into govern-first sorting, risk multipliers, control backlog priority, review queue target selection, and BOM summary counts.
- Preserve detailed `write_path_classes` for backward compatibility.
- Add schema/docs/changelog updates.

Repo paths:
- `core/detect/workflowcap/analyze.go`
- `core/detect/workflowcap/analyze_test.go`
- `core/detect/mcp/detector.go`
- `core/detect/a2a/detector.go`
- `core/aggregate/inventory/privileges.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/risk/action_paths.go`
- `core/risk/govern_first.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/risk/controlbacklog.go`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/workflowcap ./core/detect/mcp ./core/detect/a2a -count=1`
- `go test ./core/aggregate/privilegebudget ./core/risk ./core/aggregate/controlbacklog -run 'Test.*ActionClass|Test.*Standing|Test.*Govern' -count=1`
- `make test-risk-lane`
- `make test-contracts`
- `make test-fast`

Test requirements:
- Table tests for permission-to-action-class mapping, including delete and egress.
- Standing privilege tests for PAT, deploy key, IAM/cloud key, inherited human, JIT, workload identity, and unknown durable cases.
- Sort-order tests proving standing static authority can make a path control-first even when shared identity heuristics are absent.
- Backward compatibility tests proving existing `write_path_classes` remain stable.

Matrix wiring:
- Fast lane: workflowcap, aggregation, and risk tests.
- Core CI lane: contracts and `make test-fast`.
- Acceptance lane: scenario coverage in Story 4.2.
- Cross-platform lane: pure parser/classifier logic.
- Risk lane: `make test-risk-lane`, `make test-hardening`, `make test-chaos`, `make test-perf`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Every BOM item has normalized action classes when any actionable permission exists.
- Standing privilege reason text identifies the exact evidence that caused the classification.
- JIT/workload identity paths are not incorrectly marked standing without durable evidence.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Normalized agent action classes and made standing privilege an explicit control priority when static, durable, or inherited credentials back risky paths.
Semver marker override: [semver:minor]
Contract/API impact: Additive action-class and standing-privilege reason fields; risk ordering may change for better control-first prioritization.
Versioning/migration impact: No migration; old states normalize missing action classes from permissions at report time where possible.
Architecture constraints: Detectors emit capabilities; aggregation/risk derive normalized classes and priorities.
ADR required: no
TDD first failing test(s): `TestActionPathStandingPrivilegePrioritizesSingleBroadStaticCredential`.
Cost/perf impact: medium
Chaos/failure hypothesis: Unknown durable credentials fail toward review/control priority with explicit low-confidence reasons instead of being treated as safe.

### Story 2.4: Add built-in production target classification packs

Priority: P1
Recommendation coverage: 6
Strategic direction: Provide deterministic default target packs so obvious deploy/IaC/package/release/database workflows do not stay `not_configured` on first-run scans.
Expected benefit: Demos and first-time operators see decisive target labels without writing custom production-target config first.

Tasks:
- Add built-in production target packs for deploy workflows, Terraform/IaC, Kubernetes, package publishing, release automation, database migration, and customer-impacting workflows.
- Match workflow commands, protected branch/environment names, registry hosts, Terraform/Kubernetes operations, database migration tools, deploy CLIs, and release automation patterns.
- Add a config option or mode that makes built-ins explicit and demo-ready without weakening custom `--production-targets` behavior.
- Emit evidence basis for each matched target label and preserve existing `configured`, `not_configured`, and `invalid` status semantics.
- Update docs/examples with built-in pack examples and override guidance.
- Add scenario fixtures proving built-ins produce stable target matches without runtime execution.
- Add changelog entry under `Added`.

Repo paths:
- `core/policy/productiontargets/`
- `core/productiontargets/`
- `core/detect/workflowcap/`
- `core/aggregate/privilegebudget/budget.go`
- `docs/examples/production-targets.v1.yaml`
- `docs/commands/scan.md`
- `docs/examples/operator-playbooks.md`
- `schemas/v1/policy/production-targets.schema.json`
- `CHANGELOG.md`

Run commands:
- `go test ./core/policy/productiontargets ./core/detect/workflowcap ./core/aggregate/privilegebudget -run 'Test.*Production|Test.*Target|Test.*BuiltIn' -count=1`
- `scripts/validate_scenarios.sh`
- `make test-scenarios`
- `make test-contracts`
- `make test-fast`

Test requirements:
- Built-in pack table tests for deploy, Terraform, Kubernetes, package publish, release, database migration, and customer-impacting labels.
- Override tests proving custom target files remain authoritative when supplied.
- Determinism test proving matched target order and evidence basis are stable.
- Negative tests for docs/build/test workflows that should not be marked production targets.

Matrix wiring:
- Fast lane: production target and workflowcap tests.
- Core CI lane: contracts and `make test-fast`.
- Acceptance lane: scenarios and `make test-scenarios`.
- Cross-platform lane: pure YAML/string matching.
- Risk lane: `make test-risk-lane`, `make test-perf`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Obvious deploy/IaC/package/release/database workflows produce production target labels in action paths and BOM items without source upload or execution.
- Existing custom production target config behavior remains backward compatible.
- Docs explain built-ins, custom overrides, and evidence basis.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added deterministic built-in production target packs for deploy, IaC, Kubernetes, package publishing, release automation, database migration, and customer-impacting workflows.
Semver marker override: [semver:minor]
Contract/API impact: Additive target labels and evidence fields; possible risk-priority changes when built-ins identify production-backed paths.
Versioning/migration impact: No migration; built-ins can be documented as default or opt-in depending on implementation decision.
Architecture constraints: Production target classification stays in policy/aggregation and never executes workflow code.
ADR required: no
TDD first failing test(s): `TestBuiltInProductionTargetsClassifyTerraformApplyWorkflow`.
Cost/perf impact: medium
Chaos/failure hypothesis: Malformed or ambiguous built-in pack data fails closed to no built-in matches with a policy warning rather than false production claims.

### Story 2.5: Attach reachable MCP/A2A servers, tools, APIs, and trust depth to BOM items

Priority: P1
Recommendation coverage: 12
Strategic direction: Join MCP, A2A, AGNT, and custom agent reachability evidence to the same BOM item that carries workflow, credential, owner, target, and control status.
Expected benefit: Operators can answer which servers, tools, APIs, and agent-to-agent capabilities the risky agent path can reach from one artifact.

Tasks:
- Define BOM item fields `reachable_servers[]`, `reachable_tools[]`, `reachable_apis[]`, `reachable_agents[]`, `trust_depth`, and reachability evidence refs.
- Join MCP/A2A findings by repo, location/config refs, agent identity, declared manifest refs, observed tool names, and action-path tool type.
- Preserve trust-depth metadata from inventory/action paths and avoid duplicating raw MCP config content.
- Add conflict/unknown states when multiple configs could apply to one agent path.
- Add schema and report tests for MCP stdio/SSE/HTTP, WebMCP, A2A agent card, AGNT, and custom agent fixtures.
- Update docs to explain reachability is static declaration reachability, not runtime observation.
- Add changelog entry under `Added`.

Repo paths:
- `core/detect/mcp/`
- `core/detect/a2a/`
- `core/detect/agnt/`
- `core/detect/agentcustom/`
- `core/aggregate/attackpath/graph.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `core/report/build.go`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/mcp ./core/detect/a2a ./core/detect/agnt ./core/detect/agentcustom -count=1`
- `go test ./core/risk ./core/report -run 'Test.*Reachability|Test.*BOM' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-fast`

Test requirements:
- Join tests for same-repo/same-agent reachability.
- Negative tests proving unrelated MCP/A2A declarations do not attach.
- Conflict tests for multiple possible configs with explicit uncertainty.
- Golden BOM fixture showing reachable servers/tools/APIs with trust metadata.

Matrix wiring:
- Fast lane: detector and report join tests.
- Core CI lane: contracts and fast tests.
- Acceptance lane: scenario coverage where BOM item includes reachable MCP/A2A context.
- Cross-platform lane: pure structured parsing and joins.
- Risk lane: `make test-risk-lane`, `make test-hardening`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- BOM items show reachable MCP/A2A context when deterministic joins exist.
- Reachability fields include evidence refs and trust-depth metadata.
- Docs do not imply runtime observation unless runtime evidence exists.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added static MCP/A2A reachability context to Agent Action BOM items, including reachable servers, tools, APIs, trust depth, and evidence references.
Semver marker override: [semver:minor]
Contract/API impact: Additive BOM/report schema fields.
Versioning/migration impact: No migration; absent reachability fields mean no deterministic join.
Architecture constraints: Detection owns parsed declarations; report/BOM builder owns static joins from saved state.
ADR required: no
TDD first failing test(s): `TestAgentActionBOMAttachesReachableMCPServersByAgentAndLocation`.
Cost/perf impact: medium
Chaos/failure hypothesis: Ambiguous reachability is marked unknown/conflict and does not inflate risk without evidence.

## Epic 3: Policy, Runtime Evidence, and Introduction Attribution

Objective: close the loop from discovered risky path to policy coverage, runtime controls, proof evidence, and optional origin attribution.

### Story 3.1: Map Gait policy coverage per action path and BOM item

Priority: P0
Recommendation coverage: 7
Strategic direction: Correlate static Gait policy refs and runtime evidence to action classes, agents, tools, targets, repo/workflow locations, and proof refs without adding enforcement.
Expected benefit: The BOM directly answers whether a risky agent action is uncovered, declared, matched, runtime proven, stale, or conflicting.

Tasks:
- Add `PolicyCoverageStatus` constants: `none`, `declared`, `matched`, `runtime_proven`, `stale`, and `conflict`.
- Add policy coverage fields to action paths, control backlog where relevant, report summary, and BOM items.
- Map Gait policy detector findings to action classes, agent/tool IDs, targets, and repo/workflow locations.
- Merge runtime evidence policy decisions from ingest when they reference the same path, agent, tool, target, policy ref, or proof ref.
- Emit matched policy refs, missing coverage reasons, stale/conflict reasons, confidence, and evidence refs.
- Add docs clarifying Wrkr reports coverage and evidence only; Gait remains enforcement.
- Add changelog entry under `Added`.

Repo paths:
- `core/detect/gaitpolicy/detector.go`
- `core/detect/gaitpolicy/detector_test.go`
- `core/risk/action_paths.go`
- `core/risk/action_paths_test.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/risk/controlbacklog.go`
- `core/ingest/ingest.go`
- `core/report/build.go`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`
- `docs/commands/ingest.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/gaitpolicy ./core/risk ./core/aggregate/controlbacklog -run 'Test.*Policy|Test.*Coverage|Test.*Gait' -count=1`
- `go test ./core/ingest ./core/report -run 'Test.*Policy|Test.*Runtime|Test.*BOM' -count=1`
- `make test-contracts`
- `make test-risk-lane`
- `make test-fast`

Test requirements:
- Static policy coverage tests for no policy, declared-only, matched policy, stale policy, and conflict.
- Runtime evidence test that promotes matched static coverage to `runtime_proven`.
- Missing coverage reason tests for action class, target, tool, and workflow gaps.
- Contract tests proving statuses are schema-enumerated and deterministic.

Matrix wiring:
- Fast lane: gaitpolicy, risk, ingest, and report tests.
- Core CI lane: schema/contract tests and `make test-fast`.
- Acceptance lane: scenario before/after coverage in Story 4.2.
- Cross-platform lane: pure file parsing/correlation.
- Risk lane: `make test-risk-lane`, `make test-hardening`, `make test-chaos`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Every BOM item has a policy coverage status and missing/matched evidence where applicable.
- Runtime evidence can prove coverage without mutating static scan findings.
- Docs avoid enforcement claims and route enforcement to Gait.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added per-action-path Gait policy coverage status in reports and Agent Action BOM output so operators can distinguish uncovered, declared, matched, runtime-proven, stale, and conflicting controls.
Semver marker override: [semver:minor]
Contract/API impact: Additive report/risk/BOM fields and schema enum.
Versioning/migration impact: Missing coverage normalizes to `none`.
Architecture constraints: Gait policy detector emits policy refs; risk/report correlate coverage; no enforcement in Wrkr.
ADR required: no
TDD first failing test(s): `TestActionPathPolicyCoveragePromotesRuntimeEvidenceToRuntimeProven`.
Cost/perf impact: medium
Chaos/failure hypothesis: Conflicting policy refs produce `conflict` with evidence refs instead of selecting an arbitrary policy.

### Story 3.2: Normalize runtime control evidence classes and correlate to BOM items

Priority: P0
Recommendation coverage: 8
Strategic direction: Extend ingest so runtime decisions, approvals, JIT receipts, freeze-window decisions, kill-switch blocks, action outcomes, and proof verification attach cleanly to action paths and BOM items.
Expected benefit: The demo can show discovered risky path -> controlled action -> proof evidence on the same item.

Tasks:
- Define normalized evidence classes: `policy_decision`, `approval`, `jit_credential`, `freeze_window`, `kill_switch`, `action_outcome`, and `proof_verification`.
- Validate evidence classes in `ingest.Normalize` while preserving backward compatibility for unknown legacy classes if needed through `other` or warnings.
- Extend correlation keys to include `target`, workflow/location, action class, policy ref, proof ref, and graph/path refs while keeping existing `path_id` and `agent_id` joins.
- Expose matched runtime evidence details on BOM items and report summaries.
- Add evidence bundle outputs for BOM runtime correlation.
- Add CLI docs and examples for ingesting Gait runtime evidence sidecars.
- Add changelog entry under `Added`.

Repo paths:
- `core/ingest/ingest.go`
- `core/ingest/ingest_test.go`
- `core/cli/ingest.go`
- `core/evidence/evidence.go`
- `core/evidence/evidence_test.go`
- `core/report/build.go`
- `core/report/artifacts.go`
- `schemas/v1/evidence/evidence-bundle.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/ingest.md`
- `docs/commands/evidence.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/ingest ./core/cli -run 'Test.*Ingest|Test.*RuntimeEvidence' -count=1`
- `go test ./core/evidence ./core/report -run 'Test.*Runtime|Test.*BOM|Test.*Evidence' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-fast`

Test requirements:
- Validation tests for every normalized evidence class.
- Correlation tests by `path_id`, by agent/tool/repo/workflow fallback, by policy ref, and by proof ref.
- Evidence bundle test proving runtime correlation is included and signed bundle generation remains atomic.
- Negative tests for malformed evidence and stale/unknown refs.

Matrix wiring:
- Fast lane: ingest/report/evidence tests.
- Core CI lane: contracts and `make test-fast`.
- Acceptance lane: runtime evidence after remediation in Story 4.2.
- Cross-platform lane: JSON file behavior and path handling on Windows smoke.
- Risk lane: `make test-hardening`, `make test-chaos`, `make test-risk-lane`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- BOM items show runtime control evidence classes and correlation status when sidecar records exist.
- `wrkr evidence --json` includes BOM runtime correlation without mutating saved scan state.
- Malformed runtime evidence fails closed with existing error classes.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added normalized runtime control evidence classes and BOM-item correlation for policy decisions, approvals, JIT credentials, freeze windows, kill switches, action outcomes, and proof verification.
Semver marker override: [semver:minor]
Contract/API impact: Additive ingest/evidence/report fields plus stricter evidence-class normalization.
Versioning/migration impact: Runtime evidence schema remains `v1`; compatibility behavior for unknown classes must be explicit.
Architecture constraints: Ingest owns sidecar normalization and correlation; report/evidence consume correlations.
ADR required: no
TDD first failing test(s): `TestRuntimeEvidenceCorrelatesPolicyDecisionAndJITReceiptToBOMItem`.
Cost/perf impact: low
Chaos/failure hypothesis: Corrupt or partially written runtime evidence sidecars fail closed without corrupting saved scan state or evidence bundle output.

### Story 3.3: Add optional PR and commit introduction attribution

Priority: P1
Recommendation coverage: 5
Strategic direction: Attribute risky path introduction from local git history deterministically, with hosted GitHub PR association only when explicitly available.
Expected benefit: Operators can answer where the risky agent action was introduced and route remediation to the right PR/commit context.

Tasks:
- Add a new `core/attribution` package that accepts repo root, file path, location range, and optional hosted provider metadata.
- For local scans, use `git blame --porcelain` and commit metadata for the matched file/range with deterministic fallback to latest relevant commit when range is unavailable.
- Add optional hosted GitHub PR association only for hosted mode with token/API context already configured; never make attribution a default network dependency.
- Add `introduced_by` metadata to action paths and BOM items: PR number, commit SHA, author, timestamp, changed file, line/range, provider URL, source, and confidence.
- Emit confidence and missing reason when history is shallow, file is untracked, line is unavailable, or hosted PR association is absent.
- Add docs for local-only and hosted attribution behavior.
- Add changelog entry under `Added`.

Repo paths:
- `core/attribution/`
- `core/source/local/local.go`
- `core/source/github/connector.go`
- `core/cli/scan.go`
- `core/risk/action_paths.go`
- `core/report/build.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/attribution -count=1`
- `go test ./core/source/local ./core/source/github -run 'Test.*Attribution|Test.*Git|Test.*PR' -count=1`
- `go test ./core/risk ./core/report -run 'Test.*IntroducedBy|Test.*BOM' -count=1`
- `make test-contracts`
- `make test-fast`

Test requirements:
- Temporary git repo tests with commits introducing a workflow line and stable blame output.
- Shallow/no-git/untracked-file tests proving low-confidence/missing attribution rather than runtime failure.
- Hosted connector unit tests with mocked PR association responses and deterministic no-token fallback.
- BOM/report contract tests for `introduced_by` shape.

Matrix wiring:
- Fast lane: attribution and local/source tests.
- Core CI lane: contracts and fast tests.
- Acceptance lane: demo fixture includes deterministic git history where feasible.
- Cross-platform lane: local git tests must be platform-stable or guard with deterministic skip reason.
- Risk lane: `make test-hardening`, `make test-chaos`.
- Release/UAT lane: `make prepush-full`.

Acceptance criteria:
- Local scans can populate `introduced_by` for matched files/ranges when git metadata exists.
- Missing attribution is explicit and does not block scans, reports, or evidence generation.
- Hosted PR lookup is opt-in and never required for deterministic local output.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added optional introduction attribution for risky action paths and Agent Action BOM items using deterministic local git history, with hosted PR association available only in explicit hosted contexts.
Semver marker override: [semver:minor]
Contract/API impact: Additive action path and BOM fields.
Versioning/migration impact: Missing attribution normalizes to absent or low-confidence metadata.
Architecture constraints: Source/attribution package gathers metadata; risk/report attach normalized results.
ADR required: yes
TDD first failing test(s): `TestLocalAttributionFindsCommitIntroducingWorkflowActionPath`.
Cost/perf impact: medium
Chaos/failure hypothesis: Git command failure, shallow history, or provider API loss produces explicit low-confidence attribution without changing scan exit code for otherwise valid scans.

## Epic 4: Demo Fixtures, Golden Contracts, and Acceptance Proof

Objective: make the full Agent Action BOM story reproducible for engineering, product, docs, CI, and sales.

### Story 4.1: Add deterministic before/after Agent Action BOM scenario fixtures

Priority: P0
Recommendation coverage: 9
Strategic direction: Create fixture repos and scripts that reproduce a PR-introduced CI coding agent with broad credential access, deploy/write authority, missing approval/proof/policy, and later Gait-covered runtime evidence.
Expected benefit: Demos and regression tests no longer depend on scratch repos or manual setup.

Tasks:
- Add `scenarios/wrkr/agent-action-bom-demo/before` and `after` fixture repos with deterministic workflows, agent configs, secret references, production target signals, Gait policy refs, and runtime evidence sidecars.
- Include expected scan JSON, report JSON, evidence JSON, and evidence bundle key artifacts as golden outputs with timestamps normalized where required.
- Add scripts under `scripts/` or scenario helpers that run `wrkr scan`, `wrkr report --template agent-action-bom`, `wrkr ingest`, and `wrkr evidence`.
- Document the fixture in `docs/examples` with exact commands and expected top BOM item.
- Ensure fixture contents contain no real secrets and use only reference names.
- Add changelog entry under `Added`.

Repo paths:
- `scenarios/wrkr/agent-action-bom-demo/`
- `scripts/run_agent_action_bom_demo.sh`
- `internal/scenarios/`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `docs/examples/quickstart.md`
- `CHANGELOG.md`

Run commands:
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -run 'Test.*AgentActionBOM|TestScenarioContracts' -count=1`
- `go test ./internal/scenarios -tags=scenario -run 'Test.*AgentActionBOM' -count=1`
- `make test-scenarios`
- `make test-fast`

Test requirements:
- Scenario contract test proving required fixture files and expected outputs exist.
- Golden regeneration path with deterministic normalization for timestamps/proof head where appropriate.
- Negative fixture check proving fake secret refs do not include raw secret values.
- Docs example smoke test for the scenario command sequence.

Matrix wiring:
- Fast lane: scenario contract tests and script shellcheck/lint where available.
- Core CI lane: `make test-fast` plus scenario contract validation.
- Acceptance lane: `make test-scenarios` and scenario-tagged test.
- Cross-platform lane: scripts must either be POSIX-only docs/demo helpers or have Windows-compatible Go test coverage.
- Risk lane: `make test-risk-lane`, `make test-hardening`.
- Release/UAT lane: `make prepush-full` and release smoke.

Acceptance criteria:
- A clean checkout can run the fixture scenario and produce the same top BOM item.
- Before output shows risky CI agent, workflow path, static credential, deploy/write classes, target, owner gap, approval gap, policy/proof gap, and graph refs.
- After ingest/report output shows Gait policy/runtime/proof coverage on the same BOM item.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added deterministic Agent Action BOM demo fixtures and scripts covering risky CI agent discovery, credential provenance, control gaps, runtime evidence, and proof/evidence output.
Semver marker override: [semver:minor]
Contract/API impact: Adds scenario and demo artifacts; no runtime API break.
Versioning/migration impact: Scenario goldens become contract fixtures and must be updated intentionally.
Architecture constraints: Scenarios exercise public CLI only and must not rely on private package internals.
ADR required: no
TDD first failing test(s): `TestScenarioAgentActionBOMDemoContract`.
Cost/perf impact: medium
Chaos/failure hypothesis: Demo scripts fail fast with clear missing prerequisite messages rather than generating partial or untracked artifacts.

### Story 4.2: Add end-to-end Agent Action BOM acceptance tests and golden contracts

Priority: P0
Recommendation coverage: 1, 2, 8, 9, 10, 14
Strategic direction: Lock the complete narrative with outside-in tests from static discovery through report BOM generation, ingest, evidence bundle output, and proof correlation.
Expected benefit: Future detector, aggregation, report, or ingest changes cannot silently break the demo’s central promises.

Tasks:
- Add acceptance tests for `wrkr scan --json`, `wrkr report --template agent-action-bom --json --evidence-json`, `wrkr ingest`, and `wrkr evidence --json`.
- Assert top BOM item contains risky CI agent, workflow path, credential kind/provenance, normalized action classes, production target, owner state, approval gap, policy gap, proof gap, graph refs, and control priority.
- After ingest, assert the same path ID shows runtime evidence classes, policy coverage `runtime_proven`, JIT/approval/proof refs where present, and reduced missing-control gaps where appropriate.
- Validate `agent-action-bom.schema.json`, report summary schema, risk-report schema, and evidence bundle schema against golden outputs.
- Add byte-stability repeated-run tests with timestamp/proof normalization.
- Wire acceptance into scenario/test matrix and docs.
- Add changelog entry under `Added`.

Repo paths:
- `core/cli/root_test.go`
- `core/cli/report_contract_test.go`
- `core/evidence/evidence_test.go`
- `core/ingest/ingest_test.go`
- `internal/acceptance/`
- `internal/scenarios/`
- `scenarios/wrkr/agent-action-bom-demo/`
- `schemas/v1/`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/cli -run 'Test.*AgentActionBOM|Test.*ReportContract|Test.*ScanContract' -count=1`
- `go test ./core/ingest ./core/evidence -run 'Test.*AgentActionBOM|Test.*RuntimeEvidence' -count=1`
- `go test ./internal/acceptance -run 'Test.*AgentActionBOM' -count=1`
- `go test ./internal/scenarios -tags=scenario -run 'Test.*AgentActionBOM' -count=1`
- `scripts/validate_scenarios.sh`
- `make test-contracts`
- `make test-scenarios`
- `make test-risk-lane`
- `make prepush-full`

Test requirements:
- Outside-in CLI tests for scan/report/ingest/evidence commands.
- Golden tests for report JSON, report evidence JSON, evidence bundle files, and runtime correlation.
- Schema validation tests for every new/extended schema.
- Determinism test running the scenario twice and diffing normalized artifacts.
- Proof-chain verification test proving BOM proof refs point to existing chain records.

Matrix wiring:
- Fast lane: focused CLI, ingest, evidence, and schema tests.
- Core CI lane: `make test-contracts`, `make test-fast`.
- Acceptance lane: `make test-scenarios`, scenario-tagged tests, and `scripts/run_v1_acceptance.sh --mode=local`.
- Cross-platform lane: Windows smoke for CLI report/evidence paths and deterministic path separators in golden normalization.
- Risk lane: `make test-risk-lane`, `make test-hardening`, `make test-chaos`, `make test-perf`.
- Release/UAT lane: `make prepush-full`, `make test-release-smoke`, docs-site gates, and CodeQL before release.

Acceptance criteria:
- Acceptance tests fail if the top BOM item loses credential provenance, action classes, graph refs, policy/proof gaps, runtime evidence, or proof-chain correlation.
- Scenario outputs are stable and schema-valid.
- Docs and scripts use the same canonical command path as tests.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added end-to-end Agent Action BOM acceptance tests that verify static discovery, report/evidence BOM output, runtime evidence correlation, proof references, graph edges, and demo fixture stability.
Semver marker override: [semver:minor]
Contract/API impact: Adds acceptance/golden contracts for BOM behavior; no runtime API break beyond prior stories.
Versioning/migration impact: Golden artifacts become compatibility fixtures for future additive changes.
Architecture constraints: Acceptance tests exercise public CLI and artifact files, not private builders except where unit tests are already scoped.
ADR required: no
TDD first failing test(s): `TestAgentActionBOMAcceptanceStaticToRuntimeEvidence`.
Cost/perf impact: high
Chaos/failure hypothesis: Partial evidence bundle generation, malformed ingest sidecars, or missing proof refs fail acceptance with explicit artifact-level diagnostics instead of silently passing.

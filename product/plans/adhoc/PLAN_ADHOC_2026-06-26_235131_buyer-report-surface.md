# Adhoc Plan: Buyer Report Surface

Date: 2026-06-26
Profile: `wrkr`
Slug: `buyer-report-surface`
Recommendation source: user-provided review of customer-redacted Agent Action BOM scan artifacts, focused on buyer-readable report quality, remediation priority, evidence-gap framing, attack-path explanation, and report QA hardening.

All paths in this plan are repo-relative. This is a local planning artifact for implementation only; it does not ship a plan-only PR because the user explicitly requested implementation without shipping yet.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control sequence. This work must not add Axym compliance-engine behavior, Gait enforcement behavior, scan-time LLM calls, live provider API dependency, hidden telemetry, or default network enrichment.
- Scope is the buyer-facing report surface and report QA. Detection, scoring, proof-chain semantics, JSON evidence shape, saved-state schema, exit codes, and policy decisions remain unchanged unless a test proves a report-only helper needs a strictly additive internal field.
- The detailed current rows remain available in evidence JSON and appendices. The primary Markdown lead becomes a decision-oriented view with grouped/collapsed action paths and stronger remediation language.
- First-run approval/proof gaps are evidence onboarding state. Markdown should not repeat unknown evidence fields as if each row is a separate scanner failure when the scan simply has no imported or declared approval/proof evidence for those paths.
- Blocked standing credential paths must lead with reduce, replace, revoke, rotate, or move to brokered/JIT authority. "Accept risk with expiry" may remain a secondary closure action, but it must not be the first buyer-facing recommendation for blocked credential authority.
- Attack-path language must stay static and evidence-bounded. When no attack paths are generated despite high-impact governable paths, Wrkr explains that graph prerequisites or attack-path joins were not available rather than implying no attack path risk exists.
- Report QA must block buyer-hostile output patterns in addition to unsupported claims: weak primary remediation verbs for blocked credentials, long field-dump lines, internal enum/token leakage in primary sections, and repeated raw unknown-evidence phrasing.
- Changelog entries are required because the work changes public report wording and buyer-facing governance guidance.

## Current Baseline (Observed)

- `core/report/render_markdown.go` renders the Agent Action BOM lead, diagnostic cards, primary workflow section, compact top action paths, workflow appendix, control backlog, and other appendices.
- `core/report/primary_view.go` selects the primary Agent Action BOM path and builds `recommended_next_actions` from BOM item state.
- `core/report/build.go` builds attack-path facts and currently emits `attack paths: none generated from current findings` when there are no top attack paths.
- `core/report/qa.go` blocks unsupported buyer phrases and unbacked agent-framework wording, but it does not yet check density, internal token leakage, repeated evidence-gap phrasing, or weak remediation ordering.
- `core/risk/closure_actions.go`, `core/risk/path_type_guidance.go`, and related projection code already provide path-specific closure actions and remediation text that can be reused rather than inventing a parallel report-only model.
- `docs/commands/report.md` already describes `agent_action_bom.summary.primary_view`, suppressed counts, closure actions, redaction, and buyer-safe report expectations.
- Existing tests cover primary-view line budgets, focused BOM ordering, report overclaim language, buyer projection parity, enterprise-pressure size/readability constraints, and markdown budget truncation.

## Exit Criteria

- Agent Action BOM Markdown starts with a buyer-first decision lead: at most five distinct grouped action paths by default, duplicate repo/workflow/path-type rows collapsed, and full detail preserved in appendix/evidence JSON.
- The first page includes a concise evidence-onboarding sentence when approval/proof evidence is broadly not imported or observed, instead of repeating raw unknown evidence labels on every lead row.
- Blocked standing credential paths lead with reduce, replace, revoke, rotate, or JIT/brokered access wording in primary cards, primary workflow next actions, and top action-path bullets.
- Attack-path appendix/facts explain why no attack paths were generated when governable critical paths exist but attack-path graph joins are unavailable.
- Buyer artifact QA fails deterministic tests for weak blocked-credential remediation, overly long primary-section field dumps, internal enum/token leakage in the primary buyer section, and repeated raw unknown-evidence phrasing.
- User-facing report docs and the unreleased changelog describe the refined buyer Markdown behavior without claiming enforcement, runtime observation, or detection improvements.

## Public API and Contract Map

- CLI contracts:
  - Preserve `wrkr report --md`, `--json`, `--evidence-json`, `--quiet`, and exit-code behavior.
  - Do not change command flags, exit codes, or JSON field names.
  - Markdown wording and ordering are public report behavior and must be documented.
- JSON and schema contracts:
  - No required JSON shape changes are planned.
  - Existing `agent_action_bom.items[*]`, `workflow_highlights`, `attack_paths`, `suppressed_counts`, and appendix/evidence-JSON detail remain available.
  - Any helper fields introduced during implementation must be additive and redaction-safe.
- Detection, aggregation, risk, and proof contracts:
  - Do not change detector coverage, risk scoring, proof record generation, chain verification, or compliance mapping.
  - Recommendation priority may be rendered more strongly from existing action-path authority/readiness evidence, but must not alter scanner findings or proof records.
- Documentation contracts:
  - `docs/commands/report.md` must state that the Markdown lead is grouped and buyer-readable while JSON/appendices retain detail.
  - Docs must preserve the static posture boundary and avoid enforcement/runtime claims.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `docs/commands/report.md`
  - `CHANGELOG.md`
- Test and fixture surfaces impacted:
  - `core/report/*_test.go`
  - `internal/scenarios/wave5_focused_bom_scenario_test.go`
  - `internal/scenarios/wave42_enterprise_pressure_scenario_test.go`
- OSS trust baseline:
  - No real customer scan artifacts, Drive exports, proof chains, raw repo names, owners, credentials, or transient reports may be committed.
  - New tests must use synthetic repo/path IDs and deterministic fixtures.
  - Customer-safe redaction behavior must remain default for shareable report artifacts.

## Recommendation Traceability

| Recommendation | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| Stricter buyer-first Markdown layer | P0 | Story 1.1 | Large scans repeat rows and feel like a scanner dump. | Group/collapse primary lead rows and cap the default view. | Buyers can understand the top risks quickly. |
| First-run evidence gaps as onboarding state | P0 | Story 1.2 | Repeated approval/proof unknowns make first scans feel noisy. | Add a concise evidence-onboarding summary and reduce repeated labels. | Customers know what evidence to import next. |
| Severity-aware remediation verbs | P0 | Story 1.3 | Blocked standing credentials should not lead with accept-risk. | Prioritize reduce/replace/revoke/JIT wording for blocked credential paths. | Reports drive safer immediate remediation. |
| QA for density and internal tokens | P0 | Story 1.4 | Existing QA blocks overclaims but not buyer-hostile format. | Extend deterministic report QA and tests. | Future reports regress before reaching customers. |
| Explain attack-path non-generation | P1 | Story 1.5 | "No attack paths generated" beside critical paths reads inconsistent. | Explain missing graph/attack-path prerequisites. | Static report boundaries stay credible. |

## Test Matrix Wiring

- Fast lane:
  - `go test ./core/report -run 'Test.*Buyer|Test.*Primary|Test.*Markdown|Test.*Attack|Test.*QA|TestAgentActionBOMPrimaryViewLineBudget|TestApplyMarkdownBudgetKeepsTruncationInsideLineCap' -count=1`
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
- Acceptance lane:
  - `go test ./internal/scenarios -run 'Test.*FocusedBOM|Test.*EnterprisePressure|Test.*ReportOverclaim' -count=1`
  - `make test-scenarios` if scenario harness changes beyond focused report assertions.
- Cross-platform lane:
  - No platform-specific path behavior is expected. Tests must avoid POSIX-only assumptions and use synthetic repo/path IDs.
- Risk lane:
  - `make test-contracts` if additive JSON/schema behavior is introduced.
  - `make codeql` is not required unless implementation touches parsing, CI, dependencies, generated-code intake, security-sensitive scanner logic, or file mutation beyond docs/tests.
- Gating rule:
  - Story 1.1 should land before QA assertions that depend on grouped primary output.
  - Story 1.3 should land before QA blocks weak blocked-credential remediation.
  - Story 1.5 can land independently after baseline report tests pass.

## Minimum-Now Sequence

- Wave 1 - Buyer report surface hardening:
  - Story 1.1 groups and caps primary Markdown action paths.
  - Story 1.2 reframes first-run evidence gaps as onboarding state.
  - Story 1.3 strengthens blocked credential remediation wording.
  - Story 1.4 adds buyer artifact QA and focused regression tests.
  - Story 1.5 explains attack-path non-generation.

## Explicit Non-Goals

- No detector additions or detection coverage expansion.
- No risk-score, control-state, or proof-record semantic changes.
- No JSON evidence shape or schema migration unless an additive helper is strictly required by implementation.
- No runtime observation, provider API lookup, enforcement claim, or external network access.
- No change to exit-code contracts.
- No committing, pushing, or PR creation in this implementation pass.

## Definition of Done

- All in-scope stories are implemented locally on an implementation branch.
- Markdown primary report output is grouped, bounded, and less repetitive while appendix/evidence JSON detail remains available.
- Blocked standing credential findings render a strong primary remediation verb before any accept-risk option.
- Attack-path absence wording is evidence-bounded and explains missing prerequisites when applicable.
- QA and tests cover the new buyer-surface invariants.
- Docs and changelog are updated only for the user-visible report behavior.
- Required focused validation passes, and any skipped final/risk lane has an explicit reason.

## Epic 1: Buyer Report Surface Hardening

Objective: make Agent Action BOM Markdown read like a buyer decision memo while preserving deterministic evidence detail in JSON and appendices.
Traceability: Recommendations 1 through 5.

### Story 1.1: Group And Cap Primary Markdown Action Paths

Priority: P0
Recommendation coverage: 1

Tasks:

- Collapse duplicate primary lead/top-action rows by repo, workflow/location, action-path type, target class, readiness, and authority family.
- Cap the default primary buyer view at five grouped action paths while keeping detailed rows in appendix/evidence JSON.
- Prefer grouped language such as "plus N related authorities" for duplicate workflow rows.
- Preserve deterministic ordering by original rank, severity, readiness, and stable string tie-breakers.
- Add focused tests for duplicate collapse and primary-section line budget.

Repo paths:

- `core/report/render_markdown.go`
- `core/report/primary_view.go`
- `core/report/primary_view_test.go`
- `core/report/render_markdown_test.go`
- `core/report/sprint0_signal_test.go`
- `internal/scenarios/wave5_focused_bom_scenario_test.go`

Run commands:

- `go test ./core/report -run 'Test.*Primary.*Grouped|Test.*TopAction|TestAgentActionBOMPrimaryViewLineBudget|TestApplyMarkdownBudgetKeepsTruncationInsideLineCap' -count=1`
- `go test ./internal/scenarios -run 'Test.*FocusedBOM' -count=1`

Test requirements:

- A fixture with repeated repo/workflow rows renders one primary row plus a related-count phrase.
- The primary section remains under the existing lead line budget.
- Appendix/evidence detail remains available and is not removed from BOM item output.

Matrix wiring:

- Fast lane: focused `core/report` grouping and markdown budget tests.
- Core CI lane: `make lint-fast` and `make test-fast`.
- Acceptance lane: focused BOM scenario.
- Cross-platform lane: deterministic synthetic IDs only.
- Risk lane: not required beyond report contract tests unless JSON shape changes.

Acceptance criteria:

- Duplicate primary rows are collapsed in Markdown.
- Top Action Paths shows no more than five grouped buyer-facing rows by default.
- Detailed current rows remain in the Workflow BOM Appendix.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Agent Action BOM Markdown now groups repeated top action paths in the buyer lead while preserving full detail in appendices and evidence JSON.
Semver marker override: [semver:patch]
Contract/API impact: Public Markdown wording and ordering changes; JSON and CLI contracts remain unchanged.
Versioning/migration impact: No migration required.
Architecture constraints: Report layer consumes existing projected path data and does not re-score findings.
ADR required: no
TDD first failing test(s): grouped primary Markdown and duplicate workflow collapse tests.
Cost/perf impact: low
Chaos/failure hypothesis: If grouping keys are too broad, unrelated action paths could be collapsed; tests must cover different target/action/authority cases.

### Story 1.2: Reframe First-Run Evidence Gaps

Priority: P0
Recommendation coverage: 2

Tasks:

- Add a concise first-run evidence-onboarding note when approval/proof evidence is broadly not imported or observed across governable paths.
- Reduce repeated raw approval/proof unknown labels in the primary buyer cards when the same gap applies broadly.
- Keep exact evidence states in JSON and appendix detail.
- Update report docs to describe first-run evidence-gap framing.

Repo paths:

- `core/report/render_markdown.go`
- `core/report/qa.go`
- `core/report/primary_view_test.go`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/report -run 'Test.*Evidence.*Onboarding|Test.*Buyer.*QA|Test.*Primary' -count=1`

Test requirements:

- A first-run fixture renders one evidence-onboarding note.
- The primary lead does not repeat raw approval/proof unknown labels on every row.
- Appendix detail still contains exact evidence states.

Matrix wiring:

- Fast lane: focused `core/report` tests.
- Core CI lane: `make lint-fast` and `make test-fast`.
- Acceptance lane: report overclaim scenario if existing assertions are affected.
- Cross-platform lane: no platform-specific behavior.
- Risk lane: not required because detection/proof semantics do not change.

Acceptance criteria:

- Buyer-facing first-run output clearly says approval/proof evidence was not imported or observed.
- Repeated evidence gaps are summarized once in the lead.
- Docs explain the distinction between evidence gaps and scanner/parser failure.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: First-run Agent Action BOM reports now summarize approval/proof evidence gaps as onboarding context instead of repeating raw unknown evidence fields throughout the lead.
Semver marker override: [semver:patch]
Contract/API impact: Public Markdown wording changes only.
Versioning/migration impact: No migration required.
Architecture constraints: Preserve evidence-state values in JSON and appendix outputs.
ADR required: no
TDD first failing test(s): first-run evidence onboarding Markdown test and QA repetition test.
Cost/perf impact: low
Chaos/failure hypothesis: If summarized too aggressively, a path-specific verified gap could be hidden; tests must cover mixed evidence states.

### Story 1.3: Prioritize Strong Remediation For Blocked Credentials

Priority: P0
Recommendation coverage: 3

Tasks:

- Render blocked standing credential primary recommendations with reduce, replace, revoke, rotate, or brokered/JIT access before any accept-risk closure.
- Apply the same priority to diagnostic cards, primary workflow next actions, and compact top action-path bullets.
- Preserve secondary closure actions where they remain valid.
- Add tests that fail if a blocked credential lead starts with "Accept risk with expiry".

Repo paths:

- `core/report/render_markdown.go`
- `core/report/primary_view.go`
- `core/risk/closure_actions.go`
- `core/report/primary_view_test.go`
- `core/report/render_markdown_test.go`
- `core/report/declaration_export_test.go`
- `CHANGELOG.md`

Run commands:

- `go test ./core/report ./core/risk -run 'Test.*Blocked.*Credential|Test.*ClosureAction|Test.*RecommendedNextAction' -count=1`

Test requirements:

- Blocked standing credential primary output starts with strong remediation wording.
- Accept-risk remains available only after stronger closure actions when applicable.
- Non-credential review-required paths keep review/approval guidance.

Matrix wiring:

- Fast lane: focused `core/report` and `core/risk` tests.
- Core CI lane: `make lint-fast` and `make test-fast`.
- Acceptance lane: enterprise-pressure scenario top-path assertions.
- Cross-platform lane: no platform-specific behavior.
- Risk lane: not required unless risk projection semantics are changed.

Acceptance criteria:

- Blocked PAT/static-secret rows no longer lead with accept-risk language.
- Strong remediation verbs are deterministic and authority-aware.
- Existing closure-action JSON remains compatible.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Blocked standing-credential report guidance now leads with reducing, replacing, revoking, rotating, or moving authority to JIT/brokered access before any accept-risk option.
Semver marker override: [semver:patch]
Contract/API impact: Public Markdown remediation wording changes; closure-action JSON remains compatible.
Versioning/migration impact: No migration required.
Architecture constraints: Use existing action-path authority/readiness fields rather than reclassifying findings in the report layer.
ADR required: no
TDD first failing test(s): blocked credential primary recommendation ordering test.
Cost/perf impact: low
Chaos/failure hypothesis: If the blocked-credential predicate is too broad, ordinary review paths may get revoke wording; tests must cover no-credential and JIT cases.

### Story 1.4: Add Buyer Artifact QA For Density And Internal Tokens

Priority: P0
Recommendation coverage: 4

Tasks:

- Extend buyer artifact QA to flag weak blocked-credential primary remediation, very long primary lead lines, internal enum/token leakage in the lead, and repeated raw evidence-gap phrasing.
- Keep appendix detail and JSON fields exempt where field-level diagnostics are expected.
- Add deterministic unit tests for each QA failure class.
- Wire QA from existing report build/render validation points without changing CLI exit codes unless an existing QA error path already applies.

Repo paths:

- `core/report/qa.go`
- `core/report/report_test.go`
- `core/report/render_markdown_test.go`
- `internal/scenarios/report_overclaim_scenario_test.go`
- `internal/scenarios/wave42_enterprise_pressure_scenario_test.go`

Run commands:

- `go test ./core/report -run 'Test.*BuyerArtifactQA|Test.*RenderMarkdown' -count=1`
- `go test ./internal/scenarios -run 'Test.*ReportOverclaim|Test.*EnterprisePressure' -count=1`

Test requirements:

- QA rejects blocked credential lead text that starts with accept-risk.
- QA rejects primary lead lines above the selected density threshold.
- QA rejects internal enum/token leakage in primary buyer sections.
- QA permits detailed appendix rows and machine-readable JSON fields.

Matrix wiring:

- Fast lane: focused QA unit tests.
- Core CI lane: `make lint-fast` and `make test-fast`.
- Acceptance lane: report overclaim and enterprise-pressure scenarios.
- Cross-platform lane: no platform-specific behavior.
- Risk lane: not required beyond scenario validation.

Acceptance criteria:

- New QA failures are deterministic and deduplicated.
- Existing supported report artifacts still pass.
- Buyer-hostile primary Markdown patterns are test-blocked.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Report QA now blocks buyer-hostile primary Markdown patterns such as weak blocked-credential remediation, internal token leakage, repeated raw evidence gaps, and oversized lead lines.
Semver marker override: [semver:patch]
Contract/API impact: Internal QA hardening plus public report quality guardrails; no CLI/JSON contract change.
Versioning/migration impact: No migration required.
Architecture constraints: QA validates rendered text and path evidence without re-parsing source or mutating scan state.
ADR required: no
TDD first failing test(s): buyer artifact QA density, token leakage, repetition, and weak-remediation tests.
Cost/perf impact: low
Chaos/failure hypothesis: If QA scans appendices too broadly, legitimate diagnostic rows could fail; tests must scope checks to primary buyer sections.

### Story 1.5: Explain Attack-Path Non-Generation

Priority: P1
Recommendation coverage: 5

Tasks:

- Replace bare "attack paths: none generated from current findings" with an explanation when governable high-impact action paths exist.
- The explanation should mention missing attack-path graph joins or prerequisites and preserve static posture boundaries.
- Keep the existing simple wording when there are no governable action paths.
- Add tests for critical action paths with no generated attack paths.

Repo paths:

- `core/report/build.go`
- `core/report/render_markdown.go`
- `core/report/report_test.go`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/report -run 'Test.*AttackPath.*Explanation|Test.*Report' -count=1`

Test requirements:

- Critical governable paths with no top attack paths render an explanatory non-generation reason.
- Reports do not imply absence of attack-path risk when graph evidence was not generated.
- Reports without governable paths keep a concise none-generated message.

Matrix wiring:

- Fast lane: focused `core/report` attack-path fact tests.
- Core CI lane: `make lint-fast` and `make test-fast`.
- Acceptance lane: enterprise-pressure scenario if attack-path appendix text is asserted.
- Cross-platform lane: no platform-specific behavior.
- Risk lane: not required because attack-path scoring is unchanged.

Acceptance criteria:

- Markdown/evidence facts explain non-generation for high-impact governable paths.
- Existing attack-path totals and top-path IDs remain unchanged when attack paths exist.
- Docs preserve the difference between static action paths and generated attack paths.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Reports now explain attack-path non-generation when high-impact action paths exist but attack-path graph prerequisites were not available.
Semver marker override: [semver:patch]
Contract/API impact: Public report wording changes only.
Versioning/migration impact: No migration required.
Architecture constraints: Report layer explains existing attack-path state without changing attack-path generation or scoring.
ADR required: no
TDD first failing test(s): attack-path non-generation explanation test.
Cost/perf impact: low
Chaos/failure hypothesis: If explanation appears for clean scans, it could create false concern; tests must cover empty/no-governable reports.

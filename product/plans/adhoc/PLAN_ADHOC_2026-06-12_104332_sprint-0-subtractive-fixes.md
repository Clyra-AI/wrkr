# Adhoc Plan: Sprint 0 Subtractive Fixes

Date: 2026-06-12
Profile: `wrkr`
Slug: `sprint-0-subtractive-fixes`
Recommendation source: user-provided Sprint 0 completion recommendations for real-scan size/signal regressions, canonical reference completion, owner-safe redaction, generation caps, bounded stdout, focused BOM readability, grouped policy state, parser coverage truth, changelog receipts, and the temporary freeze gate.

All paths in this plan are repo-relative. Developer-specific checkout roots from the source recommendations have been normalized. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, report, evidence, docs, release, or workflow changes.

## Global Decisions (Locked)

- Sprint 0 is subtractive work. Do not add new detector surfaces, report sections, graph fields, sidecars, or buyer-facing claims unless they are directly required to prove the size, redaction, readability, parser-coverage, or finding-noise fixes in this plan.
- The first implementation PR must create failing, sanitized real-scan-shaped fixtures before deleting payload clones or changing projections. Size and signal regressions need executable receipts, not prose confidence.
- Canonical reference fields are the stable cross-artifact join contract: `mutable_endpoint_semantic_refs`, `credential_authority_ref`, and `authority_binding_refs`. Repeated projections must carry refs plus bounded summary facts, not embedded full endpoint/authority payloads.
- Full endpoint semantics, credential authority, and authority-binding objects may exist only in one canonical per-scan store or explicitly internal diagnostic surfaces that are marked non-shareable.
- Default and shareable artifacts are customer-safe by default. Cleartext owners, reviewers, identity labels, account-like subjects, local filesystem roots, and internal-only joins require explicit internal profile selection.
- Bounded stdout and streaming file sinks are contract work, not cosmetic output work. `--json` stdout should summarize and point to artifacts; large state/report/evidence files should be encoded directly to file sinks.
- Saved state and scoring inputs must be high-signal. Group repeated policy outcomes before they inflate posture counts, and carry affected-scope detail through evidence refs or appendix detail.
- Parser failures are coverage facts unless a user-actionable config contract failed. JS/TS-heavy parse failures must degrade scan-quality confidence instead of becoming noisy security findings.
- Changelog and release-note claims about scale, privacy, redaction, or customer safety require measured artifact-size deltas, redaction test names, and fixture coverage.
- Every story in this plan changes user-visible behavior, public contracts, docs/governance posture, or report/evidence semantics. Changelog review is required for each implementation PR.

## Current Baseline (Observed)

- Current code already contains canonical store primitives in `core/aggregate/inventory/canonical_refs.go` and canonical refs on inventory, risk, graph, backlog, BOM, and registry models.
- Remaining clone sites are still present in repeated projections, including `core/risk/action_paths.go`, `core/risk/workflow_chain.go`, `core/aggregate/attackpath/graph.go`, `core/aggregate/controlbacklog/controlbacklog.go`, `core/aggregate/privilegebudget/authority.go`, `core/aggregate/privilegebudget/budget.go`, `core/report/action_surface_registry.go`, `core/report/agent_action_bom.go`, `core/report/build.go`, and `core/report/redaction_summary.go`.
- Current scan/report hardening primitives exist, including grouped report policy outcomes and suppression counters in `core/report/signal_hardening.go`, scan-quality output in `core/aggregate/scanquality`, and bounded scan JSON tests in `core/cli/scan_output_signal_test.go`.
- The source recommendations report that v1.7.x introduced refs and surface-area tests, but did not fail when `last-scan.json` and Agent Action BOM evidence grew after the ref migration.
- The source recommendations identify customer-safety risk from owner/reviewer/account-like leakage in shareable/default artifacts, even when internal remediation context remains useful.
- Existing command implementation paths are under `core/cli/`, not `cmd/wrkr/`, so implementation stories use `core/cli/scan.go`, `core/cli/report.go`, `core/cli/evidence.go`, `core/cli/assess.go`, and `core/cli/jsonmode.go`.
- Relevant existing tests and scenario roots are present: `internal/scenarios`, `internal/acceptance`, `core/cli/report_contract_test.go`, `core/report/primary_view_test.go`, and `testinfra/hygiene/wave31_focus_and_gate_test.go`.
- `CHANGELOG.md`, `CONTRIBUTING.md`, `AGENTS.md`, `product/PLAN_NEXT.md`, and `docs/commands/report.md` exist and are the likely docs/governance touch points for implementation work.

## Exit Criteria

- A sanitized, synthetic real-scan-shaped fixture fails when repeated endpoint, credential, authority, policy, parser, BOM, markdown, or owner-leak payloads exceed explicit budgets.
- `last-scan.json`, `agent-action-bom-evidence.json`, and `agent-action-bom.md` have deterministic byte/line/noise budgets that would have blocked the reported regression.
- Repeated projections carry `MutableEndpointSemanticRefs`, `CredentialAuthorityRef`, and `AuthorityBindingRefs` as canonical joins and stop embedding full endpoint/authority objects by default.
- Any required schema or artifact-version transition for removing embedded clones is explicit, tested, documented, and compatible with deterministic readers.
- Default/shareable reports, BOM JSON, evidence JSON, redaction summaries, exported bundles, and markdown artifacts mask cleartext owners, reviewers, identity labels, account-like subjects, and local paths unless an explicit internal profile is selected.
- Derived collections are capped at generation with deterministic ordering, stable top-N selection, `suppressed_count` or equivalent metadata, and stable refs to full canonical detail where full detail remains required.
- `wrkr scan --json`, `wrkr report --json`, `wrkr evidence --json`, and `wrkr assess --json` emit bounded stdout summaries and stream large disk artifacts without whole-blob JSON assembly on hot paths.
- Agent Action BOM primary markdown fits the agreed primary-view budget and pushes repeated findings, hash-heavy refs, diagnostics, and repeated explanations into appendices.
- Policy outcomes are grouped in saved state and scoring inputs by rule, outcome, and affected scope; posture-score denominators use grouped outcomes where appropriate.
- JS/TS-heavy parser fixtures prove modern ESM, generated bundles, Yarn PnP, large package trees, and unsupported syntax produce honest scan-quality coverage without noisy security findings.
- Release notes and PR templates require measured receipts for scale, privacy, redaction, customer-safe, and readability claims.
- The temporary freeze gate blocks new scan/report surface expansion until size, redaction, and readability gates are green.

## Public API and Contract Map

- CLI contracts:
  - Preserve exit codes `0` through `8` as stable API surface.
  - Preserve `--json`, `--explain`, and `--quiet` semantics while making stdout bounded by default.
  - Require explicit `--share-profile internal` or equivalent for cleartext owner/reviewer/account-like fields in remediation-oriented outputs.
  - Keep full artifact paths discoverable from bounded stdout summaries.
- JSON and schema contracts:
  - `mutable_endpoint_semantic_refs`, `credential_authority_ref`, and `authority_binding_refs` remain stable join fields.
  - Repeated projection fields that previously carried full embedded objects require compatibility tests, artifact version notes, and docs updates before removal.
  - `suppressed_count`, artifact budget metadata, grouped policy outcomes, and scan-quality coverage fields must be schema-backed and deterministic.
  - Saved state, report JSON, BOM JSON, evidence JSON, and exported bundles must not include raw secret values or cleartext owner/account-like fields in default/shareable profiles.
- Architecture boundary contracts:
  - Detection owns parser diagnostics and detector scope decisions.
  - Aggregation owns canonical stores, repo exposure, privilege budget, control backlog, and grouped state.
  - Risk owns action path references, scoring, grouped policy input interpretation, and top-N ordering.
  - Report/evidence owns primary view rendering, appendices, redaction profiles, and shareable output contracts.
  - Proof emission remains file-based and verifiable; no story may weaken chain integrity or shared `Clyra-AI/proof` record contracts.
- Docs and release contracts:
  - Public behavior changes must update relevant `docs/commands/*`, `CHANGELOG.md`, and governance docs in the same implementation PR.
  - Claims about "hardened", "customer-safe", "smaller", "bounded", or "readable" output require measured receipts in the PR description or release-note process.

## Docs and OSS Readiness Baseline

- User-facing docs likely impacted:
  - `CHANGELOG.md`
  - `CONTRIBUTING.md`
  - `AGENTS.md`
  - `product/PLAN_NEXT.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/commands/assess.md`
  - `docs/trust/contracts-and-schemas.md`
- Contract and scenario assets likely impacted:
  - `internal/scenarios`
  - `internal/acceptance`
  - `core/cli/report_contract_test.go`
  - `core/report/primary_view_test.go`
  - `schemas/v1`
  - `testinfra/hygiene/wave31_focus_and_gate_test.go`
  - `testinfra/contracts`
- OSS trust baseline:
  - Do not commit private scan outputs, private owner names, private repo names, raw source snippets, raw prompt/session payloads, credential values, private proof chains, generated binaries, or transient reports.
  - Synthetic fixtures must use fake owners, fake repos, fake account subjects, and generated high-cardinality data.
  - Shared/default sample outputs must demonstrate redaction and bounded output without exposing private identities.
  - Size/noise/readability budgets must run offline and deterministically.

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| 1. Real-scan size/signal regression fixtures | P0 | Story 1.1 | Previous tests did not fail when artifacts grew. | Synthetic endpoint-heavy, policy-heavy, JS-heavy, BOM-heavy fixtures with byte/line/leak budgets. | Future releases block before customer-facing artifacts bloat or leak. |
| 2. Delete cloned payloads | P0 | Story 2.1 | Refs do not shrink artifacts while repeated full payloads remain. | Canonical per-scan stores plus refs in graph, paths, BOM, backlog, registry, budget, and redaction. | Large scans become portable and predictable. |
| 3. Owner masking safe-by-default | P0 | Story 2.2 | Users should not need to remember a redaction flag for customer-safe output. | Default/shareable profiles redact owners, reviewers, identity labels, local paths, and account-like subjects. | Shareable artifacts are safer and more trustworthy. |
| 4. Cap derived state collections at generation | P0 | Story 3.1 | Clone removal alone does not prevent combinatorial fan-out. | Deduplicate, rank, cap, and emit suppression metadata before serialization. | Saved state and reports stay bounded under enterprise scans. |
| 5. Finish stdout and streaming work | P0 | Story 3.1 | Streaming reduces memory spikes; bounded stdout protects CI and terminals. | Shared bounded-output pattern plus `json.NewEncoder` file sinks. | Large artifacts no longer require whole-blob memory assembly. |
| 6. Markdown/BOM line budget | P0 | Story 4.1 | The BOM must be buyer-readable without live explanation. | Strict primary-view line/section budget with appendices for detail. | First-screen BOM becomes concise and actionable. |
| 7. De-noise state findings | P0 | Story 3.2 | Raw per-rule per-repo findings inflate posture and counts. | Group policy outcomes in saved state and scoring inputs. | Risk and posture reflect actual risk shape. |
| 8. Parser coverage verification on JS-heavy repos | P0 | Story 4.2 | Reduced parser coverage must not be presented as a clean negative claim. | JS/TS fixtures, detector scoping, and scan-quality coverage statuses. | Reports are honest about complete, reduced, not-scanned, or unsupported coverage. |
| 9. Changelog truth reconciliation | P0 | Story 1.2 | Release credibility depends on evidence matching claims. | PR/release checklist receipts for size, redaction, privacy, and customer-safe claims. | Changelog trust debt is reduced. |
| 10. Make the freeze gate actually gate | P0 | Story 1.2 | New fields and views can reintroduce output entropy. | Hygiene tests block new surface expansion until Sprint 0 gates pass. | The repo finishes subtractive work before adding surface area. |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - `make test-fast`
  - Focused package tests listed in each story.
- Core CI lane:
  - `make prepush-full` for architecture, schema, CLI, risk, report, evidence, redaction, or scoring contract changes.
  - `make test-contracts` for JSON shape, schema, exit-code, artifact budget, redaction, and docs parity checks.
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `go test ./internal/acceptance -count=1`
  - `scripts/run_v1_acceptance.sh --mode=local` when buyer-facing scan/report/BOM behavior changes.
- Cross-platform lane:
  - Required for file paths, redaction, artifact serialization, stdout contracts, markdown output, and generated fixtures.
  - Validate deterministic ordering and path normalization on Linux, macOS, and Windows smoke lanes.
- Risk lane:
  - `make test-hardening` for fail-closed redaction, unsafe output paths, schema transitions, policy grouping, and ambiguous parser coverage.
  - `make test-chaos` for interrupted streaming writes, malformed canonical stores, corrupt saved state, and missing ref targets.
  - `make test-perf` for endpoint-heavy, policy-heavy, graph-heavy, BOM-heavy, and markdown-heavy fixtures.
  - `make codeql` when scanner logic, CI workflow logic, generated-code intake, or security-sensitive redaction changes are touched.
- Release/UAT lane:
  - `make test-release-smoke`
  - `scripts/run_v1_acceptance.sh --mode=release` when schemas, docs, CLI help, evidence bundles, report artifacts, or release-note claim rules change.
- Gating rule:
  - Story 1.1 lands first and must fail against the current regression shape before Stories 2.1, 2.2, 3.1, 3.2, 4.1, or 4.2 can be marked complete.
  - Story 1.2 lands alongside or immediately after Story 1.1 so new surface area remains blocked during Sprint 0.
  - Story 2.1 precedes Story 3.1 where caps depend on canonical refs.
  - Story 2.2 must be green before any implementation PR claims customer-safe output.
  - Story 4.1 must be green before buyer-facing docs call the Agent Action BOM one-page or share-ready.

## Minimum-Now Sequence

- Wave 1 - Measurement and gates:
  - Story 1.1 adds real-scan-shaped size/signal regression fixtures.
  - Story 1.2 adds changelog receipt rules and the temporary freeze gate.
- Wave 2 - Canonical refs and safe-by-default privacy:
  - Story 2.1 deletes remaining repeated endpoint/authority payload clones.
  - Story 2.2 makes default/shareable owner masking fail closed.
- Wave 3 - Bounded state, stdout, and scoring signal:
  - Story 3.1 caps derived collections at generation and completes bounded stdout plus streaming file sinks.
  - Story 3.2 groups policy outcomes inside saved state and scoring inputs.
- Wave 4 - Buyer-readable BOM and parser honesty:
  - Story 4.1 enforces Agent Action BOM primary-view line/section budgets.
  - Story 4.2 proves JS/TS parser coverage honesty on enterprise-shaped fixtures.

## Explicit Non-Goals

- No implementation in this plan-only PR.
- No edits to `product/PLAN_NEXT.md` in this plan-only PR.
- No Axym compliance-engine features or Gait runtime-enforcement features.
- No scan-time, risk-time, proof-time, report-time, evidence-time, or docs-generation-time LLM calls.
- No default network calls, live endpoint probing, managed SaaS dependency, telemetry on scan contents, or background daemon.
- No commitment of customer/private scan data, raw source, raw prompts, raw secrets, private proof chains, generated binaries, or transient reports.
- No raw secret extraction or serialization, even in internal profiles.
- No new detector/report/evidence surface expansion unless it is necessary to close a Sprint 0 gate and stays inside size/noise/readability budgets.
- No removal of public contract fields without compatibility handling, schema/version notes, docs, and migration tests.

## Definition of Done

- Every recommendation maps to at least one story and at least one acceptance check.
- Story 1.1 fails on the pre-fix regression shape and passes only after the relevant subtractive fix is complete.
- Every story includes TDD-first tests, repo paths, commands, lane wiring, changelog intent, contract impact, versioning/migration impact, architecture constraints, ADR decision, cost/perf notes, and failure hypotheses.
- `make lint-fast`, `make test-fast`, focused story commands, and required contract/scenario lanes pass for implementation PRs.
- Public CLI/schema/docs behavior changes include docs and changelog updates in the same implementation PR.
- No default/shareable output leaks owner-like, reviewer-like, account-like, credential-subject, local-path, raw-source, or raw-secret values in the new fixtures.
- Generated artifacts remain deterministic and portable across checkout paths.

## Wave 1: Measurement And Gates

Objective: create executable receipts for the reported failure classes and prevent new surface area while Sprint 0 subtractive fixes land.
Traceability: Recommendations 1, 9, and 10.

### Story 1.1: Add Real-Scan Size And Signal Regression Fixtures

Priority: P0
Recommendation coverage: 1
Tasks:
- Add sanitized synthetic fixtures that approximate large real scans without customer code: thousands of endpoints/nodes, repeated mutable endpoint semantics, repeated credential authority bindings, policy fanout across many repos, JS parse-noise cases, and large BOM/evidence output.
- Assert byte budgets for `last-scan.json` and `agent-action-bom-evidence.json`.
- Assert line and section budgets for `agent-action-bom.md`.
- Assert repeated projections do not contain embedded full authority/endpoint objects when canonical refs are present.
- Assert default/shareable outputs contain no cleartext owner, reviewer, identity-label, account-like subject, local checkout path, or raw source token.
- Assert policy outcomes are grouped and include bounded examples plus suppressed counts.
- Add coverage in `core/cli/report_contract_test.go`, `core/report/primary_view_test.go`, `internal/scenarios`, and `internal/acceptance`.
Repo paths:
- `internal/scenarios`
- `internal/acceptance`
- `core/cli/report_contract_test.go`
- `core/report/primary_view_test.go`
- `schemas/v1`
Run commands:
- `go test ./core/cli -run 'Test.*ReportContract|Test.*SizeSignal|Test.*AgentActionBOM' -count=1`
- `go test ./core/report -run 'Test.*PrimaryView|Test.*LineBudget|Test.*Redaction|Test.*PolicyOutcome' -count=1`
- `go test ./internal/scenarios -run 'Test.*Sprint0|Test.*SizeSignal|Test.*LargeScan' -count=1 -tags=scenario`
- `go test ./internal/acceptance -run 'Test.*Sprint0|Test.*AgentActionBOM' -count=1`
- `make test-contracts`
Test requirements:
- Tier 3 CLI contract tests for bounded stdout and report artifact handoff.
- Tier 4 acceptance tests for real-scan-shaped artifact sizes and BOM readability.
- Tier 9 schema/golden tests for suppression counts, grouped policy outcomes, canonical refs, and redaction metadata.
- Tier 11 scenario tests for endpoint-heavy, policy-heavy, JS-heavy, and BOM-heavy fixtures.
Matrix wiring:
- Fast lane: focused `core/cli` and `core/report` tests.
- Core CI lane: `make test-contracts` and schema/golden checks.
- Acceptance lane: `go test ./internal/scenarios -count=1 -tags=scenario` and `go test ./internal/acceptance -count=1`.
- Cross-platform lane: required for path normalization and markdown line counting.
- Risk lane: `make test-perf` after fixture size is stable.
Acceptance criteria:
- The fixture fails if full endpoint/authority objects appear in repeated projections.
- The fixture fails if artifact byte budgets, BOM markdown line budgets, or owner-leak checks regress.
- The fixture reports grouped policy outcomes with deterministic counts and bounded affected-scope examples.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Added real-scan-shaped size, signal, redaction, and BOM readability regression fixtures to block artifact bloat and shareable-output leaks before release.
Semver marker override: [semver:patch]
Contract/API impact: Adds explicit test-enforced artifact budget and shareable-output leak contracts for scan/report/BOM/evidence outputs.
Versioning/migration impact: No user-facing schema migration by itself, but establishes gates for subsequent compatibility changes.
Architecture constraints: Keep fixtures outside private data; exercise Detection, Aggregation, Risk, Proof emission, and Compliance mapping/evidence output boundaries without collapsing them.
ADR required: yes
TDD first failing test(s): `TestSprint0LargeScanSizeSignalBudget`, `TestAgentActionBOMPrimaryViewLineBudget`, and `TestShareableArtifactsDoNotLeakOwners`.
Cost/perf impact: medium
Chaos/failure hypothesis: A large fixture with repeated authority and parser noise should fail deterministically before fixes and should not require excessive memory or network access.

### Story 1.2: Add Changelog Receipts And Temporary Freeze Gate

Priority: P0
Recommendation coverage: 9, 10
Tasks:
- Update PR/release guidance so size, redaction, privacy, readability, and customer-safe claims require measured artifact-size deltas, redaction test names, and fixture coverage.
- Add a v1.7.3 clarification workflow item that records actual before/after artifact sizes and redaction-test coverage before release notes claim hardening.
- Extend `testinfra/hygiene/wave31_focus_and_gate_test.go` or adjacent hygiene checks so new scan/report fields, sidecars, detector expansions, report sections, or context dimensions fail review unless directly required by Stories 1.1 through 4.2 or all Sprint 0 gates are green.
- Update `CONTRIBUTING.md`, `AGENTS.md`, and `CHANGELOG.md` guidance as needed.
- Keep `product/PLAN_NEXT.md` implementation edits scoped and explicit; do not overwrite rolling plans mechanically.
Repo paths:
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `AGENTS.md`
- `product/PLAN_NEXT.md`
- `testinfra/hygiene/wave31_focus_and_gate_test.go`
Run commands:
- `go test ./testinfra/hygiene -run 'Test.*Wave31|Test.*Freeze|Test.*LaunchTruth|Test.*Changelog' -count=1`
- `make lint-fast`
- `make test-fast`
- `make test-contracts`
Test requirements:
- Tier 1/9 hygiene tests for release-note receipt requirements and surface-area freeze behavior.
- Tier 9 docs/governance contract checks for PR checklist and changelog language.
Matrix wiring:
- Fast lane: hygiene tests and `make lint-fast`.
- Core CI lane: `make test-contracts`.
- Acceptance lane: not required unless command examples are changed.
- Cross-platform lane: not required unless path parsing is added to hygiene tests.
- Risk lane: not required unless release workflow policy is changed.
Acceptance criteria:
- A PR adding unrelated scan/report surface area fails the hygiene gate while Sprint 0 gates are incomplete.
- Release-note claims about size, privacy, redaction, customer safety, or readability require measured evidence.
- Governance docs explain the temporary freeze without weakening Wrkr's scope or deterministic constraints.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Required measured receipts for size, redaction, privacy, and customer-safe release claims, and added a temporary freeze gate for new scan/report surface expansion until Sprint 0 gates pass.
Semver marker override: [semver:patch]
Contract/API impact: Changes contribution/release governance, not runtime CLI API.
Versioning/migration impact: No artifact migration; release-note discipline changes apply immediately to implementation PRs.
Architecture constraints: Preserve Wrkr-only scope and do not use governance docs to authorize new Axym/Gait feature work.
ADR required: no
TDD first failing test(s): `TestWave31FreezeBlocksNewSurfaceBeforeSprint0Gates` and `TestChangelogPrivacyClaimsRequireMeasuredReceipts`.
Cost/perf impact: low
Chaos/failure hypothesis: A broad new report field should be blocked by hygiene tests until it names a Sprint 0 gate or the gate status is green.

## Wave 2: Canonical Refs And Safe-By-Default Privacy

Objective: remove repeated payload clones and make customer-safe sharing the default posture.
Traceability: Recommendations 2 and 3.

### Story 2.1: Delete Remaining Embedded Endpoint And Authority Payload Clones

Priority: P0
Recommendation coverage: 2
Tasks:
- Make `MutableEndpointSemanticRefs`, `CredentialAuthorityRef`, and `AuthorityBindingRefs` the canonical joins across graph nodes, action paths, BOM items, backlog rows, action surface registry entries, privilege budget rows, workflow chains, and report projections.
- Remove repeated `CloneMutableEndpointSemantics`, `CloneCredentialAuthority`, and `CloneAuthorityBindings` assignments from projection builders where canonical refs are available.
- Keep full endpoint/authority objects only in canonical per-scan stores or explicitly internal non-shareable diagnostic surfaces.
- Update report, redaction, appendix, and evidence rendering to resolve refs only when detail is requested.
- Add compatibility handling and schema/version notes for downstream consumers that currently expect embedded objects.
Repo paths:
- `core/aggregate/inventory/canonical_refs.go`
- `core/aggregate/inventory/endpoint_semantics.go`
- `core/aggregate/inventory/credential_authority.go`
- `core/aggregate/inventory/authority_binding.go`
- `core/aggregate/attackpath/graph.go`
- `core/risk/action_paths.go`
- `core/risk/workflow_chain.go`
- `core/report/agent_action_bom.go`
- `core/report/action_surface_registry.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/aggregate/privilegebudget/authority.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/report/build.go`
- `core/report/redaction_summary.go`
- `schemas/v1`
Run commands:
- `go test ./core/aggregate/... -count=1`
- `go test ./core/risk/... -count=1`
- `go test ./core/report/... -count=1`
- `go test ./core/cli -run 'Test.*ReportContract|Test.*ScanOutputSignal' -count=1`
- `make test-contracts`
- `make test-scenarios`
Test requirements:
- Tier 1 unit tests for ref preservation and resolver behavior.
- Tier 2 integration tests proving canonical stores contain full detail once while projections carry refs.
- Tier 9 schema/golden compatibility tests for removed embedded payloads and artifact version markers.
- Tier 11 scenario checks from Story 1.1 proving artifact size drops under endpoint-heavy inputs.
Matrix wiring:
- Fast lane: targeted `core/aggregate`, `core/risk`, and `core/report` tests.
- Core CI lane: `make prepush-full` and `make test-contracts`.
- Acceptance lane: `make test-scenarios`.
- Cross-platform lane: required for stable serialized ordering.
- Risk lane: `make test-perf` and `make test-chaos` for malformed/missing ref stores.
Acceptance criteria:
- Repeated projections contain canonical refs and no full mutable endpoint, credential authority, or authority-binding payload clones by default.
- Internal detail views can resolve refs deterministically from the canonical store.
- Schema/docs/changelog describe the compatibility transition.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed large scan projections to use canonical endpoint and authority references instead of repeated embedded payloads, reducing saved-state and BOM artifact size.
Semver marker override: [semver:minor]
Contract/API impact: Potentially breaking for consumers that depended on embedded projection payloads; requires explicit compatibility/versioning coverage.
Versioning/migration impact: Bump relevant artifact schema/version markers or add reader fallback so older saved states remain readable.
Architecture constraints: Aggregation owns canonical stores; Risk and Report must consume refs without re-owning source detail.
ADR required: yes
TDD first failing test(s): `TestCanonicalRefsReplaceEmbeddedAuthorityPayloadsAcrossProjections` and `TestLegacyEmbeddedAuthorityStateStillReads`.
Cost/perf impact: medium
Chaos/failure hypothesis: Missing or corrupt canonical refs should produce deterministic degraded detail or validation errors, not panic or silently rehydrate wrong authority.

### Story 2.2: Make Owner Masking Safe By Default

Priority: P0
Recommendation coverage: 3
Tasks:
- Require explicit `--share-profile internal` or equivalent for cleartext owners, reviewers, identity labels, local paths, provider/account-like subjects, and credential subjects.
- Mark internal artifacts as non-shareable in artifact metadata and docs.
- Extend redaction rules across rendered Markdown, BOM JSON, evidence JSON, redaction summary, report appendices, exported bundles, provenance redaction, and paired artifact outputs.
- Add leak tests using fake but realistic owner handles, reviewer names, account subjects, local paths, repo names, and identity labels.
- Preserve internal remediation usefulness by keeping cleartext detail available only under explicit internal profile.
Repo paths:
- `core/cli/report.go`
- `core/cli/evidence.go`
- `core/report/redaction.go`
- `core/report/redaction_summary.go`
- `core/report/provenance_redaction.go`
- `core/report/build.go`
- `core/report/agent_action_bom.go`
- `docs/commands/report.md`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
Run commands:
- `go test ./core/report -run 'Test.*Redaction|Test.*ShareProfile|Test.*Owner|Test.*Leak' -count=1`
- `go test ./core/cli -run 'Test.*Report.*ShareProfile|Test.*Assess.*ShareProfile' -count=1`
- `go test ./core/cli -run 'Test.*Evidence.*ShareProfile|Test.*Evidence.*Redaction|Test.*Evidence.*Owner' -count=1`
- `go test ./internal/acceptance -run 'Test.*Redaction|Test.*Shareable|Test.*AgentActionBOM' -count=1`
- `make test-hardening`
- `make test-contracts`
Test requirements:
- Tier 1 redaction-selector and profile tests.
- Tier 3 CLI share-profile contract tests for direct report, assess, and evidence command output.
- Tier 4 acceptance leak tests across Markdown, BOM JSON, evidence JSON, and exports.
- Tier 5 fail-closed tests for unknown or ambiguous share profiles.
- Tier 9 schema and docs parity checks.
Matrix wiring:
- Fast lane: focused redaction tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: shareable-output acceptance tests.
- Cross-platform lane: required for local path masking.
- Risk lane: `make test-hardening`.
Acceptance criteria:
- Default/shareable outputs mask all owner-like and account-like tokens from the Story 1.1 fixture.
- Internal profile outputs are clearly marked non-shareable and require explicit selection.
- Docs and schema metadata describe the profile behavior.
Changelog impact: required
Changelog section: Security
Draft changelog entry: Made shareable/default report and BOM artifacts redact owners, reviewers, identity labels, local paths, and account-like subjects unless an explicit internal profile is selected.
Semver marker override: [semver:patch]
Contract/API impact: Changes default shareable artifact visibility and metadata semantics; CLI flags remain compatible.
Versioning/migration impact: No schema break expected if metadata is additive, but golden outputs and docs must be updated.
Architecture constraints: Report/evidence owns redaction; Detection and Risk must not pre-redact canonical facts.
ADR required: yes
TDD first failing test(s): `TestShareableDefaultMasksOwnerLikeTokensAcrossArtifacts` and `TestInternalProfileIsExplicitAndNonShareable`.
Cost/perf impact: low
Chaos/failure hypothesis: Unknown share profile or ambiguous redaction state should fail closed rather than emitting partially redacted artifacts.

## Wave 3: Bounded State, Stdout, And Scoring Signal

Objective: prevent combinatorial output growth and keep saved state/scoring focused on real governance signal.
Traceability: Recommendations 4, 5, and 7.

### Story 3.1: Cap Derived Collections At Generation And Finish Streaming Output

Priority: P0
Recommendation coverage: 4, 5
Tasks:
- Deduplicate and cap action paths, workflow chains, graph nodes/edges, backlog rows, BOM items, ranked findings, inventory previews, exposure groups, and repeated evidence links before serialization.
- Emit deterministic ordering, top-N selection rationale, stable refs, and `suppressed_count` metadata for every capped collection.
- Keep complete canonical stores only where required for determinism, drift, verification, or explicit internal detail.
- Replace full findings/inventory arrays in stdout summaries with previews, suppressed counts, and artifact paths.
- Use streaming JSON encoders for large state/report/evidence file sinks instead of whole-blob marshal paths on hot paths.
- Share one bounded-output pattern across scan, report, evidence, and assess.
Repo paths:
- `core/risk/action_paths.go`
- `core/aggregate/attackpath/graph.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/aggregate/agentresolver/workflow_chain.go`
- `core/report/agent_action_bom.go`
- `core/report/signal_hardening.go`
- `core/cli/jsonmode.go`
- `core/cli/scan.go`
- `core/cli/report.go`
- `core/cli/evidence.go`
- `core/cli/assess.go`
- `core/cli/managed_artifacts.go`
Run commands:
- `go test ./core/risk ./core/aggregate/... ./core/report -run 'Test.*Cap|Test.*Suppressed|Test.*Bounded|Test.*Streaming' -count=1`
- `go test ./core/cli -run 'Test.*ScanOutputSignal|Test.*JSONMode|Test.*ReportContract|Test.*Evidence|Test.*Assess' -count=1`
- `go test ./internal/acceptance -run 'Test.*Large|Test.*BOM|Test.*Report' -count=1`
- `make test-perf`
- `make test-chaos`
Test requirements:
- Tier 1 cap and deterministic top-N tests.
- Tier 2 integration tests for bounded projections across risk/report/evidence.
- Tier 3 CLI stdout contract tests for scan/report/evidence/assess.
- Tier 5 interrupted-write and unsafe-path hardening tests.
- Tier 6 chaos tests for partial streaming writes and malformed canonical stores.
- Tier 7 performance tests for large fixtures.
Matrix wiring:
- Fast lane: focused cap/output tests.
- Core CI lane: `make prepush-full`.
- Acceptance lane: large-output acceptance tests.
- Cross-platform lane: required for file path and newline behavior.
- Risk lane: `make test-chaos` and `make test-perf`.
Acceptance criteria:
- Bounded stdout never emits full large arrays from the Story 1.1 fixture.
- Full artifacts are written by streaming file sinks and include suppression metadata.
- Repeated collection caps are deterministic and visible to users.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Bounded large scan/report/evidence stdout previews and capped derived collections at generation while streaming full artifacts to disk with explicit suppression metadata.
Semver marker override: [semver:patch]
Contract/API impact: Changes stdout shape for large outputs while preserving machine-readable summary contracts and artifact handoff fields.
Versioning/migration impact: Update docs and golden fixtures; add compatibility notes for consumers expecting full arrays inline on stdout.
Architecture constraints: CLI owns stdout envelopes; aggregation/risk/report own generation caps before serialization.
ADR required: yes
TDD first failing test(s): `TestLargeScanJSONStdoutIsBoundedWithArtifactPaths` and `TestDerivedCollectionsCarrySuppressedCountsAtGeneration`.
Cost/perf impact: high
Chaos/failure hypothesis: Interrupted streaming writes should leave no mixed or partially trusted managed artifact set.

### Story 3.2: Group Policy Outcomes In Saved State And Scoring Inputs

Priority: P0
Recommendation coverage: 7
Tasks:
- Emit grouped policy results by rule, outcome, severity, and affected scope in saved state, not only in report stdout.
- Preserve per-repo detail through evidence refs or appendix detail where full traceability is required.
- Update scoring inputs so posture-score denominators and finding counts are based on grouped outcomes when policy fanout would otherwise inflate noise.
- Keep stable rule IDs, reason codes, and remediation semantics.
- Add migration/compatibility handling for older saved states that only carry raw per-repo policy findings.
Repo paths:
- `core/policy/eval/eval.go`
- `core/policy/profileeval/eval.go`
- `core/score`
- `core/state/state.go`
- `core/report/signal_hardening.go`
- `schemas/v1/score/score.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/findings/finding.schema.json`
Run commands:
- `go test ./core/policy/... -count=1`
- `go test ./core/score/... -count=1`
- `go test ./core/report -run 'Test.*PolicyOutcome|Test.*Grouped' -count=1`
- `go test ./internal/scenarios -run 'Test.*PolicyOutcome|Test.*PostureScore' -count=1 -tags=scenario`
- `make test-contracts`
Test requirements:
- Tier 1 grouping and denominator unit tests.
- Tier 2 policy-to-score integration tests.
- Tier 3 CLI scan/report/score contract tests for grouped outcomes.
- Tier 9 schema and golden tests for grouped policy result compatibility.
- Tier 11 scenario tests for policy fanout without inflated posture counts.
Matrix wiring:
- Fast lane: `core/policy`, `core/score`, and focused `core/report` tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: policy scenario tests.
- Cross-platform lane: not required unless path examples are serialized.
- Risk lane: `make test-hardening` for malformed policy packs and fail-closed paths.
Acceptance criteria:
- A policy fanout fixture reports grouped outcomes with correct affected-scope counts.
- Posture score and finding counts do not inflate one logical rule failure into many equivalent risks.
- Per-repo traceability remains available through bounded refs or appendices.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Grouped repeated policy outcomes in saved state and scoring inputs so posture counts reflect logical governance failures instead of per-repo fanout noise.
Semver marker override: [semver:patch]
Contract/API impact: Changes saved-state/report/score interpretation of policy outcomes; raw compatibility detail must remain traceable.
Versioning/migration impact: Add reader fallback for older states with only raw policy findings.
Architecture constraints: Policy evaluation emits stable outcomes; Score consumes grouped state without re-evaluating rules.
ADR required: yes
TDD first failing test(s): `TestPolicyFanoutGroupsBeforePostureScoring` and `TestLegacyPolicyFindingsGroupOnRead`.
Cost/perf impact: medium
Chaos/failure hypothesis: Malformed grouped policy state should fail closed or fall back deterministically, not double count and raw count simultaneously.

## Wave 4: Buyer-Readable BOM And Parser Honesty

Objective: make the Agent Action BOM readable by default and make parser coverage truthful on JS/TS-heavy repos.
Traceability: Recommendations 6 and 8.

### Story 4.1: Enforce Agent Action BOM Primary-View Line Budget

Priority: P0
Recommendation coverage: 6
Tasks:
- Define the Agent Action BOM primary-view contract: one-page executive rollup, top action paths, control coverage, unresolved evidence, risk tier, recommended policy posture, and concise next actions.
- Group duplicates and repeated explanations before markdown rendering.
- Remove raw hash-heavy labels, repeated key=value prose, and appendix-level diagnostics from the lead view.
- Push detailed findings, refs, diagnostics, repeated explanations, parser details, and canonical store detail into appendices.
- Add tests that fail when the primary view exceeds the configured line or section budget.
Repo paths:
- `core/report/render_markdown.go`
- `core/report/primary_view.go`
- `core/report/agent_action_bom.go`
- `core/report/primary_view_test.go`
- `docs/commands/report.md`
- `schemas/v1/agent-action-bom.schema.json`
Run commands:
- `go test ./core/report -run 'Test.*PrimaryView|Test.*AgentActionBOM|Test.*MarkdownBudget|Test.*LineBudget' -count=1`
- `go test ./core/cli -run 'Test.*ReportContract|Test.*Assess' -count=1`
- `go test ./internal/acceptance -run 'Test.*AgentActionBOM|Test.*ReportPDF' -count=1`
- `make test-contracts`
Test requirements:
- Tier 1 renderer and primary-view unit tests.
- Tier 3 report/assess CLI contract tests.
- Tier 4 acceptance tests for buyer-readable BOM and PDF/markdown parity where relevant.
- Tier 9 golden markdown and schema tests.
Matrix wiring:
- Fast lane: focused `core/report` tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: BOM/report acceptance tests.
- Cross-platform lane: required for markdown line counting and snapshot stability.
- Risk lane: `make test-perf` for markdown-heavy fixtures.
Acceptance criteria:
- The Story 1.1 BOM fixture stays within the primary-view budget.
- Details remain available in appendices without polluting the lead view.
- Buyer-facing docs describe primary view versus appendix behavior.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Tightened the Agent Action BOM primary view into a bounded buyer-readable rollup with detailed findings, refs, and diagnostics moved to appendices.
Semver marker override: [semver:patch]
Contract/API impact: Changes markdown/report layout and may change golden output snapshots; JSON detail remains available through appendices/evidence artifacts.
Versioning/migration impact: Update markdown golden fixtures and docs; no schema break expected unless section metadata changes.
Architecture constraints: Report rendering consumes already-bounded model data and must not re-rank facts differently from Risk.
ADR required: no
TDD first failing test(s): `TestAgentActionBOMPrimaryViewFitsLineBudget` and `TestPrimaryViewMovesDiagnosticsToAppendix`.
Cost/perf impact: medium
Chaos/failure hypothesis: A markdown-heavy fixture should truncate or appendix details deterministically without dropping top risks.

### Story 4.2: Prove Parser Coverage On JS/TS-Heavy Enterprise Fixtures

Priority: P0
Recommendation coverage: 8
Tasks:
- Add fixtures for modern ESM, generated bundles, Yarn PnP, large package trees, unsupported syntax, and known generated-directory suppression cases.
- Ensure parse failures land in scan quality, detector diagnostics, or debug-only appendix surfaces instead of ranked security findings unless the config itself is actionable.
- Tighten detector scoping so detectors avoid irrelevant/generated files in governance mode and report generated suppression explicitly.
- Emit primary-view coverage status as `complete`, `reduced`, `not_scanned`, or `unsupported_surface` where applicable.
- Prevent negative MCP/WebMCP/agent-surface claims when parser coverage was reduced.
Repo paths:
- `core/detect/parse.go`
- `core/detect/detect.go`
- `core/detect/promptchannel`
- `core/detect/webmcp/detector.go`
- `core/aggregate/scanquality`
- `core/report/render_markdown.go`
- `core/report/primary_view.go`
- `internal/scenarios`
Run commands:
- `go test ./core/detect/... -run 'Test.*Parse|Test.*Generated|Test.*JS|Test.*WebMCP|Test.*Prompt' -count=1`
- `go test ./core/aggregate/scanquality -count=1`
- `go test ./core/report -run 'Test.*ScanQuality|Test.*Coverage|Test.*NegativeClaim' -count=1`
- `go test ./internal/scenarios -run 'Test.*Parse|Test.*ScanQuality|Test.*Coverage' -count=1 -tags=scenario`
- `make test-scenarios`
Test requirements:
- Tier 1 parser/scoping unit tests.
- Tier 2 detector-to-scan-quality integration tests.
- Tier 4 acceptance tests for JS/TS-heavy repositories.
- Tier 5 fail-closed tests for ambiguous high-risk parser failures.
- Tier 9 report/schema tests for coverage statuses and no negative overclaims.
- Tier 11 scenario tests for complete/reduced/not-scanned/unsupported coverage states.
Matrix wiring:
- Fast lane: focused detect, scanquality, and report tests.
- Core CI lane: `make prepush-full` when detector scoping changes.
- Acceptance lane: scenario tests and `make test-scenarios`.
- Cross-platform lane: required for path/generated-directory matching.
- Risk lane: `make test-hardening` for ambiguous parser failure behavior.
Acceptance criteria:
- JS/TS-heavy fixtures produce honest scan-quality coverage without noisy parse-error findings.
- Primary report/BOM language avoids negative claims when detector coverage is reduced.
- Generated and package-manager paths are suppressed deterministically in governance mode.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Verified JS/TS-heavy parser coverage so generated or unsupported syntax is reported as scan-quality context rather than noisy security findings or overconfident negative claims.
Semver marker override: [semver:patch]
Contract/API impact: Changes classification of parser diagnostics and coverage language in scan/report/BOM outputs.
Versioning/migration impact: Update scan-quality/report schemas and golden fixtures if new coverage statuses or fields are introduced.
Architecture constraints: Detection owns parser scope; Report may summarize coverage but must not reinterpret parser failures as risk findings.
ADR required: yes
TDD first failing test(s): `TestJSHeavyGeneratedParseFailuresStayInScanQuality` and `TestReducedCoverageBlocksNegativeMCPClaim`.
Cost/perf impact: medium
Chaos/failure hypothesis: Unsupported syntax in high-cardinality JS trees should not cascade into thousands of findings or a false clean-coverage claim.

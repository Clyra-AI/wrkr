# Adhoc Plan: Stdout, Scale, And Buyer BOM Hardening

Date: 2026-06-14
Profile: `wrkr`
Slug: `stdout-scale-bom-hardening`
Recommendation source: user-provided recommendations covering interactive JSON stdout safety, recursive redaction, endpoint-scale memory and artifact bloat, action-path semantic correctness, and buyer-readable Agent Action BOM output.

All paths in this plan are repo-relative. Developer-specific checkout roots from the source recommendations have been normalized. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, report, evidence, docs, release, or workflow changes.

## Global Decisions (Locked)

- This plan is a Sprint 0 subtractive hardening continuation. It fixes trust, scale, correctness, and readability gaps before new scan/report surface area expands.
- `--state` and `.wrkr/last-scan.json` remain the canonical large scan artifacts. `--json` is a command-response contract, not a replacement for saved state.
- Full machine-readable JSON must remain byte-compatible when stdout is piped or redirected unless a story explicitly versions a schema change. Interactive TTY stdout receives compact summaries by default.
- Shareable and customer-redacted artifacts must fail closed or omit unsafe values when recursive redaction cannot prove safety.
- Public/default outputs must route through one shared finalization path before bytes are written. Writer-specific stripping, capping, or redaction is treated as a regression risk.
- Endpoint-heavy evidence is represented by canonical groups, counts, and bounded samples. Repeated full endpoint arrays or embedded projection payloads are not acceptable in public/default artifacts.
- Graph and analysis construction must avoid cloning large endpoint, credential-authority, or authority-binding payloads into every node. Save-time stripping is not sufficient if peak heap already explodes during analysis.
- Static context surfaces such as OpenAPI specs, route files, generated clients, docs, and dependency-only signals are valuable target context, but they are not eligible top action paths unless joined to a real actor, workflow, credential, MCP/tool, deploy, runtime, or PR/change binding.
- Agent instruction files are first-class governance surfaces with their own owner/review closure language. They must not be described like generic source files or executable CI workflows.
- Default buyer-facing Markdown should answer what to inspect first in under a minute, then move IDs, graph refs, policy outcome noise, and full diagnostics to appendix or opt-in artifacts.
- Every story in this plan changes user-visible behavior, JSON/artifact contracts, schema semantics, risk/report meaning, docs, or release gating. Changelog review is required for every implementation PR.

## Current Baseline (Observed)

- `core/cli/jsonmode.go`, `core/cli/scan.go`, `core/cli/report.go`, `core/cli/evidence.go`, and `core/cli/assess.go` exist as the relevant CLI output surfaces.
- `scan` already writes durable state such as `.wrkr/last-scan.json`, but the recommendation source identifies interactive `--json` stdout as a large-payload operator hazard.
- Existing Sprint 0 work added size, redaction, signal, and canonicalization gates in `internal/acceptance/sprint0_size_signal_acceptance_test.go`, but the recommendation source identifies remaining nested redaction leaks and repeated endpoint ref bloat.
- Enterprise pressure fixtures already exist under `internal/enterprisepressure` and `internal/scenarios`, but they stress repo count more than endpoint density. They did not catch the reported 151M state / 140M evidence shape or the analysis-time OOM.
- The graph, action path, Agent Action BOM, control backlog, and saved-state paths already have canonical-ref concepts, but repeated `mutable_endpoint_semantic_refs` and embedded projection clones can still fan out across graph nodes, action paths, BOM items, and evidence artifacts.
- Report rendering already has primary view, focus, signal hardening, recent PR review, and Agent Action BOM packages, but latest report output can still lead with machine-like IDs, overlong Markdown, and misleading context-only action paths.
- Risk and privilege-budget code currently has repo-wide authority joins that can attach standing credential/source-control context to static context surfaces such as OpenAPI or route files without sufficient direct correlation.
- JS/TS parse-quality fixtures exist, including `internal/scenarios/wave43_js_ts_signal_scenario_test.go`, but the recommendation source asks to keep enterprise-shaped parse coverage verification active and explicitly bounded.
- Relevant implementation and contract surfaces include:
  - CLI/output: `core/cli/jsonmode.go`, `core/cli/scan.go`, `core/cli/report.go`, `core/cli/evidence.go`, `core/cli/assess.go`, `core/cli/report_artifacts.go`
  - Report/evidence: `core/report/agent_action_bom.go`, `core/report/primary_view.go`, `core/report/render_markdown.go`, `core/report/focus.go`, `core/report/signal_hardening.go`, `core/report/recent_pr_review.go`, `core/report/redaction_summary.go`, `core/report/types.go`, `core/evidence/evidence.go`
  - Risk/aggregation/state: `core/risk/action_paths.go`, `core/risk/buyer_projection.go`, `core/risk/govern_first_model.go`, `core/risk/evidence_context.go`, `core/risk/evidence_language.go`, `core/risk/action_path_type.go`, `core/risk/agentic_projection.go`, `core/risk/wave4_projection.go`, `core/aggregate/attackpath/graph.go`, `core/aggregate/controlbacklog/controlbacklog.go`, `core/aggregate/privilegebudget/budget.go`, `core/aggregate/privilegebudget/authority.go`, `core/aggregate/agentresolver/workflow_chain.go`, `core/state/state.go`
  - Scale/scenario/schema/docs: `internal/enterprisepressure/fixture.go`, `internal/scenarios/wave42_enterprise_pressure_scenario_test.go`, `internal/scenarios/wave43_js_ts_signal_scenario_test.go`, `internal/acceptance/sprint0_size_signal_acceptance_test.go`, `schemas/v1`, `docs/commands/scan.md`, `docs/commands/report.md`

## Exit Criteria

- Interactive `wrkr scan --json`, `wrkr report --json`, `wrkr evidence --json`, and `wrkr assess --json` do not dump large JSON payloads to TTY stdout unless the operator explicitly opts into full stdout JSON.
- Piped or redirected stdout preserves full JSON behavior for automation and CI.
- `scan` output and docs clearly identify `.wrkr/last-scan.json` and `--state` as canonical scan artifacts, and describe `--json` as a command-response payload.
- Customer-redacted and shareable artifacts recursively redact owner-like, identity-like, provider-ref, local-path, repo, PR URL, and credential-subject values across nested JSON arrays and free-form evidence strings.
- Endpoint-dense fixtures with 1,000 to 2,000 mutable endpoint semantics complete deterministically, stay within byte and heap budgets, and do not leak embedded projection payloads into shareable outputs.
- Graph nodes, action paths, BOM items, workflow chains, saved state, report JSON, evidence JSON, and assess output carry endpoint group IDs, counts, and bounded samples instead of repeated endpoint ref arrays or embedded full endpoint objects.
- A shared output finalizer backfills refs, strips embedded details when refs exist, applies caps, carries suppression metadata, and runs recursive redaction for shareable profiles before serialization.
- Analysis emits deterministic subphase progress and optional heap receipts for inventory, action paths, control graph, workflow chains, backlog, state finalization, and artifact writes without breaking JSON stdout contracts.
- Top Action Paths include only eligible bound or partially bound executable/governable paths. Static context, generated files, docs, dependency-only signals, and unbound Swagger/OpenAPI routes move to Target Surface Context.
- Repo-wide credential or authority evidence no longer attaches to static context surfaces without same-location, workflow, runtime, MCP/tool, deploy, or explicit authority binding correlation.
- Agent instruction surfaces have dedicated type, owner/review closure guidance, and report language distinct from source/API files and CI workflows.
- Default Markdown leads with a one-page buyer BOM and human-readable "what to look at first" cards, with full IDs, graph refs, policy outcomes, and diagnostics moved to appendices or opt-in exports.
- Action Contract readiness matches actual blockers, path eligibility, and context-only correlation state.
- Focused evidence bundles and recent PR review output become named buyer workflows rather than appendix-style side effects.
- JS/TS parser verification remains bounded on enterprise-shaped fixtures, with parse failures reported as scan-quality coverage facts instead of findings or action paths.

## Public API and Contract Map

- CLI stdout contract:
  - `--json` keeps full machine-readable JSON when stdout is piped or redirected.
  - Interactive TTY stdout defaults to a compact completion summary for large-output commands.
  - A new explicit opt-in such as `--json-stdout=full` is required for full interactive stdout JSON.
  - Compact summaries include artifact paths, suppressed counts, and enough operator next steps to avoid hiding the canonical state location.
- State and command-response contract:
  - `.wrkr/last-scan.json` and `--state` remain canonical scan artifacts.
  - `--json-path` is documented as a command-response payload unless implementation intentionally changes and versions the contract.
- Redaction and share-profile contract:
  - `customer-redacted`, `external-redacted`, focused BOM, and shareable paired artifacts recursively redact nested structured values and free-form evidence strings.
  - Unsafe residual token detection fails closed in shareable profiles.
- Canonicalization and artifact-size contract:
  - Endpoint, credential-authority, and authority-binding projections use canonical stores plus refs or group IDs.
  - Public/default repeated projections may include counts and small deterministic samples, not unbounded arrays.
  - Suppression metadata is explicit through fields such as `suppressed_counts`, `artifact_budget`, `appendix_available`, `focused_bundle_available`, and `full_export_available`.
- Schema and JSON contract:
  - Impacted schemas likely include `schemas/v1/agent-action-bom.schema.json`, `schemas/v1/control-path-graph.schema.json`, `schemas/v1/evidence/evidence-bundle.schema.json`, `schemas/v1/report/report-summary.schema.json`, `schemas/v1/risk/risk-report.schema.json`, and `schemas/v1/cli/command-envelope.schema.json`.
  - Schema additions should be additive when possible. Enum changes require compatibility tests and docs.
- Risk/action-path contract:
  - Add or harden `action_path_eligible` and `action_binding_state` with deterministic states such as `bound`, `partially_bound`, `unbound_context`, and `contradictory`.
  - Static target surfaces move to a first-class Target Surface Context bucket until correlated to a real execution or control path.
  - Action Contract readiness uses deterministic readiness states: `blocked_by_contradiction`, `blocked`, `needs_approval_evidence`, `needs_proof_evidence`, `needs_owner`, `needs_correlation`, `ready_for_report_only`, and `ready_for_control`.
- Report and evidence contract:
  - Default Agent Action BOM Markdown leads with top eligible paths, visible controls, unresolved evidence, and recommended controls.
  - Focused evidence bundles include selected BOM item(s), compact graph refs, lineage, scan coverage summary, closure evidence, and relevant appendix context.
  - Recent PR review output is a named workflow with ranked PR/MR action paths and focus-path drilldown.
- Progress contract:
  - Analysis subphase progress and optional heap stats are emitted only through progress/JSONL surfaces that do not corrupt `--json` stdout.

## Docs and OSS Readiness Baseline

- User-facing docs likely impacted:
  - `CHANGELOG.md`
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/commands/assess.md`
  - `docs-site/public/llms.txt`
  - `docs-site/public/llm/`
- Governance and planning docs likely impacted:
  - `AGENTS.md`
  - `CONTRIBUTING.md`
  - `product/PLAN_NEXT.md`
  - `product/dev_guides.md` only if command or release gates change
- Contract and acceptance surfaces likely impacted:
  - `core/cli/jsonmode_test.go`
  - `core/cli/report_contract_test.go`
  - `core/cli/sprint0_report_contract_test.go`
  - `internal/acceptance/sprint0_size_signal_acceptance_test.go`
  - `internal/scenarios/wave42_enterprise_pressure_scenario_test.go`
  - `internal/scenarios/wave43_js_ts_signal_scenario_test.go`
  - `schemas/v1`
- OSS trust baseline:
  - No implementation PR may commit private customer repo contents, raw owner handles, real PR URLs, real credential subjects, generated binaries, or transient scan reports.
  - Endpoint-dense and JS/TS fixtures must be synthetic or sanitized, reviewable, deterministic, and safe to commit.
  - Changelog or release-note claims about size, privacy, redaction, customer-safe sharing, or readability require measured artifact-size deltas, redaction test names, and fixture coverage receipts in the same PR.

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| 1. Stop full JSON dumps to interactive stdout | P0 | Story 1.1 | Large interactive stdout can crash terminals and confuse canonical artifact usage. | TTY-aware compact completion summaries with explicit full JSON opt-in. | Operators get safe output while automation keeps full JSON. |
| 2. Recursive shareable redaction gate | P0 | Story 1.2 | Nested evidence strings can leak owner-like values. | Recursive redaction plus fail-closed unsafe-token gates. | Customer-safe artifacts become trustworthy by default. |
| 3. Endpoint-dense failing fixture | P0 | Story 2.1 | Existing fixtures missed endpoint fan-out failures. | Synthetic OpenAPI/Swagger route density scenarios and byte/heap assertions. | Scale regressions become reproducible before customer scans. |
| 4. Endpoint ref group projection | P0 | Story 2.2 | Repeated endpoint ref arrays create massive artifacts. | Canonical endpoint groups with IDs, counts, and samples. | Evidence and state size remain bounded and readable. |
| 5. Stop in-memory payload cloning on graph nodes | P0 | Story 2.2 | Save-time stripping does not fix analysis-time OOM. | Graph nodes carry refs/group IDs/counts only. | Peak heap falls before artifact writes. |
| 6. Unified canonical output finalizer | P0 | Story 1.3 | Writers apply different stripping/redaction behavior. | One finalizer for scan, state, report, evidence, paired artifacts, and assess. | Output contracts become uniform across surfaces. |
| 7. Analysis-time caps and route grouping | P0 | Story 2.2 | Route-heavy repos fan out refs and graph nodes. | Group before graph/workflow/backlog expansion. | Readability and memory stay bounded. |
| 8. Analysis subphase progress and heap receipts | P1 | Story 2.3 | Operators cannot tell which analysis step is stuck. | Deterministic progress checkpoints and optional heap stats. | Long scans become diagnosable without corrupting JSON. |
| 9. Primary view coverage join fix | P1 | Story 4.1 | Primary BOM can say not scanned when reduced coverage exists. | Fallback from repo-specific joins to BOM-level compact coverage. | Buyer view is honest and less misleading. |
| 10. Action path eligibility gate | P0 | Story 3.1 | Swagger/source/docs context is being treated as governable action paths. | Require real actor/workflow/credential/runtime/tool binding for top paths. | Top risks stop overclaiming approval needs. |
| 11. Context-surface authority correlation fix | P0 | Story 3.1 | Repo-wide credential signals bleed into static context surfaces. | Restrict authority joins unless directly correlated. | Privilege claims become evidence-backed. |
| 12. Target surface appendix model | P0 | Story 3.2 | Unbound API/routes are useful context but not action paths. | First-class Target Surface Context with correlation status. | Reports preserve context without false actionability. |
| 13. Agent instruction control surface model | P1 | Story 3.2 | AGENTS/CLAUDE/Cursor/Codex surfaces need distinct governance language. | Path-type-specific instruction surface model and closure evidence. | Agent governance findings become accurate. |
| 14. Path-type-specific closure guidance | P1 | Story 3.3 | Generic closure text is wrong for many path types. | Generate closure guidance by path type and binding state. | Remediation becomes specific and credible. |
| 15. Human-readable what-to-look-at-first Markdown | P1 | Story 4.1 | Reports lead with IDs and machine text. | Diagnostic cards with why/evidence/unresolved/action. | Humans can inspect the right thing quickly. |
| 16. Agent Action BOM path-type framing | P1 | Story 3.3 | BOM can imply every finding is agentic. | Distinguish delegated/action-capable paths from supporting context. | Buyer language matches evidence confidence. |
| 17. One-page buyer BOM default | P1 | Story 4.1 | Current Markdown is too long for fast customer review. | Default to top 5 eligible paths and compact unresolved controls. | Design partners get signal in under a minute. |
| 18. Action Contract readiness consistency | P1 | Story 3.3 | Readiness labels can contradict blockers and eligibility. | Deterministic readiness states tied to blockers and correlation. | Contracts are generated only for eligible paths. |
| 19. Evidence suppression and budget metadata | P1 | Story 1.3 | Evidence JSON lacks bounded-output receipts. | Add suppression and artifact-budget metadata. | Customers and tests can see what was intentionally bounded. |
| 20. Focused evidence bundle mode | P1 | Story 4.2 | One issue should not require a huge evidence bundle. | Focused artifact for one path or top 5 eligible paths. | Shareable evidence becomes practical for design partner conversations. |
| 21. Recent PR review lead output | P2 | Story 4.3 | Recent PR review exists as scaffolding but reads like appendix output. | Promote to named buyer workflow with ranked changed paths. | Product promise around recent AI-assisted PRs becomes visible. |
| 22. JS/TS parser coverage verification | P2 | Story 5.1 | Parse quality must stay honest and bounded on enterprise shapes. | Modern JS/TS fixtures with scan-quality, not finding, assertions. | Reduced coverage is visible without becoming noisy risk. |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - `make test-fast`
  - Focused `go test` commands listed under each story.
- Core CI lane:
  - `make prepush-full` for architecture, risk, schema, report/evidence writer, CLI contract, or output finalization changes.
  - `make test-contracts` for JSON shape, schema, artifact, redaction, action-path eligibility, exit-code, and stdout contract changes.
- Acceptance lane:
  - `go test ./internal/acceptance -count=1`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `scripts/run_v1_acceptance.sh --mode=local` when buyer-facing report behavior changes.
- Cross-platform lane:
  - Required for terminal detection, path redaction, artifact path normalization, Markdown wrapping, and deterministic ordering.
  - Use the repo-local cross-platform lane from `product/dev_guides.md`.
- Risk lane:
  - `make test-hardening` for fail-closed redaction, unsafe output, artifact persistence, and ambiguous eligibility behavior.
  - `make test-chaos` for writer finalization, artifact write, progress, or failure-mode changes.
  - `make test-perf` for endpoint-density, grouping, parse fan-out, graph memory, and report-size work.
  - `make codeql` when detector logic, CLI output safety, workflow, or security-sensitive writer behavior changes.
- Release/UAT lane:
  - `make test-release-smoke`
  - `scripts/run_v1_acceptance.sh --mode=release` when release notes, buyer claims, or external docs change.
- Gating rule:
  - Wave 1 lands before user-facing claims about safe interactive JSON, recursive redaction, or bounded evidence.
  - Wave 2 lands before reopening endpoint-heavy customer-scale validation or new scan/report expansion.
  - Wave 3 lands before buyer-facing BOM copy claims actionability for Swagger/API/source-like surfaces.
  - Wave 4 lands after Wave 3 so one-page output is based on corrected eligibility and target-surface semantics.
  - Wave 5 can run in parallel only after Wave 2 fixture infrastructure is available, and must not relax parser coverage honesty.

## Minimum-Now Sequence

- Wave 1 - Operator and artifact safety:
  - Story 1.1 prevents interactive full JSON stdout dumps.
  - Story 1.2 closes recursive redaction leaks.
  - Story 1.3 centralizes output finalization and exposes suppression metadata.
- Wave 2 - Endpoint-scale and analysis visibility:
  - Story 2.1 creates endpoint-dense failing fixtures and receipts.
  - Story 2.2 removes endpoint fan-out from graph/report/state construction.
  - Story 2.3 adds analysis subphase progress and heap receipts.
- Wave 3 - Action-path semantic correctness:
  - Story 3.1 adds eligibility and authority-correlation gates.
  - Story 3.2 adds Target Surface Context and agent instruction surface modeling.
  - Story 3.3 aligns closure guidance, BOM framing, and readiness states.
- Wave 4 - Buyer-ready report and evidence workflows:
  - Story 4.1 fixes primary coverage and one-page default Markdown.
  - Story 4.2 adds focused evidence bundles.
  - Story 4.3 promotes recent PR review to a named workflow.
- Wave 5 - Parser coverage receipts:
  - Story 5.1 keeps JS/TS parser verification bounded and honest.

## Explicit Non-Goals

- No implementation in this plan-only PR.
- No edits to `product/PLAN_NEXT.md` in this plan-only PR.
- No new Axym or Gait product feature implementation.
- No LLM calls in scan, risk, proof, report, evidence, canonicalization, redaction, parser, or test paths.
- No live customer repo acquisition, network scanning, or nondeterministic hosted dependency in default validation.
- No commitment of private scan artifacts, real owner data, real repo URLs, real PR URLs, raw credential subjects, generated binaries, or transient measurement outputs.
- No default full graph or full evidence export expansion as part of buyer Markdown readability work.
- No removal of full JSON for piped or redirected automation unless an explicit versioned migration is approved.

## Definition of Done

- Every recommendation maps to at least one story and at least one deterministic acceptance check.
- Implementation PRs land in dependency order or explicitly document a safe narrower order.
- `scan`, `report`, `evidence`, and `assess` stdout, JSON, artifact, state, and docs contracts are synchronized.
- Recursive redaction and canonical finalization apply before any shareable/default artifact is written.
- Endpoint-heavy fixture receipts include byte-size, suppression, heap or allocation, and runtime evidence where relevant.
- Top Action Paths are eligible, evidence-backed, and distinct from Target Surface Context.
- Buyer-facing Markdown starts with human-readable top issues and keeps default output within the configured signal/noise budget.
- Changelog entries, semver markers, schema docs, and user docs are updated in the same implementation PRs that alter public behavior.
- Fast, contract, acceptance, risk, and release/UAT lanes required by story scope are green or have a documented approved exception.

## Wave 1: Operator And Artifact Safety

Objective: make CLI output safe for interactive operators, then make shareable/default artifact finalization and redaction uniform before later scale and report changes.
Traceability: Recommendations 1, 2, 6, and 19.

### Story 1.1: Suppress Full JSON On Interactive TTY Stdout

Priority: P0
Recommendation coverage: 1
Tasks:
- Add a TTY-aware output policy in `core/cli/jsonmode.go` that distinguishes interactive stdout from piped or redirected stdout.
- For `scan --json`, `report --json`, `evidence --json`, and `assess --json`, emit compact interactive completion summaries when stdout is a TTY and the payload is large or large-output capable.
- Add explicit opt-in such as `--json-stdout=full` for operators who intentionally want full JSON on interactive stdout.
- Keep full JSON unchanged for piped stdout, redirected stdout, and existing CI automation.
- Ensure compact scan summaries name `.wrkr/last-scan.json`, `--state`, `--json-path`, suppressed counts, and next-step artifact paths accurately.
- Update docs to stop recommending `--json` as the default manual workflow for large scans.
Repo paths:
- `core/cli/jsonmode.go`
- `core/cli/scan.go`
- `core/cli/report.go`
- `core/cli/evidence.go`
- `core/cli/assess.go`
- `core/cli/jsonmode_test.go`
- `docs/commands/scan.md`
- `docs/commands/report.md`
Run commands:
- `go test ./core/cli -run 'Test.*JSONMode|Test.*TTY|Test.*Scan.*JSON|Test.*Report.*JSON|Test.*Evidence.*JSON|Test.*Assess.*JSON' -count=1`
- `make test-contracts`
- `make test-focused-scan`
- `make prepush-full`
Test requirements:
- Tier 1 unit tests for TTY detection, opt-in parsing, compact summary formatting, and payload-threshold behavior.
- Tier 3 CLI contract tests proving piped/redirected stdout keeps full JSON and TTY stdout suppresses large payloads.
- Tier 9 contract tests for command-envelope stability and exit-code preservation.
- Docs parity tests for scan/report examples and new opt-in flag wording.
Matrix wiring:
- Fast lane: focused `core/cli` tests plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: focused scan acceptance if manual workflow docs change.
- Cross-platform lane: required because TTY detection differs by platform.
- Risk lane: `make test-hardening` for unsafe output and exit-code preservation.
Acceptance criteria:
- Interactive `--json` on large-output commands prints a compact completion summary with artifact paths instead of a full JSON dump.
- Piped and redirected `--json` output remains full JSON and schema-compatible.
- `--json-stdout=full` or equivalent explicit opt-in restores full interactive stdout JSON.
- Docs identify saved state as canonical for scan artifacts and no longer promote full stdout JSON for manual large-scan workflows.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed interactive `--json` output for large scan, report, evidence, and assess commands to show compact artifact summaries by default while preserving full JSON for pipes, redirects, and explicit full-stdout opt-in.
Semver marker override: [semver:minor]
Contract/API impact: Changes interactive TTY behavior for `--json`; preserves machine-readable stdout behavior for automation.
Versioning/migration impact: Requires docs and compatibility notes for operators who manually relied on full interactive stdout JSON.
Architecture constraints: CLI output policy owns TTY behavior; scan/report/evidence/assess command logic must not duplicate suppression decisions.
ADR required: yes
TDD first failing test(s): `TestJSONModeSuppressesFullPayloadOnTTY`, `TestJSONModeKeepsFullPayloadWhenPiped`, and `TestScanJSONSummaryNamesCanonicalStateArtifact`.
Cost/perf impact: low
Chaos/failure hypothesis: If TTY detection is unavailable or ambiguous, automation safety wins by preserving full JSON for non-interactive stdout and requiring explicit opt-in for terminal dumps.

### Story 1.2: Enforce Recursive Redaction Across Shareable Artifacts

Priority: P0
Recommendation coverage: 2
Tasks:
- Add a recursive redaction pass after artifact construction and before serialization for shareable/default profiles.
- Redact owner-like, identity-like, provider-ref, local-path, repo, PR URL, and credential-subject values in structured fields, nested arrays, maps, and free-form evidence strings.
- Apply unsafe residual-token detection to customer-redacted and external-redacted profiles and fail closed when unsafe values remain.
- Keep internal/debug profiles intentional and clearly separated from shareable outputs.
- Extend acceptance fixtures to include nested owner strings such as `owner=@local/...`, repo paths, PR URLs, provider refs, and credential subjects.
Repo paths:
- `core/report/redaction_summary.go`
- `core/cli/report_artifacts.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/evidence/evidence.go`
- `internal/acceptance/sprint0_size_signal_acceptance_test.go`
- `schemas/v1/evidence/evidence-bundle.schema.json`
Run commands:
- `go test ./core/report -run 'Test.*Redaction|Test.*Owner|Test.*Shareable' -count=1`
- `go test ./core/cli -run 'Test.*Shareable|Test.*ReportContract|Test.*Evidence' -count=1`
- `go test ./internal/acceptance -run 'Test.*Sprint0.*Redaction|Test.*Shareable.*Leak' -count=1`
- `make test-contracts`
- `make test-hardening`
Test requirements:
- Tier 1 recursive walker and token-classification tests.
- Tier 3 CLI contract tests for report, evidence, and assess share-profile behavior.
- Tier 4 acceptance tests that deep-walk JSON and Markdown artifacts.
- Tier 9 schema and redaction metadata contract tests.
- Tier 5 hardening tests for fail-closed unsafe residual behavior.
Matrix wiring:
- Fast lane: focused `core/report`, `core/cli`, and `core/evidence` tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: `go test ./internal/acceptance -count=1`.
- Cross-platform lane: required for path and URL normalization.
- Risk lane: `make test-hardening`.
Acceptance criteria:
- Shareable artifacts contain no cleartext fixture owner handles, repo paths, PR URLs, provider refs, or credential-subject values in nested JSON or Markdown.
- Free-form evidence strings are redacted with deterministic replacements or the shareable write fails closed.
- Internal artifacts can retain intentional cleartext only when the selected profile is not shareable.
Changelog impact: required
Changelog section: Security
Draft changelog entry: Added recursive shareable-artifact redaction and fail-closed residual-token checks for owner, identity, provider, path, repo, PR URL, and credential-subject values.
Semver marker override: [semver:patch]
Contract/API impact: Strengthens shareable redaction guarantees and may replace previously visible values with deterministic redaction tokens.
Versioning/migration impact: No schema break intended; shareable output values become more aggressively redacted.
Architecture constraints: Redaction belongs to report/evidence output finalization and must not mutate authoritative source facts, saved internal state, or proof-chain facts.
ADR required: yes
TDD first failing test(s): `TestShareableArtifactsRedactNestedIdentityValues`, `TestFreeformEvidenceStringsAreRedacted`, and `TestCustomerRedactedProfileFailsOnResidualUnsafeTokens`.
Cost/perf impact: medium
Chaos/failure hypothesis: A deeply nested unsafe string added by a new artifact field should be found by the recursive gate before bytes are written.

### Story 1.3: Centralize Output Finalization And Suppression Metadata

Priority: P0
Recommendation coverage: 6, 19
Tasks:
- Introduce a shared output finalizer for scan JSON, saved state, report JSON, evidence JSON, paired artifacts, and assess output.
- Backfill refs, strip embedded details when refs exist, apply deterministic caps, record suppressed counts, and run recursive redaction for shareable profiles before serialization.
- Add evidence/report metadata fields such as `suppressed_counts`, `artifact_budget`, `appendix_available`, `focused_bundle_available`, and `full_export_available`.
- Ensure `scan --json-path` behavior is documented as command-response output unless implementation intentionally changes the contract.
- Keep finalizer order deterministic: ref backfill, clone stripping, grouping/capping, suppression metadata, redaction, schema validation, write.
Repo paths:
- `core/state/state.go`
- `core/cli/jsonmode.go`
- `core/cli/scan.go`
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `core/cli/evidence.go`
- `core/cli/assess.go`
- `core/evidence/evidence.go`
- `core/report/types.go`
- `schemas/v1/evidence/evidence-bundle.schema.json`
- `schemas/v1/report/report-summary.schema.json`
Run commands:
- `go test ./core/cli -run 'Test.*Scan.*JSON|Test.*Report.*Contract|Test.*Evidence|Test.*Assess' -count=1`
- `go test ./core/evidence -run 'Test.*Bundle|Test.*Suppress|Test.*Finalize' -count=1`
- `go test ./core/report -run 'Test.*Artifact|Test.*Budget|Test.*Suppress' -count=1`
- `go test ./core/state -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 2 integration tests proving all public/default writers invoke the shared finalizer.
- Tier 3 CLI contract tests for scan/report/evidence/assess JSON shape.
- Tier 9 schema tests for suppression and artifact-budget metadata.
- Tier 11 scenario coverage for bounded artifacts on large projections.
Matrix wiring:
- Fast lane: focused `core/cli`, `core/evidence`, `core/report`, and `core/state` tests.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: targeted acceptance for report/evidence artifacts.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf`.
Acceptance criteria:
- Every public/default writer uses the same finalizer before serialization.
- Evidence JSON includes deterministic suppression and artifact-budget metadata when caps are applied.
- Saved state, scan JSON, report JSON, evidence JSON, paired artifacts, and assess JSON share clone-strip and redaction semantics.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Unified scan, state, report, evidence, paired artifact, and assess output finalization with shared suppression and artifact-budget metadata.
Semver marker override: [semver:minor]
Contract/API impact: Adds metadata fields and tightens serialization semantics across public/default outputs.
Versioning/migration impact: Additive schema updates expected; any removed embedded fields require compatibility notes.
Architecture constraints: Finalization is a boundary between internal aggregation/risk construction and public compliance/evidence output.
ADR required: yes
TDD first failing test(s): `TestAllPublicWritersUseSharedOutputFinalizer`, `TestEvidenceBundleIncludesSuppressionMetadata`, and `TestFinalizerRunsBeforeShareableSerialization`.
Cost/perf impact: medium
Chaos/failure hypothesis: If a writer bypasses the shared finalizer, contract tests should detect missing metadata, leaked clones, or unsafe redaction before release.

## Wave 2: Endpoint-Scale And Analysis Visibility

Objective: reproduce endpoint-dense failures, remove analysis-time fan-out, and make long analysis phases observable.
Traceability: Recommendations 3, 4, 5, 7, and 8.

### Story 2.1: Add Endpoint-Dense Failing Fixture And Receipts

Priority: P0
Recommendation coverage: 3
Tasks:
- Generate synthetic OpenAPI/Swagger specs with 1,000 to 2,000 mutable endpoint semantics across route families, methods, and sensitive operation classes.
- Extend enterprise pressure scenarios to assert scan completion, bounded state/evidence bytes, bounded graph ref repetition, and no embedded projection payloads in shareable outputs.
- Capture deterministic before/after receipts for artifact size, suppression counts, route group counts, and scan-quality coverage.
- Keep fixtures synthetic and avoid customer-derived paths, owners, PR URLs, repo names, or credential subjects.
Repo paths:
- `internal/enterprisepressure/fixture.go`
- `internal/scenarios/wave42_enterprise_pressure_scenario_test.go`
- `internal/acceptance/sprint0_size_signal_acceptance_test.go`
- `internal/scenarios`
- `schemas/v1/control-path-graph.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
Run commands:
- `go test ./internal/enterprisepressure -count=1`
- `go test ./internal/scenarios -run 'Test.*Wave42|Test.*Enterprise.*Pressure' -count=1 -tags=scenario`
- `go test ./internal/acceptance -run 'Test.*Sprint0.*Size|Test.*Endpoint.*Dense' -count=1`
- `make test-perf`
- `make test-contracts`
Test requirements:
- Tier 4 acceptance tests for artifact byte budgets and shareable output safety.
- Tier 7 performance checks for route-density scan and analysis budgets.
- Tier 9 contract tests for schema-compatible grouped endpoint output.
- Tier 11 scenario fixtures for endpoint density and graph ref repetition.
Matrix wiring:
- Fast lane: targeted fixture generator tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: scenario and acceptance commands listed above.
- Cross-platform lane: required for path and fixture ordering determinism.
- Risk lane: `make test-perf`.
Acceptance criteria:
- Endpoint-dense synthetic fixtures reproduce the previous fan-out class without customer data.
- Scan, evidence, and saved state stay inside explicit byte budgets.
- Shareable artifacts omit embedded projection payloads and report suppression metadata.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Added endpoint-dense enterprise pressure fixtures and artifact-size receipts to prevent route-heavy scans from regressing into oversized state or evidence outputs.
Semver marker override: [semver:patch]
Contract/API impact: Strengthens acceptance and artifact-budget contracts for endpoint-heavy scans.
Versioning/migration impact: No schema migration expected unless grouped endpoint fields are introduced by Story 2.2 first.
Architecture constraints: Fixtures validate Source, Detection, Aggregation, Risk, and Compliance mapping/evidence output boundaries without live network dependencies.
ADR required: no
TDD first failing test(s): `TestEndpointDenseFixtureStaysWithinArtifactBudgets` and `TestEndpointDenseShareableOutputsDoNotEmbedProjectionPayloads`.
Cost/perf impact: medium
Chaos/failure hypothesis: A route-heavy repo should degrade to grouped context and suppression metadata rather than causing OOM or unbounded artifact writes.

### Story 2.2: Replace Endpoint Fan-Out With Grouped Projections

Priority: P0
Recommendation coverage: 4, 5, 7
Tasks:
- Replace repeated `mutable_endpoint_semantic_refs` arrays on graph nodes, action paths, BOM items, workflow chains, and backlog items with canonical group references.
- Emit fields such as `endpoint_ref_group_id`, `endpoint_ref_count`, route group labels, operation class summaries, and bounded sample lists.
- Stop cloning full mutable endpoint semantics, credential authority, and authority bindings onto graph nodes during analysis.
- Add analysis-time caps and grouping before endpoint-heavy paths expand into graph, workflow, backlog, and report projections.
- Keep detail hydration limited to explicit internal/debug paths and never use it during default graph construction or shareable output.
Repo paths:
- `core/aggregate/attackpath/graph.go`
- `core/risk/action_paths.go`
- `core/report/agent_action_bom.go`
- `core/state/state.go`
- `core/aggregate/agentresolver/workflow_chain.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `schemas/v1/control-path-graph.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
Run commands:
- `go test ./core/aggregate/... -run 'Test.*Graph|Test.*Workflow|Test.*Backlog|Test.*Endpoint' -count=1`
- `go test ./core/risk -run 'Test.*ActionPath|Test.*Endpoint|Test.*Projection' -count=1`
- `go test ./core/report -run 'Test.*AgentActionBOM|Test.*Endpoint|Test.*Projection' -count=1`
- `go test ./core/state -run 'Test.*Endpoint|Test.*Canonical' -count=1`
- `make test-contracts`
- `make test-perf`
- `make prepush-full`
Test requirements:
- Tier 1 grouping and cap unit tests.
- Tier 2 integration tests for graph, workflow, backlog, and BOM projection shape.
- Tier 7 performance tests for heap/alloc reduction on endpoint-dense fixtures.
- Tier 9 schema compatibility and JSON golden tests.
- Tier 11 scenario coverage using Story 2.1 fixtures.
Matrix wiring:
- Fast lane: focused `core/aggregate`, `core/risk`, `core/report`, and `core/state` tests.
- Core CI lane: `make prepush-full` and `make test-contracts`.
- Acceptance lane: endpoint-dense scenario and acceptance suites.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf`.
Acceptance criteria:
- Default graph construction carries endpoint group IDs, counts, and samples rather than full endpoint payloads.
- Public/default artifacts do not repeat thousands of endpoint refs per node or item.
- Endpoint grouping preserves enough context for reports to say how many endpoints and route groups are implicated.
- Peak heap and artifact bytes are measurably lower on endpoint-dense fixtures.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Replaced endpoint-heavy graph and BOM fan-out with grouped endpoint projections that preserve counts and samples without repeated ref arrays or embedded payload clones.
Semver marker override: [semver:minor]
Contract/API impact: Changes JSON/report projection shape for endpoint-heavy graphs, action paths, BOM items, and saved state.
Versioning/migration impact: Requires additive schema updates and compatibility notes for consumers that read repeated endpoint ref arrays directly.
Architecture constraints: Aggregation owns grouped graph projections; Risk and Report consume groups rather than hydrating source payloads.
ADR required: yes
TDD first failing test(s): `TestGraphNodesUseEndpointRefGroups`, `TestActionPathsCapEndpointSamples`, and `TestAgentActionBOMDoesNotRepeatEndpointRefs`.
Cost/perf impact: high
Chaos/failure hypothesis: A single repo with thousands of routes should produce bounded grouped projections even when many graph nodes reference the same target surface.

### Story 2.3: Add Analysis Subphase Progress And Heap Receipts

Priority: P1
Recommendation coverage: 8
Tasks:
- Add deterministic progress checkpoints for inventory, action paths, control graph, workflow chains, backlog, state finalization, and artifact write.
- Emit optional heap stats under progress/JSONL mode without interleaving with or corrupting `--json` stdout.
- Include subphase names and stable counters that let operators distinguish slow parsing from graph expansion, backlog projection, or artifact serialization.
- Add acceptance coverage for long-running endpoint-heavy analysis and progress event ordering.
Repo paths:
- `core/cli/scan.go`
- `core/cli/jsonmode.go`
- `core/cli`
- `internal/acceptance/sprint0_size_signal_acceptance_test.go`
- `docs/commands/scan.md`
Run commands:
- `go test ./core/cli -run 'Test.*Progress|Test.*JSONL|Test.*Scan.*Phase' -count=1`
- `go test ./internal/acceptance -run 'Test.*Progress|Test.*Endpoint.*Dense' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-perf`
Test requirements:
- Tier 1 progress event formatting and phase-order tests.
- Tier 3 CLI tests proving progress/JSONL mode stays separate from `--json` stdout.
- Tier 4 acceptance tests for endpoint-dense long analysis progress.
- Tier 7 performance tests proving heap stats are optional and low overhead.
Matrix wiring:
- Fast lane: focused `core/cli` progress tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: targeted acceptance progress tests.
- Cross-platform lane: required for terminal/progress behavior.
- Risk lane: `make test-hardening` and `make test-perf`.
Acceptance criteria:
- Operators can identify the analysis subphase that is slow or memory-heavy.
- JSON stdout remains valid when progress is enabled through the supported progress/JSONL channel.
- Heap receipts are deterministic enough for diagnostics without becoming a required stable JSON contract for normal output.
Changelog impact: required
Changelog section: Added
Draft changelog entry: Added analysis subphase progress events and optional heap receipts so long scans identify slow or memory-heavy phases without breaking JSON output contracts.
Semver marker override: [semver:minor]
Contract/API impact: Adds progress/JSONL event semantics; must not alter standard `--json` response shape except documented metadata.
Versioning/migration impact: New progress fields or events need docs and contract tests; no migration for default output.
Architecture constraints: CLI progress reports orchestrated phase state; aggregation/risk internals expose stable progress points without leaking raw source data.
ADR required: no
TDD first failing test(s): `TestScanProgressReportsAnalysisSubphases` and `TestProgressJSONLDoesNotCorruptJSONStdout`.
Cost/perf impact: low
Chaos/failure hypothesis: A scan killed during graph expansion should leave enough prior progress events to identify the last completed deterministic subphase.

## Wave 3: Action-Path Semantic Correctness

Objective: stop treating static context as executable action paths, then make closure guidance and readiness match the corrected semantics.
Traceability: Recommendations 10, 11, 12, 13, 14, 16, and 18.

### Story 3.1: Gate Action Path Eligibility And Authority Correlation

Priority: P0
Recommendation coverage: 10, 11
Tasks:
- Add or harden `action_path_eligible` and `action_binding_state` fields with deterministic states: `bound`, `partially_bound`, `unbound_context`, and `contradictory`.
- Require top action paths to join to a real binding such as CI/CD workflow, agent/automation, MCP/tool call, credential use, deploy/publish path, recent PR/change provenance, or runtime evidence.
- Prevent standalone source files, Swagger/OpenAPI specs, routes, generated files, dependency-only signals, and documentation from appearing in Top Action Paths without a binding.
- Restrict repo-wide credential and authority joins for context surfaces unless same-location evidence, workflow invocation, runtime caller, deploy binding, MCP/tool binding, or explicit authority binding exists.
- Add contradiction tests for mismatched authority, stale owner evidence, and unsupported context-only privilege claims.
Repo paths:
- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/risk/govern_first_model.go`
- `core/report/focus.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/privilegebudget/authority.go`
- `internal/scenarios/wave42_enterprise_pressure_scenario_test.go`
- `schemas/v1/risk/risk-report.schema.json`
Run commands:
- `go test ./core/risk -run 'Test.*ActionPath.*Eligible|Test.*Binding|Test.*Authority|Test.*Contradict' -count=1`
- `go test ./core/aggregate/privilegebudget -run 'Test.*Authority|Test.*Context|Test.*Credential' -count=1`
- `go test ./core/report -run 'Test.*BOM|Test.*Focus|Test.*Eligibility' -count=1`
- `go test ./internal/scenarios -run 'Test.*Wave42|Test.*ActionPath.*Eligibility' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 1 risk and privilege-budget unit tests for eligibility and correlation.
- Tier 2 integration tests for report and buyer projection filtering.
- Tier 9 schema tests for new eligibility/binding fields.
- Tier 11 scenario coverage proving Swagger/API context does not become a top action path without binding.
Matrix wiring:
- Fast lane: focused `core/risk`, `core/report`, and `core/aggregate/privilegebudget` tests.
- Core CI lane: `make prepush-full` and `make test-contracts`.
- Acceptance lane: wave42 scenario coverage.
- Risk lane: `make test-hardening` because ambiguous high-risk joins must fail closed.
Acceptance criteria:
- Top Action Paths exclude unbound specs, routes, source files, generated files, dependency-only signals, and docs.
- Static target surfaces do not inherit repo-wide authority unless directly correlated.
- Contradictory or unbound context is represented explicitly and does not receive full action-path closure requirements.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Tightened action-path eligibility and authority correlation so static context surfaces no longer appear as governable top paths without real workflow, credential, tool, runtime, or change bindings.
Semver marker override: [semver:minor]
Contract/API impact: Adds or changes action-path eligibility and binding-state semantics in risk/report JSON and BOM output.
Versioning/migration impact: Consumers may see fewer top action paths and more target-context entries for the same scan.
Architecture constraints: Risk owns action-path eligibility; Aggregation owns authority evidence; Report must not re-promote unbound context.
ADR required: yes
TDD first failing test(s): `TestSwaggerFilesAreUnboundContextWithoutActorBinding`, `TestRepoWideCredentialDoesNotAttachToOpenAPISurface`, and `TestTopActionPathsRequireEligibleBinding`.
Cost/perf impact: medium
Chaos/failure hypothesis: Ambiguous or contradictory authority evidence should demote to unresolved/correlation-needed context instead of producing a false high-privilege action path.

### Story 3.2: Model Target Surfaces And Agent Instruction Control Surfaces

Priority: P0
Recommendation coverage: 12, 13
Tasks:
- Add a first-class Target Surface Context bucket for unbound API specs, route files, data model files, generated clients, plain source targets, and other sensitive context that needs correlation.
- Include repo, file, endpoint group count, sensitive operation classes, target class, owner evidence, and correlation status for target surfaces.
- Treat `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, Codex/Claude/Cursor configs, and skill files as agent instruction control surfaces with distinct messaging.
- Add closure evidence support for instruction surfaces: CODEOWNERS, branch protection export, provider team export, app catalog owner, or customer declaration.
- Ensure target context and instruction surfaces do not inflate agent counts or imply full action contracts unless eligibility is proven.
Repo paths:
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/primary_view.go`
- `core/report/focus.go`
- `core/risk/wave4_projection.go`
- `core/risk/action_path_type.go`
- `core/risk/evidence_context.go`
- `core/detect`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
Run commands:
- `go test ./core/risk -run 'Test.*TargetSurface|Test.*ActionPathType|Test.*Instruction' -count=1`
- `go test ./core/report -run 'Test.*TargetSurface|Test.*Instruction|Test.*AgentActionBOM|Test.*Markdown' -count=1`
- `go test ./core/detect/... -run 'Test.*Agents|Test.*Claude|Test.*Cursor|Test.*Codex|Test.*Skill' -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 1 type-classification tests for target surfaces and instruction surfaces.
- Tier 2 report integration tests for target context sections and instruction messaging.
- Tier 9 schema tests for Target Surface Context and instruction control fields.
- Tier 11 scenario coverage for unbound API and AGENTS/CLAUDE/Cursor/Codex surfaces.
Matrix wiring:
- Fast lane: focused `core/risk`, `core/report`, and detector tests.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: scenario coverage when fixture surfaces are added.
- Risk lane: `make test-hardening`.
Acceptance criteria:
- Unbound API/routes/source targets appear under Target Surface Context with correlation status, not Top Action Paths.
- Agent instruction files produce path-type-specific governance findings and closure requirements.
- Target context and instruction surfaces do not imply agentic execution unless evidence supports it.
Changelog impact: required
Changelog section: Added
Draft changelog entry: Added Target Surface Context and agent instruction control-surface modeling so sensitive static context and agent instruction files receive accurate report placement and closure guidance.
Semver marker override: [semver:minor]
Contract/API impact: Adds new report/BOM sections or fields for target context and instruction control surfaces.
Versioning/migration impact: Additive schema changes expected; report section ordering and classification counts may change.
Architecture constraints: Detection classifies source surfaces; Risk determines eligibility and correlation; Report renders distinct buyer language without changing source facts.
ADR required: yes
TDD first failing test(s): `TestOpenAPIUnboundSurfaceMovesToTargetContext`, `TestAgentsMarkdownIsInstructionControlSurface`, and `TestInstructionSurfaceClosureAcceptsOwnerReviewEvidence`.
Cost/perf impact: medium
Chaos/failure hypothesis: A repo with only API specs and instruction files should produce target/instruction context, not executable action paths or full action contracts.

### Story 3.3: Align Closure Guidance, BOM Framing, And Readiness

Priority: P1
Recommendation coverage: 14, 16, 18
Tasks:
- Generate closure guidance by `action_path_type` and `action_binding_state`.
- Replace generic closure phrases with path-specific language for CI/CD/release paths, agent instruction surfaces, MCP/tool config, target surface context, dependency-only signals, and unknown executable paths.
- Update Agent Action BOM copy to distinguish AI-assisted workflows, agent frameworks, automation bots, CI/CD workflows, agent instruction surfaces, target surface context, plain source-code paths, and unknown executable paths.
- Add deterministic Action Contract readiness states: `blocked_by_contradiction`, `blocked`, `needs_approval_evidence`, `needs_proof_evidence`, `needs_owner`, `needs_correlation`, `ready_for_report_only`, and `ready_for_control`.
- Generate full Action Contracts only for eligible action paths and correlation guidance for target surfaces.
Repo paths:
- `core/risk/evidence_context.go`
- `core/risk/evidence_language.go`
- `core/risk/action_path_type.go`
- `core/risk/agentic_projection.go`
- `core/risk/buyer_projection.go`
- `core/report/focus.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `schemas/v1/agent-action-bom.schema.json`
Run commands:
- `go test ./core/risk -run 'Test.*Closure|Test.*Readiness|Test.*EvidenceLanguage|Test.*ActionContract' -count=1`
- `go test ./core/report -run 'Test.*Closure|Test.*BOM|Test.*Markdown|Test.*PathType' -count=1`
- `go test ./core/aggregate/controlbacklog -run 'Test.*Closure|Test.*Backlog|Test.*Readiness' -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 1 readiness ranking and language generation tests.
- Tier 2 report/control-backlog integration tests.
- Tier 9 schema and golden tests for readiness enum stability.
- Tier 11 scenario coverage when fixture outputs change.
Matrix wiring:
- Fast lane: focused `core/risk`, `core/report`, and `core/aggregate/controlbacklog` tests.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: report/BOM acceptance tests when golden output changes.
- Risk lane: `make test-hardening`.
Acceptance criteria:
- Closure guidance matches path type and binding state.
- BOM language only says agentic when evidence supports agentic execution.
- Blocked or context-only items do not receive readiness labels that imply full contract readiness.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Updated Agent Action BOM closure guidance, path-type framing, and Action Contract readiness so remediation language matches eligibility, blockers, and correlation state.
Semver marker override: [semver:minor]
Contract/API impact: Changes readiness enum semantics and report/BOM language for action contracts and target context.
Versioning/migration impact: Requires schema and docs updates for new readiness states and path-type language.
Architecture constraints: Risk owns readiness decisions; Report renders them; control backlog must not invent a more actionable state than risk provides.
ADR required: yes
TDD first failing test(s): `TestClosureGuidanceDependsOnPathType`, `TestContextOnlySurfaceNeedsCorrelationNotApproval`, and `TestReadinessBlockedByContradictionWins`.
Cost/perf impact: low
Chaos/failure hypothesis: When evidence is contradictory or only contextual, readiness should deterministically choose the most conservative unresolved state.

## Wave 4: Buyer-Ready Report And Evidence Workflows

Objective: make corrected findings readable and shareable through compact default Markdown, focused evidence, and named recent PR review output.
Traceability: Recommendations 9, 15, 17, 20, and 21.

### Story 4.1: Ship One-Page Buyer BOM Default And Coverage Honesty

Priority: P1
Recommendation coverage: 9, 15, 17
Tasks:
- Fix primary BOM coverage joins so reduced scan coverage falls back to BOM-level compact coverage instead of `not_scanned`.
- Add a first Markdown section with diagnostic cards naming the thing to inspect, why it matters, evidence found, evidence unresolved, and recommended action.
- Make default Agent Action BOM Markdown show the human-readable summary, primary workflow/path view, top 5 eligible action paths, unresolved evidence, recommended controls, and before/after governed path.
- Move raw IDs, `xrg-*`, `apc-*`, `loc-*`, graph refs, policy outcome noise, full backlog, and diagnostics to appendix or opt-in sections.
- Add line-count or output-size regression gates for default buyer-facing Markdown.
Repo paths:
- `core/report/primary_view.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/executive_rollup.go`
- `core/report/signal_hardening.go`
- `core/cli/report_artifacts.go`
- `core/report/primary_view_test.go`
- `core/report/render_markdown_test.go`
Run commands:
- `go test ./core/report -run 'Test.*PrimaryView|Test.*Coverage|Test.*Markdown|Test.*AgentActionBOM|Test.*Signal' -count=1`
- `go test ./core/cli -run 'Test.*Report.*Artifact|Test.*BOM|Test.*Markdown' -count=1`
- `go test ./internal/acceptance -run 'Test.*AgentActionBOM|Test.*Sprint0.*Signal|Test.*Buyer' -count=1`
- `make test-contracts`
- `scripts/run_v1_acceptance.sh --mode=local`
Test requirements:
- Tier 1 report model tests for coverage fallback and diagnostic card construction.
- Tier 3 CLI artifact tests for default Markdown section ordering.
- Tier 4 acceptance tests for output-size and readability budgets.
- Tier 9 golden tests for schema-compatible report summaries.
Matrix wiring:
- Fast lane: focused `core/report` and `core/cli` tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: `go test ./internal/acceptance -count=1` and `scripts/run_v1_acceptance.sh --mode=local`.
- Cross-platform lane: required for Markdown wrapping and deterministic ordering.
- Risk lane: `make test-perf` for report rendering on large fixtures.
Acceptance criteria:
- Primary view never says `not_scanned` when reduced scan coverage is available.
- Default Markdown starts with human-readable cards and a one-page buyer BOM.
- Default report length stays within configured signal/noise budgets for endpoint-heavy and design-partner fixtures.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Reworked default Agent Action BOM Markdown into a compact buyer-first view with honest coverage status, top eligible paths, unresolved evidence, and appendix-only diagnostics.
Semver marker override: [semver:minor]
Contract/API impact: Changes default Markdown structure and may alter report summary ordering and coverage wording.
Versioning/migration impact: Docs and examples must be updated; JSON contracts should remain additive unless summary fields change.
Architecture constraints: Report rendering consumes corrected risk eligibility and coverage facts; it must not reclassify source or risk evidence.
ADR required: no
TDD first failing test(s): `TestPrimaryViewFallsBackToBOMCoverage`, `TestBuyerBOMLeadsWithDiagnosticCards`, and `TestDefaultMarkdownKeepsDiagnosticsInAppendix`.
Cost/perf impact: medium
Chaos/failure hypothesis: A large report with many raw refs should still render a compact first-page view without hiding appendices or corrupting deterministic order.

### Story 4.2: Add Focused Evidence Bundle Mode

Priority: P1
Recommendation coverage: 20
Tasks:
- Add focused evidence output for one selected workflow/path or the top 5 eligible action paths.
- Under `--focus-path` or focused BOM mode, emit selected BOM item, compact graph refs, action contract, lineage, scan coverage summary, closure evidence, and relevant appendix context.
- Keep full graph/export opt-in and separate from focused shareable bundles.
- Ensure focused bundles inherit the shared output finalizer, recursive redaction, suppression metadata, and endpoint grouping contracts.
Repo paths:
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `core/report/agent_action_bom.go`
- `core/report/focus.go`
- `core/evidence/evidence.go`
- `schemas/v1/evidence/evidence-bundle.schema.json`
- `docs/commands/report.md`
Run commands:
- `go test ./core/cli -run 'Test.*Focus|Test.*Report.*Evidence|Test.*Bundle' -count=1`
- `go test ./core/report -run 'Test.*Focus|Test.*AgentActionBOM|Test.*Evidence' -count=1`
- `go test ./core/evidence -run 'Test.*Focused|Test.*Bundle|Test.*Redacted' -count=1`
- `make test-contracts`
- `make test-hardening`
Test requirements:
- Tier 1 focus-selection tests.
- Tier 3 CLI tests for `--focus-path` and top-5 focused output.
- Tier 4 acceptance tests for shareable focused artifacts.
- Tier 9 schema and redaction tests for focused evidence bundles.
Matrix wiring:
- Fast lane: focused `core/cli`, `core/report`, and `core/evidence` tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: focused artifact acceptance tests.
- Risk lane: `make test-hardening` and `make test-perf`.
Acceptance criteria:
- A focused bundle for one path or top 5 eligible paths is much smaller than full evidence and contains all context required for review.
- Focused bundles never include unredacted shareable values or unbounded graph refs.
- Full evidence/export remains opt-in.
Changelog impact: required
Changelog section: Added
Draft changelog entry: Added focused evidence bundles for selected paths or top eligible action paths with compact graph context, closure evidence, scan coverage, and bounded shareable metadata.
Semver marker override: [semver:minor]
Contract/API impact: Adds focused evidence output mode and schema metadata.
Versioning/migration impact: Additive CLI and schema surface; docs and examples required.
Architecture constraints: Focus selection belongs to report/evidence output; it must consume existing risk facts and finalization rather than creating a parallel projection.
ADR required: yes
TDD first failing test(s): `TestFocusedEvidenceBundleForPathIncludesCompactContext` and `TestFocusedEvidenceBundleUsesSharedFinalizer`.
Cost/perf impact: medium
Chaos/failure hypothesis: Focusing on a path with many endpoint refs should preserve lineage and counts while staying bounded and redacted.

### Story 4.3: Promote Recent PR Review To A Named Buyer Workflow

Priority: P2
Recommendation coverage: 21
Tasks:
- Promote `--recent-pr-review` output from appendix-style content to a named buyer workflow.
- Lead with ranked PR/MR action paths, changed workflow/config, authority, blast radius, control resolution, unresolved evidence, and draft Action Contract.
- Allow `--focus-path` to drill into one PR path and produce focused evidence through Story 4.2.
- Ensure recent PR review respects action-path eligibility, target context, readiness, and redaction contracts from earlier waves.
Repo paths:
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `core/report/recent_pr_review.go`
- `core/report/render_markdown.go`
- `core/report/agent_action_bom.go`
- `docs/commands/report.md`
Run commands:
- `go test ./core/report -run 'Test.*RecentPR|Test.*ActionContract|Test.*Markdown' -count=1`
- `go test ./core/cli -run 'Test.*RecentPR|Test.*FocusPath|Test.*Report' -count=1`
- `go test ./internal/acceptance -run 'Test.*RecentPR|Test.*Buyer' -count=1`
- `make test-contracts`
Test requirements:
- Tier 1 recent PR projection and ranking tests.
- Tier 3 CLI tests for `--recent-pr-review` and focus drilldown.
- Tier 4 acceptance tests for buyer workflow rendering.
- Tier 9 contract tests for stable output fields and redaction.
Matrix wiring:
- Fast lane: focused `core/report` and `core/cli` tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: recent PR buyer workflow acceptance tests.
- Risk lane: `make test-hardening` if PR provenance includes sensitive refs.
Acceptance criteria:
- Recent PR review output starts with ranked changed paths and buyer-relevant action context.
- Focused PR path drilldown works without requiring full graph export.
- Output uses corrected eligibility/readiness semantics and recursive redaction.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Promoted recent PR review output into a named buyer workflow with ranked changed paths, authority context, unresolved controls, and focus-path drilldown.
Semver marker override: [semver:minor]
Contract/API impact: Changes report output structure for `--recent-pr-review`.
Versioning/migration impact: Docs and examples required; JSON schema additions may be needed for named workflow fields.
Architecture constraints: Recent PR review consumes provenance and risk projections; it must not bypass action eligibility or focused evidence finalization.
ADR required: no
TDD first failing test(s): `TestRecentPRReviewLeadsWithRankedChangedPaths` and `TestRecentPRReviewFocusPathUsesFocusedEvidence`.
Cost/perf impact: low
Chaos/failure hypothesis: Missing or partial PR provenance should produce unresolved evidence and correlation guidance, not a full action contract.

## Wave 5: Parser Coverage Receipts

Objective: keep JS/TS parser coverage honest and bounded as endpoint and report changes land.
Traceability: Recommendation 22.

### Story 5.1: Verify JS/TS Parser Coverage On Enterprise-Shaped Fixtures

Priority: P2
Recommendation coverage: 22
Tasks:
- Add or refresh fixtures for generated JS, modern ESM, top-level await, Yarn/PnP, package scripts, MCP/server declarations, WebMCP, prompt-channel declarations, and route files.
- Assert parse failures stay in `scan_quality`, not findings or action paths.
- Preserve reduced detector coverage honestly in scan and report summaries.
- Track parse-failure volume and detector coverage ceilings on enterprise-shaped fixtures.
- Keep fixtures synthetic or sanitized and avoid copying customer code.
Repo paths:
- `core/detect/parse.go`
- `core/detect/webmcp/detector.go`
- `core/detect/promptchannel`
- `core/detect/routes`
- `internal/scenarios/wave43_js_ts_signal_scenario_test.go`
- `internal/acceptance/sprint0_size_signal_acceptance_test.go`
- `docs/commands/scan.md`
Run commands:
- `go test ./core/detect/... -run 'Test.*Parse|Test.*WebMCP|Test.*PromptChannel|Test.*Routes|Test.*JS|Test.*TS' -count=1`
- `go test ./internal/scenarios -run 'Test.*Wave43|Test.*ParseCoverage|Test.*JSTS' -count=1 -tags=scenario`
- `go test ./internal/acceptance -run 'Test.*ScanQuality|Test.*Parser|Test.*Sprint0' -count=1`
- `make test-perf`
- `scripts/run_v1_acceptance.sh --mode=local`
Test requirements:
- Tier 1 parser and detector tests for modern JS/TS shapes.
- Tier 4 acceptance tests for scan-quality honesty.
- Tier 7 performance tests for parser-failure ceilings.
- Tier 9 contract tests for scan-quality output and non-finding classification.
- Tier 11 scenario coverage for enterprise-shaped JS/TS repos.
Matrix wiring:
- Fast lane: focused `core/detect` tests.
- Core CI lane: `make test-contracts` if scan-quality schema or output fields change.
- Acceptance lane: scenario and acceptance commands listed above.
- Cross-platform lane: required for fixture path handling.
- Risk lane: `make test-perf`.
Acceptance criteria:
- JS/TS parse failures remain bounded on enterprise-shaped fixtures.
- Unsupported syntax and generated files produce scan-quality context, not findings or action paths.
- Reports summarize reduced coverage honestly without overclaiming discovery certainty.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Added enterprise-shaped JS/TS parser coverage verification so unsupported or generated source remains bounded scan-quality context rather than noisy findings or action paths.
Semver marker override: [semver:patch]
Contract/API impact: Strengthens scan-quality and report honesty contracts for JS/TS-heavy repositories.
Versioning/migration impact: No versioned migration expected unless scan-quality fields change.
Architecture constraints: Detection owns parser coverage facts; Risk and Report consume those facts without turning parser limitations into security findings.
ADR required: no
TDD first failing test(s): `TestJSTSParseFailuresStayInScanQuality`, `TestGeneratedRouteFilesDoNotBecomeActionPaths`, and `TestWave43EnterpriseJSTSFixtureStaysBelowParseFailureCeiling`.
Cost/perf impact: medium
Chaos/failure hypothesis: Unsupported JS/TS syntax should degrade to bounded coverage signals and never create false-positive security findings.

## Implementation Handoff

- Expected follow-up command:
  - `Use $plan-implement with plan_path: product/plans/adhoc/PLAN_ADHOC_2026-06-14_192733_stdout-scale-bom-hardening.md`
- Recommended first implementation wave:
  - Start with Story 1.1 and Story 1.2 so operators stop seeing unsafe stdout dumps and shareable artifacts are recursively safe before larger output-shape changes land.
- Recommended first validation bundle:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
  - `go test ./internal/acceptance -count=1`

# Adhoc Plan: Scan Output Signal Hardening

Date: 2026-06-09
Profile: `wrkr`
Slug: `scan-output-signal-hardening`
Recommendation source: user-provided hardening recommendations covering artifact fan-out, finding noise, parser coverage, focused Agent Action BOM output, redaction, progress UX, agentic delivery-system projection, DecisionTrace, and enterprise evidence context.

All paths in this plan are repo-relative. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, report, evidence, docs, release, or workflow changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control sequence. This plan must not add Axym compliance-engine behavior, Gait runtime enforcement, scan-time LLM calls, live private-system probing, or default scan-data exfiltration.
- The root product defect to fix first is per-occurrence emission: cloned endpoint semantics, repo-fanned policy checks, parse errors emitted as findings, and duplicate workflow path rendering. The implementation direction is reference, group, bound, and summarize.
- Sprint 1 buyer-facing BOM defaults are blocked until Sprint 0 reliability and signal gates are green: canonical endpoint references, grouped findings/paths, parser coverage moved into scan quality, bounded collections, and readable markdown output.
- Structured parsing remains mandatory for structured configs. Parser failures are coverage facts unless a relevant config contract truly failed.
- Public CLI JSON, report JSON, evidence JSON, schemas, proof refs, markdown reports, exit codes, and docs are contracts. Additive schema changes are preferred; breaking stdout/report behavior requires a documented schema/version transition.
- Redaction is audience-specific: internal/default output may show useful repo/path context while masking secrets and owners as required; shared output uses deterministic pseudonyms and stricter owner/location/proof ref masking.
- Performance and memory are first-class acceptance gates for scan/report output. Hot-path fan-out changes must include deterministic size, allocation, and top-N suppression tests.
- New enterprise/context features from later waves cannot bypass the surface-area freeze gate. They must improve focused workflow BOM clarity, recurring evidence value, or control-validation evidence while staying inside size/noise budgets.
- Every implementation story in this plan requires changelog review because it changes user-visible output, public contracts, docs, OSS governance posture, or report/evidence semantics.

## Current Baseline (Observed)

- User-provided evidence reports a 1.4 GB scan artifact with roughly 4.47 million `MutableEndpointSemantic` objects caused by endpoint semantics cloned onto graph nodes, action paths, BOM items, registry entries, privilege budget, control backlog, and report redaction paths.
- Reported finding volume is dominated by structural noise: 2,944 per-repo `policy_check` findings and 1,391 `parse_error` findings, representing about 75 percent of the displayed findings.
- Reported parser failures are concentrated in JavaScript: 1,347 of 1,391 parse failures, with 3,208 generated files suppressed and coverage confidence reduced.
- The reported lead view renders opaque hash IDs, repeated templated explanations, and key=value prose, making the "one-page" view hard for a CISO or platform owner to read.
- The reported redaction behavior hashes useful repo/location context in the default lead view while still allowing owners to appear in cleartext elsewhere; this points to redaction by the wrong axis.
- Existing target paths for this plan are present, including `core/aggregate/attackpath/graph.go`, `core/aggregate/inventory/inventory.go`, `core/aggregate/inventory/endpoint_semantics.go`, `core/risk/action_paths.go`, `core/report/agent_action_bom.go`, `core/report/action_surface_registry.go`, `core/aggregate/controlbacklog/controlbacklog.go`, `core/aggregate/privilegebudget/budget.go`, `core/report/build.go`, `core/policy/eval/eval.go`, `core/policy/profileeval/eval.go`, `core/detect/parse.go`, `core/score`, `core/cli/jsonmode.go`, `core/cli/scan.go`, `core/cli/report.go`, `core/cli/evidence.go`, `core/cli/assess.go`, `core/report/render_markdown.go`, `core/report/primary_view.go`, `core/report/redaction.go`, `core/cli/scan_progress.go`, `internal/scenarios`, `internal/acceptance`, and `schemas/v1/report`.
- The implementation must reproduce the reported behavior with sanitized fixtures or generated synthetic state before changing output semantics. Customer/private scan outputs, raw secrets, private owners, raw prompts, private proof chains, and transient reports must not be committed.

## Exit Criteria

- Endpoint semantics, credential authority, authority bindings, and related mutable endpoint facts are stored once per scan in canonical ID-keyed stores; graph nodes, action paths, BOM items, registry entries, budgets, backlog rows, and report sections reference IDs instead of cloning full endpoint lists.
- Policy checks are grouped by rule/outcome/affected repos; duplicate workflow paths are grouped by path identity with occurrence counts; parse errors are removed from `findings[]` and represented in `scan_quality`.
- Action paths, control path graph nodes/edges, workflow chains, control backlog, Agent Action BOM items, high-stakes presets, action lineage, and serialized report sections have deterministic caps, top-N ordering, and explicit `suppressed_count` fields.
- `--json` stdout emits a bounded machine-readable summary by default, while full report/evidence artifacts are written to explicit output paths using streaming encoders. Any contract transition is versioned and documented.
- Scan/report lead views state coverage plainly, render focused BOM output in human-readable prose, avoid repeated templated explanations, and keep markdown under the configured length budget.
- Redaction profiles are audience-correct and fail closed when a shared profile would leak owners, repo/location names, credential subjects, proof refs, or sensitive source context.
- Progress rendering can show a live progress bar on stderr while stdout carries JSON, with explicit events mode still available for CI.
- Focused BOM becomes the default buyer-facing report experience only after the hardening gates above are passing.
- Later agentic delivery-system fields, DecisionTrace records, runtime/model/host fields, state-retention posture, identity read-model, precedent records, and harness/eval coverage land only behind size/signal regression fixtures and schema/docs parity.

## Public API and Contract Map

- CLI contracts:
  - Preserve exit codes `0` through `8`: success, runtime failure, verification failure, policy/schema violation, approval required, regression drift, invalid input, dependency missing, and unsafe operation blocked.
  - `wrkr scan --json`, `wrkr report --json`, `wrkr evidence --json`, and `wrkr assess --json` must emit bounded stdout summaries when full artifacts are routed to disk. Any one-release deprecation warning must be machine-readable and documented.
  - `--json-path`, report output paths, evidence output paths, and markdown/PDF targets must use streaming writes and fail closed on unsafe output paths.
  - Progress display resolves independently for stderr TTYs, stdout JSON, `--quiet`, and explicit events mode.
- JSON and schema contracts:
  - Add or update schemas under `schemas/v1/report`, `schemas/v1/risk`, `schemas/v1/findings`, `schemas/v1/evidence`, and `schemas/v1/identity` for canonical references, grouped policy outcomes, scan-quality parse summaries, bounded summaries, suppression counts, DecisionTrace records, runtime/model/host context, state-retention posture, and precedent refs.
  - Stable IDs must be deterministic from normalized evidence, not display prose.
  - No existing v1 fields may be removed without explicit compatibility handling and docs.
- Detection, aggregation, risk, and report boundaries:
  - Detection owns source parsing and detector-specific parse diagnostics.
  - Aggregation owns canonical endpoint stores and repo/tool rollups.
  - Risk owns action path identity, prioritization, amplification, grouping, lineage, and DecisionTrace projection.
  - Proof emission owns record creation, signing, and chain append; report/evidence layers reference proof records instead of re-deriving proof state.
  - Compliance/evidence output owns portable evidence packaging and framework mapping.
- Proof and evidence contracts:
  - Existing proof record types remain stable: `scan_finding`, `risk_assessment`, `approval`, and `lifecycle_transition`.
  - A new `decision_trace` proof record type requires schema, verify, chain, docs, changelog, and compatibility coverage before emission.
  - Evidence artifacts must remain portable, deterministic, auditable, and free of raw secrets or private source payloads.
- Documentation contracts:
  - Public behavior changes must update `README.md`, relevant files in `docs/commands/`, schema docs, trust/privacy docs, examples, and `CHANGELOG.md`.
  - Machine-readable examples must use profile command anchors such as `wrkr scan --json`, `wrkr regress run --baseline <baseline-path> --json`, and `wrkr score --json`.

## Docs and OSS Readiness Baseline

- User-facing docs likely impacted:
  - `README.md`
  - `CHANGELOG.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/commands/assess.md`
  - `docs/commands/score.md`
  - `docs/examples/quickstart.md`
  - `docs/examples/operator-playbooks.md`
  - `docs/architecture.md`
  - `docs/contracts/compatibility_matrix.md`
  - `docs-site/public/llms.txt`
  - `docs-site/public/llm/`
- Contract and scenario assets likely impacted:
  - `schemas/v1/report`
  - `schemas/v1/risk`
  - `schemas/v1/findings`
  - `schemas/v1/evidence`
  - `schemas/v1/identity`
  - `internal/scenarios`
  - `internal/acceptance`
  - `scenarios/wrkr`
  - `testinfra/contracts`
  - `testinfra/hygiene`
- OSS trust baseline:
  - Do not commit the reported 1.4 GB scan, private org names, private owners, raw source snippets, credential material, private proof chains, private session data, generated binaries, or transient reports.
  - Reproduce failure classes using sanitized fixtures, generated synthetic scans, or checked-in reduced fixtures with fake owners/repos/credentials.
  - Public examples must show usefulness without leaking identity. Shared profiles must pseudonymize; internal examples can use fake human-readable names.
  - Size/noise gates must be deterministic and runnable without network access.
- Docs must answer:
  - Why findings are grouped and how to inspect affected repos.
  - Where parse failures appear and how coverage affects confidence.
  - What stdout summary contains versus full artifact files.
  - How suppressed counts, top-N caps, and canonical references work.
  - Which redaction profile to use for internal review versus sharing.
  - Why focused BOM is the default and where appendices/evidence JSON live.

## Recommendation Traceability

| Recommendation / Finding | Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| 1. Eliminate cross-cutting detail cloning | P0 | Story 1.2 | Cloned endpoint semantics are the reported root of multi-GB artifacts. | Canonical ID-keyed stores with references from graph, BOM, registry, backlog, and budget. | Large scans become portable and memory-safe. |
| 2. Group and deduplicate replicated findings and paths | P0 | Story 1.3 | Per-repo policy checks and parse errors dominate finding counts. | Group policy/path results and move parse errors to scan quality. | Finding counts become trustworthy and actionable. |
| 3. Bound all unbounded collections | P0 | Story 1.4 | Clone fixes alone do not prevent future combinatorial blowups. | Deterministic top-N caps at generation and serialization. | OOM and unreadable artifacts are prevented by contract. |
| 4. Decouple stdout from artifacts and stream to disk | P0 | Story 1.5 | Full JSON on stdout and whole-blob marshaling can flood terminals and memory. | Summary stdout plus streaming full artifact writers. | CI output and local terminal use stay bounded. |
| 5. Parser robustness and honest coverage | P0 | Story 1.6 | JS parse failures are coverage facts, not user-actionable findings. | Detector-scoped parsing, diagnostic causes, scan-quality coverage line. | Buyers can trust posture confidence. |
| 6. Markdown/BOM budget and lead-view readability | P0 | Story 1.7 | Current lead view is machine dump prose with repeated explanations. | Human-readable focused rollup, dedupe, section budgets. | First report screen becomes buyer-ready. |
| 7. Audience-correct redaction | P0 | Story 1.8 | Useful internal context is hashed while owners can leak elsewhere. | Redaction profiles by audience plus leak checks. | Reports are useful internally and safe externally. |
| 8. Progress bar and `--json` coexistence | P1 | Story 1.9 | stdout JSON and stderr progress can coexist. | Resolve progress mode by stream and explicit flags. | Local scans feel alive without breaking automation. |
| 9. Focused BOM as default experience | P0 | Story 2.1 | First contact should answer the top workflow/control question. | Default `assess`/BOM/report lead with primary focused path. | Buyers see signal before ontology. |
| 10. Projection consolidation pass | P0 | Story 2.2 | Divergent projections break trust and can reintroduce duplication. | One canonical buyer projection layer. | BOM, backlog, graph, evidence, and markdown agree. |
| 11. First-run path simplification | P1 | Story 2.3 | README is accurate but dense. | One path: scan repo, focused BOM, review top path. | Time-to-value improves. |
| 12. Surface-area freeze gate | P0 | Story 2.4 | Product entropy can silently undo signal gains. | PR checklist and automated size/noise/focused-BOM gates. | New surfaces justify their product value. |
| 13. Repeat-usage validation loop | P1 | Story 2.5 | Recurring use is the product risk. | Privacy-preserving local artifact recurrence signals. | Teams can see whether Wrkr becomes a habit. |
| 14. Design-partner control validation | P1 | Story 2.6 | Recurring paid/control value needs a bounded proof loop. | Pilot workflow docs and supported artifact path. | Product validates control-before/after value. |
| 15. Instruction and skillpack change projection | P1 | Story 3.1 | Agent instructions change delivery behavior. | BOM-visible agentic delivery-system change field. | Risk review sees agent changes as governance changes. |
| 16. Instruction-to-authority correlation | P1 | Story 3.2 | The valuable finding is reachable authority, not a bare config diff. | Join instruction/skill changes to action paths and credentials. | High-impact agentic changes are prioritized. |
| 17. DecisionTrace record for high-impact actions | P1 | Story 3.3 | Relevant decision context is scattered across path fields. | Bounded proof-backed DecisionTrace by reference. | Review, audit, and precedent become one compact record. |
| 18. Runtime/model/host neutrality fields | P2 | Story 4.1 | Enterprises use multiple runtimes and models. | Optional evidence-state-aware runtime/model fields. | Wrkr stays provider-neutral. |
| 19. Agent state retention posture | P2 | Story 4.2 | Agent state is the next privacy risk. | Store retention posture refs/digests, not raw contents. | Reports can flag retained state without leaking it. |
| 20. Canonical agent identity read-model | P2 | Story 4.3 | Identity fields exist but need one read-model. | Normalize existing fields under `wrkr:<tool_id>:<org>`. | Reports and DecisionTrace can point to one actor view. |
| 21. Decision precedent model | P2 | Story 4.4 | Prior decisions help future review. | Thin local lookup over prior DecisionTrace records. | Recommendations become context-aware without central state. |
| 22. Harness/resolver/eval config coverage | P2 | Story 4.5 | Agent behavior is shaped by harness and eval files too. | Add bounded detector candidates and validation requirements. | Delivery-control context is visible without becoming an eval platform. |
| 23. Focused BOM acceptance and size/signal regression fixture | P0 | Story 1.1 | The original failure must never regress. | Sanitized endpoint-heavy and repo-heavy fixture with byte/noise assertions. | Sprint 0 fixes stay protected. |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - `make test-fast`
  - Focused package commands listed in each story.
- Core CI lane:
  - `make prepush-full` for architecture, risk, schema, CLI, proof/evidence, and report contract changes.
  - `make test-contracts` for JSON, schema, exit-code, help, evidence, report, and compatibility contracts.
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `scripts/run_v1_acceptance.sh --mode=local` when the default buyer workflow changes.
- Cross-platform lane:
  - Required for CLI output, file path, markdown, evidence artifact, streaming writer, redaction, fixture, and progress-mode changes.
  - Validate stable ordering and path normalization on Linux, macOS, and Windows smoke lanes.
- Risk lane:
  - `make test-hardening` for fail-closed redaction, unsafe output paths, policy/schema violations, parser ambiguity, shared-profile leaks, and artifact boundaries.
  - `make test-chaos` for interrupted streaming writes, corrupt inputs, partial parse coverage, malformed canonical stores, and missing artifact refs.
  - `make test-perf` for endpoint-heavy, repo-heavy, graph-heavy, BOM-heavy, and markdown-heavy scenarios.
  - `make codeql` for security-sensitive scanner logic, CI/workflow changes, generated-code intake, dependency additions, or release-sensitive changes.
- Release/UAT lane:
  - `make test-release-smoke`
  - `scripts/run_v1_acceptance.sh --mode=release` when schemas, docs, CLI help, evidence bundles, report artifacts, or changelog semantics change.
- Gating rule:
  - Story 1.1 must land before Stories 1.2 through 1.9 so every fix has a failing fixture.
  - Stories 1.2 through 1.6 must land before Story 2.1 makes focused BOM the default.
  - Story 1.7 and Story 1.8 must land before buyer-facing docs claim the lead view is share-ready.
  - Story 2.4 must land before any Wave 3 or Wave 4 surface expansion.
  - No story is complete until required changelog, docs, schema, scenario, contract, hardening, chaos, perf, and cross-platform lanes for that story are either green or explicitly documented as not applicable with approval.

## Minimum-Now Sequence

- Wave 1 - Reliability, output, and signal quality:
  - Story 1.1 adds the focused BOM size/signal regression fixture and baselines.
  - Story 1.2 removes endpoint semantic cloning with canonical references.
  - Story 1.3 groups policy findings and duplicate paths, and moves parse errors to scan quality.
  - Story 1.4 adds deterministic collection caps and suppression counts.
  - Story 1.5 decouples stdout summaries from streamed full artifacts.
  - Story 1.6 improves parser robustness and honest coverage.
  - Story 1.7 adds markdown/BOM budgets and readable lead prose.
  - Story 1.8 makes redaction audience-correct and fail-closed.
  - Story 1.9 lets stderr progress coexist with stdout JSON.
- Wave 2 - Focused buyer workflow and product gates:
  - Story 2.1 makes focused Agent Action BOM the default once Wave 1 gates are green.
  - Story 2.2 consolidates buyer projections behind one canonical layer.
  - Story 2.3 simplifies first-run docs around the shortest value path.
  - Story 2.4 adds a surface-area freeze gate and output/noise budgets.
  - Story 2.5 adds local repeat-usage signals.
  - Story 2.6 adds the design-partner control validation workflow.
- Wave 3 - Agentic delivery-system control context:
  - Story 3.1 projects instruction and skillpack changes into the BOM.
  - Story 3.2 correlates those changes to reachable authority.
  - Story 3.3 emits bounded DecisionTrace records for high-impact actions.
- Wave 4 - Enterprise runtime and evidence context:
  - Story 4.1 adds runtime/model/host neutrality fields.
  - Story 4.2 adds agent state-retention posture.
  - Story 4.3 adds the canonical agent identity read-model.
  - Story 4.4 adds thin DecisionTrace precedent lookup.
  - Story 4.5 adds harness/resolver/eval config coverage under the freeze gate.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or other rolling roadmap files.
- No scan-time, risk-time, proof-time, report-time, evidence-time, or docs-generation-time LLM calls.
- No default network calls, live endpoint probing, hosted SaaS backend, billing system, or persistent daemon.
- No Axym product logic or Gait enforcement logic in Wrkr.
- No customer scan outputs, private proof chains, raw source snippets, raw prompt/session payloads, generated binaries, or transient reports committed as fixtures.
- No raw secret extraction, logging, hashing for identity, serialization, or fixture commits.
- No new detector, report mode, graph field, runtime field, or platform surface unless it passes Story 2.4's focused-BOM and size/noise gates.
- No removal of existing v1 JSON/schema fields without explicit compatibility handling.
- No unbounded collection, unbounded markdown section, or whole-report memory marshaling in touched hot paths.

## Epic 1: Reliability, Output, And Signal Quality

Objective: fix the fan-out and noise defects before making the focused BOM the default buyer experience.
Traceability: Recommendations 1 through 8 and 23.

### Story 1.1: Add Focused BOM Size And Signal Regression Fixture

Priority: P0
Recommendation coverage: 23

Tasks:
- Create sanitized endpoint-heavy and repo-heavy fixtures that reproduce the reported failure classes without committing private scan outputs.
- Add acceptance assertions for artifact byte budgets, markdown line budgets, grouped policy outcomes, parse-error placement in scan quality, canonical endpoint references, and redaction behavior.
- Add fixture generation helpers only if checked-in reduced fixtures are insufficient; generated outputs must be deterministic and excluded when transient.
- Record baseline budgets in tests and docs comments: full scan/report artifacts must stay bounded, stdout summary must stay small, markdown must stay readable, and suppressed counts must be explicit.
- Ensure the fixture can run offline and uses fake repos, owners, credentials, proof refs, workflow names, and endpoint names.

Repo paths:
- `internal/scenarios`
- `internal/acceptance`
- `scenarios/wrkr`
- `core/report/primary_view_test.go`
- `core/cli/report_contract_test.go`
- `core/cli/scan_contract_test.go`
- `testinfra/contracts`

Run commands:
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./internal/acceptance ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-perf`

Test requirements:
- Add failing acceptance tests proving cloned endpoint lists, repo-fanned policy checks, parse errors in `findings[]`, oversized markdown, cleartext shared-profile leaks, and unbounded stdout are defects.
- Add deterministic byte and line count checks with explicit fixture names and stable thresholds.
- Add golden or schema assertions that grouped outputs contain `suppressed_count`, occurrence counts, and scan-quality coverage diagnostics.

Matrix wiring:
- Fast lane: focused scenario contract and `core/report`/`core/cli` contract tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: `scripts/validate_scenarios.sh` and scenario tagged run.
- Cross-platform lane: validate fixture paths, line endings, and stable sort order.
- Risk lane: `make test-hardening` for redaction leaks; `make test-perf` for byte/line budgets.

Acceptance criteria:
- The fixture fails on the current per-occurrence/noise behavior and passes only when output is grouped, referenced, bounded, and redacted correctly.
- No private data or local absolute paths appear in fixtures, goldens, docs, or test output.
- The acceptance fixture is included in the release/UAT gate when default report behavior changes.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Add regression fixtures that prevent oversized, noisy, or unsafe focused BOM and scan output from reappearing.
Semver marker override: [semver:patch]
Contract/API impact: Adds tests for existing and upcoming report, scan, JSON, markdown, redaction, and scan-quality contracts; no runtime API change by itself.
Versioning/migration impact: none
Architecture constraints: Uses Acceptance, CLI contract, Report, and Compliance mapping/evidence output boundaries without changing runtime data flow.
ADR required: no
TDD first failing test(s): `go test ./internal/scenarios -count=1 -tags=scenario` plus focused `core/report` and `core/cli` contract tests that encode the reported failures.
Cost/perf impact: low for implementation; high leverage because it adds perf budgets.
Chaos/failure hypothesis: If fixture generation or artifact writing is interrupted, tests must fail with clear fixture/setup errors rather than partial goldens.

### Story 1.2: Replace Endpoint Semantic Cloning With Canonical References

Priority: P0
Recommendation coverage: 1

Tasks:
- Introduce a canonical per-scan store for mutable endpoint semantics, credential authority, and authority bindings with deterministic IDs and stable ordering.
- Replace clone assignments in graph nodes, action paths, BOM items, registry entries, privilege budgets, control backlog rows, and report redaction paths with reference IDs.
- Scope node/path endpoint attachments to endpoints actually touched by that node/path, not the full tool surface.
- Add compatibility adapters where existing report/evidence consumers need expanded views, ensuring expansion is bounded and explicit.
- Update schemas and docs for reference fields and any retained expanded summary fields.

Repo paths:
- `core/aggregate/inventory/endpoint_semantics.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/attackpath/graph.go`
- `core/risk/action_paths.go`
- `core/report/agent_action_bom.go`
- `core/report/action_surface_registry.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/report/build.go`
- `schemas/v1/report`
- `schemas/v1/risk`

Run commands:
- `go test ./core/aggregate/inventory ./core/aggregate/attackpath ./core/risk ./core/report ./core/aggregate/controlbacklog ./core/aggregate/privilegebudget -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-perf`
- `make prepush-full`

Test requirements:
- Add unit tests for canonical ID generation, stable sorting, reference lookup, missing reference failure behavior, and per-node endpoint scoping.
- Add contract tests proving no node/path carries a cloned full-tool endpoint list.
- Add performance tests against endpoint-heavy fixtures to assert object count and artifact size stay under budget.
- Add schema/golden tests for reference fields and bounded expanded summaries.

Matrix wiring:
- Fast lane: focused aggregate/risk/report package tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: endpoint-heavy scenario fixture from Story 1.1.
- Cross-platform lane: deterministic IDs and JSON ordering on Linux/macOS/Windows.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf`.

Acceptance criteria:
- Endpoint-heavy scans use references instead of cloning full endpoint lists across graph, BOM, registry, backlog, budget, and report artifacts.
- Missing or dangling endpoint refs fail closed with machine-readable diagnostics.
- Artifact size and allocation budgets improve against the Story 1.1 fixture without losing top-path evidence.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Reduce large scan artifact size by storing endpoint authority details once and referencing them from reports and risk projections.
Semver marker override: [semver:patch]
Contract/API impact: Additive reference fields and bounded expansion behavior in report/risk schemas; existing consumers may need compatibility notes when reading expanded endpoint lists.
Versioning/migration impact: Add schema compatibility notes and fixture migrations for old artifacts that lack canonical stores.
Architecture constraints: Aggregation owns canonical stores; Risk and Report consume references; Proof emission and Compliance mapping do not re-derive endpoint facts.
ADR required: yes
TDD first failing test(s): Contract test asserting no graph node/action path/BOM item carries a cloned full-tool endpoint list.
Cost/perf impact: high positive; hot-path memory and artifact size must be measured.
Chaos/failure hypothesis: Corrupt or missing canonical-store entries must fail closed during report/evidence build instead of silently dropping endpoint context.

### Story 1.3: Group Policy Findings, Duplicate Paths, And Parse Errors

Priority: P0
Recommendation coverage: 2

Tasks:
- Change policy evaluation output from per-repo `policy_check` findings to grouped rule/outcome records with affected repo counts and top example refs.
- Collapse near-duplicate workflow/action paths that differ only by location into one grouped path with deterministic occurrence refs.
- Move parser failures out of `findings[]` into scan-quality coverage summaries unless a relevant config contract genuinely failed.
- Recompute posture-score inputs over grouped findings and explicit coverage confidence.
- Update report rendering and JSON schemas for grouped policy outcomes, grouped paths, and parse-quality summaries.

Repo paths:
- `core/policy/eval/eval.go`
- `core/policy/profileeval/eval.go`
- `core/risk/action_paths.go`
- `core/detect/parse.go`
- `core/score`
- `core/report/build.go`
- `core/report/render_markdown.go`
- `schemas/v1/findings`
- `schemas/v1/report`
- `schemas/v1/score`

Run commands:
- `go test ./core/policy/... ./core/risk ./core/detect ./core/score ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Add policy grouping tests keyed by rule ID, outcome, severity, profile, and affected repo count.
- Add path identity tests proving duplicate locations are grouped while materially different action paths remain separate.
- Add parse-quality tests proving parse errors do not appear in findings arrays and coverage confidence is explicit.
- Add score tests proving grouped findings and reduced coverage affect posture deterministically.

Matrix wiring:
- Fast lane: policy/risk/detect/score package tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: repo-heavy fixture from Story 1.1.
- Cross-platform lane: stable path identity and sorting.
- Risk lane: `make test-hardening` for fail-closed policy/schema behavior.

Acceptance criteria:
- The reported 16 rules across many repos render as grouped policy outcomes, not thousands of findings.
- Duplicate workflow paths render once with occurrence counts and drill-down refs.
- Parser errors appear in scan quality with cause, coverage, suppressed-generated count, and confidence, not as actionable findings.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Reduce finding noise by grouping repeated policy and workflow path results and moving parser failures into scan-quality coverage.
Semver marker override: [semver:patch]
Contract/API impact: Changes finding/report JSON semantics; requires schema updates and compatibility notes for grouped policy/path outputs.
Versioning/migration impact: One-release compatibility/deprecation note for consumers expecting per-repo policy findings or parse errors in `findings[]`.
Architecture constraints: Policy evaluators emit deterministic grouped outcomes; Detection emits parse diagnostics; Risk owns path grouping; Score consumes grouped results.
ADR required: yes
TDD first failing test(s): Contract tests proving per-repo policy fan-out and parse errors in `findings[]` fail.
Cost/perf impact: medium positive; fewer findings reduce scoring/rendering work.
Chaos/failure hypothesis: Ambiguous grouping keys must keep separate findings rather than merging unrelated risks.

### Story 1.4: Bound Collection Generation And Serialization

Priority: P0
Recommendation coverage: 3

Tasks:
- Define deterministic caps for action paths, control path graph nodes/edges, workflow chains, control backlog rows, Agent Action BOM items, high-stakes presets, action lineage, and report sections.
- Enforce caps at generation sites before combinatorial expansion, not only during final serialization.
- Emit explicit `suppressed_count`, top-N criteria, and continuation refs where applicable.
- Add final serialization guardrails that fail closed when a bounded artifact still exceeds configured safety budgets.
- Document caps and inspection paths in command docs.

Repo paths:
- `core/risk/action_paths.go`
- `core/aggregate/attackpath/graph.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/aggregate/agentresolver/workflow_chain.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/cli/report.go`
- `schemas/v1/report`
- `schemas/v1/risk`
- `docs/commands/report.md`
- `docs/commands/scan.md`

Run commands:
- `go test ./core/risk ./core/aggregate/attackpath ./core/aggregate/controlbacklog ./core/aggregate/agentresolver ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-perf`
- `make test-hardening`
- `make prepush-full`

Test requirements:
- Add top-N sorting tests for each bounded collection.
- Add suppression-count schema and golden tests.
- Add perf tests for large path generation and graph rendering.
- Add hardening tests for unsafe cap values, zero caps, malformed configs, and serialization over-budget failures.

Matrix wiring:
- Fast lane: bounded collection package tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: endpoint-heavy and repo-heavy fixture assertions.
- Cross-platform lane: stable sorting and line/byte budgets.
- Risk lane: `make test-hardening`, `make test-chaos`, `make test-perf`.

Acceptance criteria:
- Every previously unbounded collection named in this story has a deterministic cap, explicit suppressed count, and documented ordering rule.
- Path generation stops before combinatorial blowup and never relies solely on final JSON truncation.
- Oversized artifacts fail with clear machine-readable diagnostics rather than OOM or terminal flood.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Add deterministic caps and suppressed counts to large scan/report collections to prevent unbounded artifacts.
Semver marker override: [semver:patch]
Contract/API impact: Additive suppression fields and possible bounded defaults in report/risk schemas.
Versioning/migration impact: Document new default caps and how to inspect suppressed details where supported.
Architecture constraints: Risk/Aggregation bound generation; Report/CLI enforce final artifact safety.
ADR required: yes
TDD first failing test(s): Perf/contract test that current unbounded generation exceeds fixture budget.
Cost/perf impact: high positive; requires measured cap budgets.
Chaos/failure hypothesis: Interrupted or over-budget serialization must leave no partial managed artifact without a failure marker.

### Story 1.5: Split JSON Stdout Summary From Streamed Full Artifacts

Priority: P0
Recommendation coverage: 4

Tasks:
- Replace whole-blob `json.Marshal` paths for full artifacts with streaming `json.Encoder` writes to managed output files.
- Define bounded stdout summary structs for scan, report, evidence, and assess commands.
- Preserve machine-readable `--json` behavior while documenting when full artifacts require explicit output paths.
- Add schema/version handling and a one-release deprecation note if stdout contract changes for existing users.
- Ensure stdout, stderr progress, quiet mode, and error envelopes remain deterministic and CI-friendly.

Repo paths:
- `core/cli/jsonmode.go`
- `core/cli/scan.go`
- `core/cli/report.go`
- `core/cli/evidence.go`
- `core/cli/assess.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/cli`
- `README.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `docs/commands/assess.md`

Run commands:
- `go test ./core/cli ./core/report ./core/evidence -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`

Test requirements:
- Add CLI contract tests for stdout summary shape, output-path full artifact shape, stderr separation, quiet mode, and error envelopes.
- Add crash/interrupt tests for streaming output paths and managed artifact safety.
- Add docs parity tests for `--json`, `--json-path`, and examples.
- Add compatibility tests for schema version/deprecation fields.

Matrix wiring:
- Fast lane: CLI JSON mode tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: local scan/report/evidence scenario path.
- Cross-platform lane: output path handling and newline stability.
- Risk lane: `make test-hardening` and `make test-chaos`.

Acceptance criteria:
- Running `wrkr scan --json` no longer writes multi-GB full payloads to stdout.
- Full artifacts are streamed to disk when requested and are safe on interruption.
- Docs explain the summary/full-artifact split with copy-pasteable commands.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Change JSON command output to prefer bounded stdout summaries and streamed full artifacts on explicit output paths.
Semver marker override: [semver:minor]
Contract/API impact: Public CLI JSON behavior changes; requires schema/version and compatibility notes.
Versioning/migration impact: Include one-release deprecation or compatibility window for consumers expecting full report payloads on stdout.
Architecture constraints: CLI owns stdout/stderr contracts; Report/Evidence own full artifact construction; output paths use managed safe writes.
ADR required: yes
TDD first failing test(s): CLI contract test proving stdout exceeds summary budget and full artifact write is whole-blob allocated.
Cost/perf impact: high positive for memory and terminal safety.
Chaos/failure hypothesis: Disk write interruption must fail closed and not leave a successful JSON summary pointing to a corrupt artifact.

### Story 1.6: Improve Parser Robustness And Coverage Honesty

Priority: P0
Recommendation coverage: 5

Tasks:
- Scope structured parsing attempts by detector and file type so JavaScript/TypeScript source is parsed only by detectors that can produce useful deterministic signals.
- Attach stable diagnostic causes to parse failures and route them to `scan_quality`.
- Track suppressed generated files, attempted files, parsed files, failed files, skipped files, and confidence by language/detector.
- Emit findings only for relevant config parse failures or security-relevant malformed declarations.
- Render a plain coverage line in scan/report/BOM lead views.

Repo paths:
- `core/detect/parse.go`
- `core/detect/detect.go`
- `core/detect/webmcp`
- `core/detect/promptchannel`
- `core/cli/scan.go`
- `core/report/primary_view.go`
- `schemas/v1/report`
- `schemas/v1/findings`
- `docs/commands/scan.md`
- `docs/commands/report.md`

Run commands:
- `go test ./core/detect/... ./core/cli ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`
- `make prepush-full`

Test requirements:
- Add JS/TS-heavy fixture tests covering generated suppression, unsupported parse skip, relevant config parse failure, and coverage confidence.
- Add report/scan JSON tests proving parse errors are absent from findings and present in scan quality.
- Add deterministic diagnostics tests with stable reason codes.
- Add docs parity tests for coverage wording.

Matrix wiring:
- Fast lane: detector parse tests and scan-quality report tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: JS-heavy scenario fixture.
- Cross-platform lane: generated-file path handling and deterministic ordering.
- Risk lane: `make test-hardening` for ambiguous malformed high-risk configs.

Acceptance criteria:
- JS-heavy scans no longer inflate findings with source parse failures.
- Coverage confidence is visible in lead views and JSON summaries.
- Malformed high-risk configs still fail closed or emit actionable findings according to existing command semantics.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Move source parse failures into scan-quality coverage and make parser diagnostics clearer for JavaScript-heavy repositories.
Semver marker override: [semver:patch]
Contract/API impact: Finding arrays and scan-quality schema semantics change; docs and schema examples must be updated.
Versioning/migration impact: Compatibility note for consumers counting `parse_error` findings.
Architecture constraints: Detection emits parse diagnostics; Report/CLI render coverage; Risk/Score consume coverage without treating it as finding noise.
ADR required: yes
TDD first failing test(s): Detector/report test proving current JS parse errors appear as findings.
Cost/perf impact: medium positive due fewer wasted parse attempts and findings.
Chaos/failure hypothesis: Detector-specific parser crashes must produce stable diagnostics and continue where safe, or fail closed for high-risk config contracts.

### Story 1.7: Add Markdown/BOM Output Budgets And Human Lead Prose

Priority: P0
Recommendation coverage: 6

Tasks:
- Add hard markdown section and total line budgets for focused BOM and report lead views.
- Replace key=value machine dumps with severity-led, plain-language executive rollup prose.
- Generate per-path explanations from evidence deltas instead of repeated templates.
- Demote opaque hash IDs to refs/appendices unless a shared profile requires pseudonym display.
- Collapse duplicate paths and repeated rows before rendering.

Repo paths:
- `core/report/render_markdown.go`
- `core/report/primary_view.go`
- `core/report/agent_action_bom.go`
- `core/report/templates`
- `docs/commands/report.md`
- `docs/examples/quickstart.md`

Run commands:
- `go test ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-perf`
- `make prepush-full`

Test requirements:
- Add markdown golden tests for focused BOM lead view, duplicate collapse, severity-led rollups, and line budget enforcement.
- Add tests proving repeated templated explanations are rejected in the focused lead view.
- Add docs examples for readable internal and shared report output.
- Add perf tests for large markdown rendering.

Matrix wiring:
- Fast lane: focused `core/report` markdown tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: focused BOM scenario fixture.
- Cross-platform lane: newline and markdown line count stability.
- Risk lane: `make test-perf`; `make test-hardening` for redaction-sensitive rendered text.

Acceptance criteria:
- The default lead view is readable without opaque key=value prose.
- Markdown report output stays under configured line budgets with explicit suppressed counts.
- Evidence refs remain available for auditors without overwhelming the first page.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Improve focused BOM markdown readability with severity-led prose, duplicate collapse, and output length budgets.
Semver marker override: [semver:minor]
Contract/API impact: Markdown/report presentation contract changes; JSON data remains additive where possible.
Versioning/migration impact: Update docs and report examples for new lead-view format.
Architecture constraints: Report rendering consumes grouped/bounded projections; it must not reintroduce raw detector or risk fan-out.
ADR required: no
TDD first failing test(s): Markdown golden showing repeated templated explanations and over-budget output.
Cost/perf impact: medium positive due bounded rendering.
Chaos/failure hypothesis: Over-budget sections must suppress deterministically and report suppressed counts rather than truncating mid-record.

### Story 1.8: Make Redaction Audience-Correct And Fail-Closed

Priority: P0
Recommendation coverage: 7

Tasks:
- Define internal/default and shared redaction profiles by audience, not blanket hashing.
- Mask owners by default where required; use deterministic pseudonyms for shared profiles; preserve useful fake/internal repo/path context where safe.
- Add fail-closed leak checks for owner names, repo/location names, credential subjects, proof refs, graph refs, private URLs, and source snippets under shared profiles.
- Apply redaction consistently across scan/report/evidence/BOM/provenance summaries.
- Update docs explaining profile selection and examples.

Repo paths:
- `core/cli/report.go`
- `core/report/redaction.go`
- `core/report/redaction_summary.go`
- `core/report/provenance_redaction.go`
- `core/report/primary_view.go`
- `core/report/agent_action_bom.go`
- `docs/commands/report.md`
- `docs/trust/security-and-privacy.md`

Run commands:
- `go test ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Add redaction tests for internal/default, shared, and strict shared profiles.
- Add leak tests for owners, repos, locations, credentials, proof refs, graph refs, private URLs, and source snippets.
- Add report/BOM/provenance golden tests proving consistent pseudonyms across sections.
- Add docs parity tests for redaction examples.

Matrix wiring:
- Fast lane: focused report redaction tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: shared-profile report fixture.
- Cross-platform lane: deterministic pseudonym stability.
- Risk lane: `make test-hardening` mandatory.

Acceptance criteria:
- Internal/default output is useful and secret-safe.
- Shared output is pseudonymized consistently and fails closed on detected leaks.
- Owners do not leak in cleartext unless an explicit, documented, tested profile allows it.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Harden report redaction profiles so shared outputs pseudonymize sensitive identity and location fields consistently.
Semver marker override: [semver:patch]
Contract/API impact: Redaction output semantics and docs change; shared profile tests become contract gates.
Versioning/migration impact: Document behavior changes for users relying on hashed internal views or owner display.
Architecture constraints: Report redaction owns presentation masking; underlying evidence stores remain deterministic and portable.
ADR required: yes
TDD first failing test(s): Shared-profile leak test showing current owner/location mismatch.
Cost/perf impact: low to medium.
Chaos/failure hypothesis: Unknown profile or redaction uncertainty must fail closed rather than emit partially redacted output.

### Story 1.9: Let Progress Rendering Coexist With JSON Stdout

Priority: P1
Recommendation coverage: 8

Tasks:
- Decouple progress-mode resolution from stdout JSON mode.
- Render the live progress bar on stderr when stderr is a TTY and `--quiet`/explicit events mode do not disable it.
- Preserve events mode for CI and non-TTY contexts.
- Add docs and tests for stdout/stderr separation.

Repo paths:
- `core/cli/scan_progress.go`
- `core/cli/scan.go`
- `docs/commands/scan.md`

Run commands:
- `go test ./core/cli -count=1`
- `make test-contracts`
- `make test-focused-scan`
- `make prepush-full`

Test requirements:
- Add TTY/non-TTY tests for progress bar, events mode, `--json`, `--quiet`, and stderr/stdout separation.
- Add CLI contract tests proving stdout remains valid JSON while progress renders to stderr.
- Add docs parity tests for progress mode behavior.

Matrix wiring:
- Fast lane: focused CLI scan progress tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: focused scan smoke.
- Cross-platform lane: terminal behavior smoke where supported.
- Risk lane: not required beyond contract checks unless scan error handling changes.

Acceptance criteria:
- Local `wrkr scan --json` can show progress on stderr without corrupting stdout JSON.
- CI and `--quiet` behavior remains deterministic and documented.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Allow scan progress on stderr while machine-readable JSON remains valid on stdout.
Semver marker override: [semver:minor]
Contract/API impact: CLI stream behavior changes without changing JSON payload semantics.
Versioning/migration impact: Update command docs for progress mode selection.
Architecture constraints: CLI only; no scan/risk/proof data flow changes.
ADR required: no
TDD first failing test(s): CLI test proving current `auto + --json` suppresses the progress bar even when stderr is a TTY.
Cost/perf impact: low.
Chaos/failure hypothesis: Terminal capability detection failures must fall back to events/no progress without corrupting stdout.

## Epic 2: Focused Buyer Workflow And Product Gates

Objective: make the focused workflow BOM the default experience once the reliability and signal-quality foundation is trustworthy.
Traceability: Recommendations 9 through 14.

### Story 2.1: Make Focused Agent Action BOM The Default Buyer Experience

Priority: P0
Recommendation coverage: 9

Tasks:
- Make `wrkr assess` and `wrkr report --template agent-action-bom` lead with `agent_action_bom.summary.primary_view`.
- Move broad rows, raw findings, scan-quality detail, graph/proof refs, and backlog detail to appendices or evidence JSON.
- Ensure the default selected action path is deterministic, severity-led, and backed by grouped findings and coverage confidence.
- Add acceptance tests that default output answers what the workflow can change, what authority it uses, what controls cover it, what proof exists, and what should change.
- Gate this story on Stories 1.2 through 1.7, including collection caps and stdout/artifact splitting, so focused BOM defaults cannot land before every Wave 1 output-safety dependency is in place.

Repo paths:
- `core/report/primary_view.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/cli/report.go`
- `core/cli/assess.go`
- `docs/commands/report.md`
- `docs/commands/assess.md`

Run commands:
- `go test ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-scenarios`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make prepush-full`

Test requirements:
- Add report/assess CLI tests proving focused BOM is first in default output.
- Add scenario tests for selected primary path determinism and appendices.
- Add docs examples for the default focused workflow.

Matrix wiring:
- Fast lane: `core/report` and `core/cli` focused BOM tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: focused BOM acceptance flow.
- Cross-platform lane: markdown/json ordering and path handling.
- Risk lane: `make test-hardening` for redaction and proof refs.

Acceptance criteria:
- First default report screen is a focused, readable workflow BOM.
- Details remain available in evidence JSON and appendices without bloating the lead view.
- The default output is blocked unless Wave 1 gates are green.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Make the focused Agent Action BOM the default report and assess lead view.
Semver marker override: [semver:minor]
Contract/API impact: Default report/assess presentation changes; JSON additions should be additive.
Versioning/migration impact: Update docs and examples for the new default output order.
Architecture constraints: Report/CLI presentation only; Risk and Aggregation must provide already grouped/bounded data.
ADR required: yes
TDD first failing test(s): CLI acceptance test proving current default does not lead with focused BOM.
Cost/perf impact: medium positive through reduced lead rendering.
Chaos/failure hypothesis: Missing primary view data must degrade to a clear coverage/status message, not a raw dump.

### Story 2.2: Consolidate Buyer Projection Logic

Priority: P0
Recommendation coverage: 10

Tasks:
- Audit duplicate derivation of control state, delegation readiness, evidence states, target class, recommendations, authority metadata, and scan quality across BOM, backlog, graph, evidence, and markdown.
- Create one canonical buyer projection package or module aligned to existing architecture boundaries.
- Ensure consumers read canonical projections and reference the canonical endpoint store from Story 1.2.
- Add equivalence tests proving BOM, backlog, graph, evidence, and markdown agree on semantics.

Repo paths:
- `core/risk/agentic_projection.go`
- `core/risk/buyer_projection.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/render_markdown.go`
- `core/evidence/evidence.go`
- `schemas/v1/report`

Run commands:
- `go test ./core/risk ./core/report ./core/aggregate/controlbacklog ./core/evidence -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Add projection parity tests across all consumers.
- Add schema/golden tests for projection fields and refs.
- Add regression tests ensuring no consumer clones endpoint semantics or re-derives conflicting evidence states.

Matrix wiring:
- Fast lane: risk/report/evidence projection tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: focused BOM scenario.
- Cross-platform lane: stable projection IDs and JSON order.
- Risk lane: `make test-hardening` for contradiction and fail-closed evidence states.

Acceptance criteria:
- One canonical projection produces the semantics consumed by BOM, backlog, graph, evidence, and markdown.
- Divergence tests fail if a consumer re-derives conflicting control/evidence/recommendation state.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Consolidate buyer projection semantics so reports, backlog, graph, and evidence artifacts agree.
Semver marker override: [semver:patch]
Contract/API impact: May add canonical projection refs/fields; no intended breaking removal.
Versioning/migration impact: Schema compatibility notes for any renamed or newly canonicalized fields.
Architecture constraints: Risk owns buyer projection; Report/Evidence/Aggregation consume it without boundary leakage.
ADR required: yes
TDD first failing test(s): Cross-consumer parity test showing divergent evidence/control state.
Cost/perf impact: medium positive.
Chaos/failure hypothesis: Partial projection inputs must produce explicit unknown/insufficient evidence states, not inferred certainty.

### Story 2.3: Simplify First-Run Docs Around One Value Path

Priority: P1
Recommendation coverage: 11

Tasks:
- Rewrite first-run docs around one path: scan repo, generate focused BOM, review top path.
- Move evidence-state ontology, scan-quality detail, advanced report modes, and caveats deeper.
- Ensure all commands are copy-pasteable and validated by docs smoke/parity tests.
- Keep local/private/no-egress guarantees prominent without making the first screen dense.

Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/commands/assess.md`
- `docs/contracts/readme_contract.md`

Run commands:
- `make test-focused-docs`
- `make test-docs-consistency`
- `scripts/run_docs_smoke.sh`
- `make prepush-full`

Test requirements:
- Update docs storyline and CLI parity tests.
- Add quickstart smoke validation for the new first-run path.
- Add readme contract checks for no-egress and focused BOM claims.

Matrix wiring:
- Fast lane: docs focused tests.
- Core CI lane: `make lint-fast`, `make test-fast`.
- Acceptance lane: docs smoke and quickstart scenario.
- Cross-platform lane: command examples must avoid shell-specific assumptions where possible.
- Risk lane: not required unless docs change security claims; then run docs trust checks.

Acceptance criteria:
- A new user can follow the first screen from install/scan to focused BOM review.
- Advanced modes are still discoverable without delaying first value.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Simplify first-run documentation around scanning a repo and reviewing the focused Agent Action BOM.
Semver marker override: [semver:minor]
Contract/API impact: Documentation contract only unless commands change.
Versioning/migration impact: none
Architecture constraints: Docs must stay aligned with CLI behavior and no-egress guarantees.
ADR required: no
TDD first failing test(s): Docs storyline/readme contract test for first-run path.
Cost/perf impact: low.
Chaos/failure hypothesis: Docs smoke failures must block docs-only claims about unsupported commands.

### Story 2.4: Add Surface-Area Freeze And Output/Noise Budgets

Priority: P0
Recommendation coverage: 12

Tasks:
- Add product gate language and automated checks requiring new detectors, report modes, graph fields, platform surfaces, and docs claims to state their effect on focused BOM clarity, recurring use, or evidence quality.
- Encode output size, markdown length, finding-noise, and grouped-signal budgets in tests.
- Update PR checklist and product governance docs.
- Ensure Wave 3 and Wave 4 stories cannot land without satisfying the gate.

Repo paths:
- `product/wrkr.md`
- `AGENTS.md`
- `docs/architecture.md`
- `testinfra/contracts`
- `testinfra/hygiene`

Run commands:
- `make test-contracts`
- `make test-focused-docs`
- `make test-perf`
- `make prepush-full`

Test requirements:
- Add hygiene tests for required PR/checklist wording where repo policy can enforce it.
- Add contract/perf tests for output/noise budgets.
- Add docs consistency tests for governance claims.

Matrix wiring:
- Fast lane: hygiene and contract checks.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: focused BOM fixture budget checks.
- Cross-platform lane: budget tests must be path/order stable.
- Risk lane: `make test-perf` mandatory.

Acceptance criteria:
- New surface area has an enforceable product justification and budget impact.
- Existing focused BOM budget tests fail if output regresses into noisy bulk.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Add product governance gates for focused BOM clarity, output size, and finding-noise budgets.
Semver marker override: [semver:minor]
Contract/API impact: Governance/docs/test contract changes; no CLI API change by itself.
Versioning/migration impact: none
Architecture constraints: Product governance must reinforce architecture boundaries and deterministic output constraints.
ADR required: no
TDD first failing test(s): Hygiene/perf tests showing missing surface-area justification or budget regression.
Cost/perf impact: low runtime, medium CI cost.
Chaos/failure hypothesis: Budget gate failures must produce actionable messages with measured values and thresholds.

### Story 2.5: Add Local Repeat-Usage Signals

Priority: P1
Recommendation coverage: 13

Tasks:
- Derive privacy-preserving recurrence signals from local artifacts: baseline used, regress run, assess rerun, drift produced, evidence exported, tickets or action contracts exported.
- Surface non-sensitive counts/status in report summaries without default telemetry or exfiltration.
- Keep signals deterministic and resettable by local artifact deletion.
- Document how recurrence signals help teams validate habit without sending data out.

Repo paths:
- `core/cli/assess.go`
- `core/regress`
- `core/report/focus.go`
- `core/evidence/portable_manifest.go`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/assess.md`
- `docs/commands/regress.md`
- `docs/commands/evidence.md`

Run commands:
- `go test ./core/cli ./core/regress ./core/report ./core/evidence -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Add local artifact fixture tests for recurrence signal derivation.
- Add schema tests for additive report summary fields.
- Add privacy tests proving no raw paths, owners, prompts, source snippets, or private URLs are emitted in shared profiles.

Matrix wiring:
- Fast lane: report/regress/evidence package tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: local recurrence scenario.
- Cross-platform lane: path normalization and artifact discovery.
- Risk lane: `make test-hardening` for privacy and unsafe path behavior.

Acceptance criteria:
- Reports can show repeat-use signals from local artifacts without telemetry.
- Shared profiles redact recurrence details safely.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Add local repeat-usage signals derived from Wrkr artifacts without enabling telemetry.
Semver marker override: [semver:minor]
Contract/API impact: Additive report summary schema fields.
Versioning/migration impact: none
Architecture constraints: Report/Evidence read local artifacts; no network or persistent daemon.
ADR required: no
TDD first failing test(s): Report summary test for missing recurrence signals from known local artifact set.
Cost/perf impact: low.
Chaos/failure hypothesis: Missing or corrupt local artifacts must produce unknown/unavailable signals, not runtime failure unless required by command mode.

### Story 2.6: Define Design-Partner Control Validation Workflow

Priority: P1
Recommendation coverage: 14

Tasks:
- Document a bounded pilot workflow: one repo/workflow or 10 PRs, focused BOM, control coverage, unresolved evidence, draft Action Contract, before/after governed path, rerun after changes.
- Add scenario or example support for the workflow using fake/synthetic data.
- Wire item 13 recurrence signals into the workflow summary.
- Keep process docs separate from runtime enforcement.

Repo paths:
- `docs/examples/operator-playbooks.md`
- `docs/examples/quickstart.md`
- `core/cli/assess.go`
- `core/report/primary_view.go`
- `docs/examples`
- `internal/scenarios`

Run commands:
- `make test-focused-docs`
- `scripts/validate_scenarios.sh`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Add docs smoke tests for the pilot workflow commands.
- Add scenario fixture proving before/after governed path output is deterministic.
- Add privacy checks for synthetic pilot data.

Matrix wiring:
- Fast lane: docs and scenario contract checks.
- Core CI lane: `make lint-fast`, `make test-fast`.
- Acceptance lane: design-partner workflow scenario.
- Cross-platform lane: docs command portability.
- Risk lane: privacy hardening if new report fields are touched.

Acceptance criteria:
- A design partner can run a bounded validation loop without exposing private data by default.
- The docs do not imply runtime enforcement or paid SaaS behavior.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Add a bounded design-partner control validation workflow for focused BOM before/after reviews.
Semver marker override: [semver:minor]
Contract/API impact: Docs and examples; runtime only if assess/report summary wiring changes.
Versioning/migration impact: none
Architecture constraints: Process support only; no Gait enforcement or Axym compliance-engine logic.
ADR required: no
TDD first failing test(s): Docs smoke/scenario test for pilot flow.
Cost/perf impact: low.
Chaos/failure hypothesis: Incomplete pilot artifacts must be reported as unresolved evidence, not success.

## Epic 3: Agentic Delivery-System Control Context

Objective: make changes to instructions, skills, MCP configs, and high-impact actions visible as governed delivery-system changes.
Traceability: Recommendations 15 through 17.

### Story 3.1: Project Instruction And Skillpack Changes Into BOM

Priority: P1
Recommendation coverage: 15

Tasks:
- Add BOM-visible `agentic_delivery_system_change` fields for changes to `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, `.codex/config.*`, skills, MCP configs, and agent rules.
- Include changed artifact, authority impact, reachable tools, credential reach, review state, and recommended control.
- Use detector outputs from Codex, Claude, Cursor, Skills, and MCP surfaces without raw secret extraction.
- Gate display through focused BOM budgets and redaction profiles.

Repo paths:
- `core/detect/codex/detector.go`
- `core/detect/claude/detector.go`
- `core/detect/cursor/detector.go`
- `core/detect/skills/detector.go`
- `core/detect/mcp`
- `core/report/primary_view.go`
- `core/report/agent_action_bom.go`
- `schemas/v1/report`

Run commands:
- `go test ./core/detect/codex ./core/detect/claude ./core/detect/cursor ./core/detect/skills ./core/detect/mcp ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Add detector fixtures for each instruction/skill/config surface.
- Add BOM schema and rendering tests for delivery-system changes.
- Add redaction tests for changed artifacts and owner/reviewer fields.

Matrix wiring:
- Fast lane: detector/report focused tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: agentic delivery-system change scenario.
- Cross-platform lane: path and glob handling.
- Risk lane: `make test-hardening` for secrets and redaction.

Acceptance criteria:
- Instruction and skillpack changes appear as agentic delivery-system changes, not ordinary config trivia.
- Focused BOM remains within size/noise budgets.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Surface instruction and skillpack changes in the Agent Action BOM as agentic delivery-system changes.
Semver marker override: [semver:minor]
Contract/API impact: Additive report/BOM schema fields.
Versioning/migration impact: none
Architecture constraints: Detection emits artifacts; Report projects them through canonical buyer projection; no runtime enforcement.
ADR required: no
TDD first failing test(s): BOM scenario showing instruction change currently lacks delivery-system context.
Cost/perf impact: medium due additional projection fields; must respect budgets.
Chaos/failure hypothesis: Malformed instruction files must produce stable diagnostics and not leak raw content.

### Story 3.2: Correlate Instruction Changes To Reachable Authority

Priority: P1
Recommendation coverage: 16

Tasks:
- Join instruction/skill findings with action paths, workflow capabilities, MCP/tool reachability, credential authority, branch/review state, and PR provenance.
- Rank the valuable finding as reachable authority, not the bare file change.
- Add explanation text for publish/deploy/credential/review-bypass reachability.
- Preserve deterministic grouping and redaction.

Repo paths:
- `core/risk/action_paths.go`
- `core/risk/action_lineage.go`
- `core/aggregate/agentresolver/workflow_chain.go`
- `core/report/agent_action_bom.go`
- `core/report/recent_pr_review.go`
- `schemas/v1/risk`
- `schemas/v1/report`

Run commands:
- `go test ./core/risk ./core/aggregate/agentresolver ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`
- `make prepush-full`

Test requirements:
- Add fixtures linking instruction changes to deploy, publish, credential, and review-bypass authority.
- Add negative tests where instruction changes have no reachable authority and should not be over-ranked.
- Add redaction and grouping tests.

Matrix wiring:
- Fast lane: risk/report correlation tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: instruction-to-authority scenario.
- Cross-platform lane: path identity and sorting.
- Risk lane: `make test-hardening` for fail-closed ambiguous authority.

Acceptance criteria:
- BOM prioritizes instruction changes that can reach meaningful authority.
- Bare config diffs without reachable authority do not crowd out higher-impact paths.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Correlate agent instruction changes with reachable workflow, credential, and review authority.
Semver marker override: [semver:minor]
Contract/API impact: Additive risk/report fields and scoring/ranking behavior.
Versioning/migration impact: Document ranking semantics.
Architecture constraints: Risk owns correlation; Aggregation provides workflow chains; Report renders results.
ADR required: yes
TDD first failing test(s): Risk scenario where instruction change with deploy authority is not prioritized.
Cost/perf impact: medium; joins must stay bounded.
Chaos/failure hypothesis: Missing authority evidence must produce unknown/insufficient evidence state, not inferred high authority.

### Story 3.3: Emit Bounded DecisionTrace Records For High-Impact Actions

Priority: P1
Recommendation coverage: 17

Tasks:
- Define a canonical bounded DecisionTrace record for high-impact actions: actor, authority, policy checked, approval/exception reason, context used, what changed, evidence refs, outcome, proof ref, and precedent ref.
- Gate emission to high-impact actions using high-stakes presets and focused BOM budgets.
- Source fields from existing attribution, credential authority, policy coverage, evidence decisions, action lineage, and proof refs.
- Add `decision_trace` proof-record schema and verify/chain coverage only after ADR approval.
- Reference DecisionTrace records from BOM/evidence instead of duplicating details.

Repo paths:
- `core/risk/agentic_projection.go`
- `core/risk/action_lineage.go`
- `core/proofmap/proofmap.go`
- `core/proofemit`
- `core/report/agent_action_bom.go`
- `schemas/v1/evidence`
- `schemas/v1/proof-outputs`
- `docs/commands/evidence.md`
- `docs/commands/report.md`

Run commands:
- `go test ./core/risk ./core/proofmap ./core/proofemit ./core/report ./core/evidence -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`
- `make prepush-full`

Test requirements:
- Add schema and proof verification tests for DecisionTrace.
- Add bounded emission tests for high-impact and non-high-impact actions.
- Add chain integrity and deterministic digest tests.
- Add redaction tests for trace refs and context summaries.

Matrix wiring:
- Fast lane: risk/proof/report focused tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: high-impact action trace scenario.
- Cross-platform lane: canonical JSON/digest stability.
- Risk lane: `make test-hardening`, `make test-chaos`, and proof chain contract tests.

Acceptance criteria:
- High-impact actions can be audited through one bounded DecisionTrace referenced by BOM/evidence.
- Trace emission is deterministic, verifiable, redacted correctly, and absent for low-impact paths unless explicitly enabled.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Add bounded DecisionTrace evidence records for high-impact agentic actions.
Semver marker override: [semver:minor]
Contract/API impact: New proof/evidence record type and schema; verify and docs contracts must update.
Versioning/migration impact: Add compatibility matrix entry and proof schema migration notes.
Architecture constraints: Proof emission owns record creation/signing; Risk supplies projection; Report/Evidence reference records.
ADR required: yes
TDD first failing test(s): Proof/evidence contract test for missing DecisionTrace on high-impact action.
Cost/perf impact: medium; emission is gated and bounded.
Chaos/failure hypothesis: Trace creation failure must fail closed for required high-impact evidence paths, with no broken chain append.

## Epic 4: Enterprise Runtime And Evidence Context

Objective: add provider-neutral context and local precedent only after focused output and freeze gates protect signal quality.
Traceability: Recommendations 18 through 22.

### Story 4.1: Add Runtime, Model, And Host Neutrality Fields

Priority: P2
Recommendation coverage: 18

Tasks:
- Thread optional `runtime_provider`, `runtime_host`, `runtime_kind`, `model_provider`, `model_version`, and `execution_environment` through session ingest, evidence packets, projections, BOM, and schemas.
- Make fields evidence-state aware and optional; unknown values must not reduce confidence silently.
- Update redaction profiles and docs.

Repo paths:
- `core/ingest/sessions.go`
- `core/ingest/evidence_packets.go`
- `core/report/agent_action_bom.go`
- `core/risk/agentic_projection.go`
- `schemas/v1`
- `docs/commands/ingest.md`
- `docs/commands/report.md`

Run commands:
- `go test ./core/ingest ./core/report ./core/risk -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Add schema tests for optional fields and evidence states.
- Add redaction tests for provider/host/model details.
- Add scenario tests for mixed runtime evidence.

Matrix wiring:
- Fast lane: ingest/report/risk tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: runtime evidence scenario.
- Cross-platform lane: JSON ordering and path refs.
- Risk lane: `make test-hardening` for redaction.

Acceptance criteria:
- Provider-neutral runtime/model/host fields appear when evidence exists and remain absent/unknown otherwise.
- Redacted outputs do not leak sensitive host/model context.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Add optional provider-neutral runtime, model, host, and execution-environment context to evidence-backed reports.
Semver marker override: [semver:minor]
Contract/API impact: Additive schema/report/evidence fields.
Versioning/migration impact: none
Architecture constraints: Ingest owns raw evidence; Risk/Report project optional context; no provider-specific runtime dependency.
ADR required: no
TDD first failing test(s): Schema/report test for missing optional runtime context from evidence packets.
Cost/perf impact: low.
Chaos/failure hypothesis: Conflicting runtime evidence must render as conflicting/unknown, not last-write-wins certainty.

### Story 4.2: Add Agent State-Retention Posture

Priority: P2
Recommendation coverage: 19

Tasks:
- Track `state_retention_status`, retained state types, state location refs, and redaction hints from session/evidence ingest.
- Store refs and digests only; never raw prompts, tool results, logs, checkpoints, sandbox files, or memory contents.
- Surface retention posture in BOM/evidence summaries and docs.

Repo paths:
- `core/ingest/sessions.go`
- `core/ingest/evidence_packets.go`
- `core/report/redaction.go`
- `core/evidence/evidence.go`
- `schemas/v1/evidence`
- `schemas/v1/report`
- `docs/commands/evidence.md`
- `docs/trust/security-and-privacy.md`

Run commands:
- `go test ./core/ingest ./core/report ./core/evidence -count=1`
- `make test-contracts`
- `make test-hardening`
- `make prepush-full`

Test requirements:
- Add tests proving raw retained state is rejected or redacted.
- Add schema tests for retention posture fields.
- Add shared-profile leak tests.

Matrix wiring:
- Fast lane: ingest/evidence/redaction tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: retention posture scenario.
- Cross-platform lane: path ref normalization.
- Risk lane: `make test-hardening` mandatory.

Acceptance criteria:
- Reports can state whether agent state may persist without storing raw contents.
- Shared evidence outputs stay safe by default.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Add agent state-retention posture fields that use refs and digests instead of raw retained content.
Semver marker override: [semver:minor]
Contract/API impact: Additive evidence/report schema fields with security semantics.
Versioning/migration impact: none
Architecture constraints: Ingest/Evidence own refs; Report renders posture; no raw content persistence.
ADR required: yes
TDD first failing test(s): Security test rejecting raw prompt/tool-result retention payloads.
Cost/perf impact: low.
Chaos/failure hypothesis: Unknown retention status must remain explicit unknown, not safe.

### Story 4.3: Add Canonical Agent Identity Read-Model

Priority: P2
Recommendation coverage: 20

Tasks:
- Build a normalized read-model over existing inventory/privilege fields: agent identity, human owner, delegated authority, runtime, credential used, and scope.
- Key identity by existing `wrkr:<tool_id>:<org>` format.
- Reference identity read-model from BOM and DecisionTrace without introducing a mutable lifecycle database.
- Add identity schema/docs coverage.

Repo paths:
- `core/aggregate/inventory/privileges.go`
- `core/identity`
- `core/report/agent_action_bom.go`
- `schemas/v1/identity/identity-manifest.schema.json`
- `docs/commands/identity.md`
- `docs/architecture.md`

Run commands:
- `go test ./core/aggregate/inventory ./core/identity ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Add deterministic identity key tests.
- Add read-model projection tests over existing fields.
- Add redaction tests for owner/credential/scope fields.
- Add docs parity tests for identity lifecycle wording.

Matrix wiring:
- Fast lane: identity/inventory/report tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: identity read-model scenario.
- Cross-platform lane: stable IDs.
- Risk lane: `make test-hardening` for identity leaks.

Acceptance criteria:
- Reports and DecisionTrace can point to one deterministic agent identity read-model.
- No mutable registry, approval workflow, or lifecycle DB is introduced.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Add a canonical read-model for agent identity and delegated authority using existing Wrkr identity conventions.
Semver marker override: [semver:minor]
Contract/API impact: Additive identity/report schema fields.
Versioning/migration impact: none
Architecture constraints: Identity read-model only; lifecycle states remain existing deterministic fields.
ADR required: no
TDD first failing test(s): Identity projection test showing existing fields cannot be referenced as one actor view.
Cost/perf impact: low.
Chaos/failure hypothesis: Missing owner/runtime/credential evidence must produce explicit unknown fields.

### Story 4.4: Add Thin Decision Precedent Lookup

Priority: P2
Recommendation coverage: 21

Tasks:
- Define local precedent records for prior approved, blocked, escalated, exception, or incident-linked paths.
- Reference prior DecisionTrace records by stable key; do not build a parallel decision store or similarity engine.
- Add fields for similar path precedent, prior decision, decision source, decision age, confidence, and expiry.
- Surface precedent in control backlog and BOM when available.

Repo paths:
- `core/risk/agentic_projection.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/config`
- `schemas/v1/evidence`
- `docs/commands/report.md`

Run commands:
- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report ./core/config -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Add lookup tests for valid, expired, conflicting, and missing precedents.
- Add schema and redaction tests.
- Add scenario tests proving precedent context changes wording without overriding current evidence.

Matrix wiring:
- Fast lane: risk/controlbacklog/report/config tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: precedent scenario.
- Cross-platform lane: stable keys and path handling.
- Risk lane: `make test-hardening` for stale/conflicting precedents.

Acceptance criteria:
- Prior decisions appear as context only and never replace current evidence.
- Expired or low-confidence precedents are labeled clearly.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Add local precedent context from prior DecisionTrace records for recurring high-impact action paths.
Semver marker override: [semver:minor]
Contract/API impact: Additive report/evidence/control-backlog fields.
Versioning/migration impact: Requires DecisionTrace support from Story 3.3 before full use.
Architecture constraints: Thin lookup only; no mutable central decision service.
ADR required: no
TDD first failing test(s): Precedent lookup test showing missing prior DecisionTrace context.
Cost/perf impact: low.
Chaos/failure hypothesis: Stale or conflicting precedent refs must not suppress current high-risk recommendations.

### Story 4.5: Detect Harness, Resolver, And Eval Config As Delivery Controls

Priority: P2
Recommendation coverage: 22

Tasks:
- Add bounded detector candidates for agent harnesses, resolver files, eval config, dry-run requirements, sandbox gates, and test gates.
- Project results into Action Contract validation requirements and focused BOM context.
- Keep scope as detection/control context; do not become an eval platform.
- Run through Story 2.4 surface-area freeze before implementation.

Repo paths:
- `core/detect`
- `core/risk/agentic_projection.go`
- `core/report/agent_action_bom.go`
- `core/report/primary_view.go`
- `schemas/v1`
- `docs/commands/report.md`
- `docs/trust/detection-coverage-matrix.md`

Run commands:
- `go test ./core/detect/... ./core/risk ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`
- `make prepush-full`

Test requirements:
- Add detector fixtures for common harness/resolver/eval config paths.
- Add negative tests to avoid overclaiming eval/platform behavior.
- Add schema/docs tests for Action Contract validation requirements.
- Add budget tests proving the new detector does not crowd out focused BOM signal.

Matrix wiring:
- Fast lane: detector/risk/report tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: harness/control validation scenario.
- Cross-platform lane: path/glob handling.
- Risk lane: `make test-hardening` for overclaiming and malformed configs.

Acceptance criteria:
- Harness/resolver/eval config appears as delivery-control context where relevant.
- Wrkr does not claim to evaluate model quality or run evals.
- Output remains within focused BOM size/noise budgets.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Detect agent harness, resolver, and eval configuration as delivery-control context for focused BOM validation requirements.
Semver marker override: [semver:minor]
Contract/API impact: Additive detector/report/schema fields.
Versioning/migration impact: none
Architecture constraints: Detection and projection only; no eval execution platform.
ADR required: yes
TDD first failing test(s): Detector scenario for harness config that currently produces no delivery-control context.
Cost/perf impact: medium; detector must be bounded and structured.
Chaos/failure hypothesis: Unknown or malformed eval configs must be scan-quality/control-context diagnostics, not high-confidence claims.

## Definition of Done

- The generated implementation PRs keep Wrkr in scope and do not implement Axym/Gait product logic.
- Deterministic behavior is preserved: same input produces same inventory, grouped findings, risk scores, proof refs, scan-quality summaries, report JSON, and markdown output except explicit timestamp/version fields.
- No scan-data exfiltration is introduced; all new recurrence, runtime, state-retention, and precedent context is local and redacted by profile.
- Proof, evidence, JSON, markdown, schema, CLI help, exit-code, and docs contracts are updated together for every externally visible change.
- Every story starts from failing tests or a documented TDD exception and includes exact commands run in the PR.
- Required lanes are green for each story: fast, core CI, acceptance, cross-platform, risk, and release/UAT where relevant.
- Changelog entries are added under valid sections with semver markers matching the story-level decisions.
- ADRs are included for boundary, public contract, failure-class, state-model, performance, or security posture changes marked `ADR required: yes`.
- Fixtures and examples are sanitized, bounded, portable, and free of developer-specific absolute paths.
- Focused BOM, stdout JSON, full artifacts, redaction, and scan-quality coverage stay inside the size/noise budgets established by Story 1.1.

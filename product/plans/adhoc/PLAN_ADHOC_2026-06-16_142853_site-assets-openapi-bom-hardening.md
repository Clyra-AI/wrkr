# Adhoc Plan: Site Assets, OpenAPI Authority, And BOM Hardening

Date: 2026-06-16
Profile: `wrkr`
Slug: `site-assets-openapi-bom-hardening`
Recommendation source: user-provided recommendations covering checked-in site asset drift, OpenAPI/Swagger authority bleed, path-type closure language, buyer-readable Agent Action BOM Markdown, analysis-time payload clone removal, and manual docs examples that still overuse `--json`.

All paths in this plan are repo-relative. Developer-specific checkout roots from the source recommendations have been normalized. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, report, evidence, docs, release, or workflow changes.

## Global Decisions (Locked)

- This plan is a subtractive correctness and readability plan. It fixes drift, false authority attribution, memory fanout, and buyer-facing report noise before adding any new scan/report surface area.
- `go test ./...` is a release-readiness signal. Checked-in generated site/demo assets must either match the deterministic generator output or the generator must be corrected before regenerated assets are committed.
- Static API specifications, Swagger/OpenAPI files, route declarations, docs, generated clients, and dependency-only signals are target context until directly correlated to an actor, workflow, runtime caller, MCP/tool binding, deployment binding, or explicit authority binding.
- Repo-wide credential or source-control authority is not enough to make a static target surface a standing-authority action path.
- Path-type closure copy is contract language. Workflow remediation text must not appear on OpenAPI, route, dependency-only, or target-context surfaces.
- Default Agent Action BOM Markdown should be readable in under one minute: inspect-first cards, primary path, top eligible paths, visible controls, unresolved evidence, and next action. IDs, graph refs, policy noise, and full diagnostics belong in appendices or machine-readable artifacts.
- Repeated analysis projections must carry refs, group IDs, counts, and bounded samples by default. Embedded `CredentialAuthority`, `AuthorityBindings`, and `MutableEndpointSemantics` clones are internal/debug detail only.
- Human/manual docs should teach `--state` and generated artifacts as durable scan/report handoffs. `--json` examples are kept for automation, CI, and machine-readable command-response workflows.
- No story in this plan may introduce scan-data exfiltration, LLM calls in scan/risk/proof/report paths, unstable ordering, raw secret extraction, or nondeterministic output.
- Every implementation story changes user-visible behavior, report semantics, docs, or release confidence. Changelog review is required for every implementation PR.

## Current Baseline (Observed)

- The recommendation source reports `internal/siteassets` failing because `docs/examples/site-assets/sample-agent-action-bom.json` no longer matches generator output from `scripts/generate_site_assets`.
- Site/demo assets are checked in under `docs/examples/site-assets/` and validated by `internal/siteassets/siteassets_test.go`.
- Privilege budget and authority correlation logic exists in `core/aggregate/privilegebudget/budget.go`, `core/aggregate/privilegebudget/authority.go`, and `core/risk/action_binding.go`.
- Action-path, target-class, and evidence-language logic exists in `core/risk/action_paths.go`, `core/risk/action_binding.go`, `core/risk/evidence_context.go`, `core/risk/evidence_language.go`, `core/risk/action_path_type.go`, and related tests under `core/risk`.
- Scenario coverage already includes `internal/scenarios/wave3_action_path_semantics_scenario_test.go` and targeted risk tests exist in `core/aggregate/privilegebudget/budget_test.go`.
- Report rendering and primary-view surfaces exist in `core/report/render_markdown.go`, `core/report/primary_view.go`, `core/report/agent_action_bom.go`, `core/report/signal_hardening.go`, and `core/cli/report_artifacts.go`.
- Analysis graph/report/control projections exist in `core/aggregate/attackpath/graph.go`, `core/risk/action_paths.go`, `core/report/agent_action_bom.go`, and `core/aggregate/controlbacklog/controlbacklog.go`.
- User-facing command docs exist in `docs/commands/scan.md`, `docs/commands/report.md`, `docs/commands/evidence.md`, and `docs/commands/assess.md`.
- The repo standards treat CLI JSON, schemas, evidence artifacts, exit codes, docs parity, scenario fixtures, and deterministic byte-stable artifacts as contracts.

## Exit Criteria

- `go test ./internal/siteassets -count=1` and `go test ./... -count=1` pass with checked-in site/demo assets matching deterministic generator output.
- Generated site assets do not contain machine-local paths, raw secrets, unstable timestamps, or nondeterministic ordering.
- Swagger/OpenAPI and route-only surfaces remain in Target Surface Context when an unrelated workflow credential exists elsewhere in the same repo.
- Top Action Paths exclude unbound static target surfaces and do not inherit standing credential authority without direct correlation.
- Regression coverage proves a repo containing Swagger/OpenAPI plus an unrelated workflow credential does not produce a blocked action path or standing-authority claim for the spec.
- Closure copy is path-type-specific for OpenAPI, route, `AGENTS.md`, MCP config, dependency-only, CI workflow, and release workflow surfaces.
- Default Agent Action BOM Markdown starts with 3 to 5 plain-language inspect-first cards and keeps default buyer output within the configured one-page/readability budget.
- Analysis-time graph, action path, BOM, and control-backlog projections stop cloning embedded credential authority, authority binding, and mutable endpoint semantic payloads by default.
- Heap and artifact-size receipts for large enterprise-shaped fixtures prove ref-only projections reduce peak analysis memory before save-time stripping occurs.
- Manual docs stop recommending `--json` for ordinary large-scan human workflows and clearly split human workflows from automation workflows.
- Changelog entries, docs, schemas, and acceptance receipts are updated in the same implementation PRs that alter public behavior or report semantics.

## Public API and Contract Map

- CLI contract:
  - Preserve exit codes `0` through `8`.
  - Preserve `--json`, `--explain`, and `--quiet` semantics.
  - Keep `--json` as the machine-readable command-response surface for automation and CI.
  - Keep `--state` and generated report/evidence artifacts as the durable human workflow handoff for large scans.
- Report and Agent Action BOM contract:
  - Default Markdown leads with inspect-first cards, primary path, top eligible paths, visible controls, unresolved evidence, and recommended next action.
  - Full IDs, graph refs, policy/debug noise, and exhaustive evidence remain available in appendices or JSON artifacts.
  - Target Surface Context is distinct from Top Action Paths.
- Risk and authority contract:
  - Static target context may receive authority only with same-location evidence, workflow invocation, runtime caller evidence, deployment binding, MCP/tool binding, or explicit authority binding.
  - Unrelated repo-wide credentials cannot make OpenAPI/route surfaces standing-authority paths.
  - Action Contract readiness must match eligibility and correlation state.
- Schema and artifact contract:
  - Ref-only projections may add explicit refs, group IDs, counts, bounded samples, and suppression metadata.
  - Removing or retyping public JSON fields requires compatibility handling, schema docs, and migration tests.
  - Site assets are generated artifacts with deterministic byte-stable output.
- Architecture boundary contract:
  - Detection owns parsed source facts and detector classifications.
  - Aggregation owns privilege budget, repo exposure, canonical stores, and control backlog.
  - Risk owns action-path eligibility, binding state, target classification, and ranking.
  - Report/evidence owns markdown framing, closure language, appendices, redaction, and shareable output.
  - Proof emission remains file-based and verifiable; this plan does not change proof-chain primitives.

## Docs and OSS Readiness Baseline

- User-facing docs likely impacted:
  - `CHANGELOG.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/commands/assess.md`
  - `docs/examples/site-assets/`
  - `docs-site/public/llms.txt`
  - `docs-site/public/llm/`
- Contract and scenario assets likely impacted:
  - `internal/siteassets/siteassets_test.go`
  - `internal/scenarios/wave3_action_path_semantics_scenario_test.go`
  - `internal/scenarios/coverage_map.json`
  - `core/aggregate/privilegebudget/budget_test.go`
  - `core/risk/evidence_context_test.go`
  - `core/report/render_markdown_test.go`
  - `core/report/primary_view_test.go`
  - `core/report/sprint0_signal_test.go`
  - `schemas/v1`
- OSS trust baseline:
  - Do not commit private customer scan outputs, raw source snippets, raw credential values, generated binaries, transient local reports, private owner handles, private repo URLs, or machine-local checkout paths.
  - Synthetic fixtures must use fake repos, fake owners, fake credentials by reference only, and deterministic generated data.
  - Buyer-facing docs and site assets must match executable behavior and pass docs/site consistency gates before release claims are made.

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| 1. Fix checked-in site asset drift | P0 | Story 1.1 | `go test ./...` fails when generated demo assets drift from checked-in copies. | Regenerate assets or fix the generator, then commit deterministic output. | Release gates become green and demo/site examples stay trustworthy. |
| 2. Fix OpenAPI / route authority bleed | P0 | Story 2.1 | Static API specs are target context, not proof of standing authority. | Remove broad repo-wide credential joins for OpenAPI/route surfaces unless directly correlated. | Top Action Paths stop overclaiming actionable risk. |
| 3. Add exact Swagger plus unrelated credential regression | P0 | Story 2.1 | The customer-visible bug needs a reproducible fixture. | Add scenario and privilege-budget tests for Swagger plus unrelated workflow credentials. | Future changes cannot reintroduce false blocked action paths. |
| 4. Tighten path-type-specific closure copy | P1 | Story 3.1 | Generic workflow closure text is misleading on target surfaces and dependency-only signals. | Generate remediation language by path type and binding state. | Reports give operators the right next action for each surface. |
| 5. Add explicit "What To Look At First" Markdown | P1 | Story 4.1 | Current Markdown still reads like machine diagnostics. | Render 3 to 5 inspect-first cards before rollups and appendices. | Buyers can inspect the right issue quickly. |
| 6. Make default BOM truly one-page | P1 | Story 4.1 | Current caps are still too large for the under-one-minute buyer view. | Keep only lead issue, primary path, top 5 eligible paths, visible controls, unresolved evidence, and action contract up front. | Default BOM becomes shareable without live explanation. |
| 7. Remove analysis-time embedded payload clones | P0 | Story 3.2 | Save-time stripping does not help when analysis already exceeds heap. | Use refs, group IDs, counts, and bounded samples during graph/path/BOM/backlog construction. | Enterprise scans reduce peak heap and artifact bloat. |
| 8. Clean up manual docs still encouraging `--json` | P1 | Story 5.1 | Operators confuse command-response JSON with durable scan artifacts. | Split human and automation docs; teach `--state` for manual large-scan workflows. | Docs match real operational workflows and reduce support confusion. |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - `make test-fast`
  - Focused `go test` commands listed under each story.
- Core CI lane:
  - `make prepush-full` for architecture, risk, report, schema, CLI, docs, or artifact behavior changes.
  - `make test-contracts` for JSON shape, schema, exit-code, artifact, report, site asset, and docs parity contracts.
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `go test ./internal/acceptance -count=1` when buyer-facing report behavior changes.
- Cross-platform lane:
  - Required for path normalization, generated docs/site assets, Markdown line budgets, deterministic ordering, and filesystem path redaction.
  - Use the repo-local cross-platform lane from `product/dev_guides.md`.
- Risk lane:
  - `make test-hardening` for fail-closed authority correlation, ambiguous binding state, unsafe output, schema compatibility, and closure/readiness correctness.
  - `make test-chaos` for generator failure modes, missing/corrupt refs, interrupted artifact writes, and stale/corrupt state handoffs.
  - `make test-perf` for heap-sensitive graph/action/BOM/control-backlog projection changes.
  - `make codeql` when detector, parser, CI, generated-code, or security-sensitive writer behavior changes.
- Release/UAT lane:
  - `make test-release-smoke`
  - `scripts/run_v1_acceptance.sh --mode=release` when checked-in site assets, buyer-facing docs, release notes, report defaults, or schema contracts change.
- Gating rule:
  - Wave 1 lands first so the repository returns to a green generated-asset baseline.
  - Wave 2 lands before any buyer-facing claim that Swagger/OpenAPI findings are actionable or authority-backed.
  - Wave 3 lands before one-page BOM copy relies on corrected closure semantics and bounded analysis projections.
  - Wave 4 lands before docs or site assets claim the default BOM is one-page, shareable, or under-one-minute readable.
  - Wave 5 lands after behavior and artifact semantics are stable so documentation does not describe a moving target.

## Minimum-Now Sequence

- Wave 1 - Restore generated asset determinism:
  - Story 1.1 fixes checked-in site/demo asset drift and validates the generator contract.
- Wave 2 - Correct static target authority semantics:
  - Story 2.1 adds the Swagger plus unrelated credential regression and tightens authority correlation.
- Wave 3 - Tighten closure semantics and analysis heap:
  - Story 3.1 makes closure language path-type-specific.
  - Story 3.2 removes default embedded payload clones during analysis.
- Wave 4 - Make the buyer BOM readable:
  - Story 4.1 adds inspect-first Markdown and makes the default Agent Action BOM one-page.
- Wave 5 - Align manual docs:
  - Story 5.1 removes misleading manual `--json` examples and splits human vs automation workflows.

## Explicit Non-Goals

- No implementation in this plan-only PR.
- No edits to `product/PLAN_NEXT.md` in this plan-only PR.
- No Axym or Gait product feature implementation.
- No new detector surfaces, report sections, schema families, sidecars, or buyer-facing claims except those directly required to close the listed drift, authority, closure, memory, readability, and docs bugs.
- No scan-time, risk-time, proof-time, report-time, evidence-time, or docs-generation-time LLM calls.
- No live customer repo acquisition, network scanning, telemetry on scan contents, hosted dependency, or background daemon.
- No raw secret extraction or serialization.
- No commitment of private scan data, raw prompts, raw source, raw credential values, generated binaries, or transient measurement outputs.
- No removal of public contract fields without compatibility handling, schema/version notes, docs, and migration tests.
- No default full graph or full evidence expansion as part of buyer Markdown readability work.

## Definition of Done

- Every source recommendation maps to at least one story and deterministic acceptance check.
- Implementation PRs land in dependency order or document a safe narrower order.
- Site assets are byte-stable and regenerated from deterministic source inputs.
- Swagger/OpenAPI plus unrelated credential fixtures prove static target surfaces are not standing-authority Top Action Paths.
- Closure copy and Action Contract readiness match path type and binding state.
- Graph, action path, BOM, and control-backlog projections use refs/group IDs/counts/samples by default and do not clone embedded authority or endpoint payloads during analysis.
- Default Agent Action BOM Markdown fits the one-page/readability budget and keeps diagnostic refs in appendices or artifacts.
- User docs clearly separate human durable-artifact workflows from automation `--json` workflows.
- Changelog entries, semver markers, docs, schemas, and receipts land with the implementation PRs that alter public behavior.
- Required fast, contract, scenario, risk, perf, docs, release/UAT, and cross-platform lanes are green or have an explicitly approved exception.

## Wave 1: Restore Generated Asset Determinism

Objective: return the repository to a green generated-asset baseline before deeper behavior changes.
Traceability: Recommendation 1.

### Story 1.1: Regenerate Or Correct Checked-In Site Assets

Priority: P0
Recommendation coverage: 1
Tasks:
- Run the site asset generator and inspect the diff for `docs/examples/site-assets/sample-agent-action-bom.json` and any adjacent generated assets.
- If the generator output is intended, commit the regenerated `docs/examples/site-assets/*` files and the updated manifest.
- If the output drift is unintended, fix the generator or source fixture before committing generated assets.
- Ensure generated output uses deterministic ordering, stable timestamps or explicit fixture timestamps, portable paths, and redacted synthetic data.
- Add or tighten a targeted test that fails when checked-in site assets drift from the generator output.
- Document the generator command in the relevant maintainer docs if it is not already discoverable.
Repo paths:
- `internal/siteassets/siteassets_test.go`
- `internal/siteassets/siteassets.go`
- `scripts/generate_site_assets`
- `docs/examples/site-assets/sample-agent-action-bom.json`
- `docs/examples/site-assets/site-asset-manifest.json`
- `docs/examples/site-assets/`
Run commands:
- `go run ./scripts/generate_site_assets`
- `go test ./internal/siteassets -count=1`
- `go test ./... -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 1 generator/unit tests for deterministic asset ordering and stable fixture inputs.
- Tier 9 contract test proving checked-in assets match generated output byte-for-byte.
- Docs/site consistency checks if generated docs examples or public site assets change.
Matrix wiring:
- Fast lane: `go test ./internal/siteassets -count=1` plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: not required unless generated assets alter buyer-facing scenario examples.
- Cross-platform lane: required because generated paths, line endings, and ordering must be portable.
- Risk lane: `make test-hardening` if generator error handling or unsafe output path behavior changes.
- Release/UAT lane: `make test-release-smoke` and docs-site validation when published examples change.
Acceptance criteria:
- `go test ./internal/siteassets -count=1` passes from a clean checkout.
- `go test ./... -count=1` no longer fails because of site asset drift.
- The committed generated assets contain no developer-specific absolute paths or private data.
- The asset diff is reviewed as intended output rather than blindly committed drift.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Corrected checked-in site/demo assets so generated Agent Action BOM examples match deterministic generator output and the repository test suite returns to a green baseline.
Semver marker override: [semver:patch]
Contract/API impact: No CLI/API contract change, but checked-in public example artifacts and generator byte-stability are treated as docs/site contracts.
Versioning/migration impact: No migration required.
Architecture constraints: Keep generation deterministic and file-based; do not introduce network, LLM, or machine-local inputs.
ADR required: no
TDD first failing test(s): `TestSiteAssetsMatchGeneratedOutput` or the current failing `internal/siteassets` drift assertion.
Cost/perf impact: low
Chaos/failure hypothesis: If the generator is interrupted or an asset source is missing, validation fails closed instead of committing partial or stale published assets.

## Wave 2: Correct Static Target Authority Semantics

Objective: stop static OpenAPI/Swagger and route context from inheriting unrelated credential authority or appearing as executable action paths.
Traceability: Recommendations 2 and 3.

### Story 2.1: Gate OpenAPI And Route Authority On Direct Correlation

Priority: P0
Recommendation coverage: 2, 3
Tasks:
- Add a failing scenario with Swagger/OpenAPI plus an unrelated workflow credential in the same repo.
- Assert the Swagger/OpenAPI file appears in Target Surface Context, not Top Action Paths.
- Assert the spec has no standing credential authority and no blocked action path solely because the repo contains an unrelated workflow secret.
- Add privilege-budget unit tests for OpenAPI, route files, generated clients, docs, dependency-only signals, and directly correlated workflow/runtime/MCP/deployment bindings.
- Remove OpenAPI and route surfaces from broad repo-wide credential joins in privilege-budget aggregation.
- Allow authority only when evidence is same-location, workflow invocation, runtime caller, deployment binding, MCP/tool binding, or explicit authority binding.
- Ensure closure language for the unbound static case says to correlate to caller/workflow/runtime instead of attaching approval evidence to the spec path.
Repo paths:
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/privilegebudget/authority.go`
- `core/aggregate/privilegebudget/budget_test.go`
- `core/risk/action_binding.go`
- `core/risk/action_paths.go`
- `core/risk/action_paths_test.go`
- `internal/scenarios/wave3_action_path_semantics_scenario_test.go`
- `internal/scenarios/coverage_map.json`
Run commands:
- `go test ./core/aggregate/privilegebudget -run 'Test.*OpenAPI|Test.*Swagger|Test.*Route|Test.*Authority|Test.*Credential' -count=1`
- `go test ./core/risk -run 'Test.*ActionBinding|Test.*OpenAPI|Test.*TargetSurface|Test.*Authority' -count=1`
- `go test ./internal/scenarios -run 'Test.*ActionPathSemantics|Test.*Swagger|Test.*OpenAPI' -count=1 -tags=scenario`
- `scripts/validate_scenarios.sh`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 1 privilege-budget and risk tests for direct vs unrelated authority joins.
- Tier 9 contract/golden tests for action-path eligibility and target-context output shape.
- Tier 11 scenario fixture for Swagger/OpenAPI plus unrelated workflow credential.
- Regression assertions for stable reason codes and deterministic ordering.
Matrix wiring:
- Fast lane: focused `core/aggregate/privilegebudget` and `core/risk` tests plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: `scripts/validate_scenarios.sh` and tagged scenario test.
- Cross-platform lane: required for path normalization and fixture portability.
- Risk lane: `make test-hardening` for ambiguous high-risk correlation and fail-closed binding states.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=release` if buyer-facing report examples or release claims are updated.
Acceptance criteria:
- A repo with Swagger/OpenAPI plus an unrelated credential reports the spec as Target Surface Context only.
- Top Action Paths exclude unbound static specs and route-only context.
- Directly correlated workflow/runtime/MCP/deploy bindings still produce authority where evidence supports it.
- Stable reason codes explain when correlation is missing.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Tightened OpenAPI and route authority correlation so static target context no longer inherits unrelated repo-wide credentials or appears as a standing-authority action path without direct binding evidence.
Semver marker override: [semver:patch]
Contract/API impact: Changes risk/report semantics and may adjust JSON fields that classify OpenAPI/route surfaces as target context rather than action paths.
Versioning/migration impact: Additive schema fields or reason-code changes require compatibility tests; no migration should be needed for consumers that tolerate lower-risk reclassification.
Architecture constraints: Keep Detection facts separate from Aggregation authority joins and Risk action-path eligibility; no raw secret extraction.
ADR required: yes
TDD first failing test(s): `TestSwaggerWithUnrelatedWorkflowCredentialStaysTargetContext` and `TestOpenAPIRouteAuthorityRequiresDirectCorrelation`.
Cost/perf impact: low
Chaos/failure hypothesis: Ambiguous correlation must fail closed to target context and correlation-needed closure, not fail open to standing authority.

## Wave 3: Tighten Closure Semantics And Analysis Heap

Objective: align remediation language to evidence type, then reduce analysis peak heap by removing repeated embedded payload clones before report rendering.
Traceability: Recommendations 4 and 7.

### Story 3.1: Generate Closure Copy By Path Type And Binding State

Priority: P1
Recommendation coverage: 4
Tasks:
- Add table-driven tests covering OpenAPI, route, `AGENTS.md`, MCP config, dependency-only, CI workflow, and release workflow surfaces.
- Define exact remediation classes for static target context, agent instruction governance, MCP configuration, dependency-only context, CI workflow, release workflow, and executable/bound action paths.
- Update evidence-context and report rendering helpers so generic workflow closure text never appears on target surfaces or dependency-only signals.
- Align control-backlog closure and Action Contract readiness with path type and binding state.
- Preserve stable reason codes and deterministic ordering for report and JSON outputs.
Repo paths:
- `core/risk/evidence_context.go`
- `core/risk/evidence_context_test.go`
- `core/risk/evidence_language.go`
- `core/risk/action_binding.go`
- `core/report/render_markdown.go`
- `core/report/render_markdown_test.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/aggregate/controlbacklog/controlbacklog_test.go`
Run commands:
- `go test ./core/risk -run 'Test.*EvidenceContext|Test.*Closure|Test.*PathType|Test.*BindingState' -count=1`
- `go test ./core/report -run 'Test.*Closure|Test.*Markdown|Test.*AgentActionBOM|Test.*PathType' -count=1`
- `go test ./core/aggregate/controlbacklog -run 'Test.*Closure|Test.*ActionContract|Test.*PathType' -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 1 table-driven tests for each path type and binding state.
- Tier 9 contract/golden tests for Markdown and JSON closure wording stability.
- Regression tests proving workflow closure language appears only on workflow-capable surfaces.
Matrix wiring:
- Fast lane: focused `core/risk`, `core/report`, and `core/aggregate/controlbacklog` tests plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: scenario coverage when closure changes affect buyer-facing reports.
- Cross-platform lane: required for Markdown wrapping and deterministic path labels.
- Risk lane: `make test-hardening` for ambiguous binding state and fail-closed remediation classes.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=release` if public report examples change.
Acceptance criteria:
- OpenAPI and route target context never says to attach approval evidence for an exact workflow path.
- Dependency-only signals use dependency remediation language, not workflow closure language.
- Agent instruction files use owner/review governance language distinct from source/API/workflow paths.
- CI and release workflow paths keep workflow-specific closure language when they are genuinely workflow-capable.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Updated Agent Action BOM and control-backlog closure guidance so OpenAPI, route, instruction, dependency, CI, and release workflow surfaces use path-type-specific remediation language.
Semver marker override: [semver:minor]
Contract/API impact: Changes user-visible report text and may adjust closure/readiness reason strings; JSON shape should remain backward-compatible.
Versioning/migration impact: No migration required if fields are unchanged; reason-code or enum additions need schema compatibility tests.
Architecture constraints: Risk owns binding state and report/evidence owns presentation; do not embed detector-specific raw source in report copy.
ADR required: no
TDD first failing test(s): `TestClosureCopyByPathType` and `TestTargetSurfacesDoNotUseWorkflowClosureCopy`.
Cost/perf impact: low
Chaos/failure hypothesis: Unknown path types should fall back to conservative correlation-needed language rather than workflow approval text.

### Story 3.2: Remove Analysis-Time Embedded Payload Clones From Default Projections

Priority: P0
Recommendation coverage: 7
Tasks:
- Inventory remaining graph, action-path, BOM, and control-backlog fields that carry embedded `CredentialAuthority`, `AuthorityBindings`, or `MutableEndpointSemantics` payloads during analysis.
- Convert default analysis projections to refs, group IDs, counts, bounded samples, and suppression metadata.
- Keep full detail hydration available only through explicit internal/debug resolver paths.
- Add fixture coverage that fails on embedded payload clones before serialization, not only after save-time stripping.
- Add heap or allocation receipts for the enterprise-shaped regression so the 337-repo analysis failure class is caught in analysis.
- Update schemas and docs only where public JSON shape changes are unavoidable.
Repo paths:
- `core/aggregate/attackpath/graph.go`
- `core/risk/action_paths.go`
- `core/risk/canonical_projection.go`
- `core/report/agent_action_bom.go`
- `core/report/canonical_projection.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/aggregate/controlbacklog/canonical_projection.go`
- `internal/acceptance/sprint0_size_signal_acceptance_test.go`
- `internal/scenarios/wave42_enterprise_pressure_scenario_test.go`
- `schemas/v1`
Run commands:
- `go test ./core/aggregate/attackpath ./core/risk ./core/report ./core/aggregate/controlbacklog -run 'Test.*Canonical|Test.*Projection|Test.*Embedded|Test.*Payload|Test.*Ref' -count=1`
- `go test ./internal/acceptance -run 'Test.*Sprint0|Test.*SizeSignal|Test.*Embedded|Test.*Heap' -count=1`
- `go test ./internal/scenarios -run 'Test.*EnterprisePressure|Test.*SizeSignal' -count=1 -tags=scenario`
- `make test-contracts`
- `make test-perf`
- `make prepush-full`
Test requirements:
- Tier 1 projection tests proving default structs carry refs/counts/samples, not embedded full payloads.
- Tier 4 acceptance tests for artifact byte budgets and pre-serialization clone absence.
- Tier 7 performance tests for heap/allocation regression receipts.
- Tier 9 schema/contract tests for any public JSON shape changes.
- Tier 11 scenario coverage for enterprise-shaped fanout.
Matrix wiring:
- Fast lane: focused projection tests plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: `go test ./internal/acceptance -count=1` and enterprise-pressure scenario.
- Cross-platform lane: required for deterministic ordering, path normalization, and fixture generation.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf`.
- Release/UAT lane: `make test-release-smoke` if schema/report artifacts change.
Acceptance criteria:
- Default analysis projections do not contain embedded credential authority, authority binding, or mutable endpoint semantic objects when refs exist.
- Internal/debug hydration can recover details by ref without changing default public output.
- Enterprise-shaped fixtures show lower peak heap or allocation receipts before artifact serialization.
- Public artifacts include deterministic suppression metadata where detail is omitted.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Removed analysis-time embedded authority and endpoint payload clones from graph, action-path, BOM, and control-backlog projections so enterprise-shaped scans use ref-only defaults before artifact serialization.
Semver marker override: [semver:patch]
Contract/API impact: May change public JSON payload detail shape from embedded objects to refs/counts/samples; schema compatibility and migration notes are required if fields are removed or retyped.
Versioning/migration impact: Prefer additive compatibility; any removal requires schema/version notes and reader compatibility tests.
Architecture constraints: Aggregation and Risk own canonical refs; Report/Evidence may hydrate only through explicit internal/debug resolver paths. No writer-only stripping as the primary fix.
ADR required: yes
TDD first failing test(s): `TestDefaultAnalysisProjectionsDoNotCarryEmbeddedPayloads` and `TestEnterprisePressureHeapReceiptsStayBounded`.
Cost/perf impact: high
Chaos/failure hypothesis: Missing ref targets should fail closed with explicit incomplete-detail metadata rather than silently re-embedding full payloads.

## Wave 4: Make The Buyer BOM Readable

Objective: make default Markdown immediately useful to a buyer while preserving full deterministic evidence in appendices and JSON artifacts.
Traceability: Recommendations 5 and 6.

### Story 4.1: Lead Agent Action BOM Markdown With Inspect-First Cards And One-Page Defaults

Priority: P1
Recommendation coverage: 5, 6
Tasks:
- Add a first report section that renders 3 to 5 plain-language inspect-first cards.
- Each card must name the specific item to inspect, why it matters, evidence found, unresolved evidence, and the next action.
- Change the default Agent Action BOM Markdown to show only the inspect-first cards, primary path, top 5 eligible paths, visible controls, unresolved evidence, and recommended action contract before the appendix boundary.
- Move `xrg-*`, `apc-*`, `loc-*`, graph refs, policy noise, full diagnostics, and low-priority repeated detail to appendices or JSON artifacts.
- Add line, section, and readability budget tests for default Markdown.
- Preserve full deterministic detail in appendix/evidence JSON and make appendix availability explicit.
Repo paths:
- `core/report/render_markdown.go`
- `core/report/render_markdown_test.go`
- `core/report/primary_view.go`
- `core/report/primary_view_test.go`
- `core/report/agent_action_bom.go`
- `core/report/signal_hardening.go`
- `core/cli/report_artifacts.go`
- `core/cli/sprint0_report_contract_test.go`
- `docs/examples/site-assets/sample-agent-action-bom.json`
Run commands:
- `go test ./core/report -run 'Test.*InspectFirst|Test.*PrimaryView|Test.*AgentActionBOM|Test.*Markdown|Test.*LineBudget' -count=1`
- `go test ./core/cli -run 'Test.*ReportContract|Test.*Sprint0|Test.*AgentActionBOM' -count=1`
- `go test ./internal/acceptance -run 'Test.*AgentActionBOM|Test.*OnePage|Test.*Buyer' -count=1`
- `go test ./internal/siteassets -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 1 report renderer tests for inspect-first cards and appendix boundary.
- Tier 3 CLI/report contract tests for artifact handoff and default Markdown shape.
- Tier 4 acceptance tests for one-page/readability budgets.
- Tier 9 golden/schema tests for any new appendix metadata or lead-view fields.
Matrix wiring:
- Fast lane: focused `core/report`, `core/cli`, and `internal/siteassets` tests plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: `go test ./internal/acceptance -count=1` and scenario tests for buyer BOM behavior.
- Cross-platform lane: required for Markdown line wrapping, path display, and deterministic ordering.
- Risk lane: `make test-hardening` for appendix/full-detail availability and fail-closed artifact handoff.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=release` and `make test-release-smoke` when public examples or buyer docs change.
Acceptance criteria:
- Default Markdown starts with inspect-first cards and no machine-ID-heavy diagnostic preamble.
- The lead view stays within the configured one-page/readability budget.
- Top 5 eligible paths exclude Target Surface Context and dependency-only signals unless they are directly bound.
- Appendix and JSON artifacts preserve full deterministic detail with clear handoff metadata.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Reworked default Agent Action BOM Markdown to lead with inspect-first cards and a one-page buyer view while moving graph refs, policy diagnostics, and full evidence detail to appendices and JSON artifacts.
Semver marker override: [semver:minor]
Contract/API impact: Changes default Markdown output and may add appendix metadata; JSON shape should remain additive unless explicitly versioned.
Versioning/migration impact: No migration required for Markdown consumers; JSON metadata additions require schema tests.
Architecture constraints: Report owns presentation and appendices; Risk supplies ranked eligible paths; Aggregation supplies visible controls and unresolved evidence without presentation coupling.
ADR required: no
TDD first failing test(s): `TestAgentActionBOMStartsWithInspectFirstCards` and `TestDefaultAgentActionBOMOnePageBudget`.
Cost/perf impact: medium
Chaos/failure hypothesis: If appendices cannot be generated, the lead view must disclose incomplete detail rather than silently dropping evidence.

## Wave 5: Align Manual Docs

Objective: make docs teach the durable human workflow and reserve `--json` examples for automation.
Traceability: Recommendation 8.

### Story 5.1: Split Human And Automation Examples For Large Scan Workflows

Priority: P1
Recommendation coverage: 8
Tasks:
- Remove `--json` from human/manual large-scan examples unless the section is explicitly about automation or machine-readable command responses.
- Add or clarify human workflows that use `--state`, `.wrkr/last-scan.json`, report artifacts, and evidence artifacts as durable handoffs.
- Add or clarify automation workflows that intentionally use `--json`, pipes, redirects, or `--json-path`.
- Keep scan/report/evidence/assess docs consistent with CLI help and generated examples.
- Update docs-site LLM/AEO surfaces if public command guidance changes there.
- Add docs consistency checks or fixtures so the human-vs-automation split does not drift.
Repo paths:
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `docs/commands/assess.md`
- `docs-site/public/llms.txt`
- `docs-site/public/llm/`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/check_docs_storyline.sh`
Run commands:
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/run_docs_smoke.sh`
- `make test-focused-docs`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 9 docs/CLI parity checks for command examples and flags.
- Docs storyline checks proving human workflows emphasize `--state` and artifacts.
- Automation-example checks proving `--json` examples are explicitly labeled as automation, CI, or machine-readable output.
Matrix wiring:
- Fast lane: docs parity/storyline scripts plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: docs smoke tests and release-mode acceptance when buyer-facing docs claims change.
- Cross-platform lane: required for path examples and shell portability.
- Risk lane: `make test-hardening` not required unless docs changes alter unsafe-output guidance; otherwise run docs consistency gates.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=release` and `make test-release-smoke` when docs-site or public release examples change.
Acceptance criteria:
- Manual large-scan docs no longer present `--json` as the default human workflow.
- Automation examples using `--json` are explicitly labeled and remain copy-pasteable.
- Docs point operators to `--state`, `.wrkr/last-scan.json`, generated reports, and evidence artifacts for durable handoff.
- Docs parity and storyline checks pass.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Clarified scan, report, evidence, and assess docs so manual large-scan workflows use `--state` and durable artifacts while `--json` examples are reserved for automation and CI.
Semver marker override: [semver:patch]
Contract/API impact: Documentation-only behavior guidance change; no CLI contract change.
Versioning/migration impact: No migration required.
Architecture constraints: Docs must stay aligned with executable CLI behavior and avoid implying `--json` is a durable scan artifact.
ADR required: no
TDD first failing test(s): `TestDocsManualLargeScanExamplesPreferState` or the equivalent docs-storyline fixture.
Cost/perf impact: low
Chaos/failure hypothesis: If docs examples drift from CLI help or supported flags, docs consistency checks fail before merge.

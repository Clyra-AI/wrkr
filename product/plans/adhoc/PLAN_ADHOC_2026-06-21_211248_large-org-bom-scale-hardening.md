# Large Org BOM Scale Hardening Adhoc Plan

Generated: 2026-06-21 21:12:48 America/Toronto
Scope: Wrkr only
Source: latest successful Guardium, agentic, and service-mesh scan review plus failed 300+ repo local scan behavior.

## Global Decisions (Locked)

- Preserve deterministic scan/report/proof behavior.
- Do not retain raw source in shareable artifacts.
- Treat report, evidence JSON, state JSON, and scan status as public contracts.
- Lead buyer output with executable delegated action paths only.
- Keep API/spec/source context as supporting evidence unless it is linked to a workflow, credential, tool, agent, or automation.
- Bound peak memory during graph construction, not only serialized output size.
- Prefer fail-closed diagnostics for interrupted large scans.

## Current Baseline (Observed)

- Latest successful artifacts are much smaller than v1.6.0 scale failures.
- Guardium 184 repos: last-scan 9.0 MB, evidence 4.6 MB, markdown 1050 lines.
- Agentic 24 repos: last-scan 27 MB, evidence 23 MB, graph had 3347 target nodes from only 8 paths.
- Service mesh 90 repos: last-scan 8.1 MB, evidence 4.9 MB, markdown 793 lines.
- Redacted artifacts did not show obvious raw repo paths, owners, or local paths.
- A 300+ repo scan still appears to be OS-killed around analysis progress 80 after detectors complete.
- Top Action Paths still promote plain source/API-spec context in ways that can read as false action-path claims.
- One latest folder showed fresh evidence JSON but stale Markdown content, so report artifact pairing needs stronger consistency checks.

## Wave 1 - Action-Path Credibility

### Story 1.1 - Demote Context-Only Source From Primary Action Paths

- Recommendation: Do not place `plain_source_code`, OpenAPI/Swagger, routes, API specs, or mutable endpoint context in the primary BOM/Top Action Paths unless tied to executable authority.
- Why: "Attach approval evidence to a Swagger file" is not credible as a buyer-facing top path.
- Strategic direction: Separate executable delegated paths from supporting target context.
- Expected benefit: Higher precision and fewer customer objections.
- Tasks:
  - Add explicit primary eligibility rules for BOM and top action path selection.
  - Require one of workflow/tool/agent/credential/executable automation for primary action paths.
  - Preserve API/spec surfaces as target context appendix evidence.
  - Add tests for Swagger/OpenAPI-only context and workflow-bound OpenAPI context.
- Repo paths:
  - `core/risk/action_paths.go`
  - `core/report/agent_action_bom.go`
  - `core/report/primary_view.go`
  - `core/report/render_markdown.go`
- TDD first failing tests:
  - `go test ./core/report -run 'Test.*ContextOnly.*Primary|Test.*TopActionPaths.*' -count=1`
  - `go test ./core/risk -run 'Test.*ActionPath.*Context' -count=1`
- Changelog impact: required
- Changelog section: Fixed
- Draft changelog entry: Tightened Agent Action BOM primary-path selection so source/API-spec context is not reported as an executable action path unless linked to workflow, credential, tool, agent, or automation evidence.
- Semver marker override: [semver:patch]
- Contract/API impact: report wording and BOM primary selection semantics.
- Versioning/migration impact: additive behavior change; no schema removal.
- Architecture constraints: Risk and Report boundaries remain separate.
- ADR required: no
- Cost/perf impact: low
- Chaos/failure hypothesis: context-only paths should move to appendix without removing supporting evidence needed to explain blast radius.

## Wave 2 - Large-Org Scale Safety

### Story 2.1 - Bound Target Nodes During Graph Construction

- Recommendation: Cap/group mutable endpoint target nodes before appending graph nodes and edges.
- Why: Save-time caps do not reduce peak memory; the current graph can create thousands of target nodes before serialization.
- Strategic direction: Build bounded graph projections by construction.
- Expected benefit: Prevent OOM on endpoint-heavy 300+ repo scans.
- Tasks:
  - Group endpoint operations into route/semantic groups before graph target node creation.
  - Preserve total endpoint counts and representative refs on grouped target nodes.
  - Apply deterministic per-path target node limits.
  - Add graph summary counts for suppressed/grouped target nodes.
- Repo paths:
  - `core/aggregate/attackpath/graph.go`
  - `core/aggregate/attackpath/graph_test.go`
  - `core/risk/action_paths.go`
- TDD first failing tests:
  - `go test ./core/aggregate/attackpath -run TestBuildControlPathGraph -count=1`
- Changelog impact: required
- Changelog section: Fixed
- Draft changelog entry: Bounded endpoint-derived control graph target nodes during graph construction to reduce peak memory for large OpenAPI-heavy scans.
- Semver marker override: [semver:patch]
- Contract/API impact: graph node detail becomes grouped earlier, while counts remain available.
- Versioning/migration impact: additive graph summary fields if needed.
- Architecture constraints: Aggregation owns graph projection; state/report should not compensate after the fact.
- ADR required: no
- Cost/perf impact: high positive
- Chaos/failure hypothesis: a 300+ repo endpoint-heavy fixture should complete without unbounded target-node fan-out.

### Story 2.2 - Add Large-Org Regression Fixture

- Recommendation: Add a synthetic large-org fixture with hundreds of repos and endpoint-heavy API specs.
- Why: Existing tests did not catch the 300+ repo memory/crash pattern.
- Strategic direction: Make scale regressions fail locally and in CI.
- Expected benefit: Prevent reintroducing graph/report size failures.
- Tasks:
  - Add generated synthetic materialization helper for endpoint-heavy repos.
  - Assert graph target node counts are bounded.
  - Assert state/evidence/Markdown size budgets.
  - Assert context-only paths do not dominate primary BOM.
- Repo paths:
  - `internal/enterprisepressure`
  - `internal/acceptance`
  - `internal/scenarios`
  - `core/report/report_contract_test.go`
- TDD first failing tests:
  - `go test ./internal/acceptance -run Test.*LargeOrg.* -count=1`
- Changelog impact: not required
- Changelog section: none
- Draft changelog entry: none
- Semver marker override: none
- Contract/API impact: none
- Versioning/migration impact: none
- Architecture constraints: Tests must not use network or nondeterministic generation.
- ADR required: no
- Cost/perf impact: medium
- Chaos/failure hypothesis: acceptance fixture should exercise the same fan-out that killed the 300+ repo scan without becoming slow.

## Wave 3 - Crash Diagnostics

### Story 3.1 - Persist Analysis Subphase And Heap Receipts

- Recommendation: Persist analysis/artifact subphases and heap receipts into `.status.json`.
- Why: OS-killed scans cannot emit Go errors; the status file must show the last durable subphase and memory trend.
- Strategic direction: Make interrupted scans diagnosable without stdout or terminal state.
- Expected benefit: Faster support and better operator trust.
- Tasks:
  - Include phase substeps in scan status tracker updates.
  - Persist heap receipts when `--progress-heap` is enabled.
  - Add subphase updates around graph, workflow chains, backlog, state save, proof emit, report generation, and JSON sink writes.
  - Add tests for status JSON subphase persistence.
- Repo paths:
  - `core/cli/scan.go`
  - `core/cli/scan_progress.go`
  - `core/cli/scan_status.go`
  - `core/state/scan_status.go`
- TDD first failing tests:
  - `go test ./core/cli -run 'Test.*ScanStatus.*Subphase|Test.*Progress.*Heap' -count=1`
- Changelog impact: required
- Changelog section: Added
- Draft changelog entry: Added persisted scan subphase and optional heap receipts to scan status so interrupted large scans show the last durable analysis/artifact step.
- Semver marker override: [semver:patch]
- Contract/API impact: additive `.status.json` fields.
- Versioning/migration impact: none; legacy status readers ignore new fields.
- Architecture constraints: CLI progress writes status; state package remains serialization owner.
- ADR required: no
- Cost/perf impact: low
- Chaos/failure hypothesis: killing a scan mid-analysis should leave a useful running/interrupted status snapshot.

### Story 3.2 - Stale Running Status Detection

- Recommendation: `wrkr scan status` should detect stale running status and tell operators how to check OS OOM evidence.
- Why: "No logs" after `Killed` is expected for SIGKILL but unacceptable as operator experience.
- Strategic direction: Fail closed with diagnostic next steps.
- Expected benefit: Devan can identify OOM vs Wrkr error on the next large run.
- Tasks:
  - Add stale status detection based on `last_progress_at`.
  - Surface `likely_interrupted` and diagnostic commands in JSON/human status output.
  - Keep the state file untouched.
- Repo paths:
  - `core/cli/scan_status.go`
  - `core/state/scan_status.go`
  - `docs/commands/scan.md`
- TDD first failing tests:
  - `go test ./core/cli -run TestScanStatus -count=1`
- Changelog impact: required
- Changelog section: Added
- Draft changelog entry: Added stale-running scan status diagnostics with OOM/log next steps for large scans interrupted outside Wrkr.
- Semver marker override: [semver:patch]
- Contract/API impact: additive scan status JSON.
- Versioning/migration impact: none.
- Architecture constraints: CLI owns operator messaging; state owns persisted status.
- ADR required: no
- Cost/perf impact: low
- Chaos/failure hypothesis: stale status must not mark a still-active long scan failed without evidence.

## Wave 4 - Buyer Artifact Coherence

### Story 4.1 - Report Artifact Consistency Guard

- Recommendation: Ensure Markdown and evidence JSON generated together share timestamp, BOM id, share profile, and source state digest.
- Why: A folder with fresh evidence and stale Markdown undermines trust.
- Strategic direction: Treat artifact bundles as atomic evidence outputs.
- Expected benefit: Prevent mixed/stale customer packets.
- Tasks:
  - Add source state digest to report summary/artifact metadata.
  - Include matching digest and generated timestamp in Markdown and JSON.
  - Validate paired outputs before reporting success.
  - Add tests that stale paired artifacts are overwritten or rejected.
- Repo paths:
  - `core/cli/report_artifacts.go`
  - `core/report/build.go`
  - `core/report/artifacts.go`
  - `core/report/render_markdown.go`
- TDD first failing tests:
  - `go test ./core/cli -run TestReport.*Artifact.*Consistency -count=1`
  - `go test ./core/report -run Test.*Artifact.*Digest -count=1`
- Changelog impact: required
- Changelog section: Fixed
- Draft changelog entry: Hardened report artifact pairing so Markdown and evidence JSON carry matching generated metadata and source-state identity.
- Semver marker override: [semver:patch]
- Contract/API impact: additive artifact metadata fields.
- Versioning/migration impact: none.
- Architecture constraints: Report build owns metadata; CLI owns write/verify behavior.
- ADR required: no
- Cost/perf impact: low
- Chaos/failure hypothesis: interrupted report generation must not leave a fresh JSON with stale Markdown presented as a coherent packet.

### Story 4.2 - One-Page Primary BOM And Paired Internal/Redacted Outputs

- Recommendation: Make the default lead view one page and support paired internal plus customer-redacted report outputs.
- Why: Redacted output is safe but hard to remediate; 793-1050 lines is not buyer-first.
- Strategic direction: Separate first-page decision artifact from appendix and private remediation.
- Expected benefit: Product demo can show top 5 executable paths clearly, while internal output keeps real remediation handles.
- Tasks:
  - Cap lead Markdown to top 5 executable paths and primary workflow BOM.
  - Move long policy outcomes and workflow chains to appendices.
  - Add paired internal/redacted artifact option when report paths are supplied.
  - Add line-budget tests.
- Repo paths:
  - `core/report/render_markdown.go`
  - `core/report/primary_view.go`
  - `core/cli/report.go`
  - `core/cli/report_artifacts.go`
  - `docs/commands/report.md`
- TDD first failing tests:
  - `go test ./core/report -run 'Test.*OnePage|Test.*Markdown.*LineBudget' -count=1`
  - `go test ./core/cli -run TestReport.*Paired -count=1`
- Changelog impact: required
- Changelog section: Changed
- Draft changelog entry: Refined Agent Action BOM markdown to keep the default lead view focused on top executable paths and support paired internal/redacted remediation artifacts.
- Semver marker override: [semver:patch]
- Contract/API impact: report output behavior and optional paired artifacts.
- Versioning/migration impact: additive flags/fields if needed.
- Architecture constraints: Redaction remains report-layer only; raw source remains out of shareable artifacts.
- ADR required: no
- Cost/perf impact: low
- Chaos/failure hypothesis: line caps must not hide all control-first paths; suppressed counts and appendix references must remain.

## Test Matrix Wiring

- Fast lane: `make lint-fast`, `make test-fast`
- Focused risk/report lane: `go test ./core/report ./core/risk ./core/aggregate/attackpath ./core/cli -count=1`
- Acceptance lane: `go test ./internal/acceptance -count=1`
- Scenario lane: `go test ./internal/scenarios -count=1`
- Contract lane: `make test-contracts`
- Cross-platform lane: `GOOS=windows GOARCH=amd64 go build -o /tmp/wrkr-windows-smoke/wrkr.exe ./cmd/wrkr`
- Final lane: `make prepush-full`
- Gating rule: focused tests must pass before broad gates; broad gates must pass before push/PR.

## Minimum-Now Sequence

1. Implement Story 1.1 so buyer-facing findings stop overclaiming.
2. Implement Story 2.1 and 2.2 so large-org scans do not OOM before save caps.
3. Implement Story 3.1 and 3.2 so future large-org failures leave useful evidence.
4. Implement Story 4.1 and 4.2 so output packets are coherent and buyer-readable.

## Explicit Non-Goals

- Do not add network enrichment.
- Do not change proof record signing semantics.
- Do not remove existing raw state fields without schema/versioning review.
- Do not add LLM-based analysis.
- Do not change hosted source retention behavior.

## Definition of Done

- Temp plan exists under `product/plans/adhoc`.
- Context-only source/API surfaces do not appear in primary Top Action Paths without executable linkage.
- Control graph target nodes are bounded during construction.
- `.status.json` includes useful analysis/artifact subphase and optional heap receipts.
- `wrkr scan status` explains stale/interrupted large scans.
- Report artifacts include matching generated metadata and source-state identity.
- Default BOM markdown lead view is capped and executable-path focused.
- Focused and broad validation commands complete locally.

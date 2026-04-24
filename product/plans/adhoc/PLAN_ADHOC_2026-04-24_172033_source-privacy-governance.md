# Adhoc Plan: Source Privacy and Governance Depth

Date: 2026-04-24
Profile: `wrkr`
Slug: `source-privacy-governance`
Local repo root: `/Users/tr/Clyra/wrkr`
Recommendation source: user-provided source privacy, artifact redaction, control-path governance, lifecycle, runtime ingest, and security-test backlog recommendations.

All absolute path examples from the recommendation source are normalized to the active workspace root `/Users/tr/Clyra/wrkr`. Story repo paths below are repo-relative for portability and resolve under that root.

## Global Decisions (Locked)

- Wrkr remains the See product only. This plan does not implement Axym or Gait product features except shared `Clyra-AI/proof` interoperability.
- Scan, risk, proof, report, evidence, regress, and export paths stay deterministic and non-generative. No LLM calls are allowed.
- Zero scan-data exfiltration remains the default. Hosted source acquisition may fetch files from GitHub only for deterministic scan inputs and must not upload source contents.
- Hosted `--repo` and `--org` scans default to ephemeral source materialization. Retention must be explicit and machine-readable.
- Public serialized locations must be logical source references, not local materialized filesystem roots. Detector execution may use private scan roots.
- Shareable artifacts must not serialize raw source contents or local materialized root paths. Internal debug detail must be explicit and isolated.
- Source, Detection, Aggregation, Identity, Risk, Proof emission, and Compliance mapping/evidence output boundaries remain separate and testable.
- Structured config parsing remains preferred over broad source-code text scanning. Generic source-file hosted materialization is opt-in only.
- Proof chains, state files, evidence bundles, reports, SARIF, and stdout are public contract surfaces when emitted by default commands.
- Changelog, docs, schema, and command help updates are required for every user-visible behavior or artifact contract change in this plan.

## Current Baseline (Observed)

- Hosted materialization exists under a managed `materialized-sources` root and is wired through `core/cli/scan_helpers.go`, `core/source/github/connector.go`, `core/source/org/materialized.go`, and `core/source/org/checkpoint.go`.
- `source.RepoManifest.Location` is used as both detector scan location and serialized source location in source manifests, findings, state, and downstream projections.
- `core/source/github/connector.go` includes sparse materialization logic with detector candidates and a generic source-extension allowlist.
- Current docs mention the materialized workspace root but do not provide one machine-readable source privacy contract across state, reports, evidence, SARIF, and status.
- Report public-share redaction exists for action-path projections, but source-root/path sanitization is not yet a reusable cross-artifact contract.
- `action_paths`, `agent_privilege_map`, execution identity fields, and attack-path graph code exist, but there is no single versioned `control_path_graph` artifact that all output surfaces consume.
- Credential posture is still primarily boolean in key outputs (`credential_access`, `standing_privilege`) and does not classify static, delegated, inherited, workload, JIT, or unknown provenance.
- MCP, A2A, and gateway detectors exist, but trust-depth fields are not yet rich enough to model delegation semantics, public exposure, policy binding, sanitization claims, and trust-gap scoring.
- Lifecycle state and approval expiry exist, but stale, ownerless, orphaned, revoked-present, over-approved, and inactive-but-credentialed states are not yet first-class deterministic lifecycle-gap findings.
- `.wrkr/agents/custom-agent.*` detection exists through `core/detect/agentcustom`, but Agnt-style governed manifests and declared-vs-observed drift are not first-class.
- Runtime evidence correlation is intentionally absent from `scan`; no separate deterministic `wrkr ingest` path exists yet.
- Control backlog and ticket/report exports exist, but deterministic security-test recipes by risky control path are not yet emitted.

## Exit Criteria

- Hosted scans delete materialized source roots by default on success and on failure, unless an explicit retention mode requires keeping them.
- Hosted scan outputs serialize logical source references only and never include `.wrkr/materialized-sources` or absolute materialized roots in default shareable artifacts.
- `source_privacy` metadata is present in state, report, evidence, bundle metadata, SARIF where applicable, and `scan status`.
- Hosted sparse materialization defaults to detector-owned high-signal paths only; generic source extensions require `--mode deep` or an explicit allow-source-materialization option.
- Privacy regression tests prove sentinel source contents and local materialized paths do not appear in `last-scan.json`, proof chains, evidence bundles, reports, SARIF, or stdout.
- A versioned `control_path_graph` schema and artifact is generated from existing identity, credential, tool/MCP, workflow/repo, target, and action-capability data.
- Credential provenance classification is included in inventory, action paths, control backlog, regress, reports, and schemas with stable enums and confidence.
- MCP/A2A trust-depth v2 fields feed `mcp-list`, inventory, risk, control backlog, reports, schemas, and docs.
- Lifecycle gap detection produces first-class findings, backlog items, regress drift reasons, and report sections.
- Agnt-style manifests are detected, compared with observed capabilities, and surfaced through inventory/report/regress contracts.
- `wrkr ingest` accepts runtime evidence artifacts without mutating scan truth and enriches reports/evidence by stable `path_id`, `agent_id`, tool, repo, policy ref, and proof ref.
- Security-test backlog outputs deterministic test recipes for risky control paths and exports them through report/ticket surfaces.

## Public API and Contract Map

- CLI flags and modes:
  - `wrkr scan --source-retention ephemeral|retain_for_resume|retain`
  - `wrkr scan --mode standard|deep`
  - `wrkr scan --allow-source-materialization`
  - `wrkr ingest --input <artifact> --json`
  - Existing `--json`, `--explain`, and `--quiet` behavior remains stable.
- Exit codes:
  - Preserve `0,1,2,3,4,5,6,7,8` contracts.
  - Unsafe cleanup, retention, or artifact-output violations should use exit `8` when blocked as unsafe operation.
  - Invalid retention/ingest input should use exit `6`.
  - Schema/policy violations should use exit `3`.
- Artifact keys:
  - `source_privacy.retention_mode`
  - `source_privacy.materialized_source_retained`
  - `source_privacy.raw_source_in_artifacts`
  - `source_privacy.serialized_locations`
  - `source_privacy.cleanup_status`
  - `source_manifest.repos[].location` as logical reference
  - internal-only `RepoManifest.ScanRoot json:"-"`
  - `control_path_graph.version`, `nodes`, `edges`, and stable node/edge IDs
  - `credential_provenance.type`, `subject`, `scope`, `confidence`, and `risk_multiplier`
  - MCP/A2A trust-depth fields for delegation, exposure, policy binding, sanitization claims, and trust gaps
  - `runtime_evidence` ingest references keyed by stable path and proof identifiers
  - `security_test_backlog` recipes keyed by path and capability class
- Schema surfaces:
  - `schemas/v1/source` if introduced for source privacy
  - `schemas/v1/inventory/inventory.schema.json`
  - `schemas/v1/report/report-summary.schema.json`
  - `schemas/v1/export/appendix-export.schema.json`
  - `schemas/v1/a2a/agent-card.schema.json`
  - new `schemas/v1/control-path-graph.schema.json`
  - new ingest schema under `schemas/v1` if a standalone runtime evidence artifact is added
- Proof and evidence:
  - Existing proof record types remain compatible.
  - New graph, provenance, lifecycle, and runtime references must be additive unless an explicit schema version bump is made.
  - `Clyra-AI/proof` primitives remain the signing and chain-integrity path.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/evidence.md`
  - `docs/commands/export.md`
  - `docs/commands/report.md`
  - `docs/commands/mcp-list.md`
  - `docs/commands/regress.md`
  - `docs/commands/lifecycle.md`
  - `docs/commands/manifest.md`
  - `docs/commands/index.md`
  - `docs/trust/security-and-privacy.md`
  - `docs/trust/contracts-and-schemas.md`
  - `docs/trust/deterministic-guarantees.md`
  - `docs/faq.md`
  - `docs/state_lifecycle.md`
  - `docs/specs/wrkr-manifest.md`
  - `product/wrkr.md`
  - `CHANGELOG.md`
- Docs must answer directly:
  - Does Wrkr upload source code?
  - Does Wrkr retain hosted source by default?
  - Which files are fetched for hosted scans by default?
  - Which artifacts are safe to share?
  - What changes when retention, resume retention, deep mode, or source materialization is explicitly enabled?
- Docs parity gates:
  - `scripts/check_docs_cli_parity.sh`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/run_docs_smoke.sh`
  - `make test-docs-consistency`

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage |
|---|---:|---|
| 1. Ephemeral hosted source materialization | P0 | Story 1.1 |
| 2. Separate scan root from serialized source location | P0 | Story 1.2 |
| 3. Remove generic source extension hosted fetching | P0 | Story 1.2 |
| 4. Source privacy contract in state and reports | P0 | Story 1.3 |
| 5. Artifact redaction for shareable outputs | P0 | Story 1.3 |
| 6. Privacy regression tests | P0 | Story 1.4 plus all Wave 1 stories |
| 7. Documentation and operator warnings | P1 | Story 1.4 |
| 8. Control path graph | P1 | Story 2.1 |
| 9. Credential provenance classification | P1 | Story 2.2 |
| 10. MCP/A2A trust depth v2 | P1 | Story 3.1 |
| 11. Lifecycle gap detection v2 | P1 | Story 3.2 |
| 12. Agnt manifest detection and drift | P2 | Story 3.3 |
| 13. Runtime evidence ingest | P2 | Story 4.1 |
| 14. Security-test backlog | P2 | Story 4.2 |

## Test Matrix Wiring

- Fast lane: focused Go unit and CLI contract tests for touched packages; default command anchor is `make lint-fast` plus `make test-fast`.
- Core CI lane: package, integration, schema/golden, and CLI JSON/exit-code coverage; default command anchor is `make prepush`.
- Acceptance lane: scenario and outside-in workflow validation through `scripts/validate_scenarios.sh`, `go test ./internal/scenarios -count=1 -tags=scenario`, and targeted CLI fixture tests.
- Cross-platform lane: Linux, macOS, and Windows coverage for path, cleanup, output, state, and CLI behavior touched by a story.
- Risk lane: `make test-contracts`, `make test-scenarios`, `make test-hardening`, `make test-chaos`, and `make test-perf` when safety, fail-closed, artifact, source, or hot-path behavior changes.
- Release/UAT lane: `make prepush-full`, `scripts/run_v1_acceptance.sh --mode=release`, `make test-release-smoke`, and docs-site checks for release-facing or docs-heavy stories.
- Gating rule: a story cannot be marked complete until every declared lane is green, docs parity is green for public changes, schemas/goldens are updated intentionally, and no default artifact contains raw source sentinels or materialized roots.

## Minimum-Now Sequence

- Wave 1 - P0 source privacy foundation:
  - Story 1.1 retention modes and cleanup lifecycle.
  - Story 1.2 private scan roots, logical source locations, and hosted sparse path plan.
  - Story 1.3 source privacy metadata and artifact sanitization.
  - Story 1.4 privacy regression matrix and docs.
- Wave 2 - P1 governance graph and credential semantics:
  - Story 2.1 versioned `control_path_graph`.
  - Story 2.2 typed credential provenance.
- Wave 3 - P1/P2 trust, lifecycle, and manifest governance:
  - Story 3.1 MCP/A2A trust depth v2.
  - Story 3.2 lifecycle gap detection v2.
  - Story 3.3 Agnt manifest detection and declared-vs-observed drift.
- Wave 4 - P2 runtime correlation and operator validation:
  - Story 4.1 runtime evidence ingest.
  - Story 4.2 security-test backlog.

## Explicit Non-Goals

- No raw source-code upload or remote analysis path.
- No LLM-based detection, scoring, summarization, or remediation generation.
- No Axym compliance engine implementation and no Gait enforcement engine implementation.
- No hidden daemon, background sync, or telemetry collector.
- No broad default source-code materialization for hosted scans.
- No destructive cleanup outside Wrkr-managed materialized roots.
- No default artifact that requires private local filesystem context to interpret.
- No breaking removal of existing artifact fields without schema versioning and migration guidance.

## Definition of Done

- Each story starts with failing tests that encode the intended contract.
- New or changed schemas have fixture/golden compatibility coverage.
- CLI help, docs, JSON examples, and failure-taxonomy docs are synchronized for public behavior changes.
- `CHANGELOG.md` has operator-facing entries in the section declared by each story.
- `make lint-fast`, `make test-fast`, and relevant focused package tests pass before handoff.
- Risk-bearing stories run `make test-contracts`, `make test-scenarios`, `make test-hardening`, and `make test-chaos` as declared.
- Full release-facing waves run `make prepush-full` or document a profile-approved narrower equivalent with the same contract coverage.
- Repeated runs over the same fixtures produce byte-stable artifacts except explicit timestamp/version fields.
- A final repo-wide search confirms no default artifact or test golden leaks `.wrkr/materialized-sources` or sentinel source contents unless the artifact is explicitly internal/debug-only.

## Epic 1: Hosted Source Privacy and Shareable Artifact Contracts

Objective: make hosted scans private by default, prove cleanup and redaction permanently, and make the privacy posture explicit to operators and machines.

### Story 1.1: Hosted source retention modes and cleanup lifecycle

Priority: P0
Recommendation coverage: 1, 6
Strategic direction: Source acquisition should be an ephemeral implementation detail by default, with explicit retention only for resume or operator debugging.
Expected benefit: Reduces customer privacy risk by preventing fetched private source files from remaining on disk or being confused with shareable evidence artifacts.

Tasks:
- Add a source-retention enum with `ephemeral`, `retain_for_resume`, and `retain`; default hosted `--repo` and `--org` scans to `ephemeral`.
- Wire CLI flag/config parsing in `core/cli/scan.go` and helper plumbing in `core/cli/scan_helpers.go`.
- Update materialized org acquisition in `core/source/org/materialized.go` and checkpoint behavior in `core/source/org/checkpoint.go` so resume retention is explicit.
- Delete the managed materialized source root after detectors, risk, proof, state, report, SARIF, and evidence writes are durably committed.
- On scan failure, clean the materialized root unless `retain_for_resume` or `retain` is active; preserve deterministic cleanup status.
- Guard cleanup with the existing managed-root marker and ownership checks so unsafe paths fail closed.

Repo paths:
- `core/cli/scan.go`
- `core/cli/scan_helpers.go`
- `core/source/org/materialized.go`
- `core/source/org/checkpoint.go`
- `core/cli/scan_materialized_root_test.go`
- `core/source/org/acquire_resume_test.go`
- `docs/commands/scan.md`
- `docs/failure_taxonomy_exit_codes.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/cli -run 'TestScan.*Materialized|TestScan.*Retention' -count=1`
- `go test ./core/source/org -run 'Test.*Checkpoint|Test.*Materialized|Test.*Resume' -count=1`
- `make test-contracts`
- `make test-chaos`
- `make test-hardening`
- `make lint-fast`

Test requirements:
- TDD unit tests for retention defaulting, flag parsing, invalid enum exit `6`, and cleanup state.
- Integration tests for success cleanup, failure cleanup, resume retention, explicit retain, and unsafe cleanup blocked with exit `8`.
- Crash/failure simulations for cleanup after partially written state and failed detector/report/evidence steps.
- Byte-stability checks for cleanup metadata fields excluding explicit timestamps.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
- Required commands: focused tests above plus `make test-contracts`, `make test-chaos`, and `make test-hardening`.
- Pipeline placement: PR fast/core, main acceptance/risk, cross-platform path cleanup on Linux/macOS/Windows.

Acceptance criteria:
- Default hosted scans remove the managed materialized root after successful artifact commit.
- Failed hosted scans remove the managed materialized root unless resume/retain mode is explicitly set.
- Resume retention preserves enough checkpoint state to resume without weakening cleanup ownership checks.
- Local path scans are unaffected and do not treat the user's repository as a cleanup target.
- Cleanup failures are visible in JSON/status and fail closed when source retention cannot be honored safely.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Hosted repository and organization scans now default to ephemeral source materialization with explicit retention modes and cleanup status.
Semver marker override: [semver:minor]
Contract/API impact: Adds public source-retention mode and cleanup status semantics for hosted scans.
Versioning/migration impact: Default hosted behavior changes from retained materialized workspace to ephemeral cleanup; retain modes provide migration escape hatches.
Architecture constraints: Source boundary owns materialization and cleanup; CLI orchestrates lifecycle after artifact commit; proof/evidence layers must not depend on scan roots.
ADR required: yes
TDD first failing test(s): `TestScanHostedDefaultRetentionIsEphemeral`, `TestScanHostedFailureCleansMaterializedRoot`, `TestScanHostedRetainForResumePreservesCheckpoint`.
Cost/perf impact: medium
Chaos/failure hypothesis: If a scan crashes or artifact commit fails, cleanup is either completed or the failure is reported deterministically without deleting non-managed paths.

### Story 1.2: Logical source references and detector-owned hosted materialization plan

Priority: P0
Recommendation coverage: 2, 3
Strategic direction: Separate private scan execution roots from public source identity and fetch only detector-owned high-signal paths by default.
Expected benefit: Avoids leaking local materialized paths and materially reduces private source copied into hosted scan workspaces.

Tasks:
- Add `ScanRoot string json:"-" yaml:"-"` to `source.RepoManifest` in `core/source/types.go`.
- Keep `RepoManifest.Location` as a logical reference for hosted scans, such as `github://org/repo` or `org/repo`, while `ScanRoot` points to the local filesystem root.
- Update GitHub connector acquisition/materialization to fill logical `Location` plus private `ScanRoot`.
- Update detector scope construction, source findings, ownership resolution, and inventory aggregation to use `ScanRoot` when present and fall back to `Location` for local scans.
- Replace the hosted generic source extension allowlist with a detector-owned path plan for AI configs, MCP declarations, agent manifests, workflow files, owner mappings, dependency manifests, policy files, compiled action specs, and explicit prompt/instruction surfaces.
- Gate broad source-code fetching behind `--mode deep` or `--allow-source-materialization`, and add operator warnings for those modes.

Repo paths:
- `core/source/types.go`
- `core/source/github/connector.go`
- `core/source/github/connector_test.go`
- `core/cli/scan_helpers.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/inventory/inventory_test.go`
- `core/detect/defaults/defaults.go`
- `core/detect/scope.go`
- `docs/commands/scan.md`
- `docs/trust/security-and-privacy.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/source/github -run 'Test.*Materialize|Test.*Sparse|Test.*SourceExtension' -count=1`
- `go test ./core/cli -run 'TestScan.*SourceManifest|TestScan.*Hosted|TestScan.*Deep' -count=1`
- `go test ./core/aggregate/inventory -run 'Test.*RepoManifest|Test.*ScanRoot|Test.*Location' -count=1`
- `go test ./core/detect/... -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-perf`

Test requirements:
- Contract tests proving `ScanRoot` is not serialized.
- Hosted fixture tests proving `source_manifest` and source discovery findings contain logical locations only.
- Sparse materialization tests proving generic `.go`, `.js`, `.ts`, `.py`, `.java`, `.rb`, and similar source extensions are skipped by default.
- Deep/allow-source-materialization tests proving explicit opt-in restores broad source fetch behavior with warnings.
- Detector coverage tests proving high-signal governance/config paths remain materialized.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
- Required commands: focused package tests, `make test-contracts`, `make test-scenarios`, `make test-perf`.
- Pipeline placement: PR fast/core, main acceptance/risk, nightly perf if hosted fixture size grows.

Acceptance criteria:
- Hosted detector scopes use `ScanRoot` while all default serialized artifacts use logical source locations.
- Existing local scan behavior remains compatible through `Location` fallback.
- Hosted default materialization no longer fetches generic source-code extensions.
- Deep/source-materialization opt-in is explicit, documented, and visible in JSON/status.
- No default test golden includes `.wrkr/materialized-sources`.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Hosted source manifests now serialize logical repository references while detector execution uses private scan roots and source-code materialization is opt-in.
Semver marker override: [semver:minor]
Contract/API impact: Adds internal `ScanRoot`, changes hosted `source_manifest.repos[].location` semantics, and adds deep/source materialization mode behavior.
Versioning/migration impact: Consumers relying on local hosted materialized paths must switch to logical source references or explicit internal/debug output.
Architecture constraints: Source boundary exposes logical identity; Detection receives private scan roots; Aggregation and reports must not infer filesystem paths from public locations.
ADR required: yes
TDD first failing test(s): `TestHostedRepoManifestSerializesLogicalLocation`, `TestHostedScanRootNotSerialized`, `TestHostedSparseMaterializationSkipsGenericSourceExtensions`.
Cost/perf impact: medium
Chaos/failure hypothesis: If a detector-owned path plan omits a needed file, scan quality degrades visibly without fetching broad source by default.

### Story 1.3: Source privacy metadata and cross-artifact sanitization

Priority: P0
Recommendation coverage: 4, 5, 6
Strategic direction: Make source privacy a first-class artifact contract and centralize sanitization for every shareable output path.
Expected benefit: Operators can prove what was retained, what was emitted, and whether artifacts are safe to share without reading code.

Tasks:
- Add a reusable source privacy model with retention mode, retained status, raw-source-in-artifacts boolean, serialized location mode, and cleanup status.
- Thread source privacy metadata through state, scan JSON, `scan status`, report build, evidence bundle metadata, proof mapping, and SARIF export where applicable.
- Add a sanitizer package or shared helper for shareable outputs that redacts absolute paths, materialized roots, and raw snippets while preserving repo-relative locations and stable identifiers.
- Apply sanitizer in `core/proofmap`, `core/evidence`, `core/report`, `core/export/sarif`, and scan stdout/JSON payload construction.
- Preserve internal/debug modes only behind explicit flags and ensure they cannot be confused with customer-facing outputs.
- Add contract assertions that no default serialized artifact contains `.wrkr/materialized-sources`, active workspace absolute roots, or sentinel source contents.

Repo paths:
- `core/state/state.go`
- `core/state/scan_status.go`
- `core/cli/scan.go`
- `core/cli/scan_status.go`
- `core/report/build.go`
- `core/evidence/evidence.go`
- `core/evidence/stage.go`
- `core/proofmap/proofmap.go`
- `core/export/sarif/sarif.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/inventory/inventory.schema.json`
- `core/evidence/evidence_test.go`
- `core/cli/scan_sarif_test.go`
- `core/cli/report_contract_test.go`
- `CHANGELOG.md`

Run commands:
- `go test ./core/state ./core/evidence ./core/proofmap ./core/export/sarif -count=1`
- `go test ./core/cli -run 'TestScan.*Privacy|TestScan.*Sarif|TestReport.*Redact|TestScanStatus' -count=1`
- `go test ./core/report -run 'Test.*Privacy|Test.*Redact|Test.*Public' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- Schema and golden tests for `source_privacy` fields.
- Artifact sanitizer tests for absolute paths, materialized roots, repo-relative paths, evidence values, parse messages, and SARIF locations.
- Proof/evidence tests proving proof records and bundles do not leak local roots or source snippets by default.
- Human report tests proving the source privacy summary is visible and concise.
- Negative tests proving internal/debug output must be explicitly requested.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
- Required commands: focused tests above plus `make test-contracts`, `make test-scenarios`, `make test-hardening`.
- Pipeline placement: PR fast/core, main acceptance/risk, cross-platform artifact path assertions.

Acceptance criteria:
- `last-scan.json`, proof chain, evidence bundle metadata, reports, SARIF, and stdout expose consistent `source_privacy` facts.
- Default artifacts set `raw_source_in_artifacts=false`.
- Default serialized hosted locations are logical.
- Sanitizer assertions fail tests if `.wrkr/materialized-sources` or active workspace absolute roots appear in shareable outputs.
- Internal/debug paths are opt-in and documented as non-shareable.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Scan state, reports, evidence, proof mapping, and SARIF now include explicit source privacy metadata and redact hosted materialized paths from shareable outputs.
Semver marker override: [semver:minor]
Contract/API impact: Adds `source_privacy` artifact fields and sanitizer guarantees for shareable outputs.
Versioning/migration impact: New fields are additive; hosted local paths are removed from default serialized surfaces.
Architecture constraints: Compliance/evidence output owns shareability; Proof emission receives sanitized event data; Source remains the only layer aware of materialized roots.
ADR required: yes
TDD first failing test(s): `TestScanStateIncludesSourcePrivacy`, `TestEvidenceBundleRedactsMaterializedRoots`, `TestSARIFDoesNotContainMaterializedSourceRoot`.
Cost/perf impact: low
Chaos/failure hypothesis: If sanitization cannot prove a shareable artifact is clean, artifact emission fails closed with a deterministic error.

### Story 1.4: Privacy regression matrix and operator documentation

Priority: P0
Recommendation coverage: 6, 7
Strategic direction: Convert source privacy into a permanent regression invariant and remove ambiguity from public docs.
Expected benefit: Future detector, report, and evidence work cannot quietly reintroduce source retention or source/path leakage.

Tasks:
- Add hosted scan fixtures containing sentinel source contents and governance/config files.
- Assert that `last-scan.json`, proof chain, evidence bundle, reports, SARIF, stdout, and scan status do not contain sentinel source contents or materialized roots by default.
- Assert materialized source directories are removed after successful hosted scans unless retention is explicitly enabled.
- Add warning text for `retain_for_resume`, `retain`, `--mode deep`, and `--allow-source-materialization`.
- Update scan, evidence, privacy, FAQ, and product docs with direct source-code handling answers.
- Add docs parity checks for new flags, source privacy fields, and warning copy.

Repo paths:
- `core/cli/scan_materialized_root_test.go`
- `core/source/github/connector_test.go`
- `core/evidence/evidence_test.go`
- `core/cli/report_contract_test.go`
- `core/cli/scan_sarif_test.go`
- `docs/commands/scan.md`
- `docs/commands/evidence.md`
- `docs/trust/security-and-privacy.md`
- `docs/faq.md`
- `product/wrkr.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/cli -run 'Test.*Privacy|Test.*Materialized|Test.*Sarif|Test.*ReportContract' -count=1`
- `go test ./core/source/github -run 'Test.*Privacy|Test.*Materialize|Test.*Sparse' -count=1`
- `go test ./core/evidence -run 'Test.*Privacy|Test.*Redact|Test.*Bundle' -count=1`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
- `make test-contracts`

Test requirements:
- Fixture-based sentinel tests covering successful scan, failed scan, retain-for-resume, retain, deep mode, and default mode.
- Golden tests for human report source privacy summary.
- Docs-vs-command parity tests for retention/deep flags and source privacy status fields.
- Cross-platform assertions for path separator normalization and absolute path redaction.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane, Release/UAT lane.
- Required commands: focused tests, docs checks, `make test-contracts`, and release docs smoke when publishing.
- Pipeline placement: PR fast/core/docs, main acceptance/cross-platform/risk, release docs-site smoke.

Acceptance criteria:
- Default hosted fixture scans leave no retained materialized source root.
- No default shareable artifact contains sentinel source text, materialized roots, or active local absolute roots.
- Retention and deep/source-materialization modes produce explicit warnings in JSON/human output and docs.
- Security and privacy docs state that Wrkr does not upload source code by default and does not include raw source contents in shareable artifacts.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Added privacy regression coverage and operator documentation proving hosted scans do not retain or serialize source code by default.
Semver marker override: [semver:minor]
Contract/API impact: Documents and tests source privacy invariants across public output contracts.
Versioning/migration impact: No breaking schema change beyond fields introduced in Story 1.3; docs clarify changed hosted defaults.
Architecture constraints: Tests must exercise full CLI paths rather than only isolated helpers for artifact leakage guarantees.
ADR required: no
TDD first failing test(s): `TestHostedScanArtifactsDoNotContainSourceSentinel`, `TestHostedScanDefaultRemovesMaterializedRoot`, `TestSourceRetentionWarningsInDocsAndCLI`.
Cost/perf impact: low
Chaos/failure hypothesis: If a new detector serializes raw evidence values or local roots, privacy contract tests fail before merge.

## Epic 2: Control Path Graph and Credential Semantics

Objective: create a typed governance graph and credential provenance layer that turn existing action-path and privilege data into a more complete control story.

### Story 2.1: Versioned control path graph artifact

Priority: P1
Recommendation coverage: 8
Strategic direction: Use one stable typed graph as the shared source for backlog, report, regress, and evidence instead of recomputing governance projections independently.
Expected benefit: Operators get one explainable model for identity to credential to tool/MCP to workflow/repo to target to action capability.

Tasks:
- Define `control_path_graph` schema with version, deterministic node IDs, deterministic edge IDs, node kinds, edge kinds, evidence refs, and source references.
- Derive graph nodes and edges from existing `path_id`, `agent_id`, execution identity, non-human identity, governance controls, production targets, and action capabilities.
- Add graph construction in the Risk/Aggregation boundary without letting report/proof layers directly read raw detector internals.
- Store graph in scan state and expose it to report, evidence/proofmap, regress, and control backlog.
- Add graph summary to human report and JSON report contracts.
- Add fixture/golden tests proving stable ordering and ID determinism.

Repo paths:
- `core/risk/action_paths.go`
- `core/risk/action_paths_test.go`
- `core/aggregate/attackpath/graph.go`
- `core/aggregate/attackpath/graph_test.go`
- `core/aggregate/inventory/privileges.go`
- `core/state/state.go`
- `core/report/build.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/proofmap/proofmap.go`
- `schemas/v1/control-path-graph.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/report.md`
- `docs/trust/contracts-and-schemas.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk ./core/aggregate/attackpath ./core/aggregate/controlbacklog ./core/state ./core/report ./core/proofmap -count=1`
- `make test-contracts`
- `make test-scenarios`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `make test-perf`

Test requirements:
- Schema validation for graph fixtures.
- Deterministic graph ID and ordering tests across repeated runs.
- Compatibility tests proving action paths remain present while graph is additive.
- Regress tests proving graph drift can be compared by stable IDs.
- Report/evidence tests proving graph references are sanitized and source-privacy compliant.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
- Required commands: focused tests, `make test-contracts`, `make test-scenarios`, `make test-perf`.
- Pipeline placement: PR fast/core/schema, main acceptance/risk/perf.

Acceptance criteria:
- `control_path_graph` is emitted in state and report/evidence paths with schema-valid versioned content.
- Graph IDs are stable for the same input and change only when graph identity inputs change.
- Control backlog and report can reference graph nodes/edges by ID.
- Existing `action_paths` consumers remain compatible.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a versioned control path graph artifact linking identities, credentials, tools, workflows, repos, targets, and action capabilities.
Semver marker override: [semver:minor]
Contract/API impact: Adds a public artifact/schema and new JSON fields for state/report/evidence outputs.
Versioning/migration impact: Additive schema introduction; existing `action_paths` remains during migration.
Architecture constraints: Risk/Aggregation derive the graph from normalized inventory/action data; reports and proof consume graph outputs only.
ADR required: yes
TDD first failing test(s): `TestControlPathGraphStableIDs`, `TestControlPathGraphLinksIdentityCredentialToolWorkflowTargetAction`, `TestReportIncludesControlPathGraphSummary`.
Cost/perf impact: medium
Chaos/failure hypothesis: If graph construction sees incomplete identity or credential data, it emits explicit unknown nodes/gaps instead of dropping paths.

### Story 2.2: Credential provenance classification

Priority: P1
Recommendation coverage: 9
Strategic direction: Replace boolean credential posture with typed provenance, confidence, scope, and risk multipliers while keeping existing booleans as compatibility projections.
Expected benefit: Security teams can distinguish static secrets, workload identity, inherited human credentials, OAuth delegation, JIT credentials, and unknown models.

Tasks:
- Add credential provenance enums and structs with type, subject, scope, confidence, evidence basis, and risk multiplier.
- Thread provenance through inventory privilege maps, action paths, control backlog, regress comparisons, reports, proofmap, and schemas.
- Extend secrets, CI agent, and non-human identity detectors to produce typed provenance evidence without extracting secret values.
- Keep `credential_access` and `standing_privilege` as derived compatibility fields where currently exposed.
- Update scoring/ranking so provenance changes affect risk deterministically.
- Add docs explaining each provenance type and how unknown provenance is treated.

Repo paths:
- `core/aggregate/inventory/privileges.go`
- `core/aggregate/inventory/inventory.go`
- `core/risk/action_paths.go`
- `core/risk/govern_first.go`
- `core/detect/secrets/detector.go`
- `core/detect/ciagent/detector.go`
- `core/detect/nonhumanidentity/detector.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/proofmap/proofmap.go`
- `core/report/build.go`
- `schemas/v1/inventory/inventory.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/report.md`
- `docs/commands/export.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/secrets ./core/detect/ciagent ./core/detect/nonhumanidentity -count=1`
- `go test ./core/aggregate/inventory ./core/risk ./core/aggregate/controlbacklog ./core/report ./core/proofmap -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- Unit tests for every provenance enum and confidence/risk multiplier.
- Detector fixture tests for static secret refs, workload identity, inherited human credential, OAuth delegation, JIT, and unknown.
- Contract tests proving compatibility booleans still serialize where expected.
- Regression tests proving provenance transitions produce deterministic drift reasons.
- Report/backlog tests proving provenance is actionable and sorted deterministically.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
- Required commands: focused tests, `make test-contracts`, `make test-scenarios`, `make test-hardening`.
- Pipeline placement: PR fast/core, main acceptance/risk.

Acceptance criteria:
- Inventory/action paths include typed `credential_provenance` while retaining compatibility booleans.
- Unknown credential models are explicit and risk-weighted without fail-open assumptions.
- Reports and backlog items explain the credential control question in operator language.
- Proof records include sanitized provenance evidence only and never secret values.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added typed credential provenance classification across inventory, action paths, control backlog, regress, reports, and proof mapping.
Semver marker override: [semver:minor]
Contract/API impact: Adds credential provenance JSON/schema fields and deterministic risk multipliers.
Versioning/migration impact: Additive fields; existing boolean credential fields remain as derived compatibility projections.
Architecture constraints: Detectors emit evidence; Aggregation normalizes provenance; Risk applies scoring; Proof/report consume sanitized normalized data.
ADR required: yes
TDD first failing test(s): `TestCredentialProvenanceClassifiesStaticSecret`, `TestCredentialProvenanceUnknownIsRiskWeighted`, `TestActionPathCarriesCredentialProvenance`.
Cost/perf impact: low
Chaos/failure hypothesis: If provenance evidence conflicts across detectors, Wrkr records conflicting evidence and selects deterministic `unknown` or highest-risk classification with rationale.

## Epic 3: Trust Depth, Lifecycle Gaps, and Governed Manifests

Objective: deepen governance signals beyond presence/status fields and turn missing control semantics into deterministic findings and drift reasons.

### Story 3.1: MCP and A2A trust depth v2

Priority: P1
Recommendation coverage: 10
Strategic direction: Extend MCP/A2A posture from declaration capture to trust-depth scoring across delegation, exposure, policy binding, gateway coverage, and sanitization claims.
Expected benefit: Operators can prioritize which MCP/A2A paths are risky because of how they delegate, expose, bind policy, and sanitize inputs.

Tasks:
- Extend MCP detector evidence for auth strength, delegation model, public/private exposure, policy references, gateway binding, sanitization claims, and trust gaps.
- Extend A2A detector and schema handling for auth schemes, protocols, capability exposure, gateway coverage, policy refs, and trust-depth scoring.
- Correlate MCP gateway detector results with MCP/A2A declarations for protected/unprotected/unknown coverage.
- Surface trust-depth fields in inventory, `mcp-list`, control backlog, reports, proofmap, and schemas.
- Update docs and examples for trust-depth interpretation.

Repo paths:
- `core/detect/mcp/detector.go`
- `core/detect/a2a/detector.go`
- `core/detect/mcpgateway/detector.go`
- `core/report/mcp_list.go`
- `core/cli/mcp_list.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/build.go`
- `core/proofmap/proofmap.go`
- `schemas/v1/a2a/agent-card.schema.json`
- `schemas/v1/inventory/inventory.schema.json`
- `docs/commands/mcp-list.md`
- `docs/trust/detection-coverage-matrix.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/mcp ./core/detect/a2a ./core/detect/mcpgateway -count=1`
- `go test ./core/report ./core/cli -run 'Test.*MCP|Test.*A2A|Test.*Gateway' -count=1`
- `go test ./core/aggregate/inventory ./core/aggregate/controlbacklog ./core/proofmap -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- Parser/schema tests for MCP/A2A trust-depth fields.
- Correlation tests for protected, unprotected, and unknown gateway coverage.
- Risk/backlog/report tests proving trust gaps influence prioritization deterministically.
- CLI `mcp-list --json` contract tests for additive fields and stable ordering.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
- Required commands: focused tests, `make test-contracts`, `make test-scenarios`, `make test-hardening`.
- Pipeline placement: PR fast/core, main acceptance/risk.

Acceptance criteria:
- MCP/A2A inventory records include trust-depth v2 fields with stable enums.
- `mcp-list` exposes trust gaps without breaking existing columns/JSON consumers.
- Control backlog and reports prioritize unprotected public/delegating/destructive paths.
- Schema validation covers A2A card additions and compatibility expectations.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added MCP and A2A trust-depth scoring for delegation, exposure, policy binding, gateway coverage, sanitization claims, and trust gaps.
Semver marker override: [semver:minor]
Contract/API impact: Adds trust-depth fields to detector evidence, inventory, `mcp-list`, report, backlog, and schema outputs.
Versioning/migration impact: Additive fields; old MCP/A2A presence and transport fields remain.
Architecture constraints: Detection extracts declarations; Aggregation correlates gateway and inventory context; Risk/report consume normalized trust-depth facts.
ADR required: yes
TDD first failing test(s): `TestMCPTrustDepthCapturesDelegationAndExposure`, `TestA2ATrustDepthCapturesPolicyBinding`, `TestMCPListIncludesTrustGaps`.
Cost/perf impact: low
Chaos/failure hypothesis: If gateway correlation is incomplete, trust depth emits `unknown` coverage with explicit rationale and risk treatment.

### Story 3.2: Lifecycle gap detection v2

Priority: P1
Recommendation coverage: 11
Strategic direction: Turn lifecycle health into deterministic findings and regress reasons, not just status fields.
Expected benefit: Security teams get a review queue for stale, ownerless, orphaned, revoked-present, inactive-but-credentialed, and over-approved paths.

Tasks:
- Define lifecycle gap enums and reason codes for stale, ownerless, inactive-but-credentialed, over-approved, orphaned, revoked-but-still-present, approval-expired, and presence/absence drift.
- Derive gaps from manifest state, saved snapshots, approval expiry, credential/write posture, and presence transitions.
- Emit lifecycle findings, control backlog items, regress drift reasons, and report sections.
- Preserve existing lifecycle states: discovered, under_review, approved, active, deprecated, revoked.
- Add docs explaining how lifecycle gaps are computed and remediated.

Repo paths:
- `core/lifecycle/lifecycle.go`
- `core/lifecycle/lifecycle_test.go`
- `core/regress/inventory_diff.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/build.go`
- `core/state/state.go`
- `core/cli/lifecycle.go`
- `core/cli/regress.go`
- `docs/state_lifecycle.md`
- `docs/commands/lifecycle.md`
- `docs/commands/regress.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/lifecycle ./core/regress ./core/aggregate/controlbacklog ./core/report ./core/state -count=1`
- `go test ./core/cli -run 'Test.*Lifecycle|Test.*Regress' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- Unit tests for each lifecycle gap reason and transition.
- Regress fixture tests proving gap transitions produce stable drift reasons and exit `5` when policy requires.
- Backlog/report tests proving gaps rank ownerless credentialed write paths above lower-risk lifecycle noise.
- Docs parity tests for lifecycle command/status changes.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
- Required commands: focused tests, `make test-contracts`, `make test-scenarios`, `make test-hardening`.
- Pipeline placement: PR fast/core, main acceptance/risk.

Acceptance criteria:
- Lifecycle gaps are emitted as first-class findings with stable reason codes.
- Regress output can explain lifecycle drift by gap reason and affected identity/path.
- Reports and backlog include a deterministic review queue.
- Existing lifecycle state semantics remain backward-compatible.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added lifecycle gap findings and regress reasons for stale, ownerless, orphaned, revoked-present, inactive-credentialed, and over-approved AI paths.
Semver marker override: [semver:minor]
Contract/API impact: Adds lifecycle gap fields/findings and drift reason codes.
Versioning/migration impact: Additive lifecycle output; regress policies may begin failing on newly visible lifecycle gaps when configured.
Architecture constraints: Identity/lifecycle derives state; Risk/regress consume gaps; Reports/backlog present normalized review work.
ADR required: yes
TDD first failing test(s): `TestLifecycleGapOwnerlessCredentialed`, `TestRegressLifecycleGapDriftReasonStable`, `TestReportIncludesLifecycleGapQueue`.
Cost/perf impact: low
Chaos/failure hypothesis: If saved snapshot state is missing or partially corrupt, lifecycle gap detection fails closed or emits explicit incomplete-state diagnostics.

### Story 3.3: Agnt manifest detection and declared-vs-observed drift

Priority: P2
Recommendation coverage: 12
Strategic direction: Add a governed manifest layer that compares declared agent permissions/tools/policy refs with observed behavior.
Expected benefit: Teams can spot when an agent's real control path exceeds its declared governance envelope.

Tasks:
- Add `core/detect/agnt` for `agent.yaml`, `agent.yml`, and Agnt-style manifest parsing using structured YAML.
- Preserve manifest identity, declared tools, MCP refs, permissions, policy refs, owner refs, and lifecycle metadata.
- Integrate declared manifest data with `agentcustom`, inventory, control path graph, lifecycle gaps, reports, and regress.
- Emit drift when observed capabilities exceed declared permissions/tools/policy refs.
- Add schema/docs for supported Agnt manifest fields and drift semantics.

Repo paths:
- `core/detect/agnt/detector.go`
- `core/detect/agnt/detector_test.go`
- `core/detect/defaults/defaults.go`
- `core/detect/agentcustom/detector.go`
- `core/aggregate/inventory/inventory.go`
- `core/risk/action_paths.go`
- `core/regress/inventory_diff.go`
- `core/report/build.go`
- `schemas/v1/inventory/inventory.schema.json`
- `docs/commands/manifest.md`
- `docs/specs/wrkr-manifest.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/agnt ./core/detect/agentcustom ./core/detect/defaults -count=1`
- `go test ./core/aggregate/inventory ./core/risk ./core/regress ./core/report -count=1`
- `make test-contracts`
- `make test-scenarios`

Test requirements:
- YAML parser tests for valid, partial, unknown, and invalid manifests.
- Drift tests for observed tool/MCP/capability exceeding declaration.
- Inventory/report/regress tests for stable manifest identity and drift reason codes.
- Scenario fixture for a governed manifest with observed excess capability.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane.
- Required commands: focused tests, `make test-contracts`, `make test-scenarios`.
- Pipeline placement: PR fast/core, main acceptance.

Acceptance criteria:
- Agnt manifests are detected and exposed as first-class governed declarations.
- Declared-vs-observed drift produces stable findings/regress reasons.
- Existing `.wrkr/agents/custom-agent.*` behavior remains compatible.
- Docs identify supported fields and limitations.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added Agnt-style manifest detection with declared-vs-observed drift for tools, MCP refs, permissions, and policy references.
Semver marker override: [semver:minor]
Contract/API impact: Adds detector output, inventory/report fields, and regress drift reason codes for governed manifests.
Versioning/migration impact: Additive detector and schema fields; invalid manifests produce deterministic parse diagnostics.
Architecture constraints: Detection parses declared manifests; Aggregation correlates declarations with observed capabilities; Risk/regress decide drift impact.
ADR required: no
TDD first failing test(s): `TestAgntDetectsAgentYAML`, `TestAgntObservedToolExceedsDeclaredTools`, `TestRegressAgntDeclaredObservedDrift`.
Cost/perf impact: low
Chaos/failure hypothesis: If manifest parsing fails, Wrkr emits deterministic parse diagnostics without treating undeclared observed capabilities as approved.

## Epic 4: Runtime Correlation and Operator Validation Backlog

Objective: keep `scan` static and deterministic while adding explicit runtime evidence correlation and concrete validation work for risky paths.

### Story 4.1: Runtime evidence ingest command

Priority: P2
Recommendation coverage: 13
Strategic direction: Add runtime evidence as a separate deterministic input that enriches reports/evidence without mutating static scan truth.
Expected benefit: Operators can prove whether risky control paths are governed at runtime while preserving scan determinism.

Tasks:
- Add `wrkr ingest` CLI command and `core/ingest` package for runtime evidence artifacts.
- Define ingest schema keyed by `path_id`, `agent_id`, tool, repo, policy ref, proof ref, source, observed_at, and evidence class.
- Store ingest artifacts separately from scan truth and reference them in state/report/evidence by stable IDs.
- Enrich reports and evidence bundles with runtime evidence status without changing static scan findings.
- Add proofmap links from runtime evidence refs to existing path/agent/proof refs.
- Document ingest input contract, determinism rules, and failure modes.

Repo paths:
- `core/cli/ingest.go`
- `core/cli/root.go`
- `core/ingest/ingest.go`
- `core/ingest/ingest_test.go`
- `core/state/state.go`
- `core/proofmap/proofmap.go`
- `core/evidence/evidence.go`
- `core/report/build.go`
- `schemas/v1/runtime-evidence.schema.json`
- `docs/commands/evidence.md`
- `docs/commands/mcp-list.md`
- `docs/commands/index.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/ingest ./core/state ./core/proofmap ./core/evidence ./core/report -count=1`
- `go test ./core/cli -run 'Test.*Ingest|TestRootIncludesIngest' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- CLI contract tests for `wrkr ingest --json`, invalid input exit `6`, schema violation exit `3`, and unsafe output path exit `8`.
- Schema validation and golden tests for ingest artifacts.
- Report/evidence tests proving runtime evidence enriches output without mutating scan truth.
- Determinism tests for stable sorting and repeated ingest rendering.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
- Required commands: focused tests, `make test-contracts`, `make test-scenarios`, `make test-hardening`.
- Pipeline placement: PR fast/core/schema, main acceptance/risk.

Acceptance criteria:
- `wrkr ingest` is available, documented, and emits machine-readable JSON.
- Runtime evidence artifacts are schema-valid, deterministic, and linked by stable identifiers.
- Static scan findings remain unchanged when ingest evidence is added.
- Reports/evidence distinguish static truth from runtime corroboration.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added `wrkr ingest` for deterministic runtime evidence correlation keyed to control paths, agents, tools, repos, policies, and proof refs.
Semver marker override: [semver:minor]
Contract/API impact: Adds a new CLI command, schema, state/report/evidence fields, and exit-code behavior.
Versioning/migration impact: Additive command and artifact contract; no scan output mutation required for users who do not ingest runtime evidence.
Architecture constraints: Ingest is separate from Source/Detection scan truth; Report/evidence enrichment must label runtime data as corroborating evidence.
ADR required: yes
TDD first failing test(s): `TestIngestValidRuntimeEvidenceJSON`, `TestIngestDoesNotMutateScanTruth`, `TestEvidenceBundleLinksRuntimeEvidenceByPathID`.
Cost/perf impact: medium
Chaos/failure hypothesis: If ingest artifacts are stale, malformed, or conflict with scan state, Wrkr reports deterministic correlation gaps rather than silently merging them.

### Story 4.2: Deterministic security-test backlog

Priority: P2
Recommendation coverage: 14
Strategic direction: Convert risky control paths into concrete test recipes operators can run next.
Expected benefit: Wrkr moves from "review this" toward "validate this control path with these deterministic security tests."

Tasks:
- Add security-test recipe generation by path and capability class: prompt injection, MCP endpoint swap, egress attempt, destructive action dry-run, untrusted repo content, and secret-scope validation.
- Attach recipes to control backlog items, report output, and ticket exports.
- Keep recipes deterministic templates with no live exploitation or unsafe execution by default.
- Include safety preconditions, expected observation, required approvals, dry-run flags, and evidence refs.
- Add docs for export/report recipe interpretation and safe operator execution.

Repo paths:
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/export/tickets/tickets.go`
- `core/report/build.go`
- `core/report/types.go`
- `core/risk/action_paths.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/export/appendix-export.schema.json`
- `docs/commands/export.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/aggregate/controlbacklog ./core/export/tickets ./core/report ./core/risk -count=1`
- `go test ./core/cli -run 'Test.*Export|Test.*Report|Test.*ControlBacklog' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`

Test requirements:
- Unit tests mapping capability classes to stable recipes.
- Contract tests proving recipe IDs, ordering, and schema fields are deterministic.
- Report/export tests proving recipes are visible but do not include raw source or unsafe commands by default.
- Scenario tests for high-risk MCP, headless CI, production-write, and secret-scope validation paths.

Matrix wiring:
- Lanes: Fast lane, Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
- Required commands: focused tests, `make test-contracts`, `make test-scenarios`, `make test-hardening`.
- Pipeline placement: PR fast/core, main acceptance/risk.

Acceptance criteria:
- Risky control paths produce deterministic security-test recipe recommendations.
- Ticket exports and reports include recipes with stable IDs, safety preconditions, and evidence refs.
- Recipes do not execute tests or mutate systems; they are backlog recommendations only.
- Source privacy sanitizer applies to recipe evidence and examples.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added deterministic security-test backlog recipes for risky control paths across prompt injection, MCP swap, egress, destructive dry-run, untrusted content, and secret-scope validation classes.
Semver marker override: [semver:minor]
Contract/API impact: Adds security-test recipe fields to control backlog, report, and ticket export contracts.
Versioning/migration impact: Additive output; existing backlog and export consumers can ignore recipe fields.
Architecture constraints: Control backlog owns recipe generation from normalized risk/path data; export/report render recipes without executing them.
ADR required: no
TDD first failing test(s): `TestSecurityTestBacklogRecipesStableByCapabilityClass`, `TestTicketExportIncludesSecurityTestRecipes`, `TestReportSecurityRecipesAreSanitized`.
Cost/perf impact: low
Chaos/failure hypothesis: If a path lacks enough capability metadata, Wrkr emits a conservative generic validation recipe with an explicit missing-context note.

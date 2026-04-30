# Adhoc Plan: Report Runtime Evidence and BOM Proof Alignment

Date: 2026-04-30
Profile: `wrkr`
Slug: `report-runtime-evidence-bom-proof`
Recommendation source: user-provided consolidated code-review and app-audit findings focused on two contract-facing gaps: missing top-level `runtime_evidence` emission from `wrkr report` and false-green Agent Action BOM proof coverage when path-level control proof is still missing.

All observed local checkout references from the recommendation source are normalized to repo-relative paths in this plan. Story repo paths below resolve from the active repository root.

## Global Decisions (Locked)

- Scope is intentionally narrow. This plan fixes the two audited report/evidence truthfulness gaps without reopening the broader Agent Action BOM roadmap already captured in `product/plans/adhoc/PLAN_ADHOC_2026-04-29_193312_agent-action-bom-runtime-evidence.md`.
- Wrkr should honor its currently published `wrkr report` JSON contract by emitting top-level `runtime_evidence` when it is available, instead of silently narrowing the contract through docs drift.
- Global proof-chain integrity and path-level proof sufficiency are separate concerns. A valid chain head may prove artifact integrity, but it must not be treated as evidence that every BOM item has the required approval/control proof.
- Contract repair must stay additive where possible: no existing JSON keys, exit codes, or template names are removed or renamed.
- CLI serialization owns top-level report payload emission; report/evidence builders own derived proof coverage semantics. Detection, source, and proof-emission layers should remain unchanged unless a test proves a missing linkage cannot be solved at the reporting boundary.
- Determinism, fail-closed behavior, zero scan-data egress, and secret non-extraction remain non-negotiable. Any ambiguous proof-coverage state must degrade to an explicit gap, not a healthy-looking default.
- Docs, changelog, and contract tests ship in the same PR as behavior changes because this scope touches public command semantics and buyer-facing output claims.

## Current Baseline (Observed)

- `core/cli/report.go` serializes top-level `action_paths`, `agent_action_bom`, `action_path_to_control_first`, and `control_path_graph`, but the report payload type does not define a top-level `runtime_evidence` field.
- `docs/commands/report.md` documents additive top-level `runtime_evidence` output and separately states that `summary.runtime_evidence` and top-level `runtime_evidence` expose deterministic path and agent correlation metadata.
- The current report command therefore documents a top-level contract it cannot emit, even when runtime evidence exists in the generated summary.
- `core/report/agent_action_bom.go` derives item `proof_coverage` only from global proof-chain presence by checking `summary.Proof.HeadHash`; `missing_proof_items` increments only when that global value is absent.
- `core/evidence/evidence.go` already emits `control_evidence[]` with explicit `missing_proof[]` arrays, so the product has a more granular proof-gap signal than the BOM summary currently reflects.
- Review evidence gathered against the evaluator-safe scenario path showed:
  - `./.tmp/wrkr report --state ./.tmp/factory-review-state.json --template agent-action-bom --json | jq '{top_level_has_runtime_evidence: has("runtime_evidence")}'` returned `false`.
  - `./.tmp/wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.tmp/factory-review-state.json --output ./.tmp/factory-review-evidence-2 --json | jq ...` returned `bom_missing_proof_items: 0` while `missing_control_evidence_items: 45`.
- Baseline health for the current tree is good: `make lint-fast`, `make test-fast`, `make test-docs-consistency`, `make build`, evaluator-safe `wrkr scan --json`, `wrkr verify --chain --json`, `wrkr evidence --json`, `wrkr report --template agent-action-bom --json`, and `wrkr regress run --baseline <baseline-path> --json` all succeeded during review.

## Exit Criteria

- `wrkr report --json` emits top-level `runtime_evidence` whenever the generated summary includes runtime evidence, and omits the field when runtime evidence is unavailable.
- Report docs, examples, and CLI contract tests agree on the presence and omission rules for top-level `runtime_evidence`.
- Agent Action BOM item `proof_coverage` reflects path-level proof sufficiency instead of global chain presence alone.
- Agent Action BOM `missing_proof_items` increments for scenarios where linked control evidence or backlog proof requirements are still missing, even when the proof chain is intact.
- Report JSON and evidence JSON agree on proof-gap interpretation for the same saved state and deterministic fixture.
- New tests cover:
  - positive runtime-sidecar report emission
  - negative runtime-evidence omission
  - chain-attached plus proof-gap BOM behavior
  - report/evidence parity for BOM proof coverage
- Implementation completes without changing existing exit codes, without introducing machine-local absolute paths into committed fixtures/docs, and without weakening fail-closed semantics.

## Public API and Contract Map

- `wrkr report --json`
  - Restore the published additive top-level `runtime_evidence` field from the generated summary object.
  - Preserve nested `summary.runtime_evidence` behavior when runtime evidence exists.
  - Preserve omission semantics when runtime evidence is unavailable instead of emitting an empty placeholder object.
- `agent_action_bom`
  - Keep `proof_refs` for chain and finding references.
  - Reinterpret `proof_coverage` as path-level proof sufficiency rather than global chain attachment.
  - If needed for clarity, add an additive chain-specific status field or summary fact instead of overloading `proof_coverage` with integrity semantics.
- `wrkr evidence --json`
  - Keep `control_evidence[]` as the granular proof-gap signal.
  - Ensure BOM proof coverage inside report/evidence artifacts derives from the same underlying sufficiency rules as `control_evidence[]`.
- Schemas and contract tests
  - Update `schemas/v1/agent-action-bom.schema.json` only if the repaired proof semantics require additive fields or tighter documented status values.
  - Keep existing report-summary schema compatibility intact; top-level report payload expectations are enforced primarily through CLI contract tests and docs.
- Architecture boundaries
  - Source and detection remain unchanged.
  - Aggregation remains the source of inventory/action-path signals.
  - Report and evidence layers own contract repair and proof sufficiency derivation.
  - Proof emission remains the authoritative chain producer and verifier, not the owner of report serialization semantics.

## Docs and OSS Readiness Baseline

- User-facing docs and trust surfaces impacted by this scope:
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/examples/quickstart.md`
  - `docs/examples/security-team.md`
  - `CHANGELOG.md`
- Required docs outcomes:
  - Clearly state when top-level `runtime_evidence` appears in report JSON and when it is omitted.
  - Explain that BOM `proof_coverage` is about path-level proof sufficiency, while proof-chain refs/integrity remain separate.
  - Keep operator guidance aligned so users do not misread a valid proof chain as proof that all path-level approvals or control evidence are complete.
- Docs parity and source-of-truth gates for this scope:
  - `scripts/check_docs_cli_parity.sh`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `make test-docs-consistency`
- OSS trust posture is already green for baseline files (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`); this plan does not alter support or disclosure policy and should not broaden scope into OSS governance changes.

## Recommendation Traceability

| Recommendation / Finding | Priority | Planned Coverage |
|---|---:|---|
| 1. Emit published top-level `runtime_evidence` from `wrkr report` | P0 | Story 1.1, Story 2.2 |
| 2. Make Agent Action BOM proof coverage truthful at the path level | P0 | Story 2.1, Story 2.2 |
| Residual gap: positive runtime-sidecar contract coverage for report | P1 | Story 2.2 |
| Residual gap: report/evidence parity test for proof-gap counts | P1 | Story 2.2 |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - focused `go test` runs for `core/cli`, `core/report`, and `core/evidence`
- Core CI lane:
  - `make test-fast`
  - `make test-contracts`
  - `make test-docs-consistency`
- Acceptance lane:
  - targeted deterministic CLI/integration coverage proving runtime-sidecar to report output and missing-proof to BOM output flows
  - `make test-scenarios` when a scenario fixture is added or updated
- Cross-platform lane:
  - keep tests path-separator neutral and avoid platform-specific temp-path assertions
  - run existing contract/e2e suites under CI platform matrix without introducing OS-specific output differences
- Risk lane:
  - `make test-hardening` for fail-closed proof-gap and omission behavior
  - `make test-scenarios` when scenario fixtures encode these regressions
  - `make test-contracts` remains required because the changed surfaces are public contracts
- Release/UAT lane when relevant:
  - `make prepush-full` before final landing
  - `make test-release-smoke` only if docs/examples or artifact packaging changes require release-smoke confirmation
- Gating rule:
  - no story is complete until its declared lanes are green, docs and behavior agree, changelog intent is explicit, and repeated runs remain deterministic aside from explicit timestamp/version fields

## Minimum-Now Sequence

- Wave 1 - Restore published report contract and truthful proof semantics:
  - Story 1.1: emit top-level `runtime_evidence` from the report payload and lock positive/negative contract behavior.
  - Story 2.1: compute BOM proof coverage from path-linked proof sufficiency instead of global chain presence.
- Wave 2 - Regression lock and cross-artifact parity:
  - Story 2.2: add deterministic fixtures and end-to-end contract coverage proving report/evidence parity for runtime evidence and proof-gap counts.

## Explicit Non-Goals

- No expansion of the broader Agent Action BOM roadmap beyond these two audited defects.
- No new detector surfaces, no new risk-scoring features, and no new production-target or policy-coverage work outside what is required to repair proof semantics for existing outputs.
- No new proof record types, no mutation of chain verification behavior, and no changes to `Clyra-AI/proof` contracts.
- No Gait enforcement behavior, Axym behavior, runtime kill-switch implementation, or policy-decision execution in Wrkr.
- No scan-time BOM generation path; `wrkr report` and evidence outputs remain the canonical derived artifact surfaces.
- No reliance on developer-specific absolute paths, external SaaS correlation, or nondeterministic network lookups.

## Definition of Done

- Top-level `runtime_evidence` is emitted by `wrkr report` exactly when available and omitted exactly when unavailable.
- Report docs/examples and contract tests describe the same runtime-evidence behavior that the CLI actually implements.
- BOM `proof_coverage` and `missing_proof_items` no longer present a false-green state when path-level control proof is missing.
- Report JSON and evidence JSON agree on proof-gap interpretation for shared deterministic fixtures.
- New tests are added at the right layers: unit/report, CLI contract, evidence parity, and scenario/integration where needed.
- `make lint-fast`, `make test-fast`, `make test-contracts`, and docs gates required by touched surfaces are wired into the implementation stories.
- Final implementation changes stay within Wrkr scope, preserve determinism and fail-closed posture, and update `CHANGELOG.md` for user-visible contract fixes.

## Epic 1: Report Contract Parity

Objective: repair the published `wrkr report` JSON contract so runtime-evidence automation can rely on the top-level payload the docs already promise.

### Story 1.1: Emit top-level runtime evidence from the report payload

Priority: P0
Recommendation coverage: 1
Strategic direction: treat the generated report summary as the single source of truth for runtime evidence and mirror it into the top-level CLI payload without inventing a second serializer path.
Expected benefit: operators and automation can consume the documented top-level `runtime_evidence` field directly after `wrkr ingest` without custom summary unwrapping or silent absence.

Tasks:
- Add a top-level `RuntimeEvidence` field to the report CLI payload and populate it from `summary.RuntimeEvidence`.
- Preserve current omission behavior when runtime evidence is unavailable so the field remains absent instead of serializing an empty object.
- Add failing CLI contract tests for both positive and negative runtime-evidence cases before implementation.
- Verify behavior across at least the default operator template and `agent-action-bom` template so emission is not template-specific.
- Update user-facing report docs and examples to describe the repaired top-level field and omission rules.
- Add a changelog entry documenting the contract fix.

Repo paths:
- `core/cli/report.go`
- `core/cli/report_contract_test.go`
- `core/cli/root_test.go`
- `docs/commands/report.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/cli -run 'TestReport.*RuntimeEvidence|TestReport.*AgentActionBOM' -count=1`
- `make lint-fast`
- `make test-fast`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `make test-docs-consistency`

Test requirements:
- TDD failing test with a saved state plus managed runtime evidence sidecar proving top-level `runtime_evidence` appears in report JSON.
- Negative test proving report JSON omits top-level `runtime_evidence` when no sidecar is present.
- Regression test proving nested `summary.runtime_evidence` and top-level `runtime_evidence` match when both are present.
- Docs parity test proving help text/examples do not drift from CLI behavior.

Matrix wiring:
- Fast lane: focused `core/cli` tests and `make lint-fast`.
- Core CI lane: `make test-fast`, `make test-contracts`, and `make test-docs-consistency`.
- Acceptance lane: positive sidecar flow is locked further in Story 2.2.
- Cross-platform lane: ensure temp-path handling and JSON assertions are platform-neutral.
- Risk lane: `make test-contracts` and `make test-hardening` because this is a public machine-readable contract with fail-closed omission semantics.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- `wrkr report --json` includes top-level `runtime_evidence` whenever report summary generation sees runtime evidence.
- `wrkr report --json` omits top-level `runtime_evidence` when runtime evidence is unavailable.
- The repaired field is documented in report command docs and examples.
- No existing top-level report keys or exit codes change.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Fixed `wrkr report --json` to emit the documented top-level `runtime_evidence` field when runtime correlation data is available from the selected saved state.
Semver marker override: [semver:patch]
Contract/API impact: Restores a documented additive top-level report JSON field without renaming or removing existing keys.
Versioning/migration impact: No migration required; consumers that already follow the docs can use the repaired field directly.
Architecture constraints: CLI serialization mirrors report-summary state only; runtime evidence correlation logic remains owned by ingest/report builders.
ADR required: no
TDD first failing test(s): `TestReportJSONIncludesTopLevelRuntimeEvidenceWhenSidecarPresent` and `TestReportJSONOmitsTopLevelRuntimeEvidenceWhenUnavailable`.
Cost/perf impact: low
Chaos/failure hypothesis: missing, stale, or malformed sidecars continue to omit runtime evidence or surface explicit runtime failure instead of emitting a misleading empty object.

## Epic 2: BOM Proof Truthfulness and Regression Lock

Objective: make Agent Action BOM proof semantics truthful at the path level and prevent report/evidence drift from reappearing.

### Story 2.1: Derive BOM proof coverage from path-linked proof sufficiency

Priority: P0
Recommendation coverage: 2
Strategic direction: compute item `proof_coverage` and summary `missing_proof_items` from path-linked control proof sufficiency, while keeping chain integrity visibility separate through proof refs or an additive chain-status field if needed.
Expected benefit: the canonical BOM artifact stops showing healthy proof coverage when approvals or control evidence are still missing for specific risky paths.

Tasks:
- Add failing tests for a scenario with an intact proof chain but missing path-level control proof so BOM items no longer report a healthy state.
- Introduce a shared proof-sufficiency evaluator for BOM/report and evidence outputs that uses linked action-path IDs, control-backlog state, proof requirements, and explicit missing-proof signals.
- Replace the current global-head-hash-only `proofCoverage` behavior with path-aware status computation.
- Recompute `missing_proof_items` from the new path-level status instead of global chain absence.
- Preserve proof refs and global chain visibility separately so integrity evidence is still available without being conflated with proof sufficiency.
- Update the BOM schema only as needed for additive fields or documented proof-status values.
- Update report/evidence docs and changelog language to reflect the repaired semantics.

Repo paths:
- `core/report/agent_action_bom.go`
- `core/report/report_test.go`
- `core/report/artifacts.go`
- `core/evidence/`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/report -run 'Test.*AgentActionBOM|Test.*ProofCoverage' -count=1`
- `go test ./core/evidence -run 'Test.*ControlEvidence|Test.*AgentActionBOM' -count=1`
- `make lint-fast`
- `make test-fast`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- TDD unit test proving `proof_coverage` is not healthy when chain integrity is intact but linked control proof is missing.
- Positive test proving a fully satisfied path reports covered proof status.
- Parity test proving BOM proof status and `missing_proof_items` remain stable across repeated runs.
- Contract test proving any new/additive proof-status field is schema-valid and backward compatible for existing consumers.

Matrix wiring:
- Fast lane: focused `core/report` and `core/evidence` tests plus `make lint-fast`.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: cross-artifact parity scenario is locked in Story 2.2.
- Cross-platform lane: keep proof-status logic free of OS-specific path or file-order assumptions.
- Risk lane: `make test-hardening` and `make test-contracts` because this story repairs a false-green compliance/reporting risk.
- Release/UAT lane: `make prepush-full` before final landing.

Acceptance criteria:
- A saved state with an intact proof chain but missing path-level proof yields non-healthy item proof coverage and `missing_proof_items > 0`.
- A saved state with satisfied linked proof requirements yields healthy item proof coverage.
- Global proof-chain refs remain visible without implying path-level sufficiency.
- Report and evidence docs describe the repaired semantics clearly.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Fixed Agent Action BOM proof coverage to reflect missing path-level approval and control proof instead of treating any attached proof chain as complete coverage.
Semver marker override: [semver:patch]
Contract/API impact: Tightens the semantics of existing BOM proof fields and may add an additive chain-status field if needed for clarity.
Versioning/migration impact: No field removals; consumers must tolerate more accurate proof-status values and any additive clarification field.
Architecture constraints: proof sufficiency belongs in report/evidence output derivation; proof emission and detector layers remain authoritative only for the raw chain and finding inputs.
ADR required: no
TDD first failing test(s): `TestBuildAgentActionBOMCountsMissingProofWhenChainAttachedButControlProofMissing`.
Cost/perf impact: low
Chaos/failure hypothesis: when proof linkage is ambiguous, the evaluator records a gap or conflict status instead of defaulting to covered.

### Story 2.2: Add deterministic regression fixtures for runtime evidence and proof-gap parity

Priority: P1
Recommendation coverage: 1, 2
Strategic direction: lock both fixes with shared deterministic fixtures so `wrkr report` and `wrkr evidence` cannot drift apart again on runtime evidence presence or BOM proof-gap counts.
Expected benefit: future refactors in CLI/report/evidence layers preserve truthful cross-artifact behavior without relying on manual reviewer comparison.

Tasks:
- Add or extend deterministic fixtures covering:
  - a saved state plus runtime sidecar that should emit top-level `runtime_evidence`
  - a saved state plus missing linked control proof that should increment BOM `missing_proof_items`
- Add end-to-end or contract-level tests that run `wrkr report --json` and `wrkr evidence --json` against the same fixture and assert parity on proof-gap interpretation.
- Add regression tests proving report docs/examples still match the exercised command path after the fixes land.
- Reuse repo-relative fixture paths and stable timestamps so outputs stay byte-stable.
- Keep this story implementation-only unless docs need final wording cleanup discovered during test authoring.

Repo paths:
- `core/cli/root_test.go`
- `core/cli/report_contract_test.go`
- `core/report/`
- `core/evidence/`
- `testinfra/contracts/`
- `internal/e2e/cli_contract/`
- `scenarios/wrkr/`

Run commands:
- `go test ./core/cli -run 'TestReport.*RuntimeEvidence|TestReport.*AgentActionBOM' -count=1`
- `go test ./core/report ./core/evidence -count=1`
- `make test-contracts`
- `make test-fast`
- `make test-scenarios`

Test requirements:
- Shared fixture proving report top-level runtime evidence and evidence-path runtime evidence both appear when expected.
- Shared fixture proving report BOM and evidence BOM agree on missing-proof counts for the same path.
- Repeated-run determinism assertion for any updated golden or JSON fixture output.
- Negative assertion that no fixture embeds developer-specific absolute checkout roots.

Matrix wiring:
- Fast lane: focused `core/cli`, `core/report`, and `core/evidence` tests.
- Core CI lane: `make test-fast` and `make test-contracts`.
- Acceptance lane: `make test-scenarios` when scenario fixtures are updated.
- Cross-platform lane: fixtures and golden assertions use repo-relative normalization only.
- Risk lane: `make test-contracts` and `make test-scenarios`; add `make test-hardening` if fixture wiring reveals a fail-open path.
- Release/UAT lane: not required unless fixture changes force user-facing release-smoke updates.

Acceptance criteria:
- The same deterministic fixture can prove both repaired behaviors without manual comparison.
- Report and evidence outputs stay aligned on runtime evidence presence and BOM proof-gap counts.
- No committed fixture, golden, or scenario file contains machine-local absolute paths.
- Regression tests fail before behavior drift can reach docs or release artifacts.

Changelog impact: not required
Changelog section: none
Draft changelog entry: none
Semver marker override: none
Contract/API impact: No new public fields; this story locks the repaired behaviors with deterministic regression coverage.
Versioning/migration impact: None.
Architecture constraints: test fixtures must exercise existing boundaries rather than introducing test-only production shortcuts.
ADR required: no
TDD first failing test(s): `TestReportAndEvidenceAgreeOnBOMMissingProofCounts` and `TestReportRuntimeEvidenceFixtureProducesTopLevelField`.
Cost/perf impact: low
Chaos/failure hypothesis: stale or incomplete fixture inputs should fail loudly in tests rather than masking parity drift with permissive assertions.

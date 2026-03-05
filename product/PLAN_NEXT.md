# PLAN NEXT: Runtime Contract and Safety Hardening

Date: 2026-03-04
Source of truth: user-provided code-review findings (P1/P2), `product/dev_guides.md`, `product/architecture_guides.md`, `AGENTS.md`
Scope: Wrkr repository only; planning artifact only (no implementation in this document).

## Global Decisions (Locked)

- Wave order is strict.
- Wave 1 is mandatory before any Wave 2 work.
- Exit-code and JSON error-envelope behavior is public contract surface.
- Contract changes are additive-first unless explicitly versioned.
- Fail-closed filesystem safety is mandatory for destructive/reset operations.
- State/proof persistence paths must be crash-safe and deterministic.
- Architecture boundaries remain enforced: Source -> Detection -> Aggregation -> Identity -> Risk -> Proof -> Compliance.
- High-risk reliability stories must run `make prepush-full`, `make test-hardening`, and `make test-chaos`.
- Contract stories must run `make test-contracts` and `make test-scenarios`.

## Current Baseline (Observed)

- `make lint-fast` and `make test-fast` passed during review baseline.
- `wrkr evidence` currently maps non-unsafe failures to `unsafe_operation_blocked` with exit `8`.
- Repo/org scan materialization path cleanup uses recursive delete without ownership gating on caller-influenced path roots.
- `core/state`, `core/proofemit`, and `core/lifecycle` persistence writes are non-atomic relative to `manifest`/`regress` temp+rename patterns.
- `wrkr verify --chain` maps malformed-chain parse failures to `invalid_input` (`6`), while trust docs define verification-failure semantics around exit `2`.

## Exit Criteria

1. `evidence` distinguishes `invalid_input` vs `runtime_failure` vs `unsafe_operation_blocked` deterministically, with stable JSON envelopes and exits.
2. Scan materialization cleanup cannot delete non-managed content; ownership marker trust checks are enforced.
3. State/proof/lifecycle writes are atomic and crash-safe, with contention-safe behavior and deterministic outcomes.
4. `verify --chain` malformed/tampered-chain failures consistently emit `verification_failure` with exit `2` (or explicitly versioned migration path if not).
5. CLI/docs contract parity is green for touched command surfaces.
6. Required matrix lanes pass for all in-scope stories.

## Public API and Contract Map

Stable/public surfaces:
- CLI exits (`0..8`) and machine-readable error envelope fields.
- `wrkr evidence --json`, `wrkr scan --json`, `wrkr verify --chain --json` behavior.
- Artifact paths and state/proof lifecycle semantics documented under `docs/`.

Internal surfaces:
- Error typing internals in `core/evidence`.
- Materialized-source ownership internals in `core/cli` + `core/source` support helpers.
- Atomic write utilities and locking internals in `core/state`, `core/proofemit`, `core/lifecycle`.

Shim/deprecation policy:
- No immediate removal of existing JSON keys.
- If any error-code/class change impacts automation, keep compatibility notes and deterministic migration guidance in docs.

Schema/versioning policy:
- No schema major bump planned.
- Any contract delta is additive unless explicitly approved and versioned.

Machine-readable error expectations:
- `invalid_input` -> exit `6` for caller input/schema violations.
- `runtime_failure` -> exit `1` for runtime/environment failures.
- `unsafe_operation_blocked` -> exit `8` only for explicit safety boundary violations.
- `verification_failure` -> exit `2` for chain verification/parsing-integrity failure class.

## Docs and OSS Readiness Baseline

README first-screen contract:
- Preserve concise what/who/first-value flow.
- Update only behavior-affecting sections for `evidence`, `scan`, `verify` semantics.

Integration-first docs flow:
- Command docs must state integration-safe error handling and expected exits before internals.

Lifecycle path model:
- Keep canonical state/proof path model aligned with `docs/state_lifecycle.md` and command docs.

Docs source-of-truth:
- `docs/commands/*` is command-contract source; README/examples must stay consistent.

OSS trust baseline files:
- Existing baseline retained; this plan does not introduce governance-file scope changes.

## Recommendation Traceability

| Recommendation ID | Finding | Story Mapping |
|---|---|---|
| R1 | Evidence misclassifies non-unsafe failures as exit `8` | S1.1 |
| R2 | Materialized-source recursive delete without ownership gating | S1.2 |
| R3 | Non-atomic state/proof/lifecycle writes | S1.3 |
| R4 | Malformed proof chain returns exit `6` instead of `2` | S1.4 |
| R5 | Missing explicit tests for classification/boundary/atomic-write failures | S1.1, S1.2, S1.3, S1.4 |
| R6 | Docs/contract parity drift around verify/evidence semantics | S2.1 |

## Test Matrix Wiring

Fast lane:
- `make lint-fast`
- `make test-fast`

Core CI lane:
- Targeted package tests for touched components (`core/cli`, `core/evidence`, `core/state`, `core/proofemit`, `core/lifecycle`, `core/source`).
- `make test-contracts`

Acceptance lane:
- `make test-scenarios`
- relevant CLI/e2e acceptance tests for command contracts

Cross-platform lane:
- Preserve Linux/macOS/Windows behavior for path handling and CLI exit-code envelopes.

Risk lane:
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-perf` for any measurable regression in persistence path changes

Merge/release gating rule:
- No Wave 2 execution until all Wave 1 stories are green across required lanes.
- No merge when any touched contract, hardening, or chaos lane is red.

## Epic 1 (Wave 1): Contract and Runtime Safety Corrections

Objective: close release-blocking P1/P2 findings on exit taxonomy, destructive path safety, and persistence durability.

### Story S1.1: Classify Evidence Failures by Deterministic Error Type
Priority: P0
Tasks:
- Introduce typed/sentinel errors in `core/evidence` for invalid input, runtime, and unsafe-operation classes.
- Map typed errors in `core/cli/evidence.go` to stable `code + exit` contract.
- Add/refresh CLI contract tests for JSON envelope and exits.
- Add command docs updates for classification semantics.
Repo paths:
- `core/evidence/evidence.go`
- `core/cli/evidence.go`
- `core/cli/root_test.go`
- `docs/commands/evidence.md`
- `docs/commands/root.md`
Run commands:
- `go test ./core/evidence ./core/cli -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- CLI behavior tests: `--json` stability, exit-code invariants, error envelope fields.
- Contract tests for `invalid_input` vs `runtime_failure` vs `unsafe_operation_blocked`.
- Regression tests to prevent class collapse back to exit `8`.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk.
Acceptance criteria:
- Missing state path yields `runtime_failure` + exit `1`.
- Invalid framework ID yields `invalid_input` + exit `6` (or explicit documented taxonomy decision if chosen otherwise).
- Unsafe output-path violations remain `unsafe_operation_blocked` + exit `8`.
Contract/API impact:
- Error/exit classification behavior is normalized to stable documented contract.
Versioning/migration impact:
- Additive/no schema version bump; release notes + docs contract note required.
Architecture constraints:
- Keep CLI as mapper/orchestrator; classification logic belongs in evidence/core errors.
- Preserve fail-closed semantics for unsafe path detection.
ADR required: yes
TDD first failing test(s):
- `TestEvidenceCommandClassifiesMissingStateAsRuntimeFailure`
- `TestEvidenceCommandClassifiesUnknownFrameworkAsInvalidInput`
- `TestEvidenceCommandRetainsUnsafePathAsExit8`
Cost/perf impact: low
Chaos/failure hypothesis:
- If evidence input and runtime failures are mixed, classification remains deterministic and never escalates non-safety failures to unsafe blocked.

### Story S1.2: Ownership-Gated Materialized Source Cleanup
Priority: P0
Tasks:
- Add managed-root marker contract for `materialized-sources` similar to evidence ownership semantics.
- Block recursive cleanup when path is non-empty and non-managed.
- Reject marker symlink/directory and invalid marker content.
- Add tests for caller-supplied state-path boundary behavior.
Repo paths:
- `core/cli/scan_helpers.go`
- `core/source/github/connector.go` (if helper reuse needed)
- `core/cli/root_test.go`
- `internal/e2e/source/*`
- `docs/commands/scan.md`
Run commands:
- `go test ./core/cli ./core/source/... -count=1`
- `go test ./internal/e2e/source -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- Fail-closed boundary tests: non-empty + non-managed => fail.
- Marker trust tests: regular-file marker only; symlink/directory marker rejected.
- Deterministic path error envelope tests for scan JSON mode.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk.
Acceptance criteria:
- Scan no longer deletes unmanaged `materialized-sources` data.
- Managed roots are safely reset with deterministic behavior.
- Boundary violations are explicit and machine-readable.
Contract/API impact:
- Scan path-safety semantics tightened; error envelope behavior documented.
Versioning/migration impact:
- Behavioral hardening only; no schema bump.
Architecture constraints:
- Source boundary owns materialization safety checks; CLI only surfaces deterministic failure class.
- Explicit side-effect semantics in helper naming (`prepare` vs `resetManaged`).
ADR required: yes
TDD first failing test(s):
- `TestPrepareMaterializedRootRejectsNonManagedNonEmptyDir`
- `TestPrepareMaterializedRootRejectsMarkerSymlink`
- `TestScanRepoDoesNotDeleteUnmanagedMaterializedSources`
Cost/perf impact: low
Chaos/failure hypothesis:
- Under concurrent or interrupted scan starts, unmanaged directories remain intact and managed reset remains idempotent.

### Story S1.3: Atomic and Crash-Safe Writes for State and Chains
Priority: P0
Tasks:
- Introduce shared atomic-write utility (`temp -> fsync -> rename`) for JSON/YAML artifacts.
- Apply utility to state snapshot writes, proof-chain writes, and lifecycle chain writes.
- Add lock/contention protection where concurrent writers can collide.
- Add crash/partial-write simulation tests.
Repo paths:
- `core/state/state.go`
- `core/proofemit/proofemit.go`
- `core/lifecycle/chain.go`
- `core/*/*_test.go` for persistence/hardening cases
- `scripts/test_hardening_core.sh` (if lane wiring update needed)
Run commands:
- `go test ./core/state ./core/proofemit ./core/lifecycle -count=1`
- `make test-hardening`
- `make test-chaos`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Atomic-write lifecycle tests (interruption and rollback behavior).
- Contention/concurrency tests with deterministic final artifact state.
- Byte-stability checks for repeated writes.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk.
Acceptance criteria:
- No truncated/corrupted state/proof/lifecycle files under induced interruption tests.
- Concurrent write attempts produce deterministic valid artifacts or explicit blocked error behavior.
- Existing command contracts remain unchanged.
Contract/API impact:
- No user-facing schema change; durability guarantees strengthened.
Versioning/migration impact:
- No migration required.
Architecture constraints:
- Keep persistence mechanics in dedicated utilities; avoid duplicating write logic across boundaries.
- Preserve deterministic serialization ordering before write commit.
ADR required: yes
TDD first failing test(s):
- `TestStateSaveIsAtomicUnderInterruption`
- `TestProofChainSaveIsAtomicUnderInterruption`
- `TestLifecycleChainSaveHandlesWriteContention`
Cost/perf impact: medium
Chaos/failure hypothesis:
- During filesystem faults and abrupt cancellation, committed artifact remains last-valid version and downstream parse succeeds.

### Story S1.4: Verify Chain Failure Taxonomy Alignment
Priority: P1
Tasks:
- Align `verify --chain` parse/integrity failure mapping to `verification_failure` exit `2`.
- Keep clear distinction between true CLI argument validation (`exit 6`) and chain verification failures (`exit 2`).
- Update command docs and trust docs for exact taxonomy.
Repo paths:
- `core/cli/verify.go`
- `core/verify/verify.go` (if typed errors needed)
- `core/cli/root_test.go`
- `docs/commands/verify.md`
- `docs/trust/proof-chain-verification.md`
Run commands:
- `go test ./core/verify ./core/cli -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- CLI exit-code envelope tests for malformed chain and tampered chain.
- Machine-readable error object stability tests (`code`, `reason`, `exit_code`, break fields).
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk.
Acceptance criteria:
- Malformed or tampered chain yields `verification_failure` + exit `2`.
- `verify` positional/flag misuse still yields `invalid_input` + exit `6`.
- Docs match runtime behavior exactly.
Contract/API impact:
- Verification failure semantics become explicitly consistent across parse/integrity failure paths.
Versioning/migration impact:
- Contract clarification and normalization; no schema version bump.
Architecture constraints:
- Verification classification belongs in verify core/CLI boundary, not caller-specific wrappers.
ADR required: yes
TDD first failing test(s):
- `TestVerifyMalformedChainReturnsExit2`
- `TestVerifyInvalidCLIArgsRemainExit6`
Cost/perf impact: low
Chaos/failure hypothesis:
- Corrupted chain bytes under repeated verify calls always map to stable failure class and deterministic envelope.

## Epic 2 (Wave 2): Docs and Contract Publication Alignment

Objective: ensure user-facing and automation-facing docs reflect final Wave 1 runtime behavior without ambiguity.

### Story S2.1: Command Contract and Taxonomy Docs Sync
Priority: P1
Tasks:
- Update docs for `evidence`, `scan`, and `verify` with final error/exit taxonomy.
- Confirm examples and expected JSON keys/envelopes reflect implemented behavior.
- Run docs consistency/storyline checks.
Repo paths:
- `README.md` (if externally visible behavior summary changes)
- `docs/commands/evidence.md`
- `docs/commands/scan.md`
- `docs/commands/verify.md`
- `docs/commands/root.md`
- `docs/failure_taxonomy_exit_codes.md`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `scripts/run_docs_smoke.sh`
- `make prepush-full`
Test requirements:
- Docs consistency checks for command/flag/exit parity.
- Storyline/smoke checks for integration-first flow.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform.
Acceptance criteria:
- No docs/runtime mismatch for modified command semantics.
- Failure taxonomy tables and command docs agree with tested exits.
Contract/API impact:
- Documentation-only publication of stabilized runtime contracts.
Versioning/migration impact:
- None.
Architecture constraints:
- Do not alter runtime behavior in docs-only story.
ADR required: no
TDD first failing test(s):
- `docs parity check` failure before doc updates.
Cost/perf impact: low

## Minimum-Now Sequence

Wave 1 (must complete first):
1. S1.2 (filesystem ownership-gated cleanup)
2. S1.3 (atomic persistence hardening)
3. S1.1 (evidence classification taxonomy)
4. S1.4 (verify taxonomy alignment)

Wave 2:
5. S2.1 (docs/contract publication sync)

Dependency rationale:
- Safety boundary and persistence fixes first to remove destructive/corruption risk.
- Error-taxonomy normalization next, then verification semantics.
- Docs last to reflect final runtime truth.

## Explicit Non-Goals

- No new product features outside these findings.
- No detector-coverage expansion unrelated to failure taxonomy/safety issues.
- No schema major-version bump.
- No Axym/Gait feature implementation in Wrkr repo.
- No release cut/PR shipping steps in this plan.

## Definition of Done

- All in-scope stories completed with required story fields satisfied.
- Wave 1 complete and green before Wave 2 work starts.
- Every recommendation mapped to at least one implemented story.
- Contract-impacting stories include deterministic tests for JSON envelope and exit code behavior.
- Reliability/safety stories include hardening + chaos evidence.
- Docs are updated in same change set for user-visible behavior changes.
- Final validation evidence includes:
  - `make prepush-full`
  - `make test-contracts`
  - `make test-scenarios`
  - `make test-hardening`
  - `make test-chaos`
  - `make test-docs-consistency`

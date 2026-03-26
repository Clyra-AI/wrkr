# PLAN WRKR_RUNTIME_INTEGRITY_STATE_SAFETY: Fail-Closed Proof, Atomic Lifecycle State, and Scan Boundary Hardening

Date: 2026-03-26
Source of truth:
- user-provided repository review findings dated 2026-03-26
- `product/dev_guides.md`
- `product/architecture_guides.md`
- `AGENTS.md`
- `README.md`
- `docs/commands/evidence.md`
- `docs/commands/identity.md`
- `docs/commands/scan.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/failure_taxonomy_exit_codes.md`
- `docs/state_lifecycle.md`
- `docs/trust/proof-chain-verification.md`
- `core/evidence/evidence.go`
- `core/cli/evidence.go`
- `core/cli/identity.go`
- `core/cli/scan.go`
- `core/source/org/materialized.go`
- `core/source/org/checkpoint.go`
- `core/detect/parse.go`
- `core/verify/verify.go`
- `core/proofemit/proofemit.go`
- `core/lifecycle/chain.go`
- `core/manifest/manifest.go`
- `.github/required-checks.json`
- `.github/wave-gates.json`
- `.github/workflows/main.yml`
- `.github/workflows/release.yml`
Scope: Wrkr repository only. Planning artifact only. Convert the four validated review findings into an execution-ready backlog that closes release-blocking integrity and boundary gaps without weakening determinism, offline-first defaults, fail-closed policy enforcement, schema stability, exit-code stability, or the authoritative Go-core architecture.

## Global Decisions (Locked)

- This is a planning-only change. No implementation work is in scope for this artifact.
- Contract/runtime correctness lands before docs-only or OSS-readiness polish.
- `core/verify` remains the single authoritative runtime for proof-chain integrity checks. Other packages may call it; they must not fork verification semantics.
- `wrkr evidence` must fail closed on malformed or tampered proof chains before bundle staging, manifest signing, or publish.
- `wrkr evidence` keeps its current public error taxonomy unless implementation proves an additive migration path is required:
  - `runtime_failure` exit `1`
  - `invalid_input` exit `6`
  - `unsafe_operation_blocked` exit `8`
- `wrkr verify --chain` remains the explicit public integrity gate and the only command that emits `verification_failure` exit `2`.
- `wrkr identity approve|review|deprecate|revoke` keeps its current success payload shape and `runtime_failure` exit `1` behavior on downstream persistence/proof failures. The required change is atomicity and rollback safety, not a new CLI contract.
- `wrkr scan` must pre-validate operator-selected artifact outputs used by scan itself before any managed state mutation:
  - `--report-md-path`
  - `--sarif-path`
  - any future scan-owned output path added in the same orchestration layer
- Existing early validation behavior for `--json-path` remains unchanged and must not regress.
- Resume-path trust violations are safety failures, not user-input mismatches:
  - symlinked or out-of-root resumed materializations must map to `unsafe_operation_blocked` exit `8`
  - missing/mismatched checkpoint metadata remains `invalid_input` exit `6`
- Managed contract artifacts under `.wrkr/` remain the authoritative commit set:
  - `.wrkr/last-scan.json`
  - `.wrkr/wrkr-manifest.yaml`
  - `.wrkr/proof-chain.json`
  - `.wrkr/identity-chain.json`
- Thin orchestration stays in `core/cli/*`. Focused helpers/packages are allowed for:
  - proof prerequisite validation
  - transactional state commit/rollback
  - scan artifact-path preflight
  - resume root trust validation
- No public schema version bump is planned. Preferred implementation path is compatibility-preserving and additive where possible.
- Stories touching architecture boundaries, failure semantics, persistence, or authoritative verification must run `make prepush-full`.
- Reliability and boundary hardening stories must also run `make test-hardening` and `make test-chaos`.
- Docs and command-contract updates ship in the same PR as the runtime behavior they describe.
- No dashboard-first, service-first, or non-deterministic network-first work is in scope for this plan.

## Current Baseline (Observed)

- Planning inputs validated:
  - `product/dev_guides.md` exists and is readable
  - `product/architecture_guides.md` exists and is readable
  - output path `product/PLAN_NEXT.md` resolves inside `/Users/tr/wrkr`
  - output path parent is writable
- Repository worktree was clean before this plan rewrite.
- Repo-wide baseline validation passed during review:
  - `go test ./... -count=1`
  - `go run ./cmd/wrkr version --json`
  - `go run ./cmd/wrkr --help`
- Current required PR checks are `fast-lane` and `windows-smoke` via `.github/required-checks.json`; release workflows additionally run contract, scenario, docs, hardening, and acceptance gates.
- Existing runtime gap 1:
  - `core/evidence/evidence.go` loads the proof chain and checks only file presence, parse success, and presence of scan records
  - it does not verify chain integrity before bundle publish
- Existing runtime gap 2:
  - `core/cli/identity.go` saves `wrkr-manifest.yaml` before lifecycle-chain and proof-chain updates complete
  - a downstream proof failure can leave approval posture committed without corresponding proof evidence
- Existing runtime gap 3:
  - `core/source/org/materialized.go` resumes repo materializations with `os.Stat`, which follows symlinks
  - detector scope resolution in `core/detect/parse.go` trusts the resolved root as the in-scope repository root
- Existing runtime gap 4:
  - `core/cli/scan.go` writes managed state/proof artifacts before `--report-md-path` and `--sarif-path` are validated
  - invalid operator paths can return `invalid_input` after managed state already advanced
- Relevant regression and contract test surfaces already exist and should be extended rather than bypassed:
  - `core/evidence/evidence_test.go`
  - `core/cli/root_test.go`
  - `core/cli/scan_json_path_test.go`
  - `core/cli/scan_progress_test.go`
  - `core/source/org/acquire_resume_test.go`
  - `core/verify/verify_test.go`
  - `internal/e2e/source`
  - `internal/e2e/verify`
  - `testinfra/contracts`
  - `testinfra/hygiene`
- Relevant docs/source-of-truth files already exist:
  - `docs/commands/evidence.md`
  - `docs/commands/identity.md`
  - `docs/commands/scan.md`
  - `docs/state_lifecycle.md`
  - `docs/failure_taxonomy_exit_codes.md`
  - `docs/trust/proof-chain-verification.md`
  - `docs/examples/quickstart.md`
  - `docs/examples/security-team.md`
- OSS trust baseline files are already present and must remain aligned if public behavior wording changes:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`

## Exit Criteria

1. `wrkr evidence --json` rejects malformed or tampered proof chains before stage publish and never emits a successful bundle from a non-intact chain.
2. `wrkr identity approve|review|deprecate|revoke --json` is transactional across manifest, identity lifecycle chain, and proof chain, or provably rollback-safe with no partial committed state.
3. `scan --org --resume` rejects symlink-swapped or out-of-root resumed repo roots before detector scopes are created or external files are read.
4. Resume safety failures are machine-readable and classified as `unsafe_operation_blocked` exit `8`; checkpoint mismatch/absence remains `invalid_input` exit `6`.
5. `wrkr scan` validates scan-owned artifact outputs before the first managed write and preserves zero managed mutations on `invalid_input` path failures.
6. Existing `--json`, `--json-path`, exit-code, and success-payload contracts remain stable unless an explicit additive migration note is approved.
7. Docs and examples stop implying that `wrkr evidence` can safely package an unreadable or tampered proof chain, and they clearly preserve `wrkr verify --chain` as the explicit integrity gate.
8. New tests cover happy path, malformed/tampered state, rollback safety, boundary trust failures, and deterministic machine-readable error envelopes.
9. Required fast/core/acceptance/cross-platform/risk lanes are wired for each story and green before merge.

## Public API and Contract Map

Stable/public surfaces touched by this plan:

- CLI commands:
  - `wrkr evidence`
  - `wrkr verify --chain`
  - `wrkr identity approve`
  - `wrkr identity review`
  - `wrkr identity deprecate`
  - `wrkr identity revoke`
  - `wrkr scan`
- Stable flags and output surfaces:
  - `wrkr evidence --frameworks --output --state --json`
  - `wrkr verify --chain --state --path --json`
  - `wrkr identity <subcommand> --state --json`
  - `wrkr scan --report-md --report-md-path --sarif --sarif-path --json --json-path --resume`
- Stable machine-readable error expectations:
  - `runtime_failure`
  - `invalid_input`
  - `unsafe_operation_blocked`
  - `verification_failure` remains specific to `verify`
- Stable managed artifact paths:
  - `.wrkr/last-scan.json`
  - `.wrkr/wrkr-manifest.yaml`
  - `.wrkr/proof-chain.json`
  - `.wrkr/identity-chain.json`
- Stable docs contract surfaces:
  - `README.md`
  - `docs/commands/*.md`
  - `docs/state_lifecycle.md`
  - `docs/trust/proof-chain-verification.md`
  - `docs/examples/*.md`

Internal surfaces expected to change:

- `core/evidence/evidence.go`
- `core/cli/evidence.go`
- `core/verify/verify.go` or a focused helper package reused by `evidence`
- `core/cli/identity.go`
- `core/lifecycle/chain.go`
- `core/proofemit/proofemit.go`
- `core/manifest/manifest.go`
- `internal/atomicwrite/`
- `core/source/org/materialized.go`
- `core/source/org/checkpoint.go`
- `core/cli/scan.go`
- `core/cli/report_artifacts.go`
- `core/detect/parse.go`
- related tests under `core/`, `internal/e2e/`, `testinfra/contracts`, and `testinfra/hygiene`

Shim/deprecation path:

- No flag removals are planned.
- No existing JSON success keys are removed or renamed.
- No exit-code remapping is planned for existing successful or invalid-input paths.
- Internal checkpoint metadata may evolve if needed for safer resume validation, but public CLI/schema versioning must remain unchanged unless an ADR explicitly approves a migration.

Schema/versioning policy:

- Preferred implementation is additive/no public schema bump.
- Strengthening fail-closed behavior without changing success payload keys is not a schema bump.
- If any story requires a public schema or exit-code change, stop and add an ADR plus migration note before merge.

Machine-readable error expectations for touched flows:

- `wrkr evidence --json` with a malformed or tampered proof chain:
  - remains `runtime_failure` exit `1`
  - message/detail must clearly identify proof-chain verification as the failed prerequisite
  - success payload shape remains unchanged
- `wrkr identity * --json` with downstream lifecycle/proof persistence failure:
  - remains `runtime_failure` exit `1`
  - no manifest/lifecycle/proof artifact may advance past the last committed consistent state
- `wrkr scan --json` with invalid `--report-md-path` or `--sarif-path`:
  - remains `invalid_input` exit `6`
  - no managed state/proof/manifest mutations are allowed
- `wrkr scan --resume` with symlinked or out-of-root resumed repo roots:
  - `unsafe_operation_blocked` exit `8`
  - deterministic message naming the rejected path and trust rule

## Docs and OSS Readiness Baseline

README first-screen contract:

- Keep the current security/platform-led first screen intact:
  - install
  - `wrkr version --json`
  - hosted scan path
  - deterministic local fallback path
- If README wording changes, it must not overstate what `evidence` proves. It may say evidence fails closed on invalid proof state, but `wrkr verify --chain` remains the explicit operator/CI integrity gate.

Integration-first docs flow:

- Keep docs grounded in the actual saved-state lifecycle:
  - `scan`
  - optional/reporting flows
  - `verify --chain` as explicit integrity gate
  - `evidence` as fail-closed packaging of already-saved posture
- Examples may keep the current high-level flow order, but they must no longer imply that `evidence` can succeed on a tampered chain.

Lifecycle path model:

- `docs/state_lifecycle.md` is the canonical path model source.
- It must reflect:
  - managed `.wrkr/` artifacts as authoritative commit points
  - preflight validation before scan-owned output writes
  - transaction/rollback safety for manual identity transitions
  - evidence publish occurring only after intact proof prerequisites and successful stage verification

Docs source-of-truth mapping:

- Command semantics: `docs/commands/evidence.md`, `docs/commands/identity.md`, `docs/commands/scan.md`
- Failure taxonomy: `docs/failure_taxonomy_exit_codes.md`
- Proof integrity authority: `docs/trust/proof-chain-verification.md`
- Path lifecycle and managed artifacts: `docs/state_lifecycle.md`
- Operator examples: `docs/examples/quickstart.md`, `docs/examples/security-team.md`
- Top-level positioning/first-screen entry: `README.md`

OSS trust baseline:

- Existing trust files are present and sufficient for this scope:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
- `CHANGELOG.md` must be updated if any user-visible CLI failure semantics or documented flow wording changes.
- No new maintainer-policy files are required for this plan unless implementation expands public support promises.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Mapped stories |
|---|---|---|---|---|---|
| R1 | Fail closed on tampered proof chains before evidence export | Prevent repackaging corrupted proof as fresh audit output | Keep proof verification authoritative and bundle publish fail closed | Stronger audit credibility and lower release/integrity risk | `W1-S1`, `W3-S1` |
| R2 | Make manual identity transitions transactional or rollback safe | Prevent manifest approval state from diverging from proof evidence | Treat managed lifecycle state as a single atomic contract set | Trustworthy approval posture and fewer operator surprise states | `W1-S2`, `W3-S1` |
| R3 | Reject symlink-swapped resumed materializations | Close resume-path boundary bypass before detector roots are trusted | Enforce ownership at execution boundaries, not just marker roots | Stronger large-org safety claims without runtime/network complexity | `W2-S1`, `W3-S1` |
| R4 | Pre-validate scan artifact output paths before managed writes | Avoid failed commands that still mutate authoritative state | Make CLI side-effect semantics explicit and fail closed on user-path errors | Cleaner CI automation and more reliable state lifecycle guarantees | `W2-S2`, `W3-S1` |

## Test Matrix Wiring

- Fast lane:
  - `make prepush`
  - targeted package tests for touched stories where faster local iteration is useful
- Core CI lane:
  - `make prepush-full`
- Acceptance lane:
  - `make test-contracts`
  - `make test-scenarios`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
- Cross-platform lane:
  - targeted Go tests for touched packages on Linux, macOS, and Windows
  - required PR check alignment with `windows-smoke`
- Risk lane:
  - `make test-hardening`
  - `make test-chaos`
  - `make test-risk-lane` before epic completion
- Merge/release gating rule:
  - no story is merge-ready until current required PR checks (`fast-lane`, `windows-smoke`) are green and the story's contract/hardening tests are wired into PR validation or an equivalent required lane
  - release validation must rerun the repo's full deterministic gates, including `go test ./... -count=1`, `make prepush-full`, `make test-contracts`, `make test-scenarios`, and the acceptance/release workflow equivalents already defined in `.github/workflows/release.yml`

## Epic Wave 1: Proof Integrity and Transactional Lifecycle State

Objective: close the highest-risk release blockers in proof and approval-state handling before touching lower-risk scan-path ergonomics.

### Story W1-S1: Reject tampered proof chains in evidence build

Priority: P0
Tasks:
- Add an authoritative proof prerequisite check in `core/evidence/` that validates proof-chain integrity before compliance rollup, bundle staging, manifest signing, or publish.
- Reuse `core/verify` semantics instead of re-implementing record-hash or head-hash verification in `core/evidence`.
- Keep `core/cli/evidence.go` error classification stable while surfacing proof-verification failure detail in the returned `runtime_failure`.
- Add deterministic tests for malformed chain JSON, tampered chain head hash, tampered record hash, and intact-chain happy path.
- Prove that a failed integrity prerequisite leaves the requested evidence output absent or leaves the prior managed bundle intact.
- Update command and lifecycle docs so they state that evidence packaging requires an intact proof chain and does not replace `wrkr verify --chain`.
Repo paths:
- `core/evidence/evidence.go`
- `core/cli/evidence.go`
- `core/verify/verify.go`
- `core/evidence/evidence_test.go`
- `core/cli/root_test.go`
- `internal/e2e/verify/`
- `docs/commands/evidence.md`
- `docs/state_lifecycle.md`
- `docs/trust/proof-chain-verification.md`
- `docs/failure_taxonomy_exit_codes.md`
Run commands:
- `go test ./core/evidence ./core/verify ./core/cli -count=1`
- `go test ./internal/e2e/verify -count=1`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- CLI behavior changes:
  - `--json` stability tests
  - machine-readable error envelope tests
  - exit-code stability tests for `wrkr evidence`
- Gate/policy/fail-closed changes:
  - deterministic fail-closed tampered-chain fixtures
  - reason/detail stability checks
- Determinism/hash/sign/packaging changes:
  - repeat-run bundle tests after successful integrity verification
  - bundle publish remains absent/intact on failure
  - `make test-contracts`
- Job runtime/state changes:
  - crash-safe publish behavior tests around staged evidence output
Matrix wiring:
- Fast lane: `go test ./core/evidence ./core/verify -count=1`
- Core CI lane: `make prepush-full`
- Acceptance lane: `make test-contracts`
- Cross-platform lane: `go test ./core/evidence ./core/verify ./core/cli -count=1`
- Risk lane: `make test-hardening`, `make test-chaos`
Acceptance criteria:
- `wrkr evidence --json` fails before publish when the proof chain is malformed or tampered.
- `wrkr verify --chain --json` and `wrkr evidence --json` agree on the integrity prerequisite while preserving their distinct public exit-code contracts.
- Success payload keys for `wrkr evidence --json` remain unchanged.
- Existing good-chain evidence flows remain deterministic across repeat runs.
Contract/API impact:
- Strengthens side-effect semantics for `wrkr evidence` without changing success payload keys.
- Preserves `runtime_failure|invalid_input|unsafe_operation_blocked` evidence error taxonomy.
- Preserves `verification_failure` exit `2` as `verify`-only public behavior.
Versioning/migration impact:
- No schema bump.
- No exit-code remap.
- Docs update required to clarify stronger fail-closed prerequisite.
Architecture constraints:
- Keep `core/verify` authoritative for proof integrity.
- Keep `core/cli/evidence.go` thin and focused on error mapping.
- Use explicit API naming that distinguishes load vs load+validate behavior.
- Do not bypass staged publish ownership rules already enforced in `core/evidence/`.
ADR required: no
TDD first failing test(s):
- `core/evidence/evidence_test.go::TestBuildRejectsTamperedProofChain`
- `core/evidence/evidence_test.go::TestBuildRejectsMalformedProofChainBeforeStagePublish`
- `core/cli/root_test.go::TestEvidenceJSONTamperedChainReturnsRuntimeFailure`
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: intact proof chain allows deterministic bundle publish.
- Fault: proof-chain JSON or integrity is corrupted before `wrkr evidence`.
- Expected: command returns `runtime_failure`, publishes nothing new, and leaves prior managed bundle intact.
- Abort condition: any managed output path appears at the final target after a failed integrity prerequisite.

### Story W1-S2: Make manual identity transitions atomic across manifest, lifecycle chain, and proof chain

Priority: P0
Tasks:
- Design and implement a focused transaction/rollback flow for manual identity transitions spanning:
  - manifest state
  - identity lifecycle chain
  - proof chain emission
- Prevent `wrkr-manifest.yaml` from being committed ahead of downstream lifecycle/proof success.
- Use atomic write primitives and explicit commit ordering so a failure after validation leaves all managed artifacts on the prior committed state.
- Add deterministic tests covering proof-chain parse failure, lifecycle-chain write failure, and proof-emission failure after operator input is accepted.
- Document the post-change lifecycle guarantee in identity and state-lifecycle docs.
- Add an ADR describing the chosen commit/rollback strategy because the change crosses identity, lifecycle, proof emission, and CLI orchestration boundaries.
Repo paths:
- `core/cli/identity.go`
- `core/manifest/manifest.go`
- `core/lifecycle/chain.go`
- `core/proofemit/proofemit.go`
- `internal/atomicwrite/`
- `core/cli/root_test.go`
- `core/lifecycle/chain_test.go`
- `docs/commands/identity.md`
- `docs/state_lifecycle.md`
- `docs/failure_taxonomy_exit_codes.md`
- `docs/decisions/`
Run commands:
- `go test ./core/cli ./core/lifecycle ./core/proofemit ./internal/atomicwrite -count=1`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- CLI behavior changes:
  - `--json` approval/review/deprecate/revoke stability tests
  - machine-readable runtime-failure envelope tests
- Gate/policy/fail-closed changes:
  - fail-closed transition tests when downstream proof/lifecycle persistence is undecidable or broken
- Job runtime/state/concurrency changes:
  - lifecycle rollback tests
  - crash-safe/atomic-write tests
  - contention tests if shared locks/helpers are added
- API/contract lifecycle changes:
  - public API map update for touched identity flows
Matrix wiring:
- Fast lane: `go test ./core/cli ./core/lifecycle -count=1`
- Core CI lane: `make prepush-full`
- Acceptance lane: `make test-contracts`
- Cross-platform lane: `go test ./core/cli ./core/lifecycle ./core/proofemit -count=1`
- Risk lane: `make test-hardening`, `make test-chaos`
Acceptance criteria:
- A downstream lifecycle-chain or proof-chain failure leaves manifest, lifecycle chain, and proof chain unchanged from the last committed good state.
- Successful manual approvals still emit the same stable success payload and visible lifecycle/proof records.
- Failure remains `runtime_failure` exit `1`.
- ADR is merged with explicit failure-mode and commit-order rationale.
Contract/API impact:
- Strengthens side-effect guarantees for manual identity transitions.
- Preserves existing success payload keys and public subcommand names.
- Preserves `runtime_failure` exit behavior on downstream persistence failures.
Versioning/migration impact:
- No public schema bump.
- No CLI rename.
- ADR required because implementation crosses required architecture boundaries.
Architecture constraints:
- Keep policy/sign/verify ownership in Go core.
- Use thin CLI orchestration and focused helper packages for transaction logic.
- Make side-effect semantics explicit in helper naming.
- Preserve deterministic ordering and avoid shared mutable global state across layers.
ADR required: yes
TDD first failing test(s):
- `core/cli/root_test.go::TestIdentityApproveRollbackOnProofChainParseFailure`
- `core/cli/root_test.go::TestIdentityReviewRollbackOnProofEmitFailure`
- `core/lifecycle/chain_test.go::TestManualTransitionCommitOrderLeavesNoPartialState`
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: manual transition updates manifest, lifecycle chain, and proof chain consistently.
- Fault: lifecycle or proof persistence fails after transition intent is computed.
- Expected: command returns `runtime_failure` and every managed artifact remains on the prior committed state.
- Abort condition: any one of the three artifacts reflects the new transition while another still reflects the old state.

## Epic Wave 2: Scan Resume Boundary and Preflight Commit Safety

Objective: harden the scan execution boundary so resume roots and invalid output paths cannot bypass trust rules or create post-failure state drift.

### Story W2-S1: Reject symlink-swapped resumed materializations before detector scope creation

Priority: P0
Tasks:
- Replace resume-root trust checks that currently follow symlinks with explicit `Lstat` and canonical-root validation.
- Prove that resumed repo roots resolve inside the canonical managed materialized root and are directories, not symlinks or redirected paths.
- Classify resume trust violations as safety failures rather than input mismatches.
- Extend unit and e2e coverage for symlink-swapped repo roots, missing materializations, and valid resume reuse.
- Keep detector root trust assumptions aligned with the stronger source-side validation.
- Update scan docs and lifecycle docs to describe the new resume safety rule.
Repo paths:
- `core/source/org/materialized.go`
- `core/source/org/checkpoint.go`
- `core/cli/scan.go`
- `core/detect/parse.go`
- `core/source/org/acquire_resume_test.go`
- `core/cli/scan_materialized_root_test.go`
- `internal/e2e/source/`
- `docs/commands/scan.md`
- `docs/state_lifecycle.md`
Run commands:
- `go test ./core/source/org ./core/cli ./core/detect -count=1`
- `go test ./internal/e2e/source -count=1`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- Gate/policy/fail-closed changes:
  - deterministic allow/block resume fixtures
  - marker trust and resumed-root trust tests
  - reason-code stability checks
- Job runtime/state/concurrency changes:
  - checkpoint/resume lifecycle tests
  - contention/concurrency tests if worker scheduling or checkpoint locking changes
- Voice/context-proof changes:
  - relevant resume scenario acceptance coverage when org-resume behavior is touched
Matrix wiring:
- Fast lane: `go test ./core/source/org -count=1`
- Core CI lane: `make prepush-full`
- Acceptance lane: `make test-contracts`, `go test ./internal/e2e/source -count=1`
- Cross-platform lane: `go test ./core/source/org ./core/cli ./core/detect -count=1`
- Risk lane: `make test-hardening`, `make test-chaos`
Acceptance criteria:
- `scan --org --resume` rejects symlinked or out-of-root resumed repo roots before detectors read any files.
- Safety violations map to `unsafe_operation_blocked` exit `8`.
- Valid resume reuse still skips re-materialization and produces the same final sorted result as before.
- Missing or mismatched checkpoints continue to fail deterministically as `invalid_input`.
Contract/API impact:
- No success payload change.
- Tightens `--resume` safety classification for boundary violations.
- Preserves checkpoint mismatch semantics for non-safety user mismatches.
Versioning/migration impact:
- No public schema bump.
- Internal checkpoint metadata/version may change only if required for safe root anchoring; if changed, legacy checkpoints must fail deterministically with a start-over instruction.
Architecture constraints:
- Enforce boundary trust at the source/materialization boundary, not in detector prompting or docs wording.
- Preserve thin `core/cli/scan.go` orchestration.
- Keep cancellation and timeout propagation intact for org scans.
- Use explicit `read` vs `read+validate` helper naming where new trust checks are introduced.
ADR required: no
TDD first failing test(s):
- `core/source/org/acquire_resume_test.go::TestAcquireMaterializedResumeRejectsSymlinkedRepoRoot`
- `core/source/org/acquire_resume_test.go::TestAcquireMaterializedResumeRejectsOutOfRootRepoLocation`
- `internal/e2e/source/source_e2e_test.go::TestE2EScanOrgResumeRejectsSymlinkSwappedRepoRoot`
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: resumed org scans reuse only trusted materialized repositories under the managed root.
- Fault: a completed repo materialization is replaced with a symlink to another directory before resume.
- Expected: resume aborts with `unsafe_operation_blocked` before detector scopes are created or external files are read.
- Abort condition: any detector reads or scope roots resolve outside the canonical managed materialized root.

### Story W2-S2: Pre-validate scan-owned artifact outputs before managed state writes

Priority: P1
Tasks:
- Move `--report-md-path` and `--sarif-path` validation to the scan preflight section before `state.Save`, lifecycle-chain writes, proof emission, or manifest save.
- Keep existing `--json-path` behavior and tests intact while aligning scan-owned output-path semantics with the stronger preflight model.
- Add regression tests that prove invalid report or SARIF paths return `invalid_input` with zero managed artifact mutation.
- Reuse or factor a focused preflight validator rather than scattering late path checks through `runScanWithContext`.
- Update scan and state-lifecycle docs to state that invalid scan-owned output paths fail before the authoritative commit point.
Repo paths:
- `core/cli/scan.go`
- `core/cli/report_artifacts.go`
- `core/cli/scan_json_path_test.go`
- `core/cli/root_test.go`
- `docs/commands/scan.md`
- `docs/state_lifecycle.md`
- `docs/failure_taxonomy_exit_codes.md`
Run commands:
- `go test ./core/cli -count=1`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- CLI behavior changes:
  - invalid-input path tests for report and SARIF outputs
  - `--json` envelope stability
  - help/usage tests if flag wording changes
- Gate/policy/fail-closed changes:
  - non-empty + non-managed fail tests remain intact where applicable
  - deterministic invalid-path preflight tests
- Job runtime/state changes:
  - state/lifecycle/proof artifact non-mutation assertions on invalid-input failure
Matrix wiring:
- Fast lane: `go test ./core/cli -count=1`
- Core CI lane: `make prepush-full`
- Acceptance lane: `make test-contracts`
- Cross-platform lane: `go test ./core/cli -count=1`
- Risk lane: `make test-hardening`, `make test-chaos`
Acceptance criteria:
- Invalid `--report-md-path` and `--sarif-path` fail before any new managed state/proof/manifest artifact exists or changes.
- Existing `--json-path` success and write-failure behavior is unchanged.
- Success-path scan output and additive report/SARIF metadata remain unchanged.
Contract/API impact:
- Preserves existing public flags and error envelope shapes.
- Strengthens commit-order semantics for `wrkr scan`.
- No new top-level JSON fields are required.
Versioning/migration impact:
- No schema bump.
- No new exit code.
- Docs update required because the authoritative commit-point wording becomes stronger and more explicit.
Architecture constraints:
- Keep `core/cli/scan.go` thin by centralizing preflight validation in a focused helper.
- Preserve deterministic ordering and existing managed-path safety checks.
- Use explicit side-effect semantics in any new preflight helper names.
ADR required: no
TDD first failing test(s):
- `core/cli/root_test.go::TestScanInvalidReportPathDoesNotWriteManagedState`
- `core/cli/root_test.go::TestScanInvalidSarifPathDoesNotWriteManagedState`
- `core/cli/scan_json_path_test.go::TestScanJSONPathBehaviorUnchangedWhenReportPreflightMovesEarlier`
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: valid scan-owned output paths allow normal managed-state commit and additive artifact writes.
- Fault: operator supplies an invalid report or SARIF path.
- Expected: command returns `invalid_input` before any managed artifact is created or mutated.
- Abort condition: any managed artifact timestamp or content changes on the invalid-input path.

## Epic Wave 3: Docs, Contract, and OSS Readiness Alignment

Objective: finalize source-of-truth docs, examples, and hygiene checks once runtime behavior is locked so operator expectations match real fail-closed semantics.

### Story W3-S1: Align README, command docs, examples, and trust docs with the hardened runtime

Priority: P1
Tasks:
- Update top-level and command docs so they accurately describe:
  - evidence fail-closed integrity prerequisite
  - manual identity transition consistency guarantees
  - resume boundary safety rules
  - scan preflight commit-order behavior
- Audit `README.md`, `docs/examples/quickstart.md`, and `docs/examples/security-team.md` for wording that could imply evidence can bless corrupted proof or that failed scans may still be safe to treat as committed.
- Update `docs/failure_taxonomy_exit_codes.md` and `docs/trust/proof-chain-verification.md` so public failure guidance stays consistent with the preserved runtime contracts.
- Add or extend docs/hygiene checks if needed so these lifecycle and integrity guarantees stay enforced in future PRs.
- Update `CHANGELOG.md` with any user-visible clarification to evidence, identity, resume, or scan commit-order behavior.
Repo paths:
- `README.md`
- `docs/commands/evidence.md`
- `docs/commands/identity.md`
- `docs/commands/scan.md`
- `docs/state_lifecycle.md`
- `docs/trust/proof-chain-verification.md`
- `docs/failure_taxonomy_exit_codes.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `CHANGELOG.md`
- `testinfra/hygiene/`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
Run commands:
- `make test-docs-consistency`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
- `make prepush`
Test requirements:
- Docs/examples changes:
  - docs consistency checks
  - storyline/smoke checks for touched user flows
  - README first-screen checks
  - integration-before-internals guidance checks for touched flows
  - docs source-of-truth mapping checks
- OSS readiness changes:
  - verify touched trust files and changelog alignment for public behavior changes
Matrix wiring:
- Fast lane: `make test-docs-consistency`
- Core CI lane: `scripts/check_docs_cli_parity.sh`, `scripts/check_docs_consistency.sh`
- Acceptance lane: `scripts/run_docs_smoke.sh`
- Cross-platform lane: docs wording only; no extra OS-specific runtime tests required beyond prior waves
- Risk lane: not required beyond prior runtime waves
Acceptance criteria:
- README, command docs, trust docs, and examples all tell the same story about proof integrity, manual transition consistency, resume safety, and scan commit order.
- No docs page implies that `wrkr evidence` replaces `wrkr verify --chain` as the explicit public integrity gate.
- Changelog entry exists for user-visible behavior clarification.
Contract/API impact:
- No runtime contract change.
- Documentation and hygiene enforcement only.
Versioning/migration impact:
- None.
Architecture constraints:
- Docs must describe the real authoritative runtime boundaries and must not shift enforcement responsibility to operator interpretation.
- Keep docs source-of-truth mapping explicit so later docs-site or README changes remain synchronized.
ADR required: no
TDD first failing test(s):
- `testinfra/hygiene::TestDocsLifecycleGuaranteesMatchRuntimeContracts` (new or extended)
- `testinfra/hygiene::TestREADMEAndCommandDocsDoNotContradictEvidenceVerifyFlow` (new or extended)
Cost/perf impact: low

## Minimum-Now Sequence

Wave 1:
- `W1-S1` reject tampered proof chains in evidence build
- `W1-S2` make manual identity transitions atomic across manifest, lifecycle chain, and proof chain
- Rationale: these are the highest-severity release blockers because they directly affect audit/proof integrity and approval-state credibility

Wave 2:
- `W2-S1` reject symlink-swapped resumed materializations before detector scope creation
- `W2-S2` pre-validate scan-owned artifact outputs before managed state writes
- Rationale: these harden source and scan execution boundaries after proof/lifecycle core state is trustworthy

Wave 3:
- `W3-S1` align README, command docs, examples, and trust docs with the hardened runtime
- Rationale: docs/OSS contract polish should land after runtime semantics are locked, but in close proximity to avoid drift

Dependency notes:

- `W1-S1` should land before `W3-S1` so docs can describe final evidence behavior.
- `W1-S2` should land before `W3-S1` and before any claim that manual approvals are rollback-safe.
- `W2-S1` should land before `W3-S1` so resume safety wording is not speculative.
- `W2-S2` should land before `W3-S1` so state-lifecycle docs can accurately describe preflight commit semantics.

## Explicit Non-Goals

- No proof-library version upgrade or cross-repo toolchain remediation wave is part of this plan.
- No new public schema version or exit-code family is planned.
- No new hosted service, daemon, or dashboard surface is in scope.
- No non-deterministic enrichment or network-first behavior is added.
- No broad refactor of unrelated scan/report/evidence flows beyond what is required to close the four findings safely.
- No weakening of current staged-output ownership markers or managed-path safety checks.

## Definition of Done

- Every recommendation `R1..R4` is implemented and mapped back to at least one merged story.
- Story acceptance criteria are satisfied with deterministic automated tests.
- Contract, docs, and lifecycle path updates ship in the same PRs as their runtime changes.
- `go test ./... -count=1` remains green after the implementation sequence.
- Required story-level lane wiring is present and green:
  - fast
  - core
  - acceptance
  - cross-platform
  - risk where required
- No story introduces a public schema bump, exit-code remap, or success-payload break without an ADR and migration note.
- Managed artifact behavior is consistent with docs:
  - no bundle publish from tampered proof
  - no partial manifest approval commit on failed manual transitions
  - no trusted resume from symlink-swapped materializations
  - no scan-managed state mutation on invalid scan-owned artifact paths
- README, command docs, lifecycle docs, trust docs, examples, and changelog are aligned with the final runtime behavior.

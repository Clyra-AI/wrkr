# PLAN WRKR_WAVE1_CONTRACT_HARDENING: Proof Integrity, Regress Compatibility, and State Safety

Date: 2026-03-10  
Source of truth: user-provided code-review findings for this run, `product/dev_guides.md`, `product/architecture_guides.md`, `AGENTS.md`, current repo baseline  
Scope: Wrkr repository only. Planning artifact only. One wave only.

## Global Decisions (Locked)

- This plan is intentionally one wave only. Scope is limited to release-blocking contract/runtime correctness and the minimum docs/schema parity required to ship those fixes safely.
- Preserve Wrkr's deterministic, offline-first, fail-closed default behavior. No new network paths, dashboard work, or UX expansion are in scope.
- Preserve architecture boundaries: Source -> Detection -> Aggregation -> Identity -> Risk -> Proof emission -> Compliance/evidence output.
- Keep existing public command names and exit taxonomy stable:
  - `wrkr verify --chain`
  - `wrkr regress init|run`
  - `wrkr evidence`
  - exit codes `0..8`
- Proof verification must always perform structural chain validation. Attestation or signature verification is an authenticity layer, not a substitute for structural integrity checks.
- Present-but-invalid or unreadable signing material is fail-closed. Silent authenticity downgrades are not allowed.
- Prefer additive `--json` fields on `verify` over envelope/key renames. If additional status is required, add optional fields instead of changing the success/error shape.
- Preserve `schemas/v1/regress/regress-baseline.schema.json` and `BaselineVersion = "v1"` if a compatibility shim can safely reconcile legacy agent IDs. Only bump the baseline version if an ADR proves that additive compatibility is unsafe or ambiguous.
- `proof-signing-key.json` must use the same atomic/locked persistence discipline already used for state, manifests, baselines, and proof chains.
- All runtime/contract/failure stories in this wave must wire `make prepush-full`. Reliability-sensitive stories must also wire `make test-hardening` and `make test-chaos`.
- Docs changes in this wave are limited to touched contracts: command docs, failure taxonomy, compatibility/versioning notes, release-integrity guidance, README/changelog wording where required by real behavior changes.

## Current Baseline (Observed)

- `go test ./... -count=1` passes in the current repository.
- Happy-path command anchors pass:
  - `wrkr scan --path scenarios/wrkr/scan-mixed-org/repos --state /tmp/wrkr-review-state.json --json`
  - `wrkr regress init --baseline /tmp/wrkr-review-state.json --output /tmp/wrkr-review-baseline.json --json`
  - `wrkr regress run --baseline /tmp/wrkr-review-baseline.json --state /tmp/wrkr-review-state.json --json`
  - `wrkr verify --chain --state /tmp/wrkr-review-state.json --json`
  - `scripts/check_branch_protection_contract.sh`
- The proof verification boundary is currently unsafe:
  - `core/verify/verify.go` returns success on attestation verification without parsing or structurally verifying the chain.
  - `core/cli/verify.go` silently falls back to unsigned verification when `LoadVerifierKey` fails.
- The regress compatibility boundary is currently unsafe:
  - `core/regress/regress.go` keeps `BaselineVersion = "v1"` and derives legacy agent IDs when `snapshot.Identities` is absent.
  - `core/cli/scan_helpers.go` now emits instance-level IDs via `AgentInstanceID`, creating a legacy/current mismatch without a migration path.
- The proof signing-material persistence boundary is currently weak:
  - `core/proofemit/signing.go` creates `proof-signing-key.json` with raw `os.WriteFile` and no path lock.
  - `core/evidence/evidence.go` hard-depends on valid signing material for bundle creation, so a torn or rotated key file becomes a release-path failure.
- `docs/commands/verify.md` currently documents only `status`, `chain.path`, `chain.intact`, `chain.count`, and `chain.head_hash`; it does not describe authenticity-degraded behavior or fail-closed key semantics.
- No `sdk/python` directory exists in this checkout, so no SDK wrapper scope is included in this plan.

## Exit Criteria

1. `wrkr verify --chain` never returns `status=ok` for non-JSON or structurally invalid proof chains, even when attestation or signature material is present and valid.
2. `wrkr verify --chain --json` no longer silently downgrades when verifier-key loading fails; missing-key and invalid-key paths are explicit, documented, and deterministic.
3. `proof-signing-key.json` initialization is atomic and contention-safe, with interruption and concurrency coverage proving no torn writes or key/chain mismatches.
4. Legacy `v1` regress baselines built before instance identities do not false-trigger drift for equivalent current identities.
5. `wrkr regress` preserves deterministic ordering, reason codes, and exit `5` semantics for genuine drift while suppressing false drift caused only by legacy/current identity format differences.
6. Docs, contract tests, and release-integrity guidance are updated in the same PR for every externally visible `verify` or `regress` behavior change.
7. All stories in this wave pass Fast, Core CI, Acceptance, Cross-platform, and Risk lane requirements before merge.

## Public API and Contract Map

Stable/public surfaces touched by this wave:
- `wrkr verify --chain --json`
- `wrkr regress init --json`
- `wrkr regress run --json`
- `wrkr evidence --frameworks ... --json`
- Machine-readable error envelope and exit code taxonomy
- `schemas/v1/regress/regress-baseline.schema.json`
- Docs contracts:
  - `README.md`
  - `docs/commands/verify.md`
  - `docs/commands/regress.md`
  - `docs/failure_taxonomy_exit_codes.md`

Internal surfaces touched by this wave:
- `core/verify/*`
- `core/cli/verify.go`
- `core/proofemit/*`
- `core/regress/*`
- `core/cli/regress.go`
- `internal/atomicwrite/*`
- `internal/e2e/verify/*`
- `internal/e2e/regress/*`
- `testinfra/contracts/*`
- `testinfra/hygiene/*`

Shim/deprecation path:
- `verify` keeps its top-level success envelope. If additional mode/status detail is required, add optional fields such as `chain.verification_mode` and `chain.authenticity_status` rather than renaming or removing existing keys.
- `regress` keeps the existing command surface and preferred `v1` baseline format. Compatibility is restored by automatic legacy-ID reconciliation if it can be done safely.
- If automatic reconciliation is unsafe, the fallback is an explicit baseline-version bump with a documented migration path in the same wave. No silent format drift is allowed.

Schema/versioning policy:
- `verify` success payload changes must be additive only.
- `regress` remains `v1` only if compatibility tests prove that legacy baselines do not false-drift against equivalent current identities.
- Any schema/version bump must ship with:
  - migration expectations
  - compatibility tests
  - docs updates
  - contract/golden updates

Machine-readable error expectations:
- Invalid `verify` input remains `invalid_input` with exit `6`.
- Non-JSON or structurally invalid proof chains return `verification_failure` with exit `2`, even when attestation/signature verification succeeds.
- Present-but-invalid or unreadable verifier key material returns `verification_failure` with exit `2`.
- Missing verifier-key material must never silently behave like “all checks passed”; the selected behavior must be explicit in JSON and documented in the same PR.
- Equivalent legacy/current regress inputs must not produce `drift_detected=true` or exit `5`.

## Docs and OSS Readiness Baseline

README first-screen contract:
- Current README promises signed proof artifacts and verifiable evidence. This wave must keep those statements accurate by fixing the implementation and tightening wording where necessary.
- No README repositioning or new onboarding narrative is planned; only touched contract language should change.

Integration-first docs flow:
- `docs/commands/verify.md` must explain success keys, failure keys, and authenticity behavior with copy-paste examples before implementation details.
- `docs/commands/regress.md` must explain legacy baseline compatibility expectations and any versioning/migration path chosen in this wave.

Lifecycle path model:
- This wave does not introduce a new lifecycle model. The work stays inside existing identity/regress semantics and compatibility repair.

Docs source-of-truth for this wave:
- `README.md`
- `docs/commands/verify.md`
- `docs/commands/regress.md`
- `docs/failure_taxonomy_exit_codes.md`
- `docs/trust/release-integrity.md`
- `docs/trust/compatibility-and-versioning.md`

OSS trust baseline:
- Existing trust files already exist: `CONTRIBUTING.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `README.md`, `LICENSE`.
- This wave only requires updates to touched command/contract docs and `CHANGELOG.md` if released behavior changes are user-visible.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Always structurally verify proof chains after attestation/signature checks | Stop invalid artifacts from passing integrity verification | Fail-closed proof verification | Restore trust in signed evidence and chain integrity claims | W1-S01 |
| R2 | Remove silent verifier-key downgrade and make authenticity state explicit | Prevent fail-open authenticity behavior | Boundary hardening at CLI/runtime edge | Safer operator automation and more truthful machine-readable outputs | W1-S01, W1-S02 |
| R3 | Restore legacy regress baseline compatibility under `v1` or ship explicit migration | Stop false drift after instance-identity rollout | Compatibility-preserving contract evolution | Preserve existing automation and prevent spurious exit `5` regressions | W1-S03 |
| R4 | Make proof signing-material creation atomic and contention-safe | Remove crash/race hazard on authoritative signing state | State-safety hardening | Keep proof emission, verification, and evidence generation reliable under interruption/contention | W1-S02 |

## Test Matrix Wiring

Fast lane:
- `make lint-fast`
- `make test-fast`

Core CI lane:
- `make prepush`
- `make test-contracts`
- Targeted package tests for `core/verify`, `core/proofemit`, `core/regress`, `core/cli`, and touched docs-contract packages

Acceptance lane:
- `go test ./internal/e2e/verify -count=1`
- `go test ./internal/e2e/regress -count=1`
- `make test-scenarios`
- `scripts/run_v1_acceptance.sh --mode=local`

Cross-platform lane:
- Existing `windows-smoke`
- Targeted path and artifact tests for `verify`/`regress` on Linux/macOS/Windows in CI where applicable

Risk lane:
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`

Merge/release gating rule:
- No story in this wave is mergeable until Fast + Core CI + Acceptance + Cross-platform + Risk lanes are green.
- No release is allowed with `verify --json` drift, exit-code drift, docs/CLI parity failures, or unresolved legacy-baseline compatibility gaps unless explicitly versioned and documented in the same change.

## Epic W1-E1 (Wave 1): Contract and Reliability Hardening for Verify, Regress, and Proof State

Objective: restore release-safe proof verification, proof signing-material persistence, and regress compatibility without expanding Wrkr scope beyond contract/runtime correctness.

### Story W1-S01: Make proof verification structurally authoritative and authenticity-explicit
Priority: P0
Tasks:
- Refactor `core/verify.ChainWithPublicKey` so structural chain verification always runs after attestation/signature verification logic.
- Separate structural integrity and authenticity checks in the result model so the CLI can report both without silent downgrade.
- Update CLI verify flow so non-JSON and structurally invalid chains return deterministic verification failures even when attestation/signature verification succeeds.
- Add targeted tests for:
  - attested non-JSON chain
  - attested structurally invalid chain
  - signed structurally invalid chain
  - explicit success output for the chosen verification/authenticity mode fields
Repo paths:
- `core/verify/*`
- `core/cli/verify.go`
- `internal/e2e/verify/*`
- `testinfra/contracts/*`
Run commands:
- `go test ./core/verify -count=1`
- `go test ./core/cli -run Verify -count=1`
- `go test ./internal/e2e/verify -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Proof/evidence contract tests for structural verification after authenticity checks
- CLI `--json` stability tests
- Exit-code and machine-readable error envelope tests
- Deterministic repeat-run tests for success/error output ordering
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- A non-JSON `proof-chain.json` with a valid attestation returns exit `2`, not `status=ok`.
- A structurally invalid but correctly signed chain returns exit `2`.
- The final `verify --json` success contract explicitly states the verification/authenticity mode without breaking the top-level envelope.
Contract/API impact:
- Touches `wrkr verify --chain --json` success/failure semantics.
- Must preserve the current top-level envelope and existing keys; any new status fields must be additive and documented.
Versioning/migration impact:
- No schema major bump expected; additive `verify` fields only.
Architecture constraints:
- Keep policy/sign/verify authority in Go core packages, not in CLI branching.
- Maintain symmetric API semantics: structural verification and authenticity verification must be explicit, ordered steps.
- No network or remote key dependency may be introduced.
ADR required: yes
TDD first failing test(s):
- `TestChainWithPublicKeyRejectsAttestedNonJSONPayload`
- `TestChainWithPublicKeyRejectsAttestedStructuralCorruption`
- `TestVerifyCLIEmitsExplicitVerificationMode`
Cost/perf impact: low
Chaos/failure hypothesis:
- If attestation or signature verification succeeds but the chain payload is malformed or structurally corrupt, verification must still fail deterministically with exit `2` and no partial-success output.

### Story W1-S02: Fail closed on bad verifier keys and harden proof-signing-key initialization
Priority: P0
Tasks:
- Change `core/cli/verify.go` to distinguish:
  - no verifier key available
  - verifier key present but unreadable/invalid
- Fail closed on unreadable/invalid key material; if no key exists, emit explicit deterministic authenticity status per the ADR in W1-S01 instead of silently falling back.
- Replace raw `os.WriteFile` in `core/proofemit/signing.go` with `atomicwrite.WriteFile` and add a per-path initialization lock for first-time key creation.
- Add interruption and contention coverage for first-write key creation and prove that `verify` and `evidence` behave consistently after fault injection.
Repo paths:
- `core/cli/verify.go`
- `core/proofemit/signing.go`
- `core/proofemit/*`
- `core/evidence/*`
- `internal/atomicwrite/*`
- `internal/e2e/verify/*`
Run commands:
- `go test ./core/proofemit -count=1`
- `go test ./core/evidence -count=1`
- `go test ./core/cli -run Verify -count=1`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- Invalid-key and missing-key contract tests
- Atomic-write interruption tests
- Contention/concurrency tests
- Hardening and chaos coverage for first-time signing-material creation
- Evidence/verify consistency tests when signing material is absent, invalid, or newly created
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- A corrupted `proof-signing-key.json` no longer yields `status=ok` from `wrkr verify --chain`.
- Missing verifier-key behavior is explicit and deterministic; no silent fallback remains.
- Concurrent first-time key initialization produces exactly one valid persisted key state and a verifiable proof chain.
- Simulated interruption during key initialization leaves no torn or partially valid key file behind.
Contract/API impact:
- Touches `verify` error behavior for key-material failures and may add explicit success-state fields for authenticity mode.
- Keeps existing exit taxonomy; invalid key material must map to stable verification failure semantics.
Versioning/migration impact:
- No schema/version bump expected.
Architecture constraints:
- Persistence safety belongs in proof/state helpers, not CLI-level ad hoc retries.
- API names should make side effects explicit (`load`, `init`, `verify`, `emit`).
- Avoid new shared mutable global state except tightly scoped path locks with tests.
ADR required: yes
TDD first failing test(s):
- `TestVerifyCLIRejectsInvalidVerifierKeyFile`
- `TestLoadSigningKeyIsAtomicUnderInterruption`
- `TestLoadSigningKeyConcurrentInitializationProducesSingleValidState`
Cost/perf impact: low
Chaos/failure hypothesis:
- Two concurrent scans against a fresh state directory or an interruption during first key creation must not leave mismatched key/chain state, torn files, or a false-green verify result.

### Story W1-S03: Restore legacy regress baseline compatibility without silent contract drift
Priority: P0
Tasks:
- Implement a compatibility shim in `core/regress` that reconciles legacy baseline agent IDs with current instance-level identities when the underlying tool is equivalent.
- Preserve deterministic sorting, reason ordering, and reason-code stability while suppressing false `new_unapproved_tool` drift for legacy/current ID format differences alone.
- Add compatibility fixtures that cover symbol/location-range instance IDs, legacy baselines built without `snapshot.Identities`, and genuine new-tool drift.
- Only if the shim is proven unsafe, version-bump the baseline format and ship an explicit migration path and contract docs in the same wave.
Repo paths:
- `core/regress/*`
- `core/identity/*`
- `core/cli/regress.go`
- `schemas/v1/regress/*`
- `internal/e2e/regress/*`
- `testinfra/contracts/*`
Run commands:
- `go test ./core/regress -count=1`
- `go test ./internal/e2e/regress -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Compatibility and migration tests for legacy baseline to current identity matching
- Exit `5` drift/no-drift contract tests
- Deterministic ordering and reason-code stability checks
- Schema validation and fixture/golden updates if any schema or payload shape changes
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- A legacy `v1` baseline describing the same tool as a current instance-identity scan returns no drift.
- A genuinely new instance identity still returns `new_unapproved_tool` and exit `5`.
- `regress` remains byte-stable and deterministically ordered across repeated runs.
- If schema/version changes are required, migration expectations and tests ship in the same PR.
Contract/API impact:
- Touches `wrkr regress` compatibility behavior and potentially baseline schema expectations.
- Must not change exit-code semantics for genuine drift.
Versioning/migration impact:
- Preferred path: preserve `v1` with automatic compatibility shim.
- Fallback path: explicit version bump with migration document and compatibility tests.
Architecture constraints:
- Keep compatibility logic inside `core/regress` and `core/identity`, not CLI glue.
- Do not leak lifecycle state reconciliation into unrelated packages.
- Reason-code stability is non-negotiable for automation consumers.
ADR required: yes
TDD first failing test(s):
- `TestCompareLegacyBaselineInstanceIdentity_NoFalseDrift`
- `TestLoadBaselineLegacyAgentIDCompatibility`
- `TestCompareStillFlagsTrueNewInstanceIdentity`
Cost/perf impact: low
Chaos/failure hypothesis:
- Mixed legacy/current baseline inputs should never produce nondeterministic drift or order-dependent results when repeated under the same input set.

### Story W1-S04: Align docs, contract tests, and release notes with the fixed verify/regress behavior
Priority: P1
Tasks:
- Update command docs, failure-taxonomy docs, and compatibility/versioning notes to match the final verify and regress contract.
- Update README wording only where current integrity/authenticity claims must become more precise after the runtime fix.
- Refresh contract/golden coverage and run docs parity checks against the actual CLI output.
- Add changelog entries for externally visible behavior changes if the fixes are intended for the next release.
Repo paths:
- `README.md`
- `CHANGELOG.md`
- `docs/commands/verify.md`
- `docs/commands/regress.md`
- `docs/failure_taxonomy_exit_codes.md`
- `docs/trust/release-integrity.md`
- `docs/trust/compatibility-and-versioning.md`
- `testinfra/contracts/*`
- `testinfra/hygiene/*`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `scripts/check_docs_cli_parity.sh`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Docs consistency and storyline checks
- CLI/docs parity checks
- Contract tests for any new `verify` fields or regress compatibility notes
- README first-screen checks if touched
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform
Acceptance criteria:
- Docs/examples match the final `verify` and `regress` behavior exactly.
- Failure taxonomy docs reflect invalid-key, missing-key, and invalid-chain semantics.
- No docs introduce contract claims not backed by code and tests.
Contract/API impact:
- Docs and tests only; no new CLI surface beyond the implementation completed in W1-S01 through W1-S03.
Versioning/migration impact:
- Documents the chosen `v1` compatibility path or the explicit version-bump migration path.
Architecture constraints:
- Documentation must mirror the authoritative Go implementation and contract tests; no docs-only contract invention.
ADR required: no
TDD first failing test(s):
- `TestVerifyDocsMatchCLIContract`
- `TestRegressDocsDescribeLegacyCompatibilityPath`
- `TestFailureTaxonomyIncludesVerifyKeyFailureCase`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not applicable; this story consumes the behavior fixed and validated in W1-S01 through W1-S03.

## Minimum-Now Sequence

1. W1-S01: lock the verify ADR and remove the structural-verification bypass first, because it defines the final verification contract for the rest of the wave.
2. W1-S02: harden verifier-key handling and proof-signing-key persistence next, because it closes the remaining fail-open path and the authoritative state-safety gap.
3. W1-S03: repair regress baseline compatibility after the proof boundary is fixed, keeping `v1` if the shim is safe.
4. W1-S04: land docs, contract/golden updates, and release-note alignment only after the runtime behavior is final.

## Explicit Non-Goals

- No new scan, detect, report, inventory, mcp-list, or docs-site feature work.
- No expansion of `--enrich` or any other non-deterministic network behavior.
- No dashboard, SaaS, or web bootstrap scope.
- No unrelated toolchain upgrades or dependency sweeps unless directly required by the implementation of this wave.
- No baseline schema `v2` unless the ADR in W1-S03 proves that additive compatibility under `v1` is unsafe.

## Definition of Done

- Every recommendation in this plan maps to at least one completed story with tests and lane wiring.
- `wrkr verify --chain` is fail-closed for invalid chains and invalid key material, with no silent authenticity downgrade.
- `proof-signing-key.json` creation is atomic, locked, and covered by interruption/concurrency tests.
- Legacy `v1` regress baselines no longer false-trigger drift for equivalent current identities, or a fully documented migration path ships in the same wave.
- All touched CLI/docs/schema contracts are updated in the same PR and pass parity checks.
- Required commands for touched stories are recorded and green, including `make prepush-full`, `make test-contracts`, and reliability gates where applicable.

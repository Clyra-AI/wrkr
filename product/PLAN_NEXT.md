# PLAN NEXT: State Mutation Safety And Lifecycle Contract Recovery

Date: 2026-04-23

Source of truth:
- User-provided code-review findings for approval propagation, managed-artifact state-path safety, and lifecycle-state contract drift.
- `AGENTS.md`.
- `product/wrkr.md`.
- `product/dev_guides.md`.
- `product/architecture_guides.md`.

Scope:
- Wrkr only.
- Planning only. No implementation is included in this plan.
- Fix the release-blocking contract gaps around stateful CLI mutation authority, fail-closed managed artifact ownership, and lifecycle-state semantics.
- Preserve deterministic, offline-first, file-based evidence behavior and existing exit-code classes.

## Global Decisions (Locked)

- Treat the approval-propagation and symlinked-state issues as the minimum blocker set for safe release posture.
- Treat `product/wrkr.md` and `AGENTS.md` as authoritative for lifecycle semantics unless a future explicit versioned migration says otherwise.
- Fail-closed decision: symlinked `--state` inputs are unsupported across all stateful Wrkr commands and must return exit `8` with `error.code=unsafe_operation_blocked` before any managed artifact mutation.
- Managed artifacts remain a same-root contract derived from one trusted state location; Wrkr must not split `state.json` and sibling manifest/proof/status artifacts across directories.
- A successful manual identity or inventory mutation must make the saved snapshot authoritative immediately for `score`, `report`, `regress init`, and `regress run`; no rescanning is required to observe approved posture.
- Mutation projection must be centralized. Do not keep separate best-effort snapshot patch logic per command family.
- Any snapshot fields affected by lifecycle or approval mutation must be updated in the same transaction or deterministically recomputed before success is returned.
- `discovered` remains the persisted first-seen lifecycle state.
- `under_review` is reserved for explicit review, approval expiry, or other explicit downgrade-to-review cases.
- `active` remains an auto-derived state for approved-present identities during scan reconciliation.
- CLI help/docs/failure-taxonomy changes ship in the same stories as runtime changes.
- No schema-major version bump is planned for this work. Use additive or behavior-fix semantics only.

## Current Baseline (Observed)

- `scan` derives sibling manifest/proof/status paths from the lexical `--state` path in `core/cli/scan.go`.
- `internal/atomicwrite` resolves a final-file symlink target when writing the state file, which allows `state.json` to land in a different directory than sibling managed artifacts when `--state` is a symlink.
- `inventory` already rejects symlinked managed mutation artifacts in `core/cli/inventory_mutations.go`, but `scan` and `identity` do not apply the same fail-closed gate.
- `identity approve|review|deprecate|revoke` updates manifest, lifecycle chain, and proof artifacts but never rewrites `state.json`.
- `inventory approve|attach-evidence|accept-risk|deprecate|exclude` updates `state.json`, but cached derived sections such as `posture_score` remain stale.
- `score`, `report`, `regress init`, and `regress run` read saved snapshot material rather than rescanning, so stale lifecycle and approval data can persist after successful mutations.
- `core/lifecycle/lifecycle.go` initializes first-seen identities as `discovered` and then immediately normalizes them to `under_review`, so the documented `discovered` state does not persist in practice.
- Existing docs already promise same-root managed artifacts, fail-closed mutation rollback, and a persisted lifecycle path that includes `discovered`, so runtime currently drifts from published behavior.
- `go test ./... -count=1` passes locally, so this work is a contract-correction plan for green-but-wrong behavior rather than a red-suite rescue.

## Exit Criteria

- `wrkr scan --state <symlink> --json` fails before any managed artifact mutation with exit `8` and `error.code=unsafe_operation_blocked`.
- `wrkr identity approve|review|deprecate|revoke --json` updates `state.json`, `wrkr-manifest.yaml`, lifecycle chain, and proof artifacts as one rollback-safe generation.
- `wrkr inventory approve|attach-evidence|accept-risk|deprecate|exclude --json` keeps the same rollback guarantees and refreshes derived posture sections that approval changes affect.
- After a successful approval mutation, `wrkr score --json`, `wrkr report --json`, and `wrkr regress init/run --json` reflect the new lifecycle and approval posture without a rescan.
- First-seen identities persist as `discovered`.
- Explicit review moves an identity to `under_review`.
- Expired approval returns an identity to `under_review`.
- Valid approved-present identities resolve to `active` on the next scan.
- CLI command docs, lifecycle docs, failure taxonomy docs, product lifecycle wording, and changelog entries match shipped behavior.
- All targeted fast/core/acceptance/cross-platform/risk lanes for these changes are green.

## Public API and Contract Map

Stable public surfaces to preserve:
- CLI commands: `scan`, `identity`, `inventory`, `score`, `report`, `regress`, `verify`.
- Exit-code contract in `core/cli/root.go`.
- Stable JSON error envelope shape under `--json`.
- Managed artifact family derived from state: scan snapshot, manifest, lifecycle chain, proof chain, proof attestation, signing key, scan status sidecar, regress baseline.
- Existing `wrkr scan --json` top-level surfaces remain additive; this plan does not remove fields.

Stable semantics to restore or preserve:
- Managed artifacts live alongside one trusted state root.
- Successful manual approval/lifecycle mutation makes the saved snapshot authoritative for downstream posture commands.
- Lifecycle path remains `discovered -> under_review -> approved -> active -> deprecated -> revoked`, with `active` auto-derived rather than directly operator-set for ongoing scans.

Internal surfaces touched by this plan:
- `core/cli/scan.go`
- `core/cli/identity.go`
- `core/cli/inventory_mutations.go`
- `core/cli/managed_artifacts.go`
- `core/cli/score.go`
- `core/cli/report.go`
- `core/cli/regress.go`
- `core/lifecycle/lifecycle.go`
- `core/state/*`
- `internal/atomicwrite/*`
- `docs/**`
- `product/wrkr.md`

Shim and deprecation path:
- No compatibility shim for symlinked `--state` inputs. They become consistently unsupported across all stateful commands.
- No removal of existing JSON fields or exit codes.
- Existing stale-state behavior is treated as a bug, not a supported migration mode.

Schema/versioning policy:
- Prefer no version bump for existing snapshot or manifest artifacts if field shape stays stable.
- If recomputation normalizes existing derived fields, the change must remain byte-stable for identical logical input state except explicit timestamps already allowed by contract.
- Fixture and golden updates that encode corrected lifecycle semantics are permitted as contract-repair changes and must be called out in changelog/docs.

Machine-readable error expectations:
- Symlinked or otherwise unsafe managed `--state` path: exit `8`, `error.code=unsafe_operation_blocked`.
- Mutation rollback failure: exit `1`, `error.code=runtime_failure`, with the prior committed generation restored.
- Approval mutation success: `status=ok`, and downstream state consumers read updated lifecycle and approval posture immediately.
- Drift remains exit `5`; this plan does not alter the drift exit-code class.

## Docs and OSS Readiness Baseline

- README first-screen contract remains mostly valid. Update `README.md` only if examples or lifecycle wording explicitly promise behavior changed by this plan.
- Integration-first docs flow for this scope is `scan -> identity/inventory mutation -> score/report/regress -> verify`.
- Lifecycle path model must explicitly describe first discovery.
- Lifecycle path model must explicitly describe explicit review.
- Lifecycle path model must explicitly describe valid approval.
- Lifecycle path model must explicitly describe active present use.
- Lifecycle path model must explicitly describe expiry back to review.
- Lifecycle path model must explicitly describe deprecation.
- Lifecycle path model must explicitly describe revocation.
- Docs source of truth for this work includes `docs/commands/scan.md`.
- Docs source of truth for this work includes `docs/commands/identity.md`.
- Docs source of truth for this work includes `docs/commands/inventory.md`.
- Docs source of truth for this work includes `docs/commands/score.md`.
- Docs source of truth for this work includes `docs/commands/report.md`.
- Docs source of truth for this work includes `docs/commands/regress.md`.
- Docs source of truth for this work includes `docs/state_lifecycle.md`.
- Docs source of truth for this work includes `docs/failure_taxonomy_exit_codes.md`.
- Docs source of truth for this work includes `product/wrkr.md`.
- Docs source of truth for this work includes `CHANGELOG.md`.
- OSS trust baseline files to verify when touched include `CHANGELOG.md`.
- OSS trust baseline files to verify when touched include `README.md`.
- OSS trust baseline files to verify when touched include `SECURITY.md` only if safety/failure wording needs to change materially.
- No expected changes to `CONTRIBUTING.md`, issue templates, or code-of-conduct material for this plan.
- Docs parity and storyline checks are mandatory for any user-visible CLI/help/contract wording change.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Planned stories |
|---|---|---|---|---|---|
| R1 | Make approval mutations authoritative for persisted posture state | Successful approvals currently leave downstream posture consumers stale | Treat saved state as the single operator authority between scans | Removes operator confusion and makes approval workflows trustworthy in CI and audit use | W2-S1, W2-S2 |
| R2 | Enforce one fail-closed managed artifact root for `--state` | Symlinked state paths can split artifacts and weaken ownership guarantees | Normalize all stateful commands around one safety boundary | Prevents artifact confusion and strengthens fail-closed local ownership controls | W1-S1 |
| R3 | Restore the persisted `discovered` lifecycle state | Runtime currently contradicts the documented lifecycle contract | Re-align lifecycle behavior, proofs, and docs around explicit review semantics | Clearer governance reasoning and less lifecycle-state ambiguity for drift and approval automation | W3-S1 |

## Test Matrix Wiring

Fast lane:
- `make lint-fast`
- `go test ./core/cli ./core/lifecycle ./core/state ./internal/atomicwrite -count=1`
- `scripts/check_docs_cli_parity.sh` when command docs or failure taxonomy files change

Core CI lane:
- `make prepush`
- `go test ./internal/e2e/cli_contract ./internal/e2e/source ./internal/e2e/regress ./internal/e2e/verify -count=1`
- `go test ./testinfra/contracts -count=1`

Acceptance lane:
- `scripts/run_v1_acceptance.sh --mode=local`
- `go test ./internal/acceptance -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- Extend scenario coverage for approval propagation and lifecycle transitions where needed

Cross-platform lane:
- Preserve `windows-smoke`
- Keep macOS/Linux symlink safety coverage for managed artifact roots
- Add explicit skips only where symlink fixtures are not portable, and assert the skip reason in tests

Risk lane:
- `make prepush-full`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `scripts/check_docs_storyline.sh` when lifecycle or operator-flow docs change

Merge/release gating rule:
- No story in this plan is mergeable without fast lane and core CI lane green.
- W1-S1 and W2-S1/W2-S2 additionally require risk lane green because they alter fail-closed persistence and rollback behavior.
- W3-S1 additionally requires docs parity/storyline and changelog updates because it changes user-visible lifecycle semantics.

## Wave 1: Fail-Closed Managed Artifact Root

Objective:
- Eliminate command-dependent `--state` path handling so scan and manual identity workflows enforce the same fail-closed ownership boundary already present in inventory mutation flows.

### Story W1-S1: Reject Symlinked `--state` Paths Across Stateful Commands

Priority:
- P0

Tasks:
- Introduce a shared trusted-state-path preflight for stateful commands that rejects symlinked `--state` files before any managed artifact mutation begins.
- Make `scan` and `identity` use the same fail-closed managed-artifact policy class as `inventory`.
- Keep sibling manifest/proof/status path derivation anchored to the trusted non-symlink state root only.
- Add rollback-safe hardening around preflight plus commit ordering so a rejected path never publishes a split artifact generation.
- Update command docs and failure taxonomy to document consistent exit `8` behavior for unsafe managed state paths.

Repo paths:
- `core/cli/scan.go`
- `core/cli/identity.go`
- `core/cli/inventory_mutations.go`
- `core/cli/managed_artifacts.go`
- `internal/atomicwrite/atomicwrite.go`
- `docs/commands/scan.md`
- `docs/commands/identity.md`
- `docs/failure_taxonomy_exit_codes.md`
- `docs/state_lifecycle.md`
- `CHANGELOG.md`

Run commands:
- `go run ./cmd/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state "$TMPDIR/state-link.json" --json`
- `go run ./cmd/wrkr identity approve <agent_id> --approver @maria --scope read-only --state "$TMPDIR/state-link.json" --json`
- `go test ./core/cli ./internal/atomicwrite -count=1`
- `go test ./internal/e2e/source ./internal/e2e/cli_contract -count=1`
- `go test ./testinfra/contracts -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`

Test requirements:
- CLI `--json` stability tests for rejected symlinked `--state` input.
- Exit-code contract tests proving `unsafe_operation_blocked` maps to exit `8`.
- Machine-readable error-envelope tests for `scan` and `identity`.
- Non-destructive fail-closed tests proving no managed artifacts are published after rejection.
- Marker-trust and regular-file tests where managed artifact families are involved.
- Cross-platform tests with explicit portability skips for symlink fixtures where needed.

Matrix wiring:
- Fast lane: targeted `core/cli` and `internal/atomicwrite` tests.
- Core CI lane: `make prepush` plus e2e CLI/source contract tests.
- Acceptance lane: extend scenario/e2e coverage if a new fixture is needed.
- Cross-platform lane: preserve `windows-smoke`, assert explicit skips for unsupported symlink fixtures.
- Risk lane: `make prepush-full`, `make test-contracts`, `make test-hardening`, `make test-chaos`.

Acceptance criteria:
- `wrkr scan --state <symlink> --json` exits `8` with `error.code=unsafe_operation_blocked`.
- `wrkr identity approve --state <symlink> --json` exits `8` with the same error class.
- No state, manifest, lifecycle, proof, attestation, signing-key, or status artifact is newly written when preflight rejects the path.
- Existing non-symlink `--state` flows continue to pass CLI contract and e2e suites unchanged.

Changelog impact: required

Changelog section: Security

Draft changelog entry: Hardened stateful CLI commands to fail closed on symlinked `--state` paths so scan, manifest, and proof artifacts cannot split across directories.

Semver marker override: none

Contract/API impact:
- Consistently rejects symlinked managed state paths across stateful commands while preserving existing error-envelope shape and exit-code taxonomy.

Versioning/migration impact:
- No schema change. Operators using symlinked `--state` paths must switch to real file paths.

Architecture constraints:
- Keep orchestration thin in `core/cli`; centralize trusted-state-path checks in a focused helper.
- Preserve explicit side-effect semantics in API names and signatures.
- Use symmetric API semantics for managed state path validation and commit helpers across `scan`, `identity`, and `inventory`.
- Preserve cancellation and timeout propagation where scan setup or state loading already accepts caller context.
- Leave extension points for additional stateful commands to reuse the same trusted-state-path policy without copying logic.
- Do not rely on hidden path canonicalization that weakens fail-closed ownership reasoning.
- Preserve deterministic local-only behavior; no network fallback or best-effort continuation.

ADR required: yes

TDD first failing test(s):
- `TestScanRejectsSymlinkedStatePath`
- `TestIdentityRejectsSymlinkedStatePath`
- `TestScanRejectsUnsafeStateBeforePublishingManagedArtifacts`

Cost/perf impact: low

Chaos/failure hypothesis:
- If the managed state path is unsafe or becomes ambiguous during mutation setup, Wrkr fails closed and leaves the prior committed artifact generation intact.

## Wave 2: Authoritative Mutation Snapshot Projection

Objective:
- Make saved snapshot state authoritative immediately after manual identity and inventory mutations, including any derived posture surfaces consumed by downstream commands.

### Story W2-S1: Centralize Identity And Inventory Mutation Projection Into Saved State

Priority:
- P0

Tasks:
- Create a shared mutation transaction helper that loads state, manifest, lifecycle chain, and proof chain from one trusted state root.
- Reuse the helper for `identity` and `inventory` command families instead of keeping an identity-only manifest/proof mutation path.
- Project the updated identity record, lifecycle transition, inventory visibility, control backlog effects, and transition history into the saved snapshot in the same transaction.
- Preserve rollback guarantees across `state.json`, manifest, lifecycle chain, proof chain, proof attestation, and signing material.
- Ensure mutation success never leaves manifest/proof ahead of saved state.

Repo paths:
- `core/cli/identity.go`
- `core/cli/inventory_mutations.go`
- `core/cli/managed_artifacts.go`
- `core/state/state.go`
- `core/lifecycle/lifecycle.go`
- `docs/commands/identity.md`
- `docs/commands/inventory.md`
- `docs/state_lifecycle.md`
- `docs/failure_taxonomy_exit_codes.md`
- `CHANGELOG.md`

Run commands:
- `go run ./cmd/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state "$TMPDIR/state.json" --json --quiet`
- `go run ./cmd/wrkr identity approve <agent_id> --approver @maria --scope read-only --expires 90d --state "$TMPDIR/state.json" --json`
- `go run ./cmd/wrkr inventory approve <agent_id> --owner team --evidence SEC-1 --expires 90d --state "$TMPDIR/state.json" --json`
- `go test ./core/cli ./core/state ./core/lifecycle -count=1`
- `go test ./internal/e2e/cli_contract ./internal/e2e/verify -count=1`
- `go test ./testinfra/contracts -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`

Test requirements:
- CLI `--json` success-path contract tests proving saved state changes on manual identity mutation.
- Rollback tests that inject failure after partial transaction progress and verify prior committed state is restored.
- Atomic-write and lifecycle contention tests for multi-artifact mutation sequencing.
- Deterministic repeat-run tests for identical mutation inputs.
- Failure taxonomy tests preserving runtime-failure behavior on downstream commit failure.

Matrix wiring:
- Fast lane: targeted `core/cli`, `core/state`, and `core/lifecycle` tests.
- Core CI lane: `make prepush` plus e2e CLI/verify coverage.
- Acceptance lane: extend acceptance coverage for post-approval saved-state authority.
- Cross-platform lane: preserve path-safe behavior on Windows/macOS/Linux.
- Risk lane: `make prepush-full`, `make test-contracts`, `make test-hardening`, `make test-chaos`.

Acceptance criteria:
- After `wrkr identity approve|review|deprecate|revoke --state <path> --json`, the corresponding record in `state.json` matches the committed manifest lifecycle and approval state.
- After equivalent `wrkr inventory` mutations, the same record family remains synchronized across state, manifest, lifecycle, and proof artifacts.
- Injected failure after any transaction step restores the prior committed generation rather than leaving mixed artifact state.
- Successful mutations never require a follow-up scan merely to make the saved snapshot internally consistent.

Changelog impact: required

Changelog section: Fixed

Draft changelog entry: Fixed manual identity and inventory mutations to update the saved scan snapshot in the same rollback-safe transaction as manifest and proof artifacts.

Semver marker override: none

Contract/API impact:
- Strengthens the existing saved-state authority contract for downstream commands without changing command names, exit codes, or JSON envelope shape.

Versioning/migration impact:
- No schema change. Historic stale-state behavior is corrected in place.

Architecture constraints:
- Use thin CLI orchestration with a focused mutation-transaction helper.
- Keep lifecycle logic in `core/lifecycle`, state persistence in `core/state`, and proof emission in `core/proofemit`.
- Make mutation helper semantics explicit in names and signatures (`load`, `project`, `commit`, `rollback`).
- Use symmetric mutation APIs so manual identity and inventory mutations share the same projection and rollback contract.
- Preserve existing context propagation and timeout boundaries where commands already support them.
- Leave extension points for future stateful mutation commands without re-implementing artifact sequencing.
- Preserve deterministic ordering and rollback guarantees across all managed artifact writes.

ADR required: yes

TDD first failing test(s):
- `TestIdentityApproveUpdatesSavedStateSnapshot`
- `TestIdentityManualTransitionRollsBackSavedStateOnDownstreamFailure`
- `TestInventoryAndIdentityMutationsShareOneArtifactGenerationContract`

Cost/perf impact: low

Chaos/failure hypothesis:
- If a mutation succeeds logically but a later artifact commit fails, Wrkr restores the prior saved generation and does not expose a partially approved posture to downstream commands.

Dependencies:
- W1-S1

### Story W2-S2: Recompute Derived Posture Surfaces After Approval Mutations

Priority:
- P1

Tasks:
- Identify which snapshot sections are approval- or lifecycle-derived and must be recomputed or invalidated after mutation success.
- Recompute `posture_score` and any directly approval-derived inventory/backlog summary surfaces as part of the mutation transaction.
- Add downstream CLI contract tests for `score`, `report`, `regress init`, and `regress run` immediately after approval mutation without rescanning.
- Keep recomputation deterministic and local; do not invoke detectors or network lookups.
- Update docs to state explicitly that saved snapshot posture remains authoritative between scans.

Repo paths:
- `core/cli/inventory_mutations.go`
- `core/cli/score.go`
- `core/cli/report.go`
- `core/cli/regress.go`
- `core/score/*`
- `core/aggregate/inventory/*`
- `internal/e2e/score/*`
- `docs/commands/score.md`
- `docs/commands/report.md`
- `docs/commands/regress.md`
- `docs/state_lifecycle.md`
- `product/wrkr.md`
- `CHANGELOG.md`

Run commands:
- `go run ./cmd/wrkr score --state "$TMPDIR/state.json" --json`
- `go run ./cmd/wrkr report --state "$TMPDIR/state.json" --json`
- `go run ./cmd/wrkr regress init --baseline "$TMPDIR/state.json" --output "$TMPDIR/baseline.json" --json`
- `go run ./cmd/wrkr regress run --baseline "$TMPDIR/baseline.json" --state "$TMPDIR/state.json" --json`
- `go test ./core/cli ./core/score ./core/aggregate/inventory -count=1`
- `go test ./internal/e2e/cli_contract ./internal/e2e/regress ./internal/e2e/score -count=1`
- `go test ./testinfra/contracts -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`

Test requirements:
- CLI `--json` stability tests for `score`, `report`, and `regress` after saved-state mutation.
- Contract tests proving approval mutation changes downstream posture outputs without rescanning.
- Determinism tests proving repeated post-mutation reads are byte-stable except for existing timestamp fields.
- Compatibility tests preserving existing output keys and exit-code classes.

Matrix wiring:
- Fast lane: targeted `core/cli`, `core/score`, and inventory aggregation tests.
- Core CI lane: `make prepush` plus e2e CLI/regress coverage.
- Acceptance lane: extend acceptance flow to cover `scan -> approve -> score/report/regress`.
- Cross-platform lane: keep snapshot-read behavior path-stable across OSes.
- Risk lane: `make prepush-full`, `make test-contracts`, `make test-hardening`, `make test-chaos`.

Acceptance criteria:
- `wrkr score --state <path> --json` changes approval-derived posture values immediately after a successful approval mutation.
- `wrkr report --state <path> --json` and `wrkr regress init/run --json` observe the updated lifecycle and approval state without a rescan.
- Downstream commands do not rerun detectors or depend on live network sources to achieve updated posture.
- Existing machine-readable output keys remain present and stable.

Changelog impact: required

Changelog section: Fixed

Draft changelog entry: Fixed saved-state posture calculations so score, report, and regress immediately reflect approval mutations without requiring a fresh scan.

Semver marker override: none

Contract/API impact:
- Corrects downstream CLI semantics for existing saved-state commands without changing their public flags or output-key inventory.

Versioning/migration impact:
- No schema change. Existing snapshots gain correct derived posture behavior after mutation.

Architecture constraints:
- Keep recomputation logic in focused state-refresh helpers rather than embedding it in CLI printing code.
- Do not call detectors, source acquisition, or remote services during mutation refresh.
- Use explicit recompute-or-invalidate semantics in helper APIs so callers do not infer partial refresh behavior.
- Preserve extension points for additional derived snapshot views without duplicating recomputation wiring.
- Preserve deterministic inputs and outputs for the same saved-state content.

ADR required: no

TDD first failing test(s):
- `TestScoreReflectsIdentityApproveWithoutRescan`
- `TestReportReflectsInventoryApproveWithoutRescan`
- `TestRegressBaselineInitializedAfterApprovalUsesUpdatedSavedState`

Cost/perf impact: low

Chaos/failure hypothesis:
- If derived posture recomputation fails after an approval mutation starts, Wrkr rolls back the mutation instead of returning success with stale derived state.

Dependencies:
- W2-S1

## Wave 3: Lifecycle Contract Realignment

Objective:
- Restore the documented persisted `discovered` lifecycle semantics and align lifecycle docs, fixtures, and downstream expectations around explicit review transitions.

### Story W3-S1: Persist `discovered` On First Observation And Reserve `under_review` For Explicit Review States

Priority:
- P2

Tasks:
- Update `core/lifecycle` reconciliation rules so first-seen identities persist as `discovered`.
- Keep `under_review` for explicit review, approval expiry, and other explicit review-required transitions rather than auto-normalizing all first-seen records.
- Preserve `active` auto-derivation from valid approval plus present detection.
- Update manifest/state/regress fixtures and acceptance tests that currently encode `under_review` for first-seen tools.
- Update command docs, lifecycle docs, and product lifecycle wording to describe the corrected transition rules precisely.

Repo paths:
- `core/lifecycle/lifecycle.go`
- `core/lifecycle/lifecycle_test.go`
- `core/cli/scan_lifecycle_manifest_test.go`
- `core/cli/root_test.go`
- `core/regress/*`
- `internal/acceptance/*`
- `internal/e2e/manifest/*`
- `docs/commands/identity.md`
- `docs/state_lifecycle.md`
- `product/wrkr.md`
- `CHANGELOG.md`

Run commands:
- `go run ./cmd/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state "$TMPDIR/state.json" --json --quiet`
- `go run ./cmd/wrkr identity review <agent_id> --state "$TMPDIR/state.json" --json`
- `go test ./core/lifecycle ./core/cli ./core/regress -count=1`
- `go test ./internal/acceptance ./internal/e2e/manifest ./internal/e2e/regress -count=1`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
- `make prepush-full`

Test requirements:
- Lifecycle unit tests for first-seen `discovered`, explicit `under_review`, expiry-to-review, and approved-present `active`.
- Regress compatibility tests proving removed/reappeared identities still behave deterministically.
- Fixture and golden updates where first-seen lifecycle state changes from `under_review` to `discovered`.
- Docs parity and storyline checks for lifecycle wording changes.

Matrix wiring:
- Fast lane: targeted lifecycle and CLI tests.
- Core CI lane: `make prepush` plus regress/e2e manifest coverage.
- Acceptance lane: acceptance and scenario flows covering the full lifecycle path.
- Cross-platform lane: preserve deterministic manifest/state serialization across OSes.
- Risk lane: `make prepush-full`, `scripts/check_docs_storyline.sh`.

Acceptance criteria:
- A fresh scan persists first-seen identities with `status=discovered`.
- `wrkr identity review` moves a discovered identity to `under_review`.
- Approval expiry returns an identity to `under_review`.
- Valid approved-present identities become `active` on subsequent scan reconciliation.
- Docs and product lifecycle wording describe the same transition conditions that runtime implements.

Changelog impact: required

Changelog section: Fixed

Draft changelog entry: Fixed lifecycle reconciliation so newly discovered tools persist as `discovered` until explicitly reviewed or approval state requires review.

Semver marker override: none

Contract/API impact:
- Corrects persisted lifecycle-state semantics in manifest/state outputs while keeping the existing state enum set.

Versioning/migration impact:
- No schema change. Fixtures, golden files, and operator expectations that encoded first-seen `under_review` must be updated to `discovered`.

Architecture constraints:
- Keep lifecycle-state authority centralized in `core/lifecycle`.
- Do not move lifecycle derivation into CLI, reporting, or regress code.
- Preserve deterministic transition ordering and `present=false` handling for removed identities.

ADR required: yes

TDD first failing test(s):
- `TestReconcilePreservesDiscoveredForFirstSeenIdentity`
- `TestReviewAndExpiryProduceUnderReviewWithoutClobberingDiscoveredFirstSeen`
- `TestApprovedPresentIdentityStillTransitionsToActive`

Cost/perf impact: low

Chaos/failure hypothesis:
- If a saved state contains expired approvals, reappeared identities, or removed identities, reconciliation still produces deterministic `discovered`, `under_review`, `active`, and `present=false` outcomes without oscillation or lifecycle clobbering.

Dependencies:
- W2-S1
- W2-S2

## Minimum-Now Sequence

Wave 1:
- W1-S1

Wave 2:
- W2-S1
- W2-S2

Wave 3:
- W3-S1

Dependency-driven execution notes:
- Do not start W2-S1 until W1-S1 has locked the trusted managed-state-path boundary.
- Do not start W2-S2 until W2-S1 has made saved-state mutation authoritative.
- Do not land W3-S1 before W2-S1 and W2-S2, because lifecycle semantics need the repaired saved-state authority path and downstream posture assertions.
- If scope must be split for reviewability, the minimum blocker release sequence is W1-S1, W2-S1, and W2-S2. W3-S1 closes the remaining documented lifecycle contract drift immediately after the blocker set.

## Explicit Non-Goals

- No new detector coverage, risk-model redesign, or report-template expansion.
- No new export or integration surfaces.
- No exit-code taxonomy redesign beyond consistent reuse of existing exit `8` and runtime-failure behavior.
- No schema-major version bump.
- No cross-repo toolchain, CI, or vulnerability-remediation wave beyond the tests already required for this plan.
- No docs-site redesign or onboarding-taxonomy rewrite outside the touched lifecycle and command-contract surfaces.

## Definition of Done

- Every story is implemented with TDD evidence: failing tests first, exact commands run, and green results recorded in the PR.
- All touched command contracts keep `--json` parseability and stable exit-code classes.
- Saved-state mutation flows are rollback-safe and deterministic under normal and injected-failure paths.
- Docs, failure taxonomy, lifecycle wording, and `CHANGELOG.md` are updated in the same implementation PRs as runtime changes.
- Fast lane, core CI lane, and the required risk lane commands for each story are green before merge.
- Acceptance/e2e coverage exists for approval propagation and lifecycle semantics.
- No implementation branch begins with unrelated dirty files beyond the generated plan file from this planning step.

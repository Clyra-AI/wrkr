# Adhoc Plan: Proof Lifecycle Release Readiness

Date: 2026-05-09
Profile: `wrkr`
Slug: `proof-lifecycle-release-readiness`
Recommendation source: user-provided combined verdict and app-audit findings covering managed artifact crash consistency, Go package scope hygiene after docs-site install, release/docs workflow action-ref exceptions, and OSS license completeness.

All paths in this plan are repo-relative. This is a planning artifact only; it does not implement runtime, workflow, test, license, or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product. These stories must not implement Axym compliance logic, Gait enforcement, or scan-time LLM behavior.
- Proof, lifecycle, state, manifest, and evidence outputs are release-promotable only after an implementation PR names an owner for the crash-consistency work and passes the risk lanes listed in this plan.
- Default scan, risk, proof, verify, report, and regress behavior must remain local-first, deterministic, and zero-egress by default.
- Managed artifact durability must be treated as a cross-artifact contract, not as independent file-level atomicity. An individual file being atomically renamed is insufficient when consumers rely on a coherent state, manifest, lifecycle chain, proof chain, attestation, signing key, and output sidecars.
- Recovery behavior must be deterministic and fail closed. If Wrkr can prove the previous or next managed artifact set is coherent, it may recover to that set; if not, commands must surface a verification/runtime failure using existing exit-code contracts.
- No raw secrets may be read or serialized while adding crash fixtures, CI package hygiene fixtures, or workflow exception metadata.
- Go package selection for local and CI gates must be first-party and reproducible. Ignored generated dependency trees such as `docs-site/node_modules` must never influence Go test, vet, release, UAT, or acceptance lanes.
- CI action refs used by release/docs workflows must either be immutable SHA pins or explicitly registered exceptions with owner, expiry, minimum scope, and recurring review evidence.
- The repository's OSS license posture must use the full Apache-2.0 license text so scanners and evaluators can classify the project without trust friction.
- Changelog entries are required because the work changes release-readiness posture, developer gate behavior, supply-chain governance surfaces, and OSS trust artifacts.

## Current Baseline (Observed)

- The recommendation source reports `make lint-fast` passed and `make test-fast` passed on the review baseline.
- The recommendation source reports scenario anchors passed for scan/evidence/verify/regress on `.tmp/combined-review-20260509183414`.
- The recommendation source reports proof verification was intact with `intact=true`, `authenticity_status=verified`, and `records=306`; regress reported `drift_detected=false`.
- `core/cli/scan.go` currently captures snapshots and rolls back managed artifacts when a write path returns an error, but commits state, lifecycle, proof, manifest, cleanup, and final state sequentially.
- `core/cli/state_mutation.go` currently commits state, lifecycle chain, proof transition records, and manifest sequentially with rollback on returned errors.
- `core/cli/managed_artifacts.go` provides snapshot/restore helpers and unsafe path checks, but it does not define a staged multi-artifact transaction, durable journal, managed-root swap, or recovery protocol for process interruption.
- Existing tests such as `core/cli/scan_transaction_test.go` and `core/cli/state_mutation_test.go` cover returned write failures through `internal/atomicwrite` hooks, not process-kill windows after a successful file rename.
- `Makefile` defines `PKGS := ./...`; the recommendation source observed `go list ./...` discovering `github.com/Clyra-AI/wrkr/docs-site/node_modules/flatted/golang/pkg/flatted` after docs-site dependencies were present.
- `.gitignore` ignores `docs-site/node_modules/`, but Go package discovery still walks ignored directories when `./...` is used from the module root.
- `.github/workflows/release.yml` uses `anchore/sbom-action@v0` and `anchore/scan-action@v4`; `.github/workflows/docs.yml` uses `actions/configure-pages@v5`.
- `product/dev_guides.md` requires exact CI/build pins and allows bounded JavaScript action runtime exceptions only when explicit, scoped, and revisited; the observed workflow action-ref exceptions do not carry owner and expiry metadata.
- `LICENSE` currently contains an abbreviated Apache notice rather than the full Apache License 2.0 text.

## Exit Criteria

- Scan artifact commits are crash-consistent across state, manifest, lifecycle chain, proof chain, proof attestation, signing key, and generated sidecar artifacts that are part of the managed output set.
- Identity and inventory lifecycle mutations use the same managed artifact commit contract as scan where they touch state, manifest, lifecycle, and proof outputs.
- A deterministic recovery or fail-closed path exists for interrupted managed artifact commits. Recovery never invents proof records, lifecycle transitions, or manifest identities.
- Cross-artifact verification can detect and explain mismatches among state, manifest, lifecycle chain, proof chain, and attestation after interruption fixtures.
- Failure-injection tests cover interruption points before and after state save, lifecycle save, proof emit, manifest save, attestation update, signing key creation, and final state save.
- `wrkr verify --chain --json` and `wrkr regress run --baseline <baseline-path> --json` continue to report coherent outcomes after recovered transactions.
- Go developer, CI, release, UAT, and acceptance lanes use first-party Go package roots and do not include ignored docs-site dependency packages after `make docs-site-install`.
- Workflow action refs in release/docs are pinned to immutable SHAs where possible, or each exception has a tracked owner, expiry, scope, and review command enforced by fast-lane tests.
- The repository contains the full Apache-2.0 license text and an OSS hygiene test or scanner smoke that catches future abbreviation regressions.
- `CHANGELOG.md` includes operator-facing entries under valid sections for all externally visible trust and gate changes.

## Public API and Contract Map

- CLI exit-code contracts:
  - Preserve `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `5` regression drift, `6` invalid input, `7` dependency missing, and `8` unsafe operation blocked.
  - Interrupted transaction recovery that cannot prove a coherent artifact set must fail closed with an existing error class rather than returning a false green result.
- Scan/proof/lifecycle contracts:
  - `scan_finding`, `risk_assessment`, `approval`, and `lifecycle_transition` proof record types remain stable.
  - Existing proof chain and attestation formats must remain verifiable by current Wrkr/proof verification paths unless a versioned migration is explicitly added.
  - Deterministic identity format `wrkr:<tool_id>:<org>` and lifecycle states remain unchanged.
- State/manifest contracts:
  - Saved state and manifest identity projections must remain mutually consistent after scan, identity, and inventory mutations.
  - Any new transaction or recovery metadata must be internal, portable, non-secret, and safe to ignore by older consumers unless a public contract version is introduced.
- Developer and CI command contracts:
  - `make lint-fast`, `make test-fast`, release workflow `go test`, UAT local `go test`, and acceptance lane `go test` commands must operate on first-party packages only.
  - If a shared package-list helper is introduced, all first-party package gates must consume it instead of reintroducing `./...`.
- Workflow governance contracts:
  - Action refs are immutable SHA pins by default.
  - Moving tags are allowed only through an explicit exception registry with owner, expiry, review command, reason, and minimum workflow scope.
- OSS trust contracts:
  - `LICENSE` must be scanner-friendly full Apache-2.0 text.
  - README/support docs may summarize the license, but the canonical file must remain complete.

## Docs and OSS Readiness Baseline

- User-facing and governance docs impacted:
  - `README.md` if the license summary or release readiness language needs sync.
  - `CONTRIBUTING.md` if local validation command guidance changes from root `./...` assumptions to first-party package helpers.
  - `product/dev_guides.md` for action-ref exception ownership, expiry, and review evidence requirements.
  - `CHANGELOG.md` for operator-facing trust and validation changes.
- Code and workflow docs impacted:
  - `.github/workflows/release.yml`
  - `.github/workflows/docs.yml`
  - `.github/workflows/pr.yml` when Go package command scope changes.
  - `scripts/run_v1_acceptance.sh` and `scripts/test_uat_local.sh` when Go package command scope changes.
- OSS trust baseline:
  - Full license text must be present.
  - No generated docs-site dependency tree, transient scan report, generated binary, or local proof output may be committed.
  - Workflow exception metadata must not become a permanent bypass. Expired exceptions fail the fast lane.
- Documentation must answer:
  - Which managed artifacts participate in a scan/lifecycle transaction?
  - What happens when a transaction is interrupted?
  - Which Go package roots are first-party and why are ignored dependency trees excluded?
  - Which action refs remain exceptions, who owns them, when do they expire, and what command reviews them?

## Recommendation Traceability

| Recommendation / Finding | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| Crash can leave scan/lifecycle/proof artifacts inconsistent | P1 high | Stories 1.1 and 1.2 | Proof/lifecycle promotion depends on coherent multi-file state, not just per-file atomicity. | Add a staged transaction/recovery contract and cross-artifact verification. | Release-promotable proof/lifecycle outputs with deterministic recovery or fail-closed behavior. |
| `PKGS := ./...` leaks into ignored docs-site dependencies | P2 high | Story 2.1 | Generated Node dependency trees can contribute arbitrary Go packages to local/CI gates. | Replace root wildcard package discovery with first-party package roots and hygiene tests. | Local/CI parity, faster gates, fewer false failures, and reproducible release lanes. |
| Release/docs action refs carry expiry-less supply-chain exceptions | P2 medium | Story 2.2 | Moving action tags can change release/docs execution code without review. | Pin immutable SHAs or enforce explicit, expiring exceptions. | Stronger release integrity and auditable exception lifecycle. |
| OSS license file is abbreviated | P2 medium | Story 2.3 | Scanners and evaluators expect canonical full license text. | Replace abbreviated notice with full Apache-2.0 text and add a regression check. | Lower legal/scanner trust friction for OSS evaluators. |

## Test Matrix Wiring

- Fast lane:
  - Focused unit and CLI tests for managed artifact transaction behavior, state mutation parity, first-party package list resolution, workflow action-ref exception enforcement, and license full-text hygiene.
  - Candidate commands: `go test ./core/cli -run 'Test.*ManagedArtifact|Test.*Transaction|Test.*Recovery|Test.*Lifecycle' -count=1`, `go test ./internal/ci/... ./testinfra/hygiene -run 'Test.*Package|Test.*Action|Test.*License' -count=1`, `make lint-fast`, and `make test-fast`.
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `scripts/run_v1_acceptance.sh --mode=local`
  - Scenario anchors for scan, evidence, verify, and regress must remain green after transaction recovery tests are added.
- Cross-platform lane:
  - Windows smoke must cover first-party package helpers, path normalization for managed artifact transaction metadata, and non-POSIX recovery paths.
  - Chmod-based failure fixtures may remain skipped on Windows, but transaction/recovery logic must have portable interruption fixtures.
- Risk lane:
  - `make test-hardening` for fail-closed transaction recovery, unsafe output path handling, proof/lifecycle verification mismatches, action-ref policy, and license hygiene.
  - `make test-chaos` for interruption windows across scan and lifecycle mutations.
  - `make test-perf` if transaction staging or package-list helpers materially change scan, verify, or release gate runtime.
- Release/UAT lane:
  - Release workflow equivalent lane must run first-party Go package tests, docs-site gates, SBOM generation, vulnerability scan, signing, and provenance verification.
  - `scripts/test_uat_local.sh` must use the same first-party Go package set as the release workflow.
- Gating rule:
  - Wave 1 is required before proof/lifecycle outputs are treated as release-promotable.
  - Final implementation requires `make prepush-full`, `make test-hardening`, `make test-chaos`, `make test-contracts`, scenario validation, and explicit release-owner signoff in the implementation PR.

## Minimum-Now Sequence

- Wave 1 - Proof and lifecycle crash consistency:
  - Story 1.1 introduces the managed artifact transaction/recovery contract for scan commits.
  - Story 1.2 routes identity and inventory lifecycle mutations through the same contract and adds read-path verification/recovery gates.
- Wave 2 - Release validation and OSS trust:
  - Story 2.1 replaces root `./...` Go package discovery with first-party package roots across local, CI, acceptance, release, and UAT lanes.
  - Story 2.2 pins release/docs action refs or formalizes expiring exceptions with enforcement.
  - Story 2.3 replaces the abbreviated license with the full Apache-2.0 text and adds license hygiene coverage.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or other rolling roadmap files.
- No Axym or Gait product behavior in Wrkr.
- No scan-time LLM calls, telemetry upload, or default live provider lookup.
- No extraction, hashing, or persistence of secret values.
- No public proof record type rename or incompatible lifecycle state migration.
- No weakening of existing symlink, ownership-marker, unsafe path, or fail-closed behavior.
- No CI bypass, branch-protection bypass, or permanent release/docs action-ref exception without owner and expiry.
- No vendoring or committing of `docs-site/node_modules`, generated reports, generated binaries, or transient proof artifacts.

## Definition of Done

- Every story starts with failing tests or contract fixtures that encode the intended behavior.
- Managed artifact transaction logic is shared by scan and state mutation paths rather than duplicated ad hoc in command handlers.
- Recovery is deterministic, bounded, and leaves a machine-readable audit trail without exposing local absolute paths or secret material.
- Cross-artifact consistency checks prove state, manifest, lifecycle, proof chain, attestation, and signing metadata agree after normal commits and injected interruptions.
- First-party package selection is centralized, reused by all relevant gates, and tested against a synthetic `docs-site/node_modules` Go package.
- Action-ref exceptions are either removed by SHA pinning or fail fast when missing owner, expiry, scope, review command, or when expired.
- The full Apache-2.0 license text is present and covered by a hygiene check.
- Docs and changelog entries are updated only where behavior, release posture, or OSS trust surfaces changed.
- Final validation records exact commands and results for `make lint-fast`, `make test-fast`, `make test-contracts`, `make test-hardening`, `make test-chaos`, `scripts/validate_scenarios.sh`, and `scripts/run_v1_acceptance.sh --mode=local`.

## Stories

### Story 1.1: Managed Artifact Transaction Envelope For Scan

Priority: P0

Tasks:

- Add a managed artifact transaction primitive near `core/cli/managed_artifacts.go` that owns the commit contract for state, manifest, lifecycle chain, proof chain, proof attestation, signing key, and managed sidecar outputs produced by scan.
- Pick one durable strategy and document it in code comments and tests: staged managed-root swap or write-ahead transaction journal with before/after digests. The selected strategy must survive process interruption after any individual file rename.
- Route the scan commit block in `core/cli/scan.go` through the transaction primitive instead of directly sequencing `state.Save`, `lifecycle.SaveChain`, `proofemit.EmitScanWithContext`, `manifest.Save`, source cleanup, and final `state.Save`.
- Add a cross-artifact consistency verifier that checks state/manifest identity parity, lifecycle transition expectations, proof chain load/verification, attestation presence, and signing-key availability without changing public proof record JSON.
- Add recovery detection before scan writes begin. If a prior transaction can be deterministically completed or rolled back, recover before the new scan; if recovery is ambiguous, fail closed with an existing error envelope.
- Preserve existing rollback behavior for returned write errors while adding explicit coverage for interruption windows after successful writes.
- Keep transaction metadata portable. Do not write developer-specific absolute paths; use repo-relative or managed-root-relative paths and stable artifact labels.
- Update `CHANGELOG.md` with a release-readiness fix entry once implementation lands.

Repo paths:

- `core/cli/scan.go`
- `core/cli/managed_artifacts.go`
- `core/cli/scan_transaction_test.go`
- `core/cli/scan_lifecycle_manifest_test.go`
- `core/state/state.go`
- `core/manifest/manifest.go`
- `core/lifecycle/chain.go`
- `core/proofemit/proofemit.go`
- `core/proofemit/chain_attestation.go`
- `core/verify`
- `internal/atomicwrite`
- `scripts/test_hardening_all.sh`
- `scripts/test_chaos_all.sh`
- `CHANGELOG.md`

Run commands:

- `go test ./core/cli -run 'TestScan.*Transaction|TestScan.*Recovery|TestManagedArtifact.*' -count=1`
- `go test ./core/state ./core/manifest ./core/lifecycle ./core/proofemit ./core/verify -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add failing tests that inject interruption after each managed artifact write in the scan commit sequence.
- Add a fixture where state is advanced but manifest/proof are not, and assert recovery rolls back or fails closed deterministically.
- Add a fixture where proof chain is advanced but final state/manifest are not, and assert verification detects the mismatch.
- Add tests proving no transaction metadata contains developer-specific absolute checkout paths.
- Add repeat-run tests proving recovered outputs are byte-stable except explicit timestamp/version fields.

Matrix wiring:

- Fast lane: focused `core/cli`, state, manifest, lifecycle, proofemit, and verify tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: scenario anchors for scan/evidence/verify/regress must remain green.
- Cross-platform lane: portable recovery fixtures must pass on Windows; chmod-only returned-error fixtures can remain POSIX-specific.
- Risk lane: `make test-hardening` and `make test-chaos` are required.
- Release/UAT lane: release candidate cannot promote proof/lifecycle outputs until this story is green.

Acceptance criteria:

- Killing or simulating interruption after any scan managed artifact write leaves the next Wrkr command with either a coherent recovered artifact set or a fail-closed error.
- `wrkr verify --chain --json` reports an intact/authentic chain after successful recovery.
- `wrkr regress run --baseline <baseline-path> --json` does not false-green against a mismatched state/proof/manifest set.
- Existing returned-error rollback tests still pass.
- The implementation PR names a release owner for this story before proof/lifecycle promotion.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: [semver:patch] Fixed scan managed artifact commits so interrupted proof, lifecycle, state, and manifest writes recover deterministically or fail closed.
Semver marker override: [semver:patch]
Contract/API impact: Preserves CLI, proof, lifecycle, and JSON contracts while tightening failure semantics for managed artifact commits.
Versioning/migration impact: No public schema migration expected; internal transaction metadata must be backward-safe or ignored after successful cleanup.
Architecture constraints: Preserve Source, Identity, Proof emission, and Compliance mapping/evidence output boundaries. Do not let proof emission own report serialization or source cleanup.
ADR required: yes
TDD first failing test(s): `TestScanInterruptedAfterStateSaveRecoversManagedArtifacts`, `TestScanInterruptedAfterProofEmitFailsClosedOnManifestMismatch`, `TestManagedArtifactTransactionMetadataIsPortable`
Cost/perf impact: medium for scan commit I/O; low for normal verification once transaction metadata is absent.
Chaos/failure hypothesis: If the process is interrupted after any managed artifact write, Wrkr either recovers to a coherent previous/next set or emits a deterministic fail-closed error before consumers read partial governance state.

### Story 1.2: Lifecycle And Inventory Mutation Transaction Parity

Priority: P1

Tasks:

- Route `commitStateMutationContext` in `core/cli/state_mutation.go` through the managed artifact transaction primitive from Story 1.1.
- Cover identity and inventory commands that update state, manifest, lifecycle chain, proof chain, proof attestation, or signing key outputs, including approve, revoke, deprecate, renew, and inventory approval/exclusion paths.
- Add a read-path preflight for commands that consume managed artifacts after lifecycle mutations, including `identity show/list`, `score`, `report`, `verify`, and `regress`.
- Ensure ambiguous recovered states fail closed with existing error envelopes and do not silently drop lifecycle transitions or proof records.
- Add state/manifest/proof parity checks after lifecycle mutation success, with stable ordering for identities and transitions.
- Keep `approval`, `lifecycle_transition`, and existing inventory mutation proof event semantics unchanged.
- Update docs or command help only if the user-visible recovery/failure behavior changes.
- Update `CHANGELOG.md` with lifecycle/proof consistency behavior once implementation lands.

Repo paths:

- `core/cli/state_mutation.go`
- `core/cli/inventory_mutations.go`
- `core/cli/lifecycle.go`
- `core/cli/state_mutation_test.go`
- `core/cli/inventory_mutations_test.go`
- `core/lifecycle`
- `core/identity`
- `core/manifest`
- `core/proofemit`
- `core/regress`
- `core/report`
- `core/score`
- `docs/commands/identity.md`
- `docs/commands/report.md`
- `docs/commands/regress.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/cli -run 'Test.*Identity.*Transaction|Test.*Inventory.*Transaction|Test.*Lifecycle.*Recovery|TestScoreReflectsIdentityApprove' -count=1`
- `go test ./core/lifecycle ./core/identity ./core/manifest ./core/proofemit ./core/regress ./core/report ./core/score -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add failing tests for interruption after state save, lifecycle save, proof transition emit, manifest save, attestation update, and signing key write during identity/inventory mutations.
- Add read-path tests proving `score`, `report`, `verify`, and `regress` do not consume mismatched lifecycle/proof state.
- Add lifecycle parity tests proving manifest and state identities agree after recovered approval/revoke/deprecate flows.
- Add tests for expired or malformed transaction metadata to ensure fail-closed behavior.

Matrix wiring:

- Fast lane: focused CLI lifecycle, identity, inventory, score, report, regress, and proofemit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: `scripts/validate_scenarios.sh` and identity/lifecycle scenario anchors if fixtures are touched.
- Cross-platform lane: path normalization and transaction metadata cleanup must pass on Windows.
- Risk lane: `make test-hardening` and `make test-chaos` are required.
- Release/UAT lane: release handoff must include lifecycle mutation recovery evidence.

Acceptance criteria:

- Identity and inventory mutations use the same transaction code path as scan for shared managed artifacts.
- Interruption fixtures either recover a coherent artifact set or fail closed before any consumer sees inconsistent lifecycle/proof output.
- `score`, `report`, `verify`, and `regress` remain coherent after lifecycle mutation recovery.
- Existing proof record types and lifecycle states remain unchanged.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: [semver:patch] Fixed identity and inventory lifecycle mutations to share crash-consistent proof, lifecycle, state, and manifest commits.
Semver marker override: [semver:patch]
Contract/API impact: Preserves public lifecycle/proof APIs while strengthening recovery and verification behavior.
Versioning/migration impact: No public migration expected; stale internal transaction metadata must be cleaned or rejected deterministically.
Architecture constraints: Preserve Identity and Proof emission boundaries; lifecycle commands must not bypass the managed artifact transaction primitive.
ADR required: yes
TDD first failing test(s): `TestIdentityApproveInterruptedAfterProofEmitRecovers`, `TestInventoryApproveInterruptedAfterManifestSaveFailsClosed`, `TestReportRejectsMismatchedLifecycleTransaction`
Cost/perf impact: low to medium; lifecycle mutations are less frequent than scans but add bounded recovery preflights.
Chaos/failure hypothesis: If an identity or inventory command is interrupted mid-commit, subsequent Wrkr commands cannot observe a state/manifest decision without the matching lifecycle/proof evidence.

### Story 2.1: First-Party Go Package Scope For Local And CI Gates

Priority: P1

Tasks:

- Replace root `./...` package discovery in `Makefile` with an explicit first-party package set or helper that includes current Go roots such as `cmd`, `core`, `internal`, `testinfra`, and Go-based `scripts`.
- Update `make lint-fast`, `make test-fast`, and any release/UAT/acceptance scripts that invoke `go test ./...` or `go vet ./...` to consume the same first-party package helper.
- Update `.github/workflows/pr.yml` and `.github/workflows/release.yml` where they invoke root wildcard Go tests.
- Ensure the helper fails if an expected first-party package root disappears unexpectedly, but ignores generated, vendored, ignored, and docs-site dependency directories.
- Add a hygiene fixture that creates a synthetic `docs-site/node_modules/flatted/golang/pkg/flatted` Go package and proves Wrkr Go gates do not list or test it.
- Keep `GOFILES := $(shell git ls-files '*.go')` or an equivalent git-tracked-file formatter so generated dependency trees are not formatted.
- Update `CONTRIBUTING.md` or validation docs if command semantics are described there.
- Update `CHANGELOG.md` with the developer gate fix.

Repo paths:

- `Makefile`
- `.github/workflows/pr.yml`
- `.github/workflows/release.yml`
- `scripts/run_v1_acceptance.sh`
- `scripts/test_uat_local.sh`
- `scripts/check_repo_hygiene.sh`
- `testinfra/hygiene`
- `CONTRIBUTING.md`
- `CHANGELOG.md`

Run commands:

- `make docs-site-install`
- `go list <first-party-package-patterns>`
- `make lint-fast`
- `make test-fast`
- `go test ./testinfra/hygiene -run 'Test.*FirstParty.*Packages|Test.*NodeModules.*Go' -count=1`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:

- Add failing hygiene tests proving `docs-site/node_modules` Go packages are excluded from package list, vet, test, release, and UAT command construction.
- Add tests or script assertions proving every tracked first-party Go package is included.
- Add CI command contract coverage preventing future reintroduction of root `go test ./...` in workflows/scripts where it would walk generated dependency trees.
- Add docs consistency checks if contributor commands change.

Matrix wiring:

- Fast lane: `make lint-fast`, `make test-fast`, and focused hygiene tests.
- Core CI lane: PR workflow package commands must use first-party package scope.
- Acceptance lane: `scripts/run_v1_acceptance.sh --mode=local` must use first-party package scope.
- Cross-platform lane: package helper must avoid shell features that break Windows smoke or provide a portable script wrapper.
- Risk lane: not required beyond hygiene unless package scope affects risk-lane command coverage.
- Release/UAT lane: release workflow and `scripts/test_uat_local.sh` must use the shared package scope.

Acceptance criteria:

- After `make docs-site-install`, `go list` as used by Wrkr gates does not include `docs-site/node_modules`.
- `make lint-fast` and `make test-fast` pass with docs-site dependencies installed.
- Release and UAT Go package commands match local first-party package scope.
- A contract test fails if future scripts/workflows reintroduce unsafe root wildcard package discovery.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: [semver:patch] Fixed Go validation gates to test only first-party Wrkr packages even when docs-site dependencies are installed locally.
Semver marker override: [semver:patch]
Contract/API impact: No CLI output or schema impact; changes developer, CI, release, UAT, and acceptance command contracts.
Versioning/migration impact: No migration required.
Architecture constraints: Preserve Go as the primary runtime and keep Node scoped to docs/UI surfaces only.
ADR required: no
TDD first failing test(s): `TestFirstPartyGoPackagesExcludeDocsSiteNodeModules`, `TestWorkflowGoTestsUseFirstPartyPackageList`, `TestReleaseUATPackageScopeMatchesMakefile`
Cost/perf impact: low; expected to reduce local/CI work when generated dependency trees exist.
Chaos/failure hypothesis: If generated docs-site dependencies include arbitrary Go packages, Wrkr gates ignore them and continue to validate only first-party code.

### Story 2.2: Release And Docs Action Ref Pin Or Expiring Exception Registry

Priority: P2

Tasks:

- Replace `anchore/sbom-action@v0`, `anchore/scan-action@v4`, and `actions/configure-pages@v5` with immutable SHA refs where a suitable upstream release/ref is available and compatible with the current workflow runtime policy.
- If immutable SHA pinning is not practical for one of these actions, add a structured exception registry with action ref, workflow path, owner role, reason, allowed scope, expiry date, and review command.
- Extend `scripts/check_actions_runtime.go` or add a companion checker so moving action refs in tracked workflows fail unless a current exception exists.
- Add tests for missing owner, missing expiry, expired exception, workflow-scope mismatch, and allowed active exception.
- Update `product/dev_guides.md` to make owner/expiry/review evidence mandatory for accepted action-ref exceptions, not only runtime-uplift exceptions.
- Update `testinfra/hygiene/toolchain_pins_test.go` or related hygiene tests so release integrity pins and exceptions stay enforced.
- Update `CHANGELOG.md` under `Security` once implementation lands.

Repo paths:

- `.github/workflows/release.yml`
- `.github/workflows/docs.yml`
- `scripts/check_actions_runtime.go`
- `scripts/check_actions_runtime.sh`
- `internal/ci/actionruntime/check.go`
- `testinfra/hygiene/toolchain_pins_test.go`
- `product/dev_guides.md`
- `CHANGELOG.md`

Run commands:

- `scripts/check_actions_runtime.sh`
- `scripts/check_toolchain_pins.sh`
- `scripts/check_no_latest.sh`
- `go test ./internal/ci/... ./testinfra/hygiene -run 'Test.*Action.*Runtime|Test.*Action.*Exception|Test.*Toolchain.*Pin' -count=1`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add failing tests for the current moving refs when no exception metadata exists.
- Add a fixture proving an unexpired owner-scoped exception passes only for the exact workflow/action ref it names.
- Add a fixture proving expired exceptions fail the fast lane.
- Add tests proving SHA-pinned actions do not require exceptions.
- Add docs tests if the exception policy wording is validated.

Matrix wiring:

- Fast lane: action runtime/ref checker, toolchain pin checker, no-latest checker, and focused hygiene tests.
- Core CI lane: `make lint-fast` and `make test-fast`.
- Acceptance lane: not required unless release acceptance scripts consume the exception registry.
- Cross-platform lane: checker must be Go-based or portable through existing shell wrapper.
- Risk lane: `make test-hardening` if exception logic affects release-integrity gates.
- Release/UAT lane: release and docs workflows must have either SHA pins or current exceptions before release handoff.

Acceptance criteria:

- Release/docs workflows contain no unowned, expiry-less moving action refs.
- Expired or malformed action-ref exceptions fail the fast lane.
- Exception metadata names the owner role and review command without granting blanket approval to unrelated workflows.
- Docs state how to renew, remove, or replace an exception with an immutable pin.

Changelog impact: required
Changelog section: Security
Draft changelog entry: [semver:patch] Tightened release and docs workflow action-ref governance with immutable pins or expiring owner-scoped exceptions.
Semver marker override: [semver:patch]
Contract/API impact: No CLI output or schema impact; strengthens CI/release integrity contracts.
Versioning/migration impact: No user migration required.
Architecture constraints: Preserve immutable build and supply-chain integrity standards from `product/dev_guides.md`.
ADR required: no
TDD first failing test(s): `TestMovingActionRefRequiresOwnedExpiryException`, `TestExpiredActionRefExceptionFails`, `TestPinnedActionRefDoesNotRequireException`
Cost/perf impact: low.
Chaos/failure hypothesis: If an upstream moving action tag changes unexpectedly, Wrkr release/docs workflows are either pinned away from the change or blocked by an expired/missing exception before promotion.

### Story 2.3: Full Apache-2.0 License Text And OSS Hygiene

Priority: P2

Tasks:

- Replace `LICENSE` with the full Apache License 2.0 text.
- Add a lightweight hygiene test that verifies `LICENSE` contains canonical Apache-2.0 sections, including terms, conditions, disclaimer, and appendix text expected by scanners.
- Keep README license references concise and aligned with the canonical `LICENSE` file.
- Check that no generated license scanner artifacts or transient reports are committed.
- Update `CHANGELOG.md` with the OSS trust fix.

Repo paths:

- `LICENSE`
- `README.md`
- `testinfra/hygiene`
- `scripts/check_repo_hygiene.sh`
- `CHANGELOG.md`

Run commands:

- `go test ./testinfra/hygiene -run 'Test.*License|Test.*OSS' -count=1`
- `scripts/check_repo_hygiene.sh`
- `make lint-fast`
- `make test-fast`

Test requirements:

- Add a failing hygiene test for the abbreviated current `LICENSE`.
- Add positive assertions for full Apache-2.0 text markers.
- Add a README/docs alignment assertion only if README license wording changes.

Matrix wiring:

- Fast lane: hygiene license test, repo hygiene check, `make lint-fast`, and `make test-fast`.
- Core CI lane: `make test-contracts` if license hygiene is housed under contract tests; otherwise `make test-fast`.
- Acceptance lane: not required.
- Cross-platform lane: no platform-specific behavior.
- Risk lane: not required beyond repo hygiene.
- Release/UAT lane: release handoff should cite the full license file as OSS readiness evidence.

Acceptance criteria:

- `LICENSE` contains the full Apache License 2.0 text.
- OSS/license hygiene tests fail if the license is reduced to a short notice again.
- README and docs do not contradict the canonical license file.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: [semver:patch] Restored full Apache-2.0 license text for OSS scanner and evaluator compatibility.
Semver marker override: [semver:patch]
Contract/API impact: No CLI output, schema, proof, or runtime impact; improves OSS governance artifact completeness.
Versioning/migration impact: No migration required.
Architecture constraints: Preserve repo hygiene and OSS trust standards without changing runtime logic.
ADR required: no
TDD first failing test(s): `TestLicenseContainsFullApache20Text`, `TestOSSTrustBaselineIncludesCanonicalLicense`
Cost/perf impact: low.
Chaos/failure hypothesis: If the license text is accidentally shortened in a future change, hygiene tests block the regression before release.

# Adhoc Plan: Audit Readiness Fixes

Date: 2026-05-07
Profile: `wrkr`
Slug: `audit-readiness-fixes`
Recommendation source: user-provided combined code-review and app-audit findings covering stale install guidance, scan-status partial-result drift, hosted progress counter drift, and slow local validation ergonomics.

All paths in this plan are repo-relative. This is a planning artifact only; it does not implement runtime or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product. These fixes must preserve scan/risk/proof determinism, zero default scan-data exfiltration, and the existing exit-code contract.
- Runtime correctness work takes priority over docs polish when a status, proof, or promotion signal could allow incomplete posture to be treated as complete.
- Public install guidance is a user-facing contract. Pinned examples must install a release that supports the commands shown in the same docs.
- Scan status is an operator and automation contract. Additive progress/status fields may evolve, but they must not contradict final scan JSON.
- Progress counters are operator UX only. Counter fixes must not change detector output, risk scores, proof records, evidence bundles, or regress baselines.
- Fast-lane ergonomics should improve without weakening required coverage. Any split between focused and full test commands must keep required CI/release lanes explicit.
- Changelog entries are required for public install guidance, scan status semantics, progress UX behavior, and validation command changes.
- Documentation updates must stay synchronized across `README.md`, `docs/`, docs-site projections when relevant, and release/UAT validation references.

## Current Baseline (Observed)

- `README.md` and `docs/install/minimal-dependencies.md` pin Go install examples to `v1.0.0`, while current docs advertise post-`v1.0.0` behavior such as `--progress`, `--json-path`, repeatable `--target`, `--profile assessment`, and current report/evidence handoff paths.
- Local tags include `v1.3.0`, and inspection of `v1.0.0` shows the older `wrkr scan` contract does not include the current progress/json-path/multi-target contract.
- `core/cli/scan.go` sets final scan JSON `partial_result=true` when `manifestOut.Failures` is non-empty.
- `core/cli/scan_status.go` currently clears `PartialResult` and `PartialResultMarker` unconditionally in `scanStatusTracker.Complete`.
- `core/source/org/materialized.go` increments the materialization completion count for failed repos, while `core/cli/scan_progress.go` also tracks `Failed`, creating a risk of double-subtracting failed repos from pending counts during hosted acquisition.
- Recent validation evidence from the audit run:
  - `make lint-fast`: passed.
  - `make test-fast`: passed.
  - Scenario scan anchor wrote `status=ok`, 21 findings, grade `C`, and no detector errors.
  - Evidence, proof verify, and regress anchors passed from the saved scenario state.
  - `make test-fast` currently includes expensive package groups such as `core/cli`, `internal/acceptance`, and `testinfra/contracts`, making the "fast" local lane slower than expected for narrow changes.

## Exit Criteria

- The pinned install examples in public docs install a release that supports every command and flag shown in the same first-value path, or the docs explicitly route users to a current validated release selector.
- Release-smoke/UAT snippets no longer hardcode a stale release version that is incompatible with current public examples.
- A scan with source failures records `partial_result=true` in both final scan JSON and `wrkr scan status --json` after completion.
- Status sidecar compatibility remains additive: old status sidecars continue to load, and existing fields remain optional-compatible.
- Hosted progress repo counters use one canonical model for total, completed, failed, succeeded, and pending so in-flight progress does not overstate completion.
- Focused tests prove install-doc contract, partial scan status semantics, and progress counter math before implementation completes.
- Validation lanes remain explicit: focused fast commands for narrow development, full `make test-fast`/contract/scenario lanes for core and release gates, and risk lanes for state/progress safety.

## Public API and Contract Map

- Install/docs contract:
  - `README.md` pinned Go install snippet.
  - `docs/install/minimal-dependencies.md` pinned install and release-smoke examples.
  - `docs/commands/action.md` packaged action examples when release refs are updated or intentionally left as historical examples.
- Scan JSON contract:
  - `wrkr scan --json` final payload retains existing keys and sets `partial_result`, `source_errors`, and `source_degraded` when source acquisition is incomplete.
  - `--json-path` remains byte-identical to stdout when both are requested.
- Scan status contract:
  - `wrkr scan status --json` preserves additive fields and must not report completed partial scans as non-partial.
  - `state.ScanStatus` remains backward-compatible with legacy sidecars.
- Progress contract:
  - Progress output remains stderr-only and suppressed by `--quiet`.
  - `repo_progress.pending` and event footer counters remain operator UX fields and must not feed risk/proof/compliance logic.
- Exit codes and error envelopes:
  - Existing exit codes remain unchanged.
  - Status/progress render fixes must not mask runtime, policy/schema, invalid input, dependency, unsafe-operation, or verification failures.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/install/minimal-dependencies.md`
  - `docs/commands/action.md` if packaged action refs are updated or annotated
  - `docs/commands/scan.md`
  - `docs/examples/security-team.md`
  - `docs/examples/operator-playbooks.md`
  - `CHANGELOG.md`
- OSS trust baseline currently present and should remain aligned:
  - `CONTRIBUTING.md`
  - `SECURITY.md`
  - `CODE_OF_CONDUCT.md`
  - `.github/ISSUE_TEMPLATE/`
  - `.github/pull_request_template.md`
  - `.github/required-checks.json`
- Docs must answer:
  - Which release tag is safe for copy-paste install today?
  - How do operators interpret `partial_result` after a completed scan?
  - How do progress counters treat failed source repositories?
  - Which validation command should a contributor run for narrow docs-only or scan-status changes?

## Recommendation Traceability

| Recommendation / Finding | Priority | Planned Coverage |
|---|---:|---|
| P1 stale pinned install path installs a CLI that does not support current docs | P0 | Story 1.1 |
| P2 completed partial scans can be reported as non-partial in scan status | P0 | Story 2.1 |
| P3 hosted progress pending count can undercount after repo failures | P1 | Story 3.1 |
| App audit notes slow local validation ergonomics for fast lane | P2 | Story 3.2 |

## Test Matrix Wiring

- Fast lane:
  - Focused docs/install contract checks and targeted CLI unit tests.
  - Candidate commands: `go test ./core/cli -run 'TestScan.*Partial|TestScanStatus|TestScan.*Progress' -count=1`, `go test ./core/source/org -run 'Test.*Progress|Test.*Failure' -count=1`, and docs checks scoped by touched surfaces.
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - Scenario or e2e fixture proving a completed partial source acquisition remains partial in status.
- Cross-platform lane:
  - Windows smoke remains required for CLI status/progress output and path rendering.
  - Install docs must avoid shell-specific assumptions except where explicitly marked as shell examples.
- Risk lane:
  - `make test-hardening` for state/status rollback and unsafe path interactions when touched.
  - `make test-chaos` for interrupted, timeout, and partial-result status behavior.
  - `make test-perf` only if progress/status writes or test-lane restructuring materially changes scan runtime.
- Release/UAT lane:
  - `scripts/test_uat_local.sh --skip-global-gates`
  - `scripts/test_uat_local.sh --release-version <current-supported-release> --skip-global-gates`
  - `scripts/test_uat_local.sh --release-version <current-supported-release> --brew-formula Clyra-AI/tap/wrkr --skip-global-gates`
- Gating rule:
  - Story completion requires focused tests plus the lane marked for that story. Release promotion requires docs install examples, scan JSON/status semantics, proof verification, and regress anchors to agree.

## Minimum-Now Sequence

- Wave 1 - Launch/onboarding contract:
  - Story 1.1 fixes stale pinned install and release-smoke references before runtime work so new users do not install an incompatible CLI.
- Wave 2 - Scan status correctness:
  - Story 2.1 fixes completed partial-result status semantics and locks the JSON/status contract with tests.
- Wave 3 - Progress and DX polish:
  - Story 3.1 fixes hosted progress pending-count math.
  - Story 3.2 documents and wires a focused local validation path without weakening required CI/release lanes.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No change to proof record types, proof-chain verification semantics, risk scoring, evidence bundle schemas, compliance mappings, or regress drift rules except where tests assert they remain unchanged.
- No removal of existing scan status fields or required migration for existing status sidecars.
- No live network probe, LLM call, telemetry upload, runtime enforcement feature, or Gait/Axym product behavior.
- No branch-protection or CI bypass. Plan-only publishing is separate from implementation validation.

## Definition of Done

- Each story starts with failing tests or docs checks that reproduce the audited issue.
- Public install docs and current CLI examples agree on a supported release path.
- Completed partial scans are visible as partial in both final scan JSON and `wrkr scan status --json`.
- Hosted progress counters remain internally consistent when some repos fail.
- Changelog entries are operator-facing and placed under the correct `CHANGELOG.md` section.
- Focused validation commands are documented without weakening `make lint-fast`, `make test-fast`, contract, scenario, risk, and release/UAT gates.
- The implementation handoff can run `plan-implement` against this plan without additional discovery.

## Stories

### Story 1.1: Current Supported Install Contract

Priority: P0

Tasks:

- Update pinned install examples so `README.md` and `docs/install/minimal-dependencies.md` install a release that supports the current first-value commands.
- Update release-smoke examples in `docs/install/minimal-dependencies.md` to use the same current supported release tag or a documented placeholder if release-specific examples are intentionally generic.
- Decide whether `docs/commands/action.md` packaged action examples should advance from `v1.0.0` or explicitly state that the version is illustrative and should be replaced with the current supported release.
- Add or update a docs consistency check that detects stale pinned install tags when current docs rely on newer public CLI flags.
- Update `CHANGELOG.md` under `Fixed`.

Repo paths:

- `README.md`
- `docs/install/minimal-dependencies.md`
- `docs/commands/action.md`
- `docs/contracts/readme_contract.md`
- `testinfra/hygiene/`
- `scripts/test_uat_local.sh`
- `CHANGELOG.md`

Run commands:

- `make lint-fast`
- `make test-docs-consistency`
- `scripts/test_uat_local.sh --release-version <current-supported-release> --skip-global-gates`
- `scripts/test_uat_local.sh --release-version <current-supported-release> --brew-formula Clyra-AI/tap/wrkr --skip-global-gates`

Test requirements:

- Add a failing docs/hygiene test that reads the pinned install snippets and rejects a release tag older than the minimum release needed by current README examples.
- Add or update release UAT fixtures so stale release-version examples fail deterministically.
- Verify `wrkr version --json` remains the post-install check shown in docs.

Matrix wiring:

- Fast lane: `make lint-fast` plus focused docs/hygiene test.
- Core CI lane: `make test-fast` when the hygiene package changes.
- Acceptance lane: not required unless quickstart smoke fixtures are touched.
- Cross-platform lane: Windows smoke not required for docs-only changes; keep command snippets shell-scoped.
- Risk lane: not required.
- Release/UAT lane: required because install/release examples changed.

Acceptance criteria:

- `README.md` no longer points new users at a stale incompatible release.
- `docs/install/minimal-dependencies.md` install and release-smoke snippets agree on the current supported release contract.
- Docs validation catches a future stale pinned install tag before merge.
- Changelog explains the fix as public onboarding/install-contract repair.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: [semver:patch] Fixed pinned install and release-smoke examples so documented first-value commands install a compatible Wrkr release.
Semver marker override: [semver:patch]
Contract/API impact: Public install guidance changes; CLI runtime contract is unchanged.
Versioning/migration impact: No migration; users following pinned docs move to the current supported release.
Architecture constraints: Preserve docs as executable contract and release/UAT validation from `product/dev_guides.md`.
ADR required: no
TDD first failing test(s): `TestInstallDocsPinnedVersionSupportsCurrentReadmeCommands`, `TestMinimalDependenciesReleaseSmokeVersionIsCurrent`
Cost/perf impact: low
Chaos/failure hypothesis: Not required; docs/release smoke coverage is sufficient.

### Story 2.1: Preserve Completed Partial Result In Scan Status

Priority: P0

Tasks:

- Add a focused failing CLI test for a scan that completes with `manifestOut.Failures` and then inspects `wrkr scan status --json`.
- Preserve `PartialResult` and `PartialResultMarker` through `scanStatusTracker.Complete` when source or detector failures were observed.
- Thread the partial-result signal into `Complete` without changing final scan JSON, proof emission, risk scoring, or evidence output.
- Ensure legacy status sidecars still load and normalize without requiring new fields.
- Update scan docs and security-team/operator examples to state that completed partial scans remain partial in status until rerun cleanly.
- Update `CHANGELOG.md` under `Fixed`.

Repo paths:

- `core/cli/scan.go`
- `core/cli/scan_status.go`
- `core/state/scan_status.go`
- `core/cli/scan_partial_errors_test.go`
- `core/cli/scan_progress_contract_test.go`
- `core/state/scan_status_test.go`
- `docs/commands/scan.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/cli -run 'TestScan.*Partial|TestScanStatus' -count=1`
- `go test ./core/state -run TestScanStatus -count=1`
- `make lint-fast`
- `make test-contracts`
- `make test-scenarios`
- `make test-chaos`

Test requirements:

- Add a test where final scan JSON includes `partial_result=true` and status JSON also includes `partial_result=true`.
- Add a compatibility test loading a legacy sidecar without progress/partial additions.
- Add a failure-path test proving interrupted scans still report interrupted partial state.
- Add a docs parity check if scan docs examples change flag/help wording.

Matrix wiring:

- Fast lane: focused `core/cli` and `core/state` tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: `make test-scenarios` because operator-visible scan status semantics change.
- Cross-platform lane: Windows smoke required because status JSON/path rendering is CLI surface.
- Risk lane: `make test-chaos` required for interruption/partial-result failure semantics.
- Release/UAT lane: not required unless release docs or install smoke scripts change in the same story.

Acceptance criteria:

- Completed scans with source failures preserve partial status in `wrkr scan status --json`.
- Completed clean scans still report non-partial status.
- Final scan JSON remains unchanged except existing partial-result behavior.
- Existing status sidecars remain readable.
- Progress footer/status wording does not pollute stdout or JSON payloads.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: [semver:patch] Fixed scan status so completed scans with source failures remain marked as partial instead of appearing complete to automation.
Semver marker override: [semver:patch]
Contract/API impact: Additive/corrective status JSON semantics; final scan JSON keys and exit codes remain unchanged.
Versioning/migration impact: No migration; old sidecars remain optional-compatible.
Architecture constraints: Preserve Source, Detection, Risk, Proof emission, and Compliance mapping boundaries; status reflects scan state but does not influence risk/proof/compliance.
ADR required: no
TDD first failing test(s): `TestScanStatusCompletedPartialResultMatchesScanJSON`, `TestScanStatusLoadsLegacySidecarWithoutPartialProgress`
Cost/perf impact: low
Chaos/failure hypothesis: A scan interrupted or partially failed after source acquisition must persist an explicit partial/interrupted status and never promote incomplete posture as complete.

### Story 3.1: Canonical Hosted Progress Counter Model

Priority: P1

Tasks:

- Define one counter model for hosted source acquisition: total, succeeded, failed, completed, and pending.
- Update progress event payloads and status sink handling so failed repos are counted once and pending never underflows or double-subtracts failures.
- Add unit tests covering success-only, failure-only, mixed success/failure, resume, and cancellation paths.
- Confirm final footer and event renderer fields remain backward-compatible for existing `progress target=... event=...` parsers.
- Update scan progress docs if any field interpretation changes.
- Update `CHANGELOG.md` under `Fixed`.

Repo paths:

- `core/source/org/materialized.go`
- `core/source/org/acquire_test.go`
- `core/source/org/acquire_resume_test.go`
- `core/cli/scan_progress.go`
- `core/cli/scan_progress_render.go`
- `core/cli/scan_progress_test.go`
- `core/cli/scan_progress_contract_test.go`
- `docs/commands/scan.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/source/org -run 'Test.*Progress|Test.*Resume|Test.*Failure' -count=1`
- `go test ./core/cli -run 'TestScan.*Progress|TestScanProgress.*Footer' -count=1`
- `make lint-fast`
- `make test-contracts`
- `make test-perf`

Test requirements:

- Add table-driven counter tests proving pending equals `total - succeeded - failed` or the final chosen canonical equivalent.
- Add renderer/event tests proving footer and event output do not regress existing machine-readable fields.
- Add non-underflow tests for repeated failure events and cancellation after partial acquisition.

Matrix wiring:

- Fast lane: focused progress/counter unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: not required unless scenario fixtures are touched.
- Cross-platform lane: Windows smoke required for stderr progress rendering behavior.
- Risk lane: `make test-perf` required because progress writes occur in large org scans; `make test-chaos` if cancellation handling changes.
- Release/UAT lane: not required.

Acceptance criteria:

- In-flight progress no longer overstates completion when one or more repo materializations fail.
- Pending counters are deterministic, non-negative, and consistent between status and event renderers.
- Existing event-style progress remains parseable by automation.
- No change to findings, inventory, risk, proof, evidence, or regress outputs.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: [semver:patch] Fixed hosted scan progress counters so failed repo materialization is counted once and pending progress remains accurate.
Semver marker override: [semver:patch]
Contract/API impact: Corrective progress/status semantics only; no scan JSON/proof contract change.
Versioning/migration impact: No migration; progress output remains additive and stderr-only.
Architecture constraints: Source layer emits source events; CLI progress layer renders counters; no risk/proof/compliance dependency on progress.
ADR required: no
TDD first failing test(s): `TestHostedProgressPendingAfterFailedMaterialization`, `TestScanProgressFooterCountsFailedReposOnce`
Cost/perf impact: low
Chaos/failure hypothesis: A hosted scan with mixed source failures must keep progress counters non-negative and must still exit with the existing partial-result semantics.

### Story 3.2: Focused Local Validation Lane For Narrow Changes

Priority: P2

Tasks:

- Document a focused local validation path for narrow docs/install/status/progress work without weakening required PR, main, nightly, or release gates.
- If needed, add Makefile targets or docs-only command aliases that run existing focused checks while leaving `make test-fast` as the full package-level fast gate.
- Update contributor docs to explain when focused commands are acceptable locally and when full `make test-fast`, contracts, scenarios, risk, or release/UAT lanes are required.
- Ensure branch protection and required-check contracts remain unchanged.
- Update `CHANGELOG.md` under `Changed` if user-facing contributor workflow docs change.

Repo paths:

- `Makefile`
- `CONTRIBUTING.md`
- `product/dev_guides.md`
- `docs/map.md`
- `.github/required-checks.json`
- `scripts/check_branch_protection_contract.sh`
- `testinfra/hygiene/`
- `CHANGELOG.md`

Run commands:

- `make lint-fast`
- `make test-fast`
- `make test-contracts`
- `scripts/check_branch_protection_contract.sh`
- `make test-docs-consistency`

Test requirements:

- Add or update hygiene tests proving required checks still include `fast-lane`, `scan-contract`, `wave-sequence`, and `windows-smoke`.
- Add docs consistency coverage for any new local validation command names.
- Do not remove full package coverage from existing required CI lanes.

Matrix wiring:

- Fast lane: required because contributor validation docs and Makefile targets are touched.
- Core CI lane: required because branch-protection and validation contracts are touched.
- Acceptance lane: not required unless scenario docs are changed.
- Cross-platform lane: required if Makefile commands or shell scripts change.
- Risk lane: not required unless validation changes affect release or security scanners.
- Release/UAT lane: not required.

Acceptance criteria:

- Contributors have a documented focused command path for narrow changes.
- Required CI and release gates remain at least as strong as before.
- `make test-fast` still exists and remains wired as a full package-level gate.
- No branch protection or required-check contract is weakened.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Clarified focused local validation guidance for narrow documentation and scan-status/progress changes while preserving required CI and release gates.
Semver marker override: none
Contract/API impact: Contributor/DX documentation only; no CLI JSON, exit-code, schema, or runtime contract change.
Versioning/migration impact: No user migration; contributors may use focused commands before full gates.
Architecture constraints: Preserve CI/release integrity and docs-as-contract enforcement from `product/dev_guides.md`.
ADR required: no
TDD first failing test(s): `TestRequiredChecksRemainEnforced`, `TestDocsMapListsFocusedValidationCommands`
Cost/perf impact: low
Chaos/failure hypothesis: Not required; branch-protection contract tests cover false-green risk.

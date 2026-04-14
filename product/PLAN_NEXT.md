# PLAN Adhoc: scan path contract hardening, managed artifact safety, and repo-local toolchain alignment

Date: 2026-04-13
Source of truth:
- user-provided full-repo code review findings in this run
- `product/dev_guides.md`
- `product/architecture_guides.md`
Scope: Planning only for the release-blocking `scan --path` contract mismatch, scan sidecar artifact collision safety, and the AGENTS/go toolchain drift. No implementation work is performed in this plan.

## Global Decisions (Locked)

- Treat the two scan findings as Wave 1 release blockers. They change real command behavior today and must land before any new outward-facing scan/report/evidence work.
- Preserve Wrkr's core contracts:
  - deterministic behavior
  - offline-first defaults for local path scans
  - fail-closed behavior for unsafe or ambiguous artifact/output configurations
  - stable exit code integers and machine-readable envelopes
- Keep existing numeric exit codes unchanged. For scan artifact aliasing, use the existing `invalid_input` envelope and exit code `6` rather than inventing a new exit code.
- Preserve the public repo-local fallback `wrkr scan --path ./your-repo --json`.
- Preserve current local repo-set workflows and shipped scenario bundle usage under `scenarios/wrkr/*/repos`.
- Define one explicit `--path` contract that supports both:
  - `repo_root`: the selected directory itself is scanned as one repo when it contains qualifying root-level repo signals
  - `repo_set`: the selected directory is scanned as a set of immediate child repos only when it lacks qualifying root-level repo signals and contains one or more non-hidden child directories
- Centralize the `repo_root` vs `repo_set` classifier in the Source layer and back it with deterministic fixtures. Do not spread heuristic decisions into detector code.
- Preflight all managed and optional scan artifact paths as one canonical set before the first write:
  - state snapshot
  - manifest
  - lifecycle chain
  - proof chain
  - proof attestation
  - signing key
  - optional `--json-path`
  - optional `--report-md-path`
  - optional `--sarif-path`
- Any collision among those paths, or between optional outputs themselves, must fail before mutation.
- Do not change schema versions in this plan. Any behavior change must fit the current `v1` scan/state/inventory/proof contracts.
- Replace the stale literal Go floor in `AGENTS.md` with a single-source-of-truth model: the repo-local guide should delegate to `go.mod` and `product/dev_guides.md`, and enforcement must catch future drift.

## Current Baseline (Observed)

- [core/source/local/local.go](/Users/tr/wrkr/core/source/local/local.go:13) treats `--path` as a directory of repos and enumerates immediate child directories only.
- [core/source/local/local_test.go](/Users/tr/wrkr/core/source/local/local_test.go:9) validates only the repo-set behavior; there is no single-repo-root coverage.
- Public docs repeatedly advertise single-repo-root usage:
  - [README.md](/Users/tr/wrkr/README.md:91)
  - [docs/commands/scan.md](/Users/tr/wrkr/docs/commands/scan.md:35)
  - [docs/examples/quickstart.md](/Users/tr/wrkr/docs/examples/quickstart.md:65)
  - [docs/faq.md](/Users/tr/wrkr/docs/faq.md:45)
  - [docs/examples/security-team.md](/Users/tr/wrkr/docs/examples/security-team.md:14)
- The existing shipped scenario path `./scenarios/wrkr/scan-mixed-org/repos` relies on the current repo-set interpretation, so the fix must preserve that supported workflow.
- [core/cli/scan.go](/Users/tr/wrkr/core/cli/scan.go:94) resolves optional sidecar outputs, but [core/cli/scan.go](/Users/tr/wrkr/core/cli/scan.go:349) does not reject alias collisions with managed artifacts before writes begin.
- [core/cli/jsonmode.go](/Users/tr/wrkr/core/cli/jsonmode.go:37) and [core/cli/report.go](/Users/tr/wrkr/core/cli/report.go:262) validate file-path shape, not artifact identity uniqueness.
- Reproduced failure path:
  - `wrkr scan --path "$tmp/root" --state "$tmp/state.json" --json-path "$tmp/state.json" --json` exits `0`
  - the saved `state.json` is overwritten with final scan payload keys like `status` and `top_findings`
  - `wrkr evidence --frameworks soc2 --state "$tmp/state.json" --output "$tmp/evidence" --json` then fails because `risk_report` is missing
- [AGENTS.md](/Users/tr/wrkr/AGENTS.md:108) still says Go `1.26.1`, while [go.mod](/Users/tr/wrkr/go.mod:3), [product/dev_guides.md](/Users/tr/wrkr/product/dev_guides.md:135), and CI pins are already on `1.26.2`.
- Working tree baseline is clean, so follow-on implementation can branch cleanly from the generated plan.

## Exit Criteria

- `wrkr scan --path <single-repo-root> --json` emits one repo in `source_manifest.repos`, detects root-level config files such as `AGENTS.md`, and no longer returns an empty false-negative result for qualifying repo roots.
- Existing repo-set fixtures and scenario bundle paths still scan as multiple repos with deterministic repo naming and order.
- `wrkr scan` rejects any collision among managed artifact paths and optional output paths with `invalid_input` and exit code `6` before mutating state/proof/manifest artifacts.
- Rejected collision runs preserve the previous committed managed artifact generation, or preserve artifact absence if no prior generation existed.
- README and command docs explain the final `--path` contract without ambiguity and keep the repo-local fallback first-value path copy-pasteable.
- `AGENTS.md` no longer conflicts with the enforced Go floor, and an automated check prevents recurrence.
- Validation passes on the mapped lanes:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
  - `make test-scenarios`
  - `make prepush-full`
  - `make test-hardening`
  - `make test-chaos`
  - docs consistency/storyline/smoke checks for touched flows

## Public API and Contract Map

- Stable public surfaces:
  - `wrkr scan`
  - the `--path` flag itself
  - existing exit code integers `0..8`
  - scan JSON top-level contract for valid runs
  - saved scan state/proof artifact locations beside `--state`
  - downstream command flow: `scan -> report/evidence/regress/verify`
- Changed public surfaces in this plan:
  - `--path` now has an explicit dual contract: deterministic `repo_root` or deterministic `repo_set`
  - previously accepted aliasing sidecar configurations become hard `invalid_input` failures before mutation
- Internal surfaces:
  - local path classifier logic in `core/source/local`
  - managed artifact collision preflight helper(s) in `core/cli`
  - AGENTS/toolchain drift enforcement in hygiene scripts/tests
- Shim/deprecation path:
  - no new scan flags are introduced
  - no deprecation notice is added for current repo-set usage
  - repo-set behavior remains supported under `--path` for shipped scenarios and local multi-repo roots
- Schema/versioning policy:
  - stay on current scan/state/inventory/proof schema versions
  - no JSON keys are removed
  - no schema bump is allowed for these fixes
  - if any additive metadata is proposed during implementation, it must be acceptance-backed and documented as additive only
- Machine-readable error expectations:
  - artifact path alias collision -> `invalid_input`, exit `6`
  - invalid sidecar path shape stays `invalid_input`, exit `6`
  - valid repo-root `--path` scan still exits `0` and returns the standard scan payload
  - valid repo-set `--path` scan still exits `0` and returns the standard scan payload

## Docs and OSS Readiness Baseline

- README first screen must continue to present `wrkr scan --path ./your-repo --json` as the local/offline fallback.
- `docs/commands/scan.md` is the command-contract source of truth for:
  - `repo_root` vs `repo_set` path semantics
  - sidecar uniqueness/fail-closed rules
  - downstream lifecycle path from saved scan state into evidence/report/regress
- `docs/examples/quickstart.md`, `docs/examples/security-team.md`, `docs/faq.md`, and `docs/positioning.md` mirror the command contract but must not redefine it.
- Integration-first flow for touched docs:
  - show the working `scan --path` repo-root flow first
  - explain repo-set/scenario-bundle usage second
  - explain fail-closed output-path rules before report/evidence examples
- Lifecycle path model for touched docs:
  - saved scan state is the canonical handoff artifact
  - optional sidecars are additive and must never replace or alias that handoff artifact
- OSS/governance trust baseline:
  - `CHANGELOG.md`: required updates for all three stories
  - `AGENTS.md`: updated as repo-local contributor/agent guidance
  - `CONTRIBUTING.md`: verify no content change is required; explicitly defer if unchanged
  - `SECURITY.md`: verify no content change is required; explicitly defer if unchanged

## Recommendation Traceability

| Recommendation | Why | Story IDs |
|---|---|---|
| Fix the public `scan --path` contract so it actually scans the supplied repo root | Current implementation silently misses root-level files while docs tell users to scan a repo root directly | W1-S1 |
| Reject sidecar output paths that alias managed scan artifacts | Current scan can succeed while clobbering its own saved state and breaking downstream commands | W1-S2 |
| Align the repo-local toolchain contract in `AGENTS.md` with the enforced Go floor | Current repo-local guidance conflicts with `go.mod`, CI, and the normative dev guide | W2-S1 |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - focused unit tests in `core/source/local`, `core/cli`, and hygiene tests
  - docs parity/storyline checks for touched command/docs flows
- Core CI lane:
  - `make prepush`
  - `make test-contracts`
  - `make test-scenarios`
- Acceptance lane:
  - targeted `internal/e2e/cli_contract` coverage for repo-root `--path`
  - targeted end-to-end safety coverage proving rejected alias collisions do not poison downstream evidence/report/regress flows
- Cross-platform lane:
  - `windows-smoke`
  - targeted path-classification and path-collision tests must avoid POSIX-only assumptions
- Risk lane:
  - `make prepush-full`
  - `make test-hardening`
  - `make test-chaos`
- Merge/release gating rule:
  - both Wave 1 stories are required before the next release candidate or release tag
  - no CLI/docs/contract story closes without docs and changelog landing in the same PR
  - no fail-closed artifact safety story closes without hardening/chaos coverage

## Epic W1: Scan Contract and State-Safety Blockers

Objective: remove the two release-blocking scan defects without weakening deterministic local/offline behavior or the existing repo-set scenario workflows.

### Story W1-S1: Make `scan --path` deterministic for both single repo roots and repo-set directories

Priority: P0
Tasks:
- Add an explicit path-target classifier in the Source layer that determines `repo_root` vs `repo_set` from deterministic root-level signals.
- Scan the selected directory itself as one repo when it qualifies as a repo root.
- Preserve immediate-child repo-set enumeration when the selected directory is a shipped or user-managed repo bundle root.
- Keep deterministic repo naming, ordering, and deduplication across both modes.
- Add contract fixtures for:
  - root-level `AGENTS.md` / `.codex` repo-root scans
  - existing multi-repo bundle directories under `scenarios/wrkr/*/repos`
- Update README and command/example docs so repo-root and repo-set semantics are explicit and non-conflicting.
Repo paths:
- `core/source/local/local.go`
- `core/source/local/local_test.go`
- `core/cli/root_test.go`
- `core/cli/scan_contract_fix_test.go`
- `internal/e2e/cli_contract/cli_contract_e2e_test.go`
- `README.md`
- `docs/commands/scan.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/faq.md`
- `docs/positioning.md`
- `docs/contracts/readme_contract.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/source/local ./core/cli ./internal/e2e/cli_contract -count=1`
- `make test-contracts`
- `make test-scenarios`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/run_docs_smoke.sh --subset`
Test requirements:
- CLI behavior changes:
  - `--json` stability tests for repo-root and repo-set path scans
  - exit-code contract tests remain `0` for valid repo-root and repo-set scans
  - machine-readable scan payload assertions for `source_manifest.repos`
- Scenario/spec tests:
  - outside-in fixture validating a single repo root with only root-level signals
  - regression fixture validating existing multi-repo bundle behavior
- Docs/examples changes:
  - docs consistency checks
  - README first-screen contract checks
  - integration-before-internals guidance checks for the updated fallback flow
Matrix wiring:
- Fast lane: focused `core/source/local` and `core/cli` tests plus docs parity
- Core CI lane: `make prepush`, `make test-contracts`, `make test-scenarios`
- Acceptance lane: `go test ./internal/e2e/cli_contract -count=1`
- Cross-platform lane: `windows-smoke` plus targeted path-behavior assertions that avoid platform-specific separators in expectations
- Risk lane: `make prepush-full`
Acceptance criteria:
- A temp repo with only a root `AGENTS.md` scanned via `wrkr scan --path <repo-root> --json` produces one repo manifest entry and at least one root-level finding.
- Existing scenario-bundle paths under `scenarios/wrkr/*/repos` still produce per-child repo manifests with deterministic ordering.
- No detector-layer code is required to guess path mode.
- README and docs no longer describe `--path` in conflicting ways.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Made `wrkr scan --path` honor single-repo root inputs while preserving deterministic repo-set scans for scenario bundles and local multi-repo roots.
Semver marker override: none
Contract/API impact:
- Public `--path` behavior is corrected and explicitly defined.
- No new flags or exit codes are introduced.
Versioning/migration impact:
- No schema/version bump.
- Automation that accidentally relied on false-negative empty results from single-repo-root scans will now receive the correct repo findings and state.
Architecture constraints:
- Keep path-mode classification inside the Source boundary.
- Use thin orchestration with focused packages; do not leak path classification into detectors or reporting.
- Preserve explicit side-effect semantics and deterministic ordering.
- Preserve cancellation/timeout propagation through the local acquisition path.
- Keep the classifier extensible so future repo-root signal additions do not require broad detector rewrites.
ADR required: yes
TDD first failing test(s):
- `core/source/local/local_test.go` single-repo-root fixture
- `core/cli/root_test.go` or a dedicated scan path contract test for `wrkr scan --path <repo-root> --json`
- `internal/e2e/cli_contract/cli_contract_e2e_test.go` repo-root fallback example
Cost/perf impact: low
Chaos/failure hypothesis:
- If the classifier over-classifies repo bundles as single repos, per-repo ownership/risk output collapses.
- If it under-classifies single repo roots as bundles, the public fallback remains a silent false negative.

### Story W1-S2: Fail closed when scan sidecar outputs alias managed artifacts

Priority: P0
Tasks:
- Add one canonical scan-artifact preflight that resolves every managed and optional artifact path before the first write.
- Reject collisions among:
  - `--state`
  - manifest path
  - lifecycle chain
  - proof chain
  - proof attestation
  - proof signing key
  - `--json-path`
  - `--report-md-path`
  - `--sarif-path`
- Return a deterministic `invalid_input` error that identifies the conflicting path pair(s).
- Preserve the existing atomic rollback model for late write failures after successful preflight.
- Add regression tests proving a rejected collision does not poison downstream `evidence`, `report`, `inventory`, or `regress` flows.
Repo paths:
- `core/cli/scan.go`
- `core/cli/jsonmode.go`
- `core/cli/managed_artifacts.go`
- `core/cli/report.go`
- `core/cli/scan_json_path_test.go`
- `core/cli/scan_transaction_test.go`
- `core/cli/root_test.go`
- `internal/e2e/cli_contract/cli_contract_e2e_test.go`
- `docs/commands/scan.md`
- `README.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/cli ./internal/e2e/cli_contract -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- CLI behavior changes:
  - `--json` stability tests for rejected alias collisions
  - exit-code contract tests for `invalid_input` / exit `6`
  - machine-readable error envelope tests naming the collision
- Gate/policy/fail-closed changes:
  - deterministic alias-collision fixtures for state/json/report/SARIF/proof path pairs
  - tests proving rejection happens before managed artifact mutation
- Job runtime/state/concurrency changes:
  - rollback preservation tests for preexisting state/proof artifacts
  - interrupted/failing write tests must still preserve the previous generation after successful preflight
- Docs/examples changes:
  - docs consistency checks for updated sidecar rules
Matrix wiring:
- Fast lane: focused `core/cli` tests
- Core CI lane: `make test-contracts`
- Acceptance lane: targeted CLI/e2e flow proving rejected collisions do not break a follow-on `wrkr evidence` or `wrkr inventory`
- Cross-platform lane: path-collision tests must normalize absolute/canonical path handling across Windows and POSIX
- Risk lane: `make prepush-full`, `make test-hardening`, `make test-chaos`
Acceptance criteria:
- `wrkr scan --json-path <state-path>` fails with `invalid_input` and exit `6` before mutating scan state.
- Sidecar-to-sidecar duplicates such as `--json-path` == `--report-md-path` also fail closed.
- Valid unique sidecar paths continue to work without JSON/exit-code drift.
- A previously valid saved state remains usable by downstream commands after a rejected collision run.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Blocked scan sidecar output paths from aliasing managed state and proof artifacts, so invalid configurations now fail fast instead of corrupting saved scan state.
Semver marker override: none
Contract/API impact:
- Previously accepted but unsafe aliasing output configurations now return `invalid_input` with exit `6`.
- Valid scan contracts are unchanged.
Versioning/migration impact:
- No schema/version bump.
- Automation using colliding output paths must switch to unique sidecar paths.
Architecture constraints:
- Keep collision detection in CLI orchestration, not in lower-level state/proof writers.
- Resolve and compare canonical paths once up front.
- Preserve explicit plan/apply style semantics: preflight first, mutate second.
- Keep the atomic-write and rollback boundaries authoritative.
- Preserve cancellation/timeout propagation and deterministic error reporting.
ADR required: yes
TDD first failing test(s):
- `core/cli/scan_json_path_test.go` alias collision case
- `core/cli/scan_transaction_test.go` preservation case for preexisting managed artifacts
- `internal/e2e/cli_contract/cli_contract_e2e_test.go` rejected-collision then downstream-command sanity flow
Cost/perf impact: low
Chaos/failure hypothesis:
- If any managed/optional alias escapes preflight, a nominally successful scan can still overwrite its own canonical handoff artifact and break downstream evidence/report/regress commands.

## Epic W2: Repo-Local Toolchain Contract Hygiene

Objective: remove contributor/agent guidance drift and prevent the repo-local Go floor from diverging again from authoritative enforcement surfaces.

### Story W2-S1: Delegate AGENTS toolchain authority to enforced sources and add a drift check

Priority: P2
Tasks:
- Replace the stale literal Go `1.26.1` declaration in `AGENTS.md` with repo-local guidance that points to `go.mod` and `product/dev_guides.md` as the authoritative toolchain floor.
- Add an enforcement check so `AGENTS.md` cannot drift back to a conflicting explicit Go floor without failing CI/local hygiene.
- Keep the guidance readable for both human contributors and repo-local coding agents.
Repo paths:
- `AGENTS.md`
- `scripts/check_toolchain_pins.sh`
- `testinfra/hygiene/toolchain_pins_test.go`
- `CHANGELOG.md`
Run commands:
- `scripts/check_toolchain_pins.sh`
- `go test ./testinfra/hygiene -count=1`
- `make lint-fast`
Test requirements:
- Docs/governance changes:
  - enforcement-first drift check for AGENTS vs authoritative toolchain sources
  - no runtime or schema contract changes
- Toolchain/runtime/security scanner changes:
  - none beyond contributor guidance alignment and enforcement
Matrix wiring:
- Fast lane: `make lint-fast`, `go test ./testinfra/hygiene -count=1`
- Core CI lane: covered by `make prepush`
- Acceptance lane: not required
- Cross-platform lane: keep the drift check in portable shell or Go test logic
- Risk lane: not required
Acceptance criteria:
- `AGENTS.md` no longer claims Go `1.26.1`.
- CI/local hygiene fails if AGENTS introduces a conflicting explicit Go floor in the future.
- No runtime behavior, JSON payload, schema, or exit code changes occur.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Clarified repo-local contributor and agent guidance so Wrkr now delegates Go toolchain authority to the enforced 1.26.2 floor in `go.mod` and the development standards.
Semver marker override: none
Contract/API impact:
- Contributor/agent governance guidance only.
- No runtime public API change.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep one authoritative toolchain source of truth.
- Prefer enforceable delegation over duplicated mutable version strings across governance docs.
ADR required: no
TDD first failing test(s):
- `testinfra/hygiene/toolchain_pins_test.go` or a dedicated AGENTS/toolchain drift fixture
Cost/perf impact: low
Chaos/failure hypothesis:
- If AGENTS drifts again, contributors and local agents can debug under an unsupported Go floor and reproduce different outcomes than CI.

## Minimum-Now Sequence

1. Wave 1, Story W1-S2: block artifact-path alias collisions before any further scan contract work lands. This removes the state-clobbering failure mode immediately.
2. Wave 1, Story W1-S1: fix the public `--path` contract while preserving repo-set behavior used by shipped scenarios and existing docs.
3. Wave 2, Story W2-S1: clean up AGENTS toolchain drift and add recurrence protection after the runtime blockers are gone.

## Explicit Non-Goals

- No new scan flags or schema versions.
- No change to hosted GitHub acquisition behavior, rate limiting, or PR publishing.
- No docs-site redesign or broader docs IA rewrite.
- No changes to proof formats, lifecycle state model, or report templates beyond what is required to keep docs/flows accurate.
- No Go toolchain uplift work in runtime/CI surfaces; the authoritative floor is already `1.26.2` and this plan only fixes repo-local drift.

## Definition of Done

- Every recommendation maps to at least one shipped story outcome.
- Wave 1 stories land with:
  - code
  - tests
  - docs
  - changelog
  - CI wiring
- `--path` repo-root and repo-set behavior are both deterministic and acceptance-backed.
- Artifact-path aliasing fails fast before mutation and is covered by hardening/chaos-aware tests.
- `AGENTS.md` no longer conflicts with enforced toolchain authority and future drift is automatically caught.
- Required PR checks remain green:
  - `fast-lane`
  - `windows-smoke`
- No dirty files remain beyond the intended implementation changes and the updated plan/changelog/docs artifacts.

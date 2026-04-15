# PLAN Adhoc: fail-closed cached posture score validation

Date: 2026-04-14
Source of truth:
- user-provided recommendation to fix the PR `#140` review feedback at `https://github.com/Clyra-AI/wrkr/pull/140#discussion_r3081985875`
- `product/dev_guides.md`
- `product/architecture_guides.md`
Scope: Planning only for the follow-up patch that restores full snapshot validation before `wrkr score` trusts cached `posture_score`, while preserving deterministic behavior and the no-recompute performance win for valid state files. No implementation work is performed in this plan.

## Global Decisions (Locked)

- This plan is a follow-up to merged PR `#140` on 2026-04-14. Do not revert the cached-score fast path outright; fix the correctness gap inside the existing design direction.
- Preserve Wrkr's non-negotiable contracts:
  - deterministic scan, score, and proof behavior
  - offline-first local execution
  - fail-closed handling for ambiguous or malformed runtime state
  - stable numeric exit codes and machine-readable error envelopes
  - portable file-based state and proof artifacts
- Preserve the current public `wrkr score` surface:
  - existing flags
  - success JSON keys and meanings
  - score math, grade thresholds, and weighted breakdown semantics
  - additive attack-path passthrough when present in saved state
- Keep malformed saved state on the existing runtime-failure family:
  - error code `runtime_failure`
  - exit code `1`
- Keep state snapshot version `v1`; this is a validation-behavior correction, not a schema or migration project.
- Keep orchestration thin:
  - `core/cli/score.go` may coordinate flag parsing and output shaping
  - full snapshot structural validation belongs in `core/state` or a tightly scoped helper, not in ad hoc CLI-only JSON checks
- Performance remains a release gate. Any extra validation on the cached-score path must be paired with measurable perf evidence so the release risk lane stays green.
- Docs and changelog updates are required because this restores a user-visible fail-closed contract on a public command.

## Current Baseline (Observed)

- `core/cli/score.go` currently reads a partial `storedScoreState` payload from disk and returns cached `posture_score` when present, without validating the entire `state.Snapshot`.
- `core/state/state.go` defines the full `state.Snapshot` contract and already reports `read state` or `parse state` failures from `LoadRaw` and `Load`.
- `core/cli/score_test.go` currently proves the minimal cached-score success path only. It does not cover malformed `findings`, `identities`, or `risk_report` sections coexisting with a valid cached score.
- `core/cli/root_test.go` and `internal/e2e/score/score_e2e_test.go` verify valid `score` command behavior, but they do not assert fail-closed handling for corrupted saved state.
- `internal/acceptance/v1_acceptance_test.go` AC20 verifies deterministic repeated `wrkr score --json` output for valid snapshots, but not malformed-state rejection.
- `docs/commands/score.md` documents flags and success JSON keys only. It does not call out malformed state behavior.
- `docs/failure_taxonomy_exit_codes.md` documents general runtime-failure behavior, but it does not include a `wrkr score` malformed-state example.
- `schemas/v1/score/score.schema.json` covers only the success payload shape. No success-schema expansion is needed for this fix.
- `scripts/test_perf_budgets.sh` already budgets short-lived `wrkr score --json` latency, so this follow-up must re-prove the cached-score path stays within current release expectations.

## Exit Criteria

- `wrkr score --state <path> --json` returns the same success payload for valid saved snapshots that already contain `posture_score`.
- A malformed or type-invalid `state.Snapshot` that still includes `posture_score` fails closed with `runtime_failure` and exit code `1` instead of returning stale cached success output.
- The implementation validates the full snapshot contract before success without recomputing score when a valid cached posture score is present.
- Cached `risk_report.attack_paths` and `risk_report.top_attack_paths` remain pass-through compatible on valid saved state.
- Valid snapshots without cached `posture_score` still use the recompute path and preserve existing output semantics.
- Score command perf budgets remain green in the release perf lane after the validation change.
- CLI contract tests, e2e coverage, acceptance coverage, docs consistency checks, and changelog updates all pass.

## Public API and Contract Map

- Stable public surfaces:
  - `wrkr score [--state <path>] [--json] [--quiet] [--explain]`
  - success JSON keys: `score`, `grade`, `breakdown`, `weighted_breakdown`, `weights`, `trend_delta`
  - optional success JSON keys: `attack_paths`, `top_attack_paths`
  - runtime error envelope contract on stderr for unreadable or malformed state
  - exit code `1` for `runtime_failure`
  - state snapshot version `v1`
- Internal surfaces expected to change:
  - `core/cli/score.go`
  - `core/state/state.go` or a new focused validation helper under `core/state`
  - targeted score command tests and perf validation coverage
- Shim and deprecation path:
  - none
  - no flag removals
  - no output key removals
  - no config or snapshot migration shims
- Schema and versioning policy:
  - `schemas/v1/score/score.schema.json` remains unchanged
  - `state.Snapshot` remains `v1`
  - no migration is planned because corrupted snapshots must be repaired or regenerated, not auto-coerced
- Machine-readable error expectations:
  - invalid JSON or type-invalid full snapshots at `--state` return stderr JSON with `error.code=runtime_failure` and `error.exit_code=1`
  - valid snapshots with cached score return unchanged success JSON on stdout
  - valid snapshots without cached score continue to recompute and return unchanged success JSON on stdout

## Docs and OSS Readiness Baseline

- `docs/commands/score.md` is the command contract source of truth and must describe malformed state behavior once the runtime fix lands.
- `docs/failure_taxonomy_exit_codes.md` should be updated if the implementation adds an operator-facing example for cached-score validation failures.
- README first-screen onboarding is out of scope; this is a command-contract correction, not a launch-story rewrite.
- `CHANGELOG.md` must record the restored fail-closed `wrkr score` behavior under `## [Unreleased]`.
- `CONTRIBUTING.md` and `SECURITY.md` should be checked for impact, but no update is expected unless contributor workflow or disclosure guidance changes.
- Docs flow for this work stays integration-first:
  - `docs/commands/score.md` for the command contract
  - `docs/failure_taxonomy_exit_codes.md` for exit semantics
  - `CHANGELOG.md` for user-visible release notes

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story IDs |
|---|---|---|---|---|---|
| R1 | Validate the full saved scan snapshot before trusting cached `posture_score` | Prevent corrupted or hand-edited state files from returning stale success output | Restore fail-closed score correctness without abandoning the cached-score performance path | Stronger CI and release trust in posture outputs | W1-S1 |
| R2 | Document and regression-test the restored cached-score contract | Keep future perf work from silently reintroducing partial-state success behavior | Make contract and release expectations explicit in docs, tests, and changelog | Better long-term contract stability and contributor clarity | W2-S1 |

## Test Matrix Wiring

- Fast lane:
  - `go test ./core/state ./core/cli -count=1`
  - `scripts/check_docs_consistency.sh`
- Core CI lane:
  - `make prepush`
  - `make test-contracts`
- Acceptance lane:
  - `go test ./internal/e2e/score -count=1`
  - `go test ./internal/acceptance -count=1 -run 'TestV1AcceptanceMatrix/AC20_posture_score_deterministic_command_output'`
- Cross-platform lane:
  - `windows-smoke`
  - keep state-path handling and stderr/stdout contract assertions platform-neutral
- Risk lane:
  - `make prepush-full`
  - `make test-hardening`
  - `make test-chaos`
  - `make test-perf`
  - `scripts/test_perf_budgets.sh`
  - `scripts/run_v1_acceptance.sh --mode=release`
- Merge/release gating rule:
  - Wave 1 runtime correctness must land before Wave 2 docs and changelog closure
  - no story closes without its declared lane coverage
  - any runtime fix that regresses score perf budgets blocks merge until corrected or re-scoped

## Epic W1: Score Snapshot Validation Contract

Objective: restore fail-closed `wrkr score` behavior for malformed saved state while preserving the cached-score no-recompute path and release perf viability.

### Story W1-S1: Validate full snapshot structure before returning cached score success

Priority: P0
Tasks:
- Refactor score state loading so the command validates the full `state.Snapshot` contract before returning success from cached `posture_score`.
- Keep cached-score behavior focused on avoiding unnecessary recomputation, not on tolerating partial or malformed saved state.
- Prefer a single-read validation/extraction path when practical; if a two-pass decode is required for correctness, document it in code comments and prove it stays inside current perf budgets.
- Preserve pass-through handling for cached attack-path data on valid snapshots.
- Add fail-closed tests for malformed `findings`, malformed `identities`, and malformed `risk_report` structures when cached `posture_score` is present.
- Add parity coverage so valid cached-score snapshots still produce the same JSON and explain output as before.
- Re-run release perf validation because this story touches a measured hot path.
Repo paths:
- `core/cli/score.go`
- `core/state/state.go`
- `core/cli/score_test.go`
- `core/cli/root_test.go`
- `internal/e2e/score/score_e2e_test.go`
- `internal/acceptance/v1_acceptance_test.go`
- `scripts/test_perf_budgets.sh`
Run commands:
- `go test ./core/state ./core/cli -count=1`
- `go test ./internal/e2e/score -count=1`
- `go test ./internal/acceptance -count=1 -run 'TestV1AcceptanceMatrix/AC20_posture_score_deterministic_command_output'`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-perf`
- `scripts/test_perf_budgets.sh`
- `scripts/run_v1_acceptance.sh --mode=release`
Test requirements:
- CLI behavior changes:
  - add exit-code and error-envelope tests for malformed saved state that still contains cached `posture_score`
  - keep `--json`, `--quiet`, and `--explain` behavior unchanged for valid snapshots
- Gate and fail-closed changes:
  - deterministic fixtures where cached score coexists with invalid `findings`
  - deterministic fixtures where cached score coexists with invalid `identities`
  - deterministic fixtures where cached score coexists with invalid `risk_report`
  - ensure no stdout success payload is emitted on malformed-state failure paths
- Determinism and perf:
  - repeat-run parity tests for valid cached-score snapshots
  - cached-score perf validation in the release budget lane
- Contract checks:
  - keep success payload schema unchanged
  - preserve `runtime_failure` classification for malformed state reads
Matrix wiring:
- Fast lane: `go test ./core/state ./core/cli -count=1`
- Core CI lane: `make prepush`, `make test-contracts`
- Acceptance lane: targeted `internal/e2e/score` and AC20 score command coverage
- Cross-platform lane: `windows-smoke`
- Risk lane: `make prepush-full`, `make test-hardening`, `make test-chaos`, `make test-perf`, `scripts/test_perf_budgets.sh`
Acceptance criteria:
- A saved state fixture with valid cached `posture_score` plus `"findings": "bad"` returns `runtime_failure` and exit `1`
- Equivalent malformed fixtures for `identities` and `risk_report` also fail closed
- A valid saved snapshot with cached `posture_score` still returns the existing success JSON keys and values
- A valid saved snapshot without cached score still recomputes and returns the existing success JSON keys and values
- Release perf validation remains green after the fix
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: `wrkr score` now validates the full saved scan snapshot before reusing cached posture scores, so malformed state files fail closed instead of returning stale success output.
Semver marker override: none
Contract/API impact: Restores the public `wrkr score` runtime contract so malformed saved state fails with `runtime_failure` even when cached score data is present; success payload schema and flags stay unchanged.
Versioning/migration impact: No schema or state version bump. Corrupted or hand-edited state files must be repaired or regenerated rather than relied on for cached success output.
Architecture constraints:
- Keep CLI orchestration thin and move structural validation into `core/state` or a similarly focused helper
- Avoid partial-state success behavior anywhere the full snapshot contract is required
- Preserve explicit side-effect-free semantics in helper names and signatures
- Keep helper semantics symmetric with existing `LoadRaw` and `Load` behavior instead of inventing a score-only parsing exception
- Keep deterministic ordering and score math unchanged for valid snapshots
- Do not introduce new timeout, cancellation, or background-work blind spots on the command path
- Prefer a reusable validation entry point that other state-consuming commands can adopt without copying score-specific logic
- Minimize extra decoding work or prove any added decode cost stays within current perf budgets
ADR required: no
TDD first failing test(s):
- `TestScoreJSONFailsClosedWhenCachedScoreStateContainsMalformedFindings`
- `TestScoreJSONFailsClosedWhenCachedScoreStateContainsMalformedIdentities`
- `TestScoreJSONFailsClosedWhenCachedScoreStateContainsMalformedRiskReport`
- `TestE2EScoreJSONFailsClosedOnMalformedStateWithCachedScore`
Cost/perf impact: medium
Chaos/failure hypothesis: If a saved snapshot is truncated, hand-edited, or partially corrupted but still carries cached score data, `wrkr score` must return `runtime_failure` without emitting stale success output; if the validation approach regresses short-lived command latency beyond budget, perf lanes must fail before merge.

## Epic W2: Docs and Release Note Alignment

Objective: make the restored cached-score validation contract explicit in operator docs and release notes so the follow-up stays visible and durable.

### Story W2-S1: Align score docs, failure taxonomy, and changelog with the restored fail-closed contract

Priority: P1
Tasks:
- Update `docs/commands/score.md` to state that malformed saved state fails with `runtime_failure` instead of returning cached success.
- Add or refresh a focused example in `docs/failure_taxonomy_exit_codes.md` if the runtime fix introduces a clearer operator-facing malformed-state path.
- Add the `CHANGELOG.md` `## [Unreleased]` entry for the user-visible behavior correction.
- Keep docs wording precise: valid cached-score snapshots stay fast and schema-stable; malformed snapshots fail closed.
- Re-run docs contract checks after the runtime story lands so wording matches shipped behavior exactly.
Repo paths:
- `docs/commands/score.md`
- `docs/failure_taxonomy_exit_codes.md`
- `CHANGELOG.md`
Run commands:
- `scripts/check_docs_consistency.sh`
- `scripts/check_docs_cli_parity.sh`
- `go test ./core/cli -count=1`
- `make prepush`
Test requirements:
- Docs and examples:
  - docs consistency checks
  - docs CLI parity checks
  - ensure score docs mention the malformed-state runtime-failure contract without inventing new flags or schema keys
- OSS readiness:
  - verify `CHANGELOG.md` includes the user-visible fix under `## [Unreleased]`
  - confirm no README or contributor workflow drift is introduced by this narrower contract update
Matrix wiring:
- Fast lane: `scripts/check_docs_consistency.sh`, `scripts/check_docs_cli_parity.sh`
- Core CI lane: `make prepush`
- Acceptance lane: inherit W1-S1 command contract reruns if docs wording changes the described behavior surface
- Cross-platform lane: none beyond inherited required checks because this story is docs and release-note only
- Risk lane: not required beyond W1-S1 because this story does not change runtime behavior
Acceptance criteria:
- `docs/commands/score.md` explicitly documents malformed-state failure behavior
- `docs/failure_taxonomy_exit_codes.md` remains aligned if touched
- `CHANGELOG.md` contains an operator-facing `Unreleased` entry for the fix
- Docs contract checks pass without drift
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Clarified the `wrkr score` command contract so malformed saved state is documented as a fail-closed runtime failure while valid cached-score output remains unchanged.
Semver marker override: none
Architecture constraints:
- Do not promise partial-state recovery, auto-repair, or schema changes that the runtime fix does not implement
- Keep docs source-of-truth ordering explicit: command doc, failure taxonomy, changelog
- Preserve operator-facing wording and stable contract terminology
ADR required: no
TDD first failing test(s):
- `scripts/check_docs_consistency.sh`
- `scripts/check_docs_cli_parity.sh`
Cost/perf impact: low
Dependencies:
- `W1-S1`

## Minimum-Now Sequence

1. Wave 1: implement `W1-S1` first so cached-score validation and perf evidence are settled before any docs or changelog wording is finalized.
2. Wave 2: complete `W2-S1` after the runtime contract is green, then re-run docs checks and confirm the `Unreleased` entry matches the shipped behavior.

## Explicit Non-Goals

- No new `wrkr score` flags or output keys
- No state snapshot version bump or migration layer
- No score algorithm, weights, or grade-threshold changes
- No broad state-file repair or auto-healing feature
- No revert of PR `#140` beyond the targeted cached-score validation correction
- No README or onboarding flow rewrite

## Definition of Done

- Every recommendation in this plan maps to an implemented story with tests, lane wiring, and changelog guidance
- `wrkr score` fails closed on malformed cached-score state and remains schema-stable on valid state
- Release perf and acceptance lanes pass after the validation change
- Docs and changelog reflect the shipped runtime behavior
- No unrelated files are left dirty beyond the generated plan during the planning handoff

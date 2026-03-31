# PLAN WRKR_FO_GAP_CLOSURE: Close Remaining First-Offer Fidelity Gaps

Date: 2026-03-30
Source of truth:
- user-provided gap findings from 2026-03-30 analysis of `product/PLAN_NEXT.md`
- `AGENTS.md`
- `product/dev_guides.md`
- `product/architecture_guides.md`
- `README.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `core/risk/action_paths.go`
- `core/risk/action_paths_test.go`
- `core/report/build.go`
- `core/report/report_test.go`
- `core/cli/report_contract_test.go`
- `core/cli/root_test.go`
- `core/policy/profile/profile_test.go`
- `internal/scenarios/contracts_test.go`
- `internal/scenarios/first_offer_regression_scenario_test.go`
- `internal/scenarios/coverage_map.json`
- `testinfra/contracts/story1_contracts_test.go`
- `testinfra/contracts/story24_contracts_test.go`
Scope: Wrkr repository only. Planning artifact only. Close the remaining plan-to-repo fidelity gaps after the first-offer implementation landed: ratify the public `path_id` contract, harden FO-14 and FO-15 regression evidence with checked-in deterministic goldens and enforced coverage mappings, and add the direct package-level tests the plan promised for assessment behavior.

## Global Decisions (Locked)

- This file is planning-only. No implementation work is in scope for this artifact.
- Treat the shipped first-offer capability set as present. This plan closes only the remaining fidelity gaps between the intended plan, public contract wording, and the current test harness.
- Preserve Wrkr's deterministic, offline-first, fail-closed posture. No story in this plan may introduce live-network-dependent regression fixtures, schema drift, or exit-code changes.
- Treat `action_paths[*].path_id` as an opaque public identifier. Unless implementation discovers a proven downstream need for a wire-format migration, keep the shipped `apc-<hex>` form and align docs/tests/contracts to that opaque contract rather than changing runtime behavior for documentation-only drift.
- First-offer regression evidence must move from broad behavioral assertions alone to checked-in, deterministic CLI/report goldens for the dedicated FO scenario packs.
- Coverage-map enforcement must fail if first-offer scenario mappings drift or disappear; FO-14 and FO-15 keys are part of the scenario contract once this plan lands.
- Direct package-level tests promised by the first-offer plan are required in addition to existing CLI contract tests; CLI contract coverage is not a substitute for report/profile package tests.
- Thin orchestration remains in `core/cli/*`; contract logic stays in `core/risk/*`, report shaping in `core/report/*`, and scenario/contract enforcement in `internal/scenarios/*` and `testinfra/contracts/*`.
- Stories that touch architecture boundaries, report contracts, risk logic, CLI help/usage, or validation gates must run `make prepush-full`.
- Docs/help/contract wording changes must ship with the corresponding docs and changelog updates in the same PR.

## Current Baseline (Observed)

- Preconditions validated:
  - `product/dev_guides.md` exists and is readable
  - `product/architecture_guides.md` exists and is readable
  - output path resolves inside `/Users/tr/wrkr`
- Standards guides already enforce the key planning constraints needed for this follow-up:
  - testing and CI gating via `make prepush`, `make prepush-full`, `make test-risk-lane`, `scripts/validate_scenarios.sh`, and `scripts/run_v1_acceptance.sh --mode=local`
  - determinism and contract stability via `testinfra/contracts`, `testinfra/hygiene`, `internal/scenarios`, and docs parity/storyline gates
  - architecture/TDD/chaos/frugal governance via `product/architecture_guides.md`
- The major first-offer product surfaces are already implemented:
  - additive `assessment` profile
  - additive `assessment_summary`
  - additive `ownerless_exposure`, `identity_exposure_summary`, `identity_to_review_first`, and `identity_to_revoke_first`
  - additive `business_state_surface` and `exposure_groups`
  - live org-scan stderr progress
  - partial-visibility surfacing
- Verified green during the gap analysis:
  - `go test ./core/risk ./core/report ./core/cli -count=1`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `go test ./testinfra/contracts -count=1`
  - `make test-docs-consistency`
  - `make test-docs-storyline`
  - `make test-risk-lane`
- Remaining fidelity gaps are now narrow and explicit:
  - `product/PLAN_NEXT.md` previously described `path_id` as lowercase hex-only while runtime/tests use `apc-<hex>`
  - first-offer scenario tests assert broad behavior but do not yet check committed CLI/report goldens for the new FO packs
  - `coverage_map.json` includes FO keys, but `TestScenarioContracts` currently enforces only the older `FR*` and `AC*` mappings
  - `core/report/report_test.go` does not yet directly cover `assessment_summary` and AI-path-first summary selection, `core/policy/profile/profile_test.go` omits `assessment`, and scan help tests do not assert the `assessment` profile text directly
- Current worktree contains unrelated untracked `scripts/__pycache__/`. Planning can proceed, but implementation follow-up should scope or clean that path before code work.

## Exit Criteria

1. The canonical public `action_paths[*].path_id` contract is explicit and aligned across runtime code, docs, and contract tests. No remaining source claims hex-only format if runtime keeps `apc-<hex>`.
2. First-offer scenario packs have checked-in deterministic scan/report goldens for the intended standard-versus-assessment and report-usefulness cases.
3. Scenario contract validation fails when FO-14 or FO-15 coverage-map keys drift, disappear, or reference unknown scenario tests.
4. Direct package-level tests exist for:
   - `core/report` assessment summary and AI-path-first selection
   - `core/policy/profile` builtin `assessment` loading
   - `core/cli` scan help/profile surface
5. All added tests preserve offline deterministic fixtures and keep runtime JSON, exit codes, and proof behavior unchanged.
6. README/docs/help/changelog surfaces touched by this work remain inside Wrkr's static-posture and offline-proof claim boundary.

## Public API and Contract Map

Stable/public surfaces touched by this plan:

- `wrkr scan --profile assessment --json`
- `wrkr report --json`
- `action_paths[*].path_id`
- `action_path_to_control_first`
- additive `assessment_summary`
- additive `ownerless_exposure`
- additive `identity_exposure_summary`
- additive `identity_to_review_first`
- additive `identity_to_revoke_first`
- `docs/commands/scan.md`
- `docs/commands/report.md`

Internal surfaces expected to change:

- `core/risk/action_paths.go`
- `core/risk/action_paths_test.go`
- `core/report/report_test.go`
- `core/cli/root_test.go`
- `core/policy/profile/profile_test.go`
- `internal/scenarios/contracts_test.go`
- `internal/scenarios/first_offer_regression_scenario_test.go`
- `internal/scenarios/coverage_map.json`
- `scenarios/wrkr/first-offer-*`
- `testinfra/contracts/story1_contracts_test.go`
- `testinfra/contracts/story24_contracts_test.go`

Shim and deprecation path:

- Preferred path: keep `path_id` opaque and stable with the shipped `apc-<hex>` form; align wording and tests to that contract.
- If implementation instead changes runtime `path_id` formatting, treat it as a public contract change even if the field name stays the same; update all exact-string fixtures and add migration notes for downstream consumers that pinned exact values.
- Existing CLI contract tests remain in place; new direct package tests are additive rather than a replacement.
- Existing broad first-offer scenario assertions may remain as coarse behavioral guards, but goldens become the authoritative regression lock for FO-14 and FO-15.

Schema and versioning policy:

- No schema fields are added or removed in this plan.
- No exit-code changes are allowed.
- Default execution path assumes no runtime `path_id` wire-format migration and therefore no schema version bump.
- If runtime `path_id` formatting changes, update exact-value fixtures and document downstream migration expectations in the same PR even if a schema bump is not taken.

Machine-readable error expectations:

- Runtime JSON envelopes remain unchanged.
- Scenario and contract drift must fail CI deterministically through test failures, not through best-effort warnings.
- Goldens must come from repo-local fixtures only; no CI step may depend on live external repo state.

## Docs and OSS Readiness Baseline

README first-screen contract:

- Lead with bounded AI-connected software-delivery paths, risky ones first, and offline-verifiable proof.
- Do not imply runtime provenance, live observation, or control-layer enforcement.
- Keep evaluator-safe and scenario-first commands explicit before widening to org scans.

Integration-first docs flow:

- `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile assessment --json`
- `wrkr report --state ./.wrkr/last-scan.json --json`
- `wrkr evidence --frameworks eu-ai-act,soc2 --state ./.wrkr/last-scan.json --json`
- `wrkr verify --chain --state ./.wrkr/last-scan.json --json`

Lifecycle path model:

- discovery
- path/risk correlation
- bounded assessment prioritization
- saved-state report rendering
- offline proof generation and verification

No story in this plan may turn Wrkr into a live observation or enforcement surface.

Docs source-of-truth mapping:

- product promise and claim boundary: `README.md`, `product/wrkr.md`
- scan contract: `docs/commands/scan.md`
- report contract: `docs/commands/report.md`
- operator examples: `docs/examples/security-team.md`, `docs/examples/operator-playbooks.md`
- docs source-of-truth coordination: `docs/map.md`

OSS trust baseline:

- `CHANGELOG.md` must be updated for any story marked `Changelog impact: required`
- `CONTRIBUTING.md` remains the contributor-facing public contract wording policy
- `SECURITY.md` remains aligned when public trust or support expectations shift
- no story may weaken deterministic or offline-first trust posture to improve test convenience

## Recommendation Traceability

| # | Recommendation | Strategic direction / benefit | Story IDs |
|---|---|---|---|
| 1 | Resolve the `path_id` public contract drift | Restore trust in the public govern-first contract without unnecessary runtime churn | `GAP-01` |
| 2 | Add checked-in FO-14/FO-15 CLI/report goldens | Make first-offer regressions fail on concrete output drift, not only broad heuristics | `GAP-02` |
| 3 | Enforce FO coverage-map keys | Keep first-offer scenario intent part of the executable scenario contract | `GAP-03` |
| 4 | Add direct `core/report` assessment tests | Match the original plan's promised package-level evidence for AI-path-first behavior | `GAP-04` |
| 5 | Add direct profile/help tests for `assessment` | Lock the additive profile into builtin loading and help surfaces without relying only on CLI integration tests | `GAP-05` |

## Test Matrix Wiring

| Lane | Purpose | Commands / Evidence |
|---|---|---|
| Fast lane | Quick author feedback for targeted contract/test work | `make lint-fast`; targeted `go test ./core/risk ./core/report ./core/cli ./core/policy/profile -count=1` |
| Core CI lane | Full architecture, contract, CLI, and docs/help gate | `make prepush`; `make prepush-full` |
| Acceptance lane | Scenario and contract behavior from outside-in fixtures | `scripts/validate_scenarios.sh`; `go test ./internal/scenarios -count=1 -tags=scenario`; `go test ./testinfra/contracts -count=1`; `scripts/run_v1_acceptance.sh --mode=local` |
| Cross-platform lane | Windows-safe CLI/help/test behavior | required `windows-smoke` workflow plus only cross-platform-safe test fixtures |
| Risk lane | Regression lock for report/risk/assessment output | `make test-risk-lane` |

Merge and release gating rule:

- Required PR checks remain `fast-lane` and `windows-smoke`.
- Stories marked `Core CI lane: required` must not merge unless `make prepush-full` passes locally and the equivalent CI lanes are green.
- Stories marked `Risk lane: required` must also pass `make test-risk-lane`.
- Stories touching scenario contracts or docs/help parity must keep `scripts/validate_scenarios.sh`, `make test-docs-consistency`, and `make test-docs-storyline` green where applicable.

## Epic WRKR-GAP-EPIC-1: Contract Alignment and First-Offer Regression Lock

Objective: close the remaining public-contract and regression-harness gaps so the already-shipped first-offer behavior is documented, validated, and locked against drift.

### Story GAP-01: Ratify and align the public `path_id` contract
Priority: P0
Tasks:
- Decide and document the canonical public `path_id` contract, defaulting to the shipped `apc-<hex>` opaque identifier unless a real downstream migration need is found.
- Align scan/report docs and contract tests so they no longer describe `path_id` as lowercase hex-only when runtime keeps the prefix.
- Add or tighten tests that assert opacity, uniqueness, determinism, and `action_path_to_control_first` alignment without encouraging downstream parsing of `path_id`.
- Update any exact-value fixtures or comments that still carry the old wording.
Repo paths:
- `core/risk/action_paths.go`
- `core/risk/action_paths_test.go`
- `core/cli/report_contract_test.go`
- `testinfra/contracts/story1_contracts_test.go`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `README.md`
Run commands:
- `go test ./core/risk ./core/cli ./testinfra/contracts -count=1`
- `make test-docs-consistency`
- `make prepush-full`
Test requirements:
- repeat-run stability tests for `path_id`
- uniqueness tests on deduped `action_paths`
- contract assertions that `action_path_to_control_first.path.path_id` references an emitted row
- docs/help parity checks for any touched public contract wording
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- no remaining public surface claims hex-only `path_id` if runtime keeps `apc-<hex>`
- `path_id` remains opaque, deterministic, and repeat-run stable
- `action_path_to_control_first` remains aligned with emitted `action_paths`
- if implementation chooses a runtime format change instead, all exact-value fixtures and migration notes are updated in the same change
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Clarified the public `action_paths[*].path_id` contract and aligned docs and contract tests with the shipped deterministic identifier format.
Semver marker override: none
Contract/API impact: public contract wording and exact-value test fixtures align to the canonical `path_id` format; field name and opacity guarantee remain unchanged.
Versioning/migration impact: no schema migration if runtime format stays unchanged; a runtime format change requires coordinated fixture updates and downstream migration notes in the same PR.
Architecture constraints:
- keep `path_id` generation authoritative in `core/risk`
- preserve opacity; downstream consumers must not infer semantics from the string format
- keep determinism and uniqueness explicit in tests, not implied by comments
ADR required: no
TDD first failing test(s):
- `core/risk/action_paths_test.go`: explicit `path_id` opacity/stability invariant
- `testinfra/contracts/story1_contracts_test.go`: contract wording and emitted `path_id` alignment
Cost/perf impact: low
Chaos/failure hypothesis: If downstream automation starts relying on parseable `path_id` structure, Wrkr must still keep the identifier opaque and stable rather than letting accidental formatting drift become a hidden contract.

### Story GAP-02: Add deterministic first-offer CLI and report goldens
Priority: P0
Tasks:
- Add committed scan/report goldens for `first-offer-noise-pack`, `first-offer-mixed-governance`, and the duplicate-path fixture path where exact output structure matters.
- Capture both the standard-versus-assessment comparison and the AI-path-first report usefulness shape in checked-in expected artifacts.
- Make scenario tests compare structured outputs against those goldens rather than only checking coarse conditions like count reduction or first finding type.
- Keep goldens small, deterministic, and derived only from repo-local fixtures.
Repo paths:
- `scenarios/wrkr/first-offer-noise-pack`
- `scenarios/wrkr/first-offer-mixed-governance`
- `scenarios/wrkr/first-offer-duplicate-paths`
- `internal/scenarios/first_offer_regression_scenario_test.go`
- `testinfra/contracts/story24_contracts_test.go`
Run commands:
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./testinfra/contracts -count=1`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make prepush-full`
Test requirements:
- committed expected scan/report artifacts for the dedicated FO packs
- structured golden comparisons for standard versus assessment outputs
- deterministic golden checks for AI-path-first `top_risks` and `action_path_to_control_first`
- no-network scenario validation
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- first-offer packs have checked-in deterministic scan/report goldens
- FO regression tests fail on substantive output drift, not only on coarse count checks
- standard-versus-assessment behavior is visible in committed expected artifacts
- no new golden depends on live external state
Changelog impact: not required
Changelog section: none
Semver marker override: none
Architecture constraints:
- scenario goldens remain outside-in evidence, not implementation-detail fixtures
- expected artifacts must stay deterministic and portable
- goldens should validate structured facts first and prose second where possible
ADR required: no
TDD first failing test(s):
- `internal/scenarios/first_offer_regression_scenario_test.go`: golden mismatch for FO noise-pack scan output
- `testinfra/contracts/story24_contracts_test.go`: golden mismatch for AI-path-first report usefulness output
Cost/perf impact: low
Chaos/failure hypothesis: If a later change quietly reintroduces noisy or secret-first first-offer output, the committed goldens must fail before the regression reaches a release.
Dependencies:
- `GAP-01`

### Story GAP-03: Enforce FO coverage-map keys in scenario contract validation
Priority: P1
Tasks:
- Extend `TestScenarioContracts` so FO-14 and FO-15 mappings are required alongside the legacy `FR*` and `AC*` keys.
- Ensure FO mapping values are validated against real scenario test symbols the same way existing coverage-map entries are.
- Keep the coverage-map gate deterministic and centralized rather than adding one-off checks in individual scenario tests.
- Update the validation script only if needed to keep the scenario contract entrypoint consistent.
Repo paths:
- `internal/scenarios/contracts_test.go`
- `internal/scenarios/coverage_map.json`
- `scripts/validate_scenarios.sh`
Run commands:
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -run '^TestScenarioContracts$' -count=1 -tags=scenario`
- `make prepush-full`
Test requirements:
- failing contract test when `FO14-*` or `FO15-*` keys are missing
- failing contract test when FO mappings reference unknown scenario symbols
- deterministic coverage-map parsing with no live repo assumptions
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- FO-14 and FO-15 mappings are required by scenario contract validation
- missing or stale FO mappings fail CI deterministically
- coverage-map enforcement stays centralized in the scenario contract gate
- no existing legacy coverage-map checks regress
Changelog impact: not required
Changelog section: none
Semver marker override: none
Architecture constraints:
- keep scenario contract enforcement in `internal/scenarios/contracts_test.go`
- avoid duplicating mapping logic across scripts and tests unless required for a single entrypoint
- preserve deterministic symbol discovery and failure messaging
ADR required: no
TDD first failing test(s):
- `internal/scenarios/contracts_test.go`: missing `FO14-*` and `FO15-*` keys fail the scenario contract gate
Cost/perf impact: low
Chaos/failure hypothesis: If a future refactor drops a first-offer scenario or renames a test, the coverage-map gate must fail immediately instead of leaving the regression harness partially disconnected.
Dependencies:
- `GAP-02`

## Epic WRKR-GAP-EPIC-2: Direct Package-Level Coverage Closure

Objective: add the direct package-level test evidence the first-offer plan promised so report/profile/help behavior is locked closer to the implementation boundary and not only through higher-level CLI contracts.

### Story GAP-04: Add direct `core/report` coverage for assessment summaries and AI-path-first output
Priority: P1
Tasks:
- Add unit tests in `core/report/report_test.go` that construct minimal deterministic report inputs with govern-first `action_paths`.
- Assert that `assessment_summary` is present, additive, and aligned with `action_path_to_control_first`.
- Assert that AI-path-present summaries lead with `finding_type=action_path` in direct report-building tests rather than only through CLI contract fixtures.
- Keep tests small and inline where practical so they validate report behavior without depending on the full scenario harness.
Repo paths:
- `core/report/report_test.go`
- `core/report/build.go`
- `core/cli/report_contract_test.go`
Run commands:
- `go test ./core/report ./core/cli -count=1`
- `make prepush-full`
Test requirements:
- deterministic report-building fixtures with `action_paths`
- direct assertions on additive `assessment_summary`
- direct assertions on top-risk ordering when AI action paths are present
- stable alignment checks between summary facts and `action_path_to_control_first`
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: not required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- `core/report/report_test.go` directly covers additive `assessment_summary`
- direct report tests prove AI-path-first summary ordering when action paths exist
- `action_path_to_control_first` remains aligned with report summary facts
- existing CLI contract tests remain additive and green
Changelog impact: not required
Changelog section: none
Semver marker override: none
Architecture constraints:
- keep report shaping logic tested at the `core/report` boundary
- do not move ranking logic out of `core/risk` just to satisfy tests
- prefer compact deterministic fixtures over scenario-scale setup for package tests
ADR required: no
TDD first failing test(s):
- `core/report/report_test.go`: `assessment_summary` present and path-centric
- `core/report/report_test.go`: top summary risk is `action_path` when govern-first paths exist
Cost/perf impact: low
Chaos/failure hypothesis: If later report refactors accidentally fall back to generic finding-first output, direct report package tests must fail even before the broader CLI contract suite runs.

### Story GAP-05: Add direct builtin and help-surface coverage for `assessment`
Priority: P2
Tasks:
- Extend `core/policy/profile/profile_test.go` so builtin profile loading explicitly includes `assessment`.
- Add direct help-surface assertions that the scan profile help text includes `assessment` and stays aligned with the CLI flag contract.
- Keep these tests cross-platform-safe and independent of scenario fixtures.
- Update docs/help parity tests only if a real mismatch is found while adding the direct assertions.
Repo paths:
- `core/policy/profile/profile_test.go`
- `core/cli/root_test.go`
- `core/cli/scan.go`
- `docs/commands/scan.md`
Run commands:
- `go test ./core/policy/profile ./core/cli -count=1`
- `make test-docs-consistency`
- `make prepush-full`
Test requirements:
- explicit builtin load test for `assessment`
- help/usage assertion for `posture profile [baseline|standard|strict|assessment]`
- docs/help parity checks if help text or docs are touched
- deterministic invalid-input or help-output coverage only if new assertions require it
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: not required
- Cross-platform lane: required
- Risk lane: not required
Acceptance criteria:
- builtin profile tests explicitly include `assessment`
- scan help tests directly assert the `assessment` profile surface
- docs and help remain aligned if any wording changes are needed
- no scenario-only dependency is required to prove the additive profile is present
Changelog impact: not required
Changelog section: none
Semver marker override: none
Architecture constraints:
- keep builtin profile coverage in `core/policy/profile`
- keep help-surface coverage close to the CLI entrypoint
- avoid introducing docs or help text drift while adding direct tests
ADR required: no
TDD first failing test(s):
- `core/policy/profile/profile_test.go`: builtin `assessment` load expectation
- `core/cli/root_test.go`: scan help includes `assessment`
Cost/perf impact: low

## Minimum-Now Sequence

Wave 1: contract alignment and regression-gate hardening

- `GAP-01` Ratify and align the public `path_id` contract
- `GAP-02` Add deterministic first-offer CLI and report goldens
- `GAP-03` Enforce FO coverage-map keys in scenario contract validation

Wave 2: direct package-level coverage closure

- `GAP-04` Add direct `core/report` coverage for assessment summaries and AI-path-first output
- `GAP-05` Add direct builtin and help-surface coverage for `assessment`

Minimum-now gap-closure point:

- After Wave 1 is green, the remaining public-contract and regression-harness drift is closed.
- After Wave 2 is green, the original plan's promised package-level test evidence is fully present.

## Explicit Non-Goals

- Reopening first-offer feature scope that is already implemented and green
- Adding new govern-first fields, report sections, or profile behavior beyond the identified gaps
- Runtime provenance, live observation, selective gating, or enforcement claims
- Live-network regression fixtures or CI dependencies
- Changing exit codes, proof record types, or raw findings behavior
- Re-ranking govern-first logic for product reasons unrelated to the identified gaps
- General repo cleanup unrelated to these stories, including `scripts/__pycache__/`

## Definition of Done

- Every gap recommendation maps to at least one implemented story and a green test signal.
- `path_id` contract wording no longer conflicts with shipped behavior.
- FO-14 and FO-15 scenario packs have deterministic committed goldens and enforced coverage-map mappings.
- Direct `core/report`, `core/policy/profile`, and CLI help tests exist for the promised assessment behavior.
- `make prepush-full` is green for stories that touch contract/report/CLI/gate surfaces.
- `make test-risk-lane` is green for the regression-harness and report-risk stories.
- `make test-docs-consistency` and `make test-docs-storyline` remain green for any touched docs/help wording.
- No story widens Wrkr beyond its static-posture and offline-proof boundary.
- Implementation follow-up explicitly scopes or cleans unrelated dirty files before code changes.

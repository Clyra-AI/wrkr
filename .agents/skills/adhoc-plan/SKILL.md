---
name: adhoc-plan
description: Convert user-provided recommended work items into an execution-ready Wrkr backlog plan at a user-provided output path, with epics, stories, test requirements, and CI matrix wiring.
disable-model-invocation: true
---

# Recommendations to Backlog Plan (Wrkr)

Execute this workflow when the user asks to turn recommended items into a concrete backlog plan before implementation.

## Scope

- Repository root: `.`
- Recommendation source: user-provided recommended items for this run
- Standards sources of truth:
  - `./product/dev_guides.md`
  - `./product/architecture_guides.md`
- No dependency on `./product/ideas.md`
- Planning-only skill. Do not implement code in this workflow.

## Input Contract (Mandatory)

- `recommended_items`: structured list or raw text of recommended work to plan.
- `output_plan_path`: absolute or repo-relative file path where the generated plan will be written.

Validation rules:
- Both arguments are required.
- `output_plan_path` must resolve inside the repository and be writable.
- If either input is missing or invalid, stop and output a blocker report.

## Preconditions

- `./product/dev_guides.md` must exist and be readable.
- `./product/architecture_guides.md` must exist and be readable.
- Both guides must contain enforceable rules for:
  - testing and CI gating
  - determinism and contract stability
  - architecture/TDD/chaos/frugal governance requirements
- If guides are missing or incomplete, stop and output a blocker report.

## Workflow

1. Read `product/dev_guides.md` and `product/architecture_guides.md`; extract locked implementation and architecture constraints.
2. Parse `recommended_items` and normalize each item to:
- recommendation
- why
- strategic direction
- expected moat/benefit
3. Remove duplicates and out-of-scope items.
4. Cluster recommendations into coherent epics.
5. Prioritize with `P0/P1/P2` using contract risk, moat gain, adoption leverage, and dependency order.
6. Create execution-ready stories with:
- tasks
- repo paths
- run commands
- test requirements
- matrix wiring
- acceptance criteria
7. For every story, classify changelog intent deterministically:
- `Changelog impact: required` when the story changes user-visible behavior, public contract wording, CLI/help/JSON/exits, install/distribution UX, docs/governance/trust surfaces, or explicitly touches `CHANGELOG.md`
- `Changelog impact: not required` only for purely internal implementation details with no user-visible, public-contract, or OSS-governance effect
- `Changelog section:` one of `Added|Changed|Deprecated|Removed|Fixed|Security|none`
- `Draft changelog entry:` required when impact is `required`; write a single operator-facing bullet body without the leading `-`
- `Semver marker override:` optional; allowed values `none`, `[semver:patch]`, `[semver:minor]`, `[semver:major]`; use only when section-based semver inference would be wrong
8. If recommendations include cross-repo toolchain or scanner-remediation work, create the earliest required remediation wave epic (typically Wave 1) that includes:
- affected repo inventory
- canonical target version
- atomic pin surfaces (`go.mod`, local toolchain files, CI, docs, enforcement tests)
- scanner-specific validation on the built artifact
- rerun of the previously failing workflow/lane
9. For every story, enforce architecture fields:
- architecture constraints
- ADR required (`yes/no`)
- TDD first failing test(s)
- cost/perf impact (`low|medium|high`)
- chaos/failure hypothesis (required for risk-bearing stories)
10. Add plan-level `Public API and Contract Map` with stable/internal surfaces, shim/deprecation path, schema/versioning policy, and machine-readable error expectations.
11. Add plan-level `Docs and OSS Readiness Baseline` with README first-screen contract, integration-first docs flow, lifecycle path model, docs source-of-truth, and OSS trust baseline files.
12. Add plan-level `Test Matrix Wiring`.
13. Add `Recommendation Traceability` mapping recommendations to epic/story IDs.
14. Add `Minimum-Now Sequence`, `Exit Criteria`, and `Definition of Done`, with explicit dependency-driven wave order:
- Use `Wave 1 .. Wave N`, where `N >= 1`
- Create only 1 wave when scope is small and a split adds no implementation value
- Create multiple waves when dependency order, risk reduction, or reviewability benefits from staging
- When both classes exist, contract/runtime correctness and architecture-boundary work must complete in earlier waves before docs, OSS hygiene, and distribution UX waves
15. Verify quality gates.
16. Overwrite `output_plan_path` with the final plan.

## Handoff Contract (Planning -> Implementation)

- This skill intentionally leaves `output_plan_path` modified in the working tree.
- Expected follow-up is `adhoc-implement` with the same `plan_path` on a new branch.
- Generated plans must leave explicit story-level changelog fields so implementation can update `CHANGELOG.md` `## [Unreleased]` without re-deciding semver intent.
- If additional dirty files exist beyond the generated plan file, stop and scope/clean before implementation.

## Command Contract (JSON Required)

Use `wrkr` commands with `--json` whenever the plan needs machine-readable evidence, for example:

- `wrkr scan --json`
- `wrkr regress init --baseline <baseline-scan-path> --json`

## Non-Negotiables

- Preserve Wrkr contracts:
- determinism
- offline-first defaults
- fail-closed policy enforcement
- schema stability
- exit code stability
- Respect architecture boundaries:
- Go core authoritative for enforcement/verification
- Python remains thin adoption layer
- Enforce both standards guides in every generated plan:
  - `product/dev_guides.md`
  - `product/architecture_guides.md`
- No dashboard-first scope in core backlog.
- No minor polish as primary backlog.
- Use dependency-driven wave sequencing.
- It may be 1 wave or many waves depending on complexity, dependencies, and implementation risk.
- When both contract/runtime and docs/onboarding/distribution classes exist, all contract/runtime waves must precede later docs/onboarding/distribution waves.
- Use shared cross-repo onboarding taxonomy when docs/onboarding stories are in scope.
- Every story must include tests and matrix wiring.

## Architecture Guides Enforcement Contract

For stories touching architecture/risk/adapter/failure semantics, plan wiring must include:

- `make prepush-full`

For reliability/fault-tolerance stories, plan wiring must include:

- `make test-hardening`
- `make test-chaos`

For performance-sensitive stories, plan wiring must include:

- `make test-perf`

For boundary-sensitive stories, architecture constraints must include:

- thin orchestration with focused packages for parsing/persistence/reporting/policy logic
- explicit side-effect semantics in API names/signatures
- symmetric API semantics (`read` vs `read+validate`, `plan` vs `apply`)
- cancellation/timeout propagation for long-running flows
- extension points to reduce enterprise fork pressure

## Test Requirements by Work Type (Mandatory)

1. Schema/artifact changes:
- schema validation tests
- fixture/golden updates
- compatibility/migration tests

2. CLI behavior changes:
- help/usage tests
- `--json` stability tests
- exit-code contract tests
- machine-readable error envelope tests for automation/library consumers when applicable

3. Gate/policy/fail-closed changes:
- deterministic allow/block/require_approval fixtures
- fail-closed undecidable-path tests
- reason-code stability checks
- For stories that clean/reset output paths, require `non-empty + non-managed => fail` tests
- Require marker trust tests (`marker must be regular file`; reject symlink/directory)

4. Determinism/hash/sign/packaging changes:
- byte-stability repeat-run tests
- canonicalization/digest checks
- verify/diff determinism tests
- `make test-contracts` when applicable

5. Job runtime/state/concurrency changes:
- lifecycle tests
- crash-safe/atomic-write tests
- contention/concurrency tests
- chaos suites when applicable

6. SDK/adapter boundary changes:
- wrapper error-mapping tests
- adapter parity/conformance tests

7. Voice/context-proof changes:
- relevant scenario acceptance suites as applicable

8. Docs/examples changes:
- docs consistency checks
- storyline/smoke checks when user flow changes
- README first-screen checks (what/who/integration/quickstart)
- integration-before-internals guidance checks for touched flows
- docs source-of-truth mapping checks when repo docs/docs-site are both changed

9. API/contract lifecycle changes:
- public API map updates (stable/internal/shim/deprecated) for touched surfaces
- schema/version bump and migration expectation checks for contract changes
- version/install discoverability checks (`wrkr version`, minimal dependency install guidance)

10. OSS readiness changes:
- verify baseline OSS trust files when touched (`CONTRIBUTING`, `CHANGELOG`, `CODE_OF_CONDUCT`, issue/PR templates, security policy links)
- ensure maintainer/support expectations are explicit for public OSS behavior changes

11. Toolchain/runtime/security scanner changes:
- atomic pin updates across `go.mod`, local toolchain files, CI, docs, and enforcement tests
- built-artifact validation with the scanner used by CI (for example `govulncheck -mode=binary ./<binary>`)
- compatibility checks for shared cross-repo dependency constraints
- rerun of the previously failing workflow or equivalent required lane
- when advisories are fixed only in a later minor version, target the first fully fixed version rather than the nearest patch release

## Test Matrix Wiring Contract (Plan-Level)

The plan must include a `Test Matrix Wiring` section with:

- Fast lane
- Core CI lane
- Acceptance lane
- Cross-platform lane
- Risk lane
- Merge/release gating rule

Every story must declare its lane wiring.

## Plan Format Contract

Required sections:

1. `# PLAN <name>: <theme>`
2. `Date`, `Source of truth`, `Scope`
3. `Global Decisions (Locked)`
4. `Current Baseline (Observed)`
5. `Exit Criteria`
6. `Public API and Contract Map`
7. `Docs and OSS Readiness Baseline`
8. `Recommendation Traceability`
9. `Test Matrix Wiring`
10. Epic sections with objectives and stories
11. `Minimum-Now Sequence`
12. `Explicit Non-Goals`
13. `Definition of Done`

Story template:

- `### Story <ID>: <title>`
- `Priority:`
- `Tasks:`
- `Repo paths:`
- `Run commands:`
- `Test requirements:`
- `Matrix wiring:`
- `Acceptance criteria:`
- `Changelog impact: required|not required`
- `Changelog section: Added|Changed|Deprecated|Removed|Fixed|Security|none`
- `Draft changelog entry:` (required when `Changelog impact: required`; entry text only, no leading `-`)
- `Semver marker override: none|[semver:patch]|[semver:minor]|[semver:major]`
- `Contract/API impact:` (required for CLI/schema/sdk/library stories)
- `Versioning/migration impact:` (required for schema/contract changes)
- `Architecture constraints:`
- `ADR required: yes|no`
- `TDD first failing test(s):`
- `Cost/perf impact: low|medium|high`
- `Chaos/failure hypothesis:` (required for risk-bearing stories)
- Optional: `Dependencies:`, `Risks:`

## Quality Gate

Before finalizing:

- Every recommendation maps to at least one epic/story.
- Every story is actionable without guesswork.
- Acceptance criteria are testable and deterministic.
- Paths are real and repo-relevant.
- Every story includes an explicit changelog decision.
- Stories marked `Changelog impact: required` include a valid changelog section and draft entry.
- Stories touching CLI/contracts/docs/install/governance/trust surfaces are not left without changelog guidance.
- Test requirements match story type.
- Matrix wiring exists for every story.
- Every story maps to enforceable rules from both guides (`dev_guides.md`, `architecture_guides.md`).
- High-risk stories include hardening/chaos lane wiring.
- CLI contract stories include explicit `--json` and exit-code invariants.
- API/contract map is explicit for touched surfaces and deprecations.
- Schema/versioning and migration expectations are explicit for contract changes.
- Docs baseline includes README first-screen, integration-first flow, and lifecycle path model.
- OSS trust baseline files/maintainer expectations are addressed or explicitly deferred.
- Sequence enforces dependency-driven wave order.
- When both contract/runtime and docs/onboarding/distribution classes are present, earlier waves cover contract/runtime before later docs/onboarding/distribution waves.
- Sequence is dependency-aware and implementation-ready.

## Failure Mode

If inputs are missing or recommendations are not plan-ready, write only:

- `No backlog plan generated.`
- `Reason:` concise blocker summary.
- `Missing inputs:` exact required fields.

Do not fabricate backlog content.

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
7. For every story, enforce architecture fields:
- architecture constraints
- ADR required (`yes/no`)
- TDD first failing test(s)
- cost/perf impact (`low|medium|high`)
- chaos/failure hypothesis (required for risk-bearing stories)
8. Add plan-level `Test Matrix Wiring`.
9. Add `Recommendation Traceability` mapping recommendations to epic/story IDs.
10. Add `Minimum-Now Sequence`, `Exit Criteria`, and `Definition of Done`.
11. Verify quality gates.
12. Overwrite `output_plan_path` with the final plan.

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
- Every story must include tests and matrix wiring.

## Architecture Guides Enforcement Contract

For stories touching architecture/risk/adapter/failure semantics, plan wiring must include:

- `make prepush-full`

For reliability/fault-tolerance stories, plan wiring must include:

- `make test-hardening`
- `make test-chaos`

For performance-sensitive stories, plan wiring must include:

- `make test-perf`

## Test Requirements by Work Type (Mandatory)

1. Schema/artifact changes:
- schema validation tests
- fixture/golden updates
- compatibility/migration tests

2. CLI behavior changes:
- help/usage tests
- `--json` stability tests
- exit-code contract tests

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
6. `Recommendation Traceability`
7. `Test Matrix Wiring`
8. Epic sections with objectives and stories
9. `Minimum-Now Sequence`
10. `Explicit Non-Goals`
11. `Definition of Done`

Story template:

- `### Story <ID>: <title>`
- `Priority:`
- `Tasks:`
- `Repo paths:`
- `Run commands:`
- `Test requirements:`
- `Matrix wiring:`
- `Acceptance criteria:`
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
- Test requirements match story type.
- Matrix wiring exists for every story.
- Every story maps to enforceable rules from both guides (`dev_guides.md`, `architecture_guides.md`).
- High-risk stories include hardening/chaos lane wiring.
- CLI contract stories include explicit `--json` and exit-code invariants.
- Sequence is dependency-aware and implementation-ready.

## Failure Mode

If inputs are missing or recommendations are not plan-ready, write only:

- `No backlog plan generated.`
- `Reason:` concise blocker summary.
- `Missing inputs:` exact required fields.

Do not fabricate backlog content.

---
name: adhoc-implement
description: Implement a user-specified Wrkr backlog plan end-to-end with strict branch bootstrap, story-by-story execution, required test-matrix wiring, CodeQL validation, and final DoD/acceptance revalidation.
disable-model-invocation: true
---

# Adhoc Plan Implementation (Wrkr)

Execute this workflow for: "implement this plan file", "run plan from <path>", or "execute backlog from a custom plan doc."

## Scope

- Repository: `.`
- Mandatory input argument: `plan_path`
- `plan_path` must point to a specific plan document provided by the user
- No default fallback to `product/PLAN_NEXT.md`
- Planning input only; this skill performs implementation work in repo

## Input Contract (Mandatory)

- Required: `plan_path`
- Accepted forms:
- absolute path
- repo-relative path
- Input must resolve to an existing readable file
- If `plan_path` is missing or invalid, stop with blocker report

## Preconditions

- Plan file includes required structure:
- `Global Decisions (Locked)`
- `Exit Criteria`
- `Test Matrix Wiring`
- Story sections with `Tasks`, `Repo paths`, `Run commands`, `Test requirements`, `Matrix wiring`, `Acceptance criteria`
- If plan defines Wave 1/Wave 2 sequencing (or this can be inferred from story intent), Wave 1 must complete before Wave 2.
- If structure is incomplete, stop and report missing sections

## Git Bootstrap Contract (Mandatory)

Run in order before implementation:

1. `git fetch origin main`
2. `git checkout main`
3. `git pull --ff-only origin main`
4. `git checkout -b codex/adhoc-<plan-scope>`

Rules:
- If worktree is dirty before step 1:
- Allow only the plan-handoff case where all modified files are planning outputs and include `plan_path`.
- Planning-output allowlist: `./product/PLAN_NEXT.md`, `./product/PLAN_v1.0.md`, and selected `plan_path`.
- In the allowlist case, require current branch is already `main`, run step 1, skip steps 2-3, and create the branch from fetched `origin/main` with `git checkout -b codex/adhoc-<plan-scope> origin/main` to preserve plan edits on an up-to-date base.
- Otherwise stop and report blocker.
- If unexpected unrelated changes appear during execution, stop immediately and ask how to proceed
- Do not auto-commit or auto-push unless explicitly requested by the user

## Workflow

1. Parse plan and build execution queue by dependency and priority (`P0 -> P1 -> P2`).
- Detect wave ordering from plan labels (or infer if missing):
  - Wave 1: contract/runtime correctness and architecture boundaries
  - Wave 2: docs, OSS hygiene, distribution UX
- Execute all Wave 1 stories before any Wave 2 story.
- Do not start Wave 2 until Wave 1 acceptance criteria and mapped lanes are green.
2. Run baseline before first edit:
- `make lint-fast`
- `make test-fast`
- Record failures as pre-existing vs introduced.
3. Implement one story at a time (no parallel story execution).
4. For each story:
- implement scoped code/docs/tests only
- run story `Run commands`
- run story `Test requirements`
- run story `Matrix wiring` lanes
- mark complete only when acceptance criteria pass
5. Run epic-level validation after epic completion.
6. Run plan-level validation:
- `make prepush-full` (preferred), or
- `make prepush` plus `make codeql`
- Never finish without CodeQL unless explicitly waived by the user.
7. Revalidate all implemented work against:
- story acceptance criteria
- plan Definition of Done
- plan Exit Criteria
- Output `met/not met` with command evidence for each item.

## Command Contract (JSON Required)

When collecting evidence or emitting machine-readable status, use `wrkr` commands with `--json`, for example:

- `wrkr scan --json`
- `wrkr regress run --baseline <baseline-path> --json`

## Test Requirements by Work Type (Mandatory)

1. Schema/artifact contract changes:
- schema validation tests
- fixture/golden updates
- compatibility or migration tests
- `make test-contracts`

2. CLI behavior changes (flags/JSON/exits):
- `cmd/wrkr/*_test.go` command coverage
- `--json` stability checks
- exit-code contract checks

3. Gate/policy/fail-closed changes:
- deterministic allow/block/require_approval fixtures
- fail-closed undecidable-path tests
- reason-code stability checks
- regression input-boundary tests (`policy_check`/`policy_violation`/`parse_error` must not become tracked tools)
- lifecycle preservation tests (`present=false` identities must not be rewritten to `present=true` by generation flows)
- filesystem boundary tests for user-supplied output paths (`non-empty + non-managed => fail`)
- ownership marker trust tests (`marker must be regular file`; reject symlink/directory)

4. Determinism/hash/sign/pack changes:
- byte-stability repeat-run tests
- canonicalization/digest stability checks
- verify/diff determinism tests
- `make test-contracts` when applicable

5. Job runtime/state/concurrency changes:
- lifecycle tests (submit/checkpoint/pause/resume/cancel)
- atomic write/crash safety tests
- contention/concurrency tests
- chaos lanes when scoped

6. SDK/adapter boundary changes:
- wrapper behavior/error-mapping tests
- adapter conformance/parity tests
- `make test-adapter-parity` when applicable

7. Voice/context changes:
- `relevant scenario acceptance suites` as applicable

8. Docs/examples changes:
- `make test-docs-consistency`
- `make test-docs-storyline` when flow changes

9. API/contract lifecycle and OSS-readiness changes:
- public API classification updates for touched surfaces (`stable/internal/shim/deprecated`)
- schema/versioning + migration compatibility checks for contract changes
- machine-readable error envelope checks for automation/library consumers when applicable
- version/install discoverability checks (`wrkr version`, install docs smoke)
- OSS trust baseline checks when scope touches OSS posture (`CONTRIBUTING`, `CHANGELOG`, `CODE_OF_CONDUCT`, issue/PR templates, security policy links)

## Test Matrix Wiring (Enforcement)

Every story must map to and run required lanes:

- Fast lane: `make lint-fast`, `make test-fast`
- Core lane: targeted unit/integration suites
- Acceptance lane: relevant `make test-*-acceptance` targets
- Cross-platform lane: preserve Linux/macOS/Windows behavior on touched surfaces
- Risk lane: determinism/safety/security/perf suites as required

No story is complete if any required lane is skipped or failing.

## Surgical Docs Sync Rule

- If a story changes user-visible behavior, update only impacted docs in the same story:
- `./README.md`
- `./docs/`
- `./docs-site/public/llms.txt`
- `./docs-site/public/llm/*.md`
- For touched docs/onboarding surfaces, enforce:
- README first screen states what/who/integration/first-value path
- integration guidance appears before internals for changed flows
- file/state lifecycle path model remains coherent
- repo docs and docs-site stay in sync with one documented source-of-truth relationship
- If internal-only behavior with no user-visible impact, avoid unnecessary doc churn.

## Safety Rules

- Preserve determinism, offline-first defaults, fail-closed enforcement, schema stability, and exit-code stability.
- Never weaken unapproved posture => regression failure behavior.
- Do not allow recursive cleanup on user-supplied paths without explicit ownership validation tests.
- No destructive git operations unless explicitly requested.
- No silent skips of required tests/checks.
- Keep changes tightly scoped to active story.

## Quality Rules

- Claims must be evidence-backed by executed commands/tests.
- Do not claim tests ran if they were not run.
- Tests must use temp dirs for generated artifacts; do not leak test outputs into tracked source paths.
- If docs/CLI drift occurs due to user-visible changes, patch docs in same story.
- If both waves are in scope, keep Wave 2 blocked until Wave 1 passes required evidence gates.

## Blocker Handling

If blocked:
1. Stop blocked story immediately.
2. Report exact blocker and affected acceptance criteria.
3. Continue only independent unblocked stories.
4. End with minimum unblock actions.

## Completion Criteria

Implementation is complete only when all are true:

- All non-blocked in-scope stories are implemented.
- Required story tests and matrix lanes pass.
- Plan Definition of Done is satisfied.
- Plan Exit Criteria is satisfied.
- CodeQL validation is green.
- If Wave 2 stories were executed, Wave 1 stories were completed and validated first.

## Expected Output

- Execution summary: completed/deferred/blocked stories
- Change log: key files per story
- Validation log: commands and pass/fail
- Revalidation report: acceptance criteria + DoD + exit criteria (`met/not met` with evidence)
- Residual risk: remaining gaps and next required actions

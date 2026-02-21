---
name: backlog-implement
description: Implement a Wrkr backlog plan end-to-end (or a selected epic) from product/PLAN_NEXT.md (or a specified plan), with strict branch bootstrap, per-story test wiring, CodeQL validation, and scoped final revalidation. No issue/PR automation.
disable-model-invocation: true
---

# Plan Implementation (Wrkr)

Execute this workflow for: "implement the plan", "execute PLAN_NEXT", "ship plan stories", or "run backlog implementation end-to-end."

## Scope

- Repository: `/Users/davidahmann/Projects/wrkr`
- Default input plan: `/Users/davidahmann/Projects/wrkr/product/PLAN_NEXT.md`
- Optional input plan: user-specified file under `/Users/davidahmann/Projects/wrkr/product/`
- Optional scope selector: specific epic number from the input plan (`epic_number`)
- This skill executes code/docs/tests for planned stories.
- Out of scope by default:
- GitHub issue creation
- PR creation
- Automated comments/discussions
- Auto-commit/auto-push

## Input Contract (Mandatory)

- Optional: `plan_path`
- If omitted, default to `/Users/davidahmann/Projects/wrkr/product/PLAN_NEXT.md`.
- Optional: `epic_number`
- Accepted forms: `3`, `Epic 3`, `E3` (must resolve to exactly one heading `## Epic 3:` in the plan).
- Mode selection:
- If `epic_number` is provided -> `epic-only` mode.
- If `epic_number` is omitted -> `full-plan` mode (current default behavior).
- `plan_path` must resolve to a readable file under `/Users/davidahmann/Projects/wrkr/`.
- If `epic_number` is invalid or not found, stop and report blocker.

## Preconditions

- Plan file exists and is readable.
- Plan includes:
- `Global Decisions (Locked)`
- `Exit Criteria`
- `Test Matrix Wiring`
- Story-level `Tasks`, `Repo paths`, `Run commands`, `Test requirements`, `Matrix wiring`, `Acceptance criteria`
- If running in `epic-only` mode:
- Selected epic exists and can be resolved uniquely from `epic_number`.
- Every story in the selected epic contains required story-level fields.
- If selected stories declare dependencies outside selected epic, stop and report dependency blocker unless already satisfied.
- If required sections are missing, stop and report blockers.

## Git Bootstrap Contract (Mandatory)

Before implementation starts, run in order:

1. `git fetch origin main`
2. `git checkout main`
3. `git pull --ff-only origin main`
4. `git checkout -b codex/<plan-scope>`

Rules:
- If working tree is dirty before step 1, stop and report blocker for user decision.
- If unexpected changes appear during implementation, stop immediately and ask how to proceed.
- Do not switch to other branches unless user explicitly requests it.

## Workflow

1. Parse plan, determine mode, and build execution queue:
- In `full-plan` mode:
- Follow `Minimum-Now Sequence` first.
- Respect dependencies and `P0 -> P1 -> P2`.
- In `epic-only` mode:
- Queue only stories under selected epic.
- Respect intra-epic dependencies and story ordering.
- Do not auto-expand to other epics.

2. Run baseline before first code change:
- `make lint-fast`
- `make test-fast`
- Record failures as `pre-existing` vs `introduced`.

3. Execute one story at a time:
- Implement only scoped story changes.
- Update tests required by story type.
- Update docs surgically only if user-facing behavior changed.
- Do not start next story until current story is validated.

4. Validate story completion:
- Run story `Run commands`.
- Run story `Test requirements`.
- Run story `Matrix wiring` lanes.
- If anything required is skipped, mark story incomplete.

5. Run epic-level validation:
- In `full-plan` mode, after each completed epic.
- In `epic-only` mode, for the selected epic only.
- Execute relevant integration/acceptance suites for impacted surfaces.

6. Run final validation:
- `make prepush-full` (preferred, includes CodeQL), or
- `make prepush` and `make codeql` explicitly.
- Never finish without CodeQL unless user explicitly waives it.

7. Revalidate implementation against plan contracts:
- Re-check every implemented story against acceptance criteria.
- Re-check plan `Definition of Done` for touched stories.
- In `full-plan` mode:
- Re-check full plan `Exit Criteria`.
- In `epic-only` mode:
- Re-check only `Exit Criteria` directly mapped to selected epic stories.
- Mark all other plan-level exit criteria as `deferred (out of scope)`; do not fail epic completion for those items.
- Produce a `met/not met` checklist with command evidence for each item.

## Command Anchors

- `wrkr scan --json` to verify local environment and dependency readiness before implementation.
- `wrkr regress run --baseline <baseline-path> --json` for policy-story contract checks.
- `wrkr verify --chain --json` for artifact-story integrity checks.

## Test Requirements by Work Type (Mandatory)

1. Schema/artifact contract changes:
- Schema validation tests
- Golden fixtures
- Compatibility/migration tests
- `make test-contracts`

2. CLI behavior changes (flags/JSON/exits):
- Command tests in `cmd/wrkr/*_test.go`
- JSON output stability tests
- Exit-code contract tests

3. Gate/policy/fail-closed changes:
- Deterministic allow/block/require_approval fixture tests
- Fail-closed undecidable-path tests
- Stable reason-code tests
- Regression input-boundary tests (`policy_check`/`policy_violation`/`parse_error` must not become tracked tools)
- Lifecycle preservation tests (`present=false` identities must not be rewritten to `present=true` by generation flows)
- Filesystem boundary tests for user-supplied output paths (`non-empty + non-managed => fail`)
- Ownership marker trust tests (`marker must be regular file`; reject symlink/directory)

4. Determinism/hash/sign/packaging changes:
- Repeat-run byte-stability tests
- Canonicalization/digest stability tests
- Verify/diff determinism checks
- `make test-contracts` when relevant

5. Job runtime/state/concurrency changes:
- Lifecycle tests (submit/checkpoint/pause/resume/cancel)
- Atomic-write/crash-safety tests
- Contention/concurrency tests
- Chaos tests when scoped

6. SDK/adapter boundary changes:
- Wrapper behavior/error-mapping tests
- Adapter parity/conformance tests
- `make test-adapter-parity` when relevant

7. Voice/context evidence changes:
- `relevant scenario acceptance suites` as applicable

8. Docs/examples changes:
- `make test-docs-consistency`
- `make test-docs-storyline` when operator flow changes

## Test Matrix Wiring (Enforcement)

Each story must map to and run required lanes:

- Fast lane: `make lint-fast`, `make test-fast`
- Core lane: targeted unit/integration suites
- Acceptance lane: relevant `make test-*-acceptance` targets
- Cross-platform lane: ensure Linux/macOS/Windows-safe behavior for touched surfaces
- Risk lane: determinism/safety/security/perf suites as required by story

No story is complete without passing its mapped lanes.
In `epic-only` mode, required lanes are computed only from selected epic stories.

## Surgical Docs Sync Rule

If a story introduces user-visible behavior changes, update only impacted docs in the same story:

- `/Users/davidahmann/Projects/wrkr/README.md`
- `/Users/davidahmann/Projects/wrkr/docs/`
- `/Users/davidahmann/Projects/wrkr/docs-site/public/llms.txt`
- `/Users/davidahmann/Projects/wrkr/docs-site/public/llm/*.md`

If story is internal-only and behavior is unchanged, do not force doc churn.

## Safety Rules

- Preserve non-negotiables: determinism, offline-first, fail-closed, schema stability, stable exit codes.
- Never weaken unapproved posture => regression failure paths.
- Do not allow recursive cleanup on user-supplied paths without explicit ownership validation tests.
- No destructive git operations unless explicitly requested.
- No auto-commit or auto-push.
- Keep changes story-scoped; no unrelated refactors.

## Quality Rules

- Facts must be backed by command/test evidence.
- Do not claim tests ran if they did not.
- No silent skips of required checks.
- Tests must use temp output paths (no artifact leakage into source tree).
- If code/docs drift is introduced by user-facing change, patch docs in same story.

## Blocker Handling

If blocked:

1. Stop the blocked story.
2. Report exact blocker and impacted acceptance criteria.
3. Continue only independent unblocked stories.
4. End with minimum unblock actions.

## Completion Criteria

Implementation is complete only when all are true for active mode:

`full-plan` mode:
- All non-blocked in-scope stories are implemented.
- Story acceptance criteria are satisfied with evidence.
- Plan `Definition of Done` is satisfied.
- Plan `Exit Criteria` is satisfied.
- Required matrix lanes and CodeQL are passing.

`epic-only` mode:
- All non-blocked stories in selected epic are implemented.
- Story acceptance criteria for selected epic are satisfied with evidence.
- Plan `Definition of Done` clauses applicable to touched stories are satisfied.
- Plan `Exit Criteria` mapped to selected epic are satisfied.
- Non-mapped plan-level `Exit Criteria` are explicitly reported as `deferred (out of scope)`.
- Required matrix lanes for selected epic stories and CodeQL are passing.

## Expected Output

- `Mode`: `full-plan` or `epic-only`
- `Selected scope`: plan path and selected epic (when provided)
- `Execution summary`: completed/deferred/blocked stories
- `Change log`: files modified per story
- `Validation log`: commands and pass/fail results
- `Revalidation report`: story acceptance + DoD + exit criteria (`met/not met` with evidence)
- `Deferred criteria report`: plan-level criteria outside selected epic scope (required in `epic-only` mode)
- `Residual risk`: remaining gaps and next required stories

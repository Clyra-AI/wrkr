---
name: pr-comments
description: Pull all comments from user-provided PR numbers, implement fixes, validate, and ship via commit-push. For closed/merged PRs, use follow-up branches from main.
disable-model-invocation: true
---

# PR Comments Implement + Ship (Wrkr)

Execute this workflow when asked to take PR number(s), address comments, implement fixes, test, and ship.

## Scope

- Repository context: `.`
- Input PRs: user-provided PR number(s)
- Mode: implementation and ship
- Comment policy: use all comments from each provided PR regardless of resolved/outdated state

## Input Contract (Mandatory)

- `pr_numbers`: one or more PR numbers
- Optional:
- `repo` (owner/name if not inferable from current git remote)

If `pr_numbers` is missing, stop and report blocker.

## Preconditions

- `gh` auth must be available for read/write operations.
- Worktree must be clean before starting.
- If unexpected unrelated changes appear during execution, stop and ask.

## Git Bootstrap Contract (Mandatory)

Run before processing the first PR:

1. `git fetch origin main`
2. `git checkout main`
3. `git pull --ff-only origin main`

Rules:
- If worktree is dirty before step 1, stop and report blocker.
- If bootstrap fails, stop and report blocker.

## Comment Collection Contract

For each provided PR number, collect all of the following without filtering by comment state:

- Review thread comments (inline)
- Review summaries/body comments
- PR issue comments

Every fetched comment must be explicitly addressed in output as one of:
- `implemented`
- `already_satisfied`
- `blocked` (with concrete blocker)

Do not skip a comment because of resolved/outdated state.

## Branch Strategy

For each PR:

1. If PR state is `OPEN`:
- Attempt to use the PR head branch for implementation.
- If head branch cannot be checked out or pushed (for example permissions/fork limits), fall back to follow-up branch from `main`:
  - `codex/pr-comments-followup-<pr-number>`

2. If PR state is `CLOSED` or `MERGED`:
- Sync main first:
  - `git fetch origin main`
  - `git checkout main`
  - `git pull --ff-only origin main`
- Create follow-up branch from main:
  - `git checkout -b codex/pr-comments-followup-<pr-number>`
  - if name exists, append suffix (`-r1`, `-r2`, ...)
- Implement fixes on this follow-up branch.
- Follow-up PR must reference original PR URL and implemented comment URLs.

## Workflow

1. Resolve repository and validate `pr_numbers`.
2. Run baseline before first edit:
- `make lint-fast`
- `make test-fast`
- record failures as pre-existing vs introduced
3. For each PR number, sequentially:
- fetch PR metadata (state, base/head, latest head SHA)
- collect all comments per Comment Collection Contract
- establish working branch per Branch Strategy
- implement changes needed to address fetched comments
- keep fixes minimal and scoped to comment evidence
- classify every fetched comment (`implemented`, `already_satisfied`, `blocked`)
- run required tests per work type (see Test Requirements by Work Type)
- run required matrix lanes (see Test Matrix Wiring)
- run `make prepush-full`
- collect command-anchor evidence (see Command Anchors)
4. For each branch with actual file changes, run [`commit-push`](../commit-push/SKILL.md).
5. If a follow-up branch was used, ensure PR body references original PR + comment links.
6. Return per-PR ship summary.

## Test Requirements by Work Type (Mandatory)

1. Docs-only changes:
- `make test-docs-consistency`

2. CLI/schema/exit-code contract changes:
- targeted CLI tests for touched commands
- JSON key and exit-code compatibility checks
- `make test-contracts` when contract surfaces are touched

3. Policy/regression/fail-closed changes:
- deterministic allow/block/approval fixtures
- fail-closed path tests
- regression boundary and lifecycle preservation tests

4. Determinism/signing/proof-chain changes:
- repeat-run stability checks
- verify/diff determinism checks

5. Integration/runtime behavior changes:
- targeted integration/e2e tests for touched surfaces

## Test Matrix Wiring

For each PR batch, run at least:
- Fast lane: `make lint-fast`, `make test-fast`
- Core lane: targeted unit/integration suites for touched code
- Contract lane: `make test-contracts` when contract surfaces change
- Final gate: `make prepush-full`

No PR batch is complete if required lanes are skipped or failing.

## Command Anchors (JSON Required)

Collect machine-readable evidence with:
- `wrkr scan --json`
- `wrkr verify --chain --json` (when chain/integrity paths are touched)
- `wrkr regress run --baseline <baseline-path> --json` (when policy/regress paths are implicated)

## Wrkr Priorities for Fixes

Prioritize fixes affecting:
1. Fail-closed behavior and safety boundaries
2. Determinism and reproducibility contracts
3. CLI/schema/output compatibility (`--json`, exit codes, stable keys)
4. Security/privacy and unsafe operation guards
5. Lifecycle/regression correctness
6. Cross-platform portability and CI stability
7. User-visible docs drift when behavior changed

## Safety Rules

- Preserve determinism, offline-first defaults, fail-closed behavior, and contract stability.
- Never use destructive git commands.
- Never amend commits unless explicitly requested.
- Do not silently skip failed validations.
- Stop and report when blocked by missing permissions, missing refs, or failing required gates.
- Keep fixes scoped; avoid broad refactors not required by comment evidence.
- Never claim a comment was implemented without file/test evidence.

## Quality Rules

- Evidence-first: every reported decision maps to a fetched comment URL/id.
- Distinguish facts from inference.
- Do not claim tests ran if they were not run.
- Prefer minimal-risk fixes over broad refactors.

## Blocker Handling

If blocked for a PR batch:
1. Stop further edits on that PR batch immediately.
2. Record each blocked comment with exact blocker.
3. Continue only to next PR number when independent and safe.
4. End with explicit unblock actions.

## Expected Output

For each processed PR number:
- source PR number/state/url
- working branch used (head branch or follow-up branch)
- total comments fetched
- comments addressed:
  - implemented (comment ref, file refs, commit SHA)
  - already_satisfied (comment ref + verification note)
  - blocked (comment ref + blocker)
- tests and validations run (commands + pass/fail)
- ship result (if changes were made):
  - PR URL
  - merge commit SHA
  - post-merge main CI status

If no code changes were needed, explicitly report:
- `No file changes required after comment implementation review.`
- and skip `commit-push` for that PR batch.

---
name: cut-release
description: Cut a new Wrkr release tag directly from main, monitor release and post-release validation, and run up to 2 hotfix PR loops when failures are actionable.
disable-model-invocation: true
---

# Cut Release (Wrkr)

Execute this workflow for: "cut release", "ship vX.Y.Z", "push tag and monitor release."

## Scope

- Repository: `.`
- Tag source branch: `main` only.
- Allow one short-lived release-prep branch and PR only for finalized changelog publication before tagging.
- Branch and PR flow is otherwise used only for hotfixes after failed checks.
- Deterministic changelog finalization is allowed only through the release helper scripts below.
- Default posture: when a release or post-release blocker is actionable from repo code, workflow config, docs, or install-path behavior, fix it in-loop and continue instead of stopping at the first failure.

## Input Contract

- Optional input argument: `release_version`
- Normalize explicit versions to `vX.Y.Z`
- If `release_version` is missing, resolve it before any tag existence checks with:
  - `python3 scripts/resolve_release_version.py --json`
- Resolution contract for `scripts/resolve_release_version.py`:
  - if no tags exist, default to `v1.0.0`
  - `[semver:major]`, `[semver:minor]`, or `[semver:patch]` markers in `CHANGELOG.md` `## [Unreleased]` entries override section-based inference
  - `major`: any non-placeholder `### Removed` entry, or any `BREAKING:` / `BREAKING CHANGE` marker in `Unreleased`
  - `minor`: any non-placeholder `### Added` entry in `Unreleased`
  - `patch`: any non-placeholder `### Changed`, `### Fixed`, `### Security`, or `### Deprecated` entry in `Unreleased`
  - if changes exist since the latest tag but `CHANGELOG.md` does not provide a releasable semver signal, stop and report a blocker instead of inventing a patch bump

## Constants

- `MAX_HOTFIX_LOOPS=2`
- `CI_TIMEOUT_MIN=25`
- `RELEASE_TIMEOUT_MIN=40`
- `POLL_SECONDS=10`

## Safety Rules

- Tag must always be created and pushed from `main`.
- `main` must be fast-forward synced with `origin/main` before each tag push.
- Do not bypass branch protection on `main`; use the release-prep PR path when changelog finalization changes files.
- No force-push to tags.
- No destructive git commands.
- No commit amend unless explicitly requested.
- Do not hand-edit `CHANGELOG.md`; use `python3 scripts/finalize_release_changelog.py --json`.
- PR bodies and comments must use EOF heredoc (`--body-file - <<'EOF' ... EOF`).
- Do not cut a second tag until the current tag either passes release plus post-release validation or is superseded by an intentional hotfix tag.

## Workflow

### Phase 0: Main Sync and Pre-Tag Validation

1. `git fetch origin main`
2. `git checkout main`
3. `git pull --ff-only origin main`
4. Ensure clean worktree:
- `git status --porcelain` must be empty
5. Resolve the target version:
- if the user provided `release_version`, normalize it
- otherwise run `python3 scripts/resolve_release_version.py --json` and capture `version`, `bump`, `base_tag`, and `reason`
- if the resolver fails because `CHANGELOG.md` has no releasable semver signal, stop and report the blocker
6. Finalize the changelog for the resolved version before any tag checks:
- `python3 scripts/finalize_release_changelog.py --release-version <version> --json`
- `python3 scripts/validate_release_changelog.py --release-version <version> --json`
- if `CHANGELOG.md` changes:
  - create release-prep branch from current `main`:
    - `git checkout -b codex/release-prep-<version>`
  - commit only the finalized changelog there:
    - `git add CHANGELOG.md`
    - `git commit -m "chore: finalize changelog for <version>"`
  - push branch:
    - `git push -u origin codex/release-prep-<version>`
  - open release-prep PR using EOF body:
    - `gh pr create --base main --head codex/release-prep-<version> --title "chore: finalize changelog for <version>" --body-file - <<'EOF'`
    - include: problem, root cause, fix, validation
    - `EOF`
  - monitor PR CI to green (`CI_TIMEOUT_MIN`)
    - required Wrkr PR checks: `fast-lane`, `scan-contract`, `wave-sequence`, `windows-smoke`
    - also monitor `CodeQL` when present
    - use non-interactive watch or polling such as:
      - `gh pr checks <number> --watch --interval 10`
  - merge the release-prep PR after green:
    - `gh pr merge <number> --rebase --delete-branch`
  - sync `main` to the merged commit before continuing:
    - `git checkout main`
    - `git pull --ff-only origin main`
  - rerun `python3 scripts/validate_release_changelog.py --release-version <version> --json` on merged `main`
7. Ensure target tag does not already exist locally or remotely.
8. Ensure release prerequisites are available:
- `gh auth status`
- `gh workflow view release --repo Clyra-AI/wrkr`
- check `HOMEBREW_TAP_GITHUB_TOKEN` availability with:
  - `gh secret list --repo Clyra-AI/wrkr`
- if the secret check cannot be confirmed due permission limits, continue with a warning and rely on the release workflow’s fail-closed validation step
- if the secret is confirmed missing, stop and report blocker
9. Run local release preflight matching the current Wrkr release workflow contract:
- `make prepush-full`
- `go test ./... -count=1`
- `make test-docs-consistency`
- `make docs-site-install`
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`
- `scripts/run_docs_smoke.sh`
- `scripts/run_v1_acceptance.sh --mode=release`
- `make test-contracts`
- `scripts/validate_contracts.sh`
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `scripts/test_hardening_core.sh`
- `scripts/test_perf_budgets.sh`
- `scripts/run_agent_benchmarks.sh --output .tmp/release/agent-benchmarks-release.json`
- `go test ./internal/integration/interop -count=1`
- `make test-release-smoke`

If any step fails:
- if the failure is actionable from repo code, release workflow config, docs, or local environment config that this repo owns, implement the minimal fix set and rerun the full preflight
- stop only for external, non-actionable, or safety blockers, or after `2` consecutive no-progress remediation passes

### Phase 1: Tag and Release Monitor

1. Create annotated tag on `main`:
- `git tag -a <version> -m "<version>"`
2. Push tag:
- `git push origin <version>`
3. Monitor GitHub workflow `release` for that tag until green (`RELEASE_TIMEOUT_MIN`)
- capture run URL and terminal status using commands such as:
  - `gh run list --repo Clyra-AI/wrkr --workflow release --limit 5`
  - `gh run watch --repo Clyra-AI/wrkr <run-id>`
- prefer the tag-triggered run for `refs/tags/<version>`
4. If the release workflow fails:
- classify as:
  - actionable repo or workflow failure
  - flaky or transient infra failure
  - non-actionable external blocker
- for flaky or transient failures, rerun the workflow once and re-monitor
- for actionable failures, go to the hotfix loop
- for non-actionable blockers, stop and report

### Phase 2: Post-Release UAT

1. Run full local UAT against the released tag:
- `WRKR_UAT_RELEASE_VERSION=<version> bash scripts/test_uat_local.sh`
2. If UAT is green, release is complete.
3. If UAT fails:
- classify actionable vs non-actionable
- actionable -> go to hotfix loop
- non-actionable -> stop and report blocker

### Phase 3: Hotfix Loop (Only if Needed, Max 2)

For loop `r1..r2`:

1. Sync main:
- `git fetch origin main`
- `git checkout main`
- `git pull --ff-only origin main`

2. Create hotfix branch:
- `git checkout -b codex/release-hotfix-<base-version>-r<rN>`

3. Implement the minimal fix set for the identified failure.

4. Validate locally:
- `make prepush-full`
- rerun the failing lane locally:
  - release workflow equivalent subset, or
  - UAT subset, or
  - install-path smoke subset, depending on the failure source

5. Commit and push all unstaged files:
- `git add -A`
- `git commit -m "hotfix: release stabilization for <base-version> (r<rN>)"`
- `git push -u origin <hotfix-branch>`

6. Open PR using EOF body:
- `gh pr create --title "hotfix: release stabilization <base-version> (r<rN>)" --body-file - <<'EOF'`
- include: problem, root cause, fix, validation
- `EOF`

7. Monitor PR CI to green (`CI_TIMEOUT_MIN`):
- required Wrkr PR checks: `fast-lane`, `scan-contract`, `wave-sequence`, `windows-smoke`
- also monitor `CodeQL` when present
- use non-interactive watch or polling such as:
  - `gh pr checks <number> --watch --interval 10`
- if CI fails and the failure is actionable, fix the full actionable set on the same branch, rerun `make prepush-full`, push, and continue
- stop only for external, non-actionable, or safety blockers, or after `2` consecutive no-progress cycles

8. Merge PR after green.

9. Sync and monitor post-merge main CI:
- `git checkout main`
- `git pull --ff-only origin main`
- monitor latest `main` runs, including `CodeQL` when present:
  - `gh run list --repo Clyra-AI/wrkr --branch main --limit 10`
  - `gh run watch --repo Clyra-AI/wrkr <run-id>`
- if post-merge `main` CI is red and actionable, continue the same loop; it counts against the max hotfix loops

10. Bump patch version:
- `vX.Y.Z -> vX.Y.(Z+1)`

11. Create and push the new tag from `main`, then monitor `release` again:
- tag must still be cut from `main` only
- monitor until green (`RELEASE_TIMEOUT_MIN`)

12. Rerun full UAT for the new tag:
- `WRKR_UAT_RELEASE_VERSION=<new-version> bash scripts/test_uat_local.sh`

13. Exit conditions:
- if release plus UAT are green: success
- if loop count exceeds `2`: stop with blocker report
- if a non-actionable blocker appears: stop with blocker report

## Command Contract (JSON Required)

Capture release diagnostics using `wrkr` commands with `--json`, for example:

- `wrkr scan --json`
- `wrkr verify --chain --json`
- `wrkr regress run --baseline <baseline-path> --json`

## EOF Rule (Mandatory)

All PR body and comment text must be provided with heredoc EOF.  
No inline multi-line `--body` strings.

## CI and Release Policy

- Pre-tag local gate must include `make prepush-full`.
- Release workflow to monitor: `release`.
- Release workflow terminal success requires the release workflow and post-release UAT to be green for the tag being shipped.
- Hotfix PRs must satisfy Wrkr’s required PR checks:
  - `fast-lane`
  - `scan-contract`
  - `wave-sequence`
  - `windows-smoke`
- Also monitor `CodeQL` when present on hotfix PRs or `main`, even though it is not one of the four merge-blocking checks in `.github/required-checks.json`.
- Release and hotfix remediation policy: continue while failures are actionable and each cycle makes progress; stop after `2` consecutive no-progress cycles or when the blocker is external or safety-critical.

## Expected Output

- Initial requested version, resolved bump kind/source/reason, and final shipped version
- All tags pushed, with confirmation each was cut from `main`
- Release workflow run URL and status per tag
- UAT result per released tag
- Hotfix branch and PR URLs plus commit SHAs, if any
- Loop count used
- Final status: success or blocker with the last failing gate

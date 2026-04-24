---
title: "Changelog And Release Versioning"
description: "How Wrkr plans changelog entries, derives semver bumps, finalizes release notes, and validates tagged releases."
---

# Changelog And Release Versioning

This page is the end-to-end reference for how Wrkr decides `patch` vs `minor` vs `major`, who updates `CHANGELOG.md`, and which files and scripts participate in the release-versioning flow.

## Why this exists

Wrkr treats `CHANGELOG.md` as the release semver source of truth.
The release process should not guess whether a change is `patch`, `minor`, or `major` from commit messages or tag naming alone.
Instead, maintainers and implementation agents stage operator-facing release notes under `## [Unreleased]`, and release tooling derives the version bump from those entries deterministically.

## High-level flow

1. Planning decides whether each story needs a changelog entry.
2. Implementation updates `CHANGELOG.md` `## [Unreleased]` for stories that require it.
3. Release prep resolves the next version from `Unreleased`.
4. Release prep finalizes the changelog into a dated versioned section on a short-lived release-prep branch.
5. That release-prep PR is merged to `main`.
6. The tag-triggered release workflow validates that the tagged commit's changelog matches the tag.
7. `Unreleased` is empty again, so the next release only considers new changes.

## Ownership model

### Planning

Planning skills are responsible for deciding changelog intent at story level.
They must emit these fields for every story:

- `Changelog impact: required|not required`
- `Changelog section: Added|Changed|Deprecated|Removed|Fixed|Security|none`
- `Draft changelog entry:`
- `Semver marker override: none|[semver:patch]|[semver:minor]|[semver:major]`

This avoids pushing release-note judgment into the release step.

Relevant planning files:

- `factory/skills/adhoc-plan/SKILL.md`
- `factory/skills/backlog-plan/SKILL.md`
- `product/PLAN_NEXT.md` or another generated plan file

### Implementation

Implementation skills are responsible for applying the plan's changelog decision to `CHANGELOG.md` `## [Unreleased]`.
They do not finalize versioned release sections.
They only add or skip `Unreleased` entries according to the plan.

Relevant implementation files:

- `factory/skills/plan-implement/SKILL.md`
- `CHANGELOG.md`

### Release prep

Release prep is responsible for turning `Unreleased` into a real release section and validating that the tagged commit contains the correct finalized changelog.

Relevant release files:

- `scripts/release_changelog.py`
- `scripts/resolve_release_version.py`
- `scripts/finalize_release_changelog.py`
- `scripts/validate_release_changelog.py`
- `factory/skills/cut-release/SKILL.md`
- `.github/workflows/release.yml`

### CI

CI validates the changelog for a tag.
It does not edit `CHANGELOG.md`.

## Semver rules

Wrkr derives the bump from `CHANGELOG.md` `## [Unreleased]` using these rules:

- `major`
  - any non-placeholder `### Removed` entry
  - any entry containing `BREAKING:` or `BREAKING CHANGE`
- `minor`
  - any non-placeholder `### Added` entry
- `patch`
  - any non-placeholder `### Changed`, `### Fixed`, `### Security`, or `### Deprecated` entry

Explicit overrides are allowed when section-based inference would be wrong:

- `[semver:patch]`
- `[semver:minor]`
- `[semver:major]`

These markers live in `Unreleased` during planning/implementation and are stripped from the final versioned release notes when the changelog is finalized.

## Canonical changelog lifecycle

### 1. During planning

The plan should state exactly what the implementation must add to `Unreleased`.

Example:

```md
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: `wrkr scan --resume` now rejects reused materialized repo roots before detector execution.
Semver marker override: none
```

### 2. During implementation

The implementation skill updates `CHANGELOG.md` `## [Unreleased]`.

Example:

```md
### Fixed

- `wrkr scan --resume` now rejects reused materialized repo roots before detector execution.
```

At this stage:

- `Unreleased` is the working area for upcoming release notes
- no versioned `## [vX.Y.Z] - YYYY-MM-DD` section is created yet
- no tag-specific release date is added yet

### 3. During release prep

Resolve the next version:

```bash
python3 scripts/resolve_release_version.py --json
```

Finalize the changelog:

```bash
python3 scripts/finalize_release_changelog.py --json
```

Validate the prepared release version:

```bash
python3 scripts/validate_release_changelog.py --release-version vX.Y.Z --json
```

Then publish that finalized changelog update through a release-prep PR before creating the tag:

```bash
git checkout -b codex/release-prep-vX.Y.Z
git add CHANGELOG.md
git commit -m "chore: finalize changelog for vX.Y.Z"
git push -u origin codex/release-prep-vX.Y.Z
gh pr create --base main --head codex/release-prep-vX.Y.Z --title "chore: finalize changelog for vX.Y.Z" --body-file - <<'EOF'
...
EOF
gh pr checks <number> --watch --interval 10
gh pr merge <number> --rebase --delete-branch
git checkout main
git pull --ff-only origin main
python3 scripts/validate_release_changelog.py --release-version vX.Y.Z --json
```

### 4. After finalization

`CHANGELOG.md` should look like this shape:

```md
## [Unreleased]

### Added

- (none yet)

### Changed

- (none yet)

...

## [v1.2.4] - 2026-03-27
<!-- release-semver: patch -->

### Fixed

- `wrkr scan --resume` now rejects reused materialized repo roots before detector execution.
```

This is important because:

- the versioned section becomes the release-note record for the tagged version
- `Unreleased` is reset to the canonical empty template
- the next release can only see new entries added after that point

### 5. During tag workflow

The tagged release workflow validates the finalized changelog on the tagged commit itself:

```bash
python3 scripts/validate_release_changelog.py --release-version "${GITHUB_REF_NAME}" --json
```

If the tagged commit does not contain the matching versioned section, the release workflow fails closed.

## Script reference

### `scripts/release_changelog.py`

Shared library used by the release scripts.
It provides the common logic for:

- parsing `CHANGELOG.md`
- classifying semver bump from changelog content
- finding versioned sections and `Unreleased`
- finalizing the changelog into a versioned section
- validating that a versioned section matches a tag

This file is the canonical implementation of changelog parsing and semver classification.

### `scripts/resolve_release_version.py`

Read-only pre-release resolver.
It answers:

- what the next version should be
- what the bump is (`bootstrap`, `patch`, `minor`, `major`)
- which base tag it is derived from
- why that bump was selected

It does not modify `CHANGELOG.md`.

### `scripts/finalize_release_changelog.py`

Release-prep mutating script.
It:

- reads `## [Unreleased]`
- derives the release version
- promotes releasable entries into `## [vX.Y.Z] - YYYY-MM-DD`
- adds a hidden `<!-- release-semver: ... -->` hint for validation
- resets `Unreleased` to the canonical empty template

It is the only supported deterministic changelog-finalization path for release prep.

### `scripts/validate_release_changelog.py`

Read-only validator.
It checks that:

- the requested versioned section exists
- the section has releasable entries
- the section has an ISO date
- the versioned section's bump matches the expected version lineage
- `Unreleased` no longer contains releasable entries
- the canonical `Unreleased` sections are still present

It is used in release prep and in the tag workflow.

## File reference

### `CHANGELOG.md`

The semver source of truth for release planning and the permanent versioned release-note archive.

### `.github/workflows/release.yml`

The tag-triggered release workflow.
It validates the finalized changelog before running the rest of the release pipeline.

### `factory/skills/cut-release/SKILL.md`

The release operator workflow for this repo.
It now requires:

- resolving the version from changelog state
- finalizing the changelog
- validating the prepared version
- landing that changelog-prep state through a release-prep PR before tagging

### `factory/skills/adhoc-plan/SKILL.md` and `factory/skills/backlog-plan/SKILL.md`

Planning contracts that decide what should be written to `Unreleased`.

### `factory/skills/plan-implement/SKILL.md`

Implementation contract that applies planned changelog entries during story execution.

### `testinfra/hygiene/release_version_test.go`

Executable coverage for:

- semver derivation
- changelog finalization
- changelog validation
- release workflow integration
- release skill references

### `testinfra/hygiene/planning_skill_changelog_test.go`

Executable coverage for:

- planning skills requiring explicit changelog fields
- implementation skills consuming those fields

## Required commands

Use these when touching release-versioning logic:

```bash
go test ./testinfra/hygiene -run 'TestResolveReleaseVersion|TestFinalizeReleaseChangelog|TestValidateReleaseChangelog|TestPlanningSkillsRequireExplicitStoryChangelogFields|TestImplementationSkillsConsumeStoryChangelogFields' -count=1
make test-contracts
make test-docs-consistency
```

## Common questions

### Who edits the changelog?

- Planning decides changelog intent.
- Implementation updates `## [Unreleased]`.
- Release prep finalizes the changelog.
- CI validates only.

### Does release CI update `CHANGELOG.md`?

No.
Release CI validates the tagged commit's changelog and fails if it is wrong.

### What happens if nobody adds `Unreleased` entries?

`scripts/resolve_release_version.py` fails closed when changes exist but `CHANGELOG.md` provides no releasable semver signal.

### What happens after a release is finalized?

`Unreleased` is reset, so the next release derives its version only from newly added entries.

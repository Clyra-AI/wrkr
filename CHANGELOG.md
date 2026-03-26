# Changelog

All notable changes to Wrkr are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions align with repository release tags.

## [Unreleased]

### Added

- (none yet)

### Changed

- Public contract wording changes now count as changelog-worthy changes under `Unreleased`, even when JSON, exit-code, and schema contracts stay unchanged.
- README, quickstart, docs-site, and PRD onboarding now lead with the evaluator-safe scenario path and explicitly explain repo-root fixture noise before widening to hosted org posture.
- `wrkr fix` now supports explicit `--apply` mode for supported repo-file changes, additive `--max-prs` deterministic PR grouping, and additive machine-readable publication details while preserving preview mode semantics.
- Wrkr now ships a repo-root `action.yml` composite action that wraps the CLI, emits deterministic outputs, and supports explicit repo-targeted scheduled remediation dispatch.
- `wrkr report --pdf` now wraps and paginates executive output deterministically, and the board-ready claim is backed by explicit executive report acceptance fixtures.

### Fixed

- `wrkr evidence` now verifies the saved proof chain before bundle staging and fails closed on malformed or tampered proof state instead of publishing a new bundle.
- `wrkr identity approve|review|deprecate|revoke` now restore the prior committed manifest, lifecycle, and proof state when a downstream lifecycle or proof write fails.
- Hosted `wrkr scan --resume` now rejects symlink-swapped checkpoint files and reused materialized repo roots instead of trusting them as in-scope detector roots.
- Invalid `wrkr scan --report-md-path` or `--sarif-path` inputs are now rejected before managed `.wrkr` state and proof artifacts are written.
- `wrkr scan` now tolerates additive Claude/Codex vendor fields in supported configs instead of treating them as parse errors when known fields still parse cleanly.
- `wrkr scan` and `wrkr mcp-list` now emit explicit MCP-visibility warnings when known MCP-bearing declaration files fail to parse and posture may be incomplete.
- Hosted `wrkr scan --repo/--org` now resolves GitHub auth from `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`, and rate-limit failures now point operators at that auth path.
- `wrkr verify --chain` now always performs structural chain verification even when attestation or signature material is present.
- Invalid or unreadable verifier-key material now fails closed instead of silently downgrading to structural-only verification.
- `wrkr regress run` now reconciles legacy `v1` baselines created before instance identities when the current identity is equivalent.

### Security

- (none yet)

## Changelog maintenance process

1. Update `## [Unreleased]` in every PR that changes user-visible behavior, contracts, or governance process.
2. Before release tagging, promote relevant entries from `Unreleased` into a versioned section (for example `## [v1.0.1] - 2026-03-04`).
3. Keep entries concise and operator-facing: what changed, why it matters, and any migration/action notes.
4. Link release notes and tag artifacts to the finalized changelog section.

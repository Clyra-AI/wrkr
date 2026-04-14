# Changelog

All notable changes to Wrkr are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions align with repository release tags.

## [Unreleased]

### Added

- (none yet)

### Changed

- (none yet)

### Deprecated

- (none yet)

### Removed

- (none yet)

### Fixed

- (none yet)

### Security

- (none yet)

## Changelog maintenance process

1. Update `## [Unreleased]` in every PR that changes user-visible behavior, contracts, or governance process.
2. Before release tagging, run `python3 scripts/finalize_release_changelog.py --json` to promote releasable `Unreleased` entries into a dated versioned section and publish that change through a short-lived release-prep PR.
3. Validate the prepared release changelog with `python3 scripts/validate_release_changelog.py --release-version vX.Y.Z --json` on merged `main` before or during the tag workflow.
4. Keep entries concise and operator-facing: what changed, why it matters, and any migration/action notes.
5. Link release notes and tag artifacts to the finalized changelog section.

## [v1.1.1] - 2026-04-14
<!-- release-semver: patch -->

### Added

- Added repeatable `wrkr scan --target <mode>:<value>` support so one scan can combine multiple hosted and local targets while preserving legacy single-target flags.
- Wrkr can now scan multiple hosted orgs and local repository roots in one deterministic run, producing a single proof/state/report generation with explicit per-target failures when needed.

### Changed

- Release prep now lands finalized changelog updates through a short-lived release-prep PR before tagging when `main` is protected.
- Hosted GitHub scans now emit a dedicated `rate_limited` JSON error code after bounded retry exhaustion while keeping the documented runtime exit code unchanged.
- Multi-org scans now expose clearer per-target progress and fail-closed resume behavior, including explicit rejection of unsupported mixed-target resume combinations.
- Govern-first summaries now highlight stronger workflow identity and ownership evidence, with unresolved or conflicting ownership treated as a higher-priority governance signal.
- Workflow-backed govern-first paths and summaries now expose static trigger posture such as scheduled, workflow-dispatch, and deploy-pipeline backed execution when it changes governance urgency.
- Govern-first ranking now prioritizes the most urgent write, deploy, production-backed, and approval-gap paths first while keeping weaker paths visible lower in the ranked output.
- `recommended_action` now separates visibility, approval, proof, and control-first path classes more sharply on real-world govern-first scans and report summaries.
- Clarified repo-local contributor and agent guidance so Wrkr now delegates Go toolchain authority to the enforced 1.26.2 floor in `go.mod` and the development standards.
- Added config-backed hosted GitHub API base support to `wrkr init` and `wrkr scan` so org-first onboarding can be configured once without weakening the existing fail-closed hosted-scan contract.
- Added explicit `coverage_note` guidance to `wrkr evidence --json` so low first-run framework coverage is framed as an evidence gap rather than unsupported framework parsing.
- Reconciled the public launch docs so hosted org posture is the primary first-screen path, with the evaluator-safe scenario preserved as the explicit fallback and demo flow.
- Updated first-run evidence docs and docs-site mirrors so evidence-gap guidance sits directly beside the first evidence workflows instead of appearing later as a separate clarification.

### Fixed

- Hosted GitHub scans now retry recognizable rate-limit `403` responses using the observed reset window instead of failing immediately as generic runtime errors.
- Blocked scan sidecar output paths from aliasing managed state and proof artifacts, so invalid configurations now fail fast instead of corrupting saved scan state.
- Made `wrkr scan --path` honor single-repo root inputs while preserving deterministic repo-set scans for scenario bundles and local multi-repo roots.

### Security

- Raised Wrkr's enforced Go toolchain floor to 1.26.2 across local, CI, and nightly scanner surfaces to clear called standard-library vulnerabilities flagged by nightly `govulncheck`.

## [v1.1.0] - 2026-03-31
<!-- release-semver: minor -->

### Added

- Added an `assessment` scan profile that sharpens govern-first action-path output for customer readouts while keeping raw findings and proof artifacts unchanged.
- Added an AI-first assessment summary to report output so customer readouts lead with governable paths, top control targets, and offline proof location.
- Added identity exposure summaries and first-review or first-revoke recommendations for non-human execution identities backing risky govern-first paths.
- Action paths now classify the business state they can change and flag shared or standing-privilege identity reuse on repeated risky paths.
- Added grouped `exposure_groups` summaries so repeated risky paths can be reviewed as stable report clusters without hiding raw path detail.

### Changed

- Release prep now uses `scripts/finalize_release_changelog.py` to promote `## [Unreleased]` entries into a dated versioned section and reset `Unreleased` for the next cycle.
- Tag workflows now use `scripts/validate_release_changelog.py` to fail closed when the prepared versioned changelog section does not match the release tag.
- `scripts/resolve_release_version.py` now validates explicit release versions against the changelog-derived semver bump instead of accepting mismatched manual versions.
- Planning skills now require every story to declare changelog impact, target changelog section, and draft `Unreleased` entry so release semver can be derived deterministically from implemented work.
- Implementation skills now apply those planned changelog fields to `CHANGELOG.md` `## [Unreleased]` instead of re-deciding release-note scope during implementation.
- Org scans now stream deterministic progress events to stderr during execution while preserving stdout JSON contracts.
- Scan and report summaries now prioritize govern-first AI action paths ahead of generic supporting findings when risky paths are present.
- Govern-first `recommended_action` output now differentiates inventory, approval, proof, and control based on path context instead of collapsing most paths to approval.
- Clarified the public `action_paths[*].path_id` contract and aligned docs and contract tests with the shipped deterministic identifier format.
- Clarified scan and report wording so Wrkr's customer-facing output stays explicitly scoped to static posture, risky paths, and offline-verifiable proof.
- Govern-first summaries now highlight ownership quality and ownerless exposure so unresolved or conflicting ownership is explicit in top action paths.
- Updated scan, evidence, campaign, and extension-detector docs plus regression coverage to match the hardened contract and boundary behavior.

### Fixed

- Deduplicated govern-first `action_paths` so each deterministic action path emits one unique `path_id` row per scan.
- Priority detectors now surface permission and stat failures consistently in scan output so incomplete visibility is explicit.
- Made scan artifact publication transactional so failed late writes no longer leave mixed state, proof, and manifest generations on disk.
- `wrkr campaign aggregate` now rejects non-scan JSON and incomplete artifacts with stable `invalid_input` errors instead of summarizing them as posture evidence.
- Repo-local extension detectors now stay on additive finding surfaces by default and no longer create implicit tool identities, action paths, or regress state.

## [v1.0.11] - 2026-03-26
<!-- release-semver: patch -->

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
- Hardened managed output and scan-owned directory ownership checks so forged marker files can no longer authorize destructive reuse of caller-selected paths.

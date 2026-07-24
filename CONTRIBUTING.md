# Contributing to Wrkr

Wrkr is a deterministic, offline-first OSS CLI for AI tooling discovery, risk scoring, and proof artifacts. Every contribution must preserve contract stability, determinism, and fail-closed behavior.

## Required Toolchain

- Go `1.26.5`
- Git
- Make

## Optional Toolchain

- Python `3.13+` for script-based checks and some docs validation helpers.
- Node `22+` only for docs-site development (`docs-site/`).
- Homebrew for local install-path UAT checks.

Node is not required for the default Go-only contribution path.

Go validation uses `scripts/first_party_go_packages.sh` instead of root `./...`
wildcards so ignored docs-site dependency trees cannot change local, CI, UAT, or
release package scope.

## GitHub Actions Runtime Policy

- Local Node `22+` is only for docs-site and maintainer tooling. It is not the same contract as the GitHub-hosted JavaScript runtime used by workflow actions.
- Workflow action refs must stay on the audited Node24-ready set enforced by `scripts/check_actions_runtime.sh` and `make lint-fast`.
- Release/docs moving action refs must either be SHA-pinned or listed in `.github/action-ref-exceptions.yaml` with an owner, reason, exact workflow scope, expiry, and review command.
- Steady-state overrides are prohibited:
  - `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`
  - `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION`
- Current bounded exceptions are tracked in `.github/action-ref-exceptions.yaml`.
- Do not add new exceptions silently. If an exception changes, update workflow YAML, tests, and docs in the same PR.

## Go-Only Contributor Path (Default)

```bash
make fmt
make lint-fast
make test-fast
make test-coverage
make test-contracts
make test-scenarios
make prepush
```

This path is sufficient for most CLI/runtime changes and does not require Node.

## Focused Local Validation (Additive)

Use these only for narrow, local iteration before you run the full gate set required by the touched surface:

- `make test-focused-docs` for install, README, docs-site quickstart, and release-parity doc changes.
- `make test-focused-scan` for scan-status, partial-result, and hosted progress-counter changes.

These commands do not replace `make test-fast`, `make prepush`, contract lanes, scenario lanes, risk lanes, or release/UAT lanes when those are required by the story or touched surface.

## CI Lane Map

| Lane | Purpose | Local command anchor |
|---|---|---|
| Fast | quick contract + lint safety | `make lint-fast && make test-fast` |
| Core CI | deterministic package, numeric coverage, and contract coverage | `make prepush && make test-coverage` |
| Acceptance | operator-path scenario flows | `make test-scenarios` |
| Cross-platform | Linux/macOS/Windows behavior parity | avoid OS-specific assumptions in paths/fixtures |
| Risk | hardening/perf/chaos lanes for scoped changes | `make test-risk-lane` |

## Determinism Requirements

- Same input must produce the same inventory/risk/proof output, excluding explicit timestamp/version fields.
- Never add LLM/network-driven nondeterminism in scan/risk/proof paths.
- Keep JSON key names, exit codes (`0..8`), and schema contracts stable unless explicitly versioned.
- Prefer additive contract evolution; include migration/compatibility tests for any contract change.

## Detector Authoring Guidance

- Parse structured formats (JSON/YAML/TOML) with typed/schema-backed logic when possible.
- Avoid regex-only extraction for structured configs.
- Do not extract secret values; only emit risk context.
- Keep detector outputs stable and explainable (deterministic ordering, explicit reason codes).
- Add unit and fixture tests for success, parse failure, and boundary conditions.

## Pull Request Workflow

1. Keep scope tight and mapped to one story/contract change when possible.
2. Run required local commands for your touched surfaces (at minimum fast + core lane anchors).
   `make test-focused-docs` or `make test-focused-scan` are acceptable as the first local pass for narrow changes, but they are additive helpers only and do not satisfy merge or release gates by themselves.
   During Sprint 0 subtractive fixes, the temporary freeze gate blocks new scan/report fields, sidecars, detector breadth, report sections, and context dimensions unless they are directly required by Stories 1.1 through 4.2 or the size, redaction, and readability gates are green. recursive redaction and clone-strip contracts are part of that temporary freeze gate.
3. If workflow refs change, rerun the affected workflow class on your branch and inspect it for the absence of the prior deprecation warning:
   - `gh workflow run pr.yml --ref <branch>`
   - `gh workflow run nightly.yml --ref <branch>`
   - `gh workflow run release.yml --ref <branch>`
   - `gh workflow run docs.yml --ref <branch>`
   - `gh run watch --repo Clyra-AI/wrkr <run-id>`
4. Document any bounded exception you touched, its owner, expiry, exact workflow scope, review command, and why it is not SHA-pinned yet.
3. Document contract impact:
   - CLI flags/help/JSON/exits changed?
   - schema/output changed?
   - docs updated in same change for user-visible behavior?
5. Include command evidence in PR description (commands and pass/fail).
   Claims about artifact size, privacy, redaction, customer-safe sharing, or readability must include measured artifact-size deltas, redaction test names, and fixture coverage in the PR description or release-prep notes.
6. If docs are touched, follow [`docs/map.md`](docs/map.md) and run docs validation bundle.
7. For user-visible changes, update [`CHANGELOG.md`](CHANGELOG.md) under `Unreleased`.
   Public contract wording changes in `README.md`, command help, `docs/`, `product/`, or docs-site projections count even when JSON, exit codes, and schemas stay unchanged.
   Maintainers finalize `Unreleased` into a versioned section immediately before tagging with `python3 scripts/finalize_release_changelog.py --json`, publish that change through a short-lived release-prep PR, merge it to `main`, and only then create the tag from merged `main`.
8. For `product/` or `.agents/skills/` changes, confirm policy conformance per [`docs/governance/content-visibility.md`](docs/governance/content-visibility.md).

## Sprint 0 Receipt Rules

- Release-note or changelog hardening claims about size, privacy, redaction, customer-safe sharing, or readability require measured artifact-size deltas, named redaction tests, and fixture coverage.
- The v1.7.3 clarification workflow item must record actual before/after artifact sizes plus the exact redaction tests and fixtures used before release notes claim Sprint 0 hardening.

Issue/PR templates:

- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/feature_request.yml`
- `.github/ISSUE_TEMPLATE/docs_change.yml`
- `.github/pull_request_template.md`

## Docs Source of Truth

Edit canonical docs in this repo first (`README.md` and `docs/`), then validate:

```bash
make test-docs-consistency
make test-docs-storyline
make docs-site-install
make docs-site-lint
make docs-site-build
make docs-site-check
```

Use issue and PR templates for reproducible reports and contract-aware review context.

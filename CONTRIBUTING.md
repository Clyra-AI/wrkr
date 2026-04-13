# Contributing to Wrkr

Wrkr is a deterministic, offline-first OSS CLI for AI tooling discovery, risk scoring, and proof artifacts. Every contribution must preserve contract stability, determinism, and fail-closed behavior.

## Required Toolchain

- Go `1.26.2`
- Git
- Make

## Optional Toolchain

- Python `3.13+` for script-based checks and some docs validation helpers.
- Node `22+` only for docs-site development (`docs-site/`).
- Homebrew for local install-path UAT checks.

Node is not required for the default Go-only contribution path.

## GitHub Actions Runtime Policy

- Local Node `22+` is only for docs-site and maintainer tooling. It is not the same contract as the GitHub-hosted JavaScript runtime used by workflow actions.
- Workflow action refs must stay on the audited Node24-ready set enforced by `scripts/check_actions_runtime.sh` and `make lint-fast`.
- Steady-state overrides are prohibited:
  - `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`
  - `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION`
- Current bounded exceptions are limited to upstream-maintained actions that do not yet publish a Node24-ready release:
  - `actions/configure-pages@v5`
  - `actions/deploy-pages@v4`
  - `Homebrew/actions/setup-homebrew@cced187498280712e078aaba62dc13a3e9cd80bf`
  - `anchore/sbom-action@v0`
  - `anchore/scan-action@v4`
- Do not add new exceptions silently. If an exception changes, update workflow YAML, tests, and docs in the same PR.

## Go-Only Contributor Path (Default)

```bash
make fmt
make lint-fast
make test-fast
make test-contracts
make test-scenarios
make prepush
```

This path is sufficient for most CLI/runtime changes and does not require Node.

## CI Lane Map

| Lane | Purpose | Local command anchor |
|---|---|---|
| Fast | quick contract + lint safety | `make lint-fast && make test-fast` |
| Core CI | deterministic package and contract coverage | `make prepush` |
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
3. If workflow refs change, rerun the affected workflow class on your branch and inspect it for the absence of the prior deprecation warning:
   - `gh workflow run pr.yml --ref <branch>`
   - `gh workflow run nightly.yml --ref <branch>`
   - `gh workflow run release.yml --ref <branch>`
   - `gh workflow run docs.yml --ref <branch>`
   - `gh run watch --repo Clyra-AI/wrkr <run-id>`
4. Document any bounded exception you touched and why no Node24-ready upstream release exists yet.
3. Document contract impact:
   - CLI flags/help/JSON/exits changed?
   - schema/output changed?
   - docs updated in same change for user-visible behavior?
5. Include command evidence in PR description (commands and pass/fail).
6. If docs are touched, follow [`docs/map.md`](docs/map.md) and run docs validation bundle.
7. For user-visible changes, update [`CHANGELOG.md`](CHANGELOG.md) under `Unreleased`.
   Public contract wording changes in `README.md`, command help, `docs/`, `product/`, or docs-site projections count even when JSON, exit codes, and schemas stay unchanged.
   Maintainers finalize `Unreleased` into a versioned section immediately before tagging with `python3 scripts/finalize_release_changelog.py --json`, publish that change through a short-lived release-prep PR, merge it to `main`, and only then create the tag from merged `main`.
8. For `product/` or `.agents/skills/` changes, confirm policy conformance per [`docs/governance/content-visibility.md`](docs/governance/content-visibility.md).

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

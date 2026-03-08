# Contributing to Wrkr

Wrkr is a deterministic, offline-first OSS CLI for AI tooling discovery, risk scoring, and proof artifacts. Every contribution must preserve contract stability, determinism, and fail-closed behavior.

## Required Toolchain

- Go `1.26.1`
- Git
- Make

## Optional Toolchain

- Python `3.13+` for script-based checks and some docs validation helpers.
- Node `22+` only for docs-site development (`docs-site/`).
- Homebrew for local install-path UAT checks.

Node is not required for the default Go-only contribution path.

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
3. Document contract impact:
   - CLI flags/help/JSON/exits changed?
   - schema/output changed?
   - docs updated in same change for user-visible behavior?
4. Include command evidence in PR description (commands and pass/fail).
5. If docs are touched, follow [`docs/map.md`](docs/map.md) and run docs validation bundle.
6. For user-visible changes, update [`CHANGELOG.md`](CHANGELOG.md) under `Unreleased`.
7. For `product/` or `.agents/skills/` changes, confirm policy conformance per [`docs/governance/content-visibility.md`](docs/governance/content-visibility.md).

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

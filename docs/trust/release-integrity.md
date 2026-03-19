---
title: "Release Integrity"
description: "Release hardening checks, reproducibility expectations, and integrity verification surfaces for Wrkr artifacts."
---

# Release Integrity

## Release checks

- Deterministic test gates in release workflow.
- Contract and scenario validation before artifact generation.
- Node24-ready action refs on the release path for all remediable workflow helpers, enforced by `make lint-fast`.
- SBOM generation and vulnerability scanning in release pipeline.
- Exact release scanner/signing versions are pinned in CI and checked by local/CI hygiene gates.
- `CHANGELOG.md` release-note entries updated before tag publication.
- Current bounded release-path exceptions are explicit and reviewed during every runtime uplift:
  - `Homebrew/actions/setup-homebrew@cced187498280712e078aaba62dc13a3e9cd80bf`
  - `anchore/sbom-action@v0`
  - `anchore/scan-action@v4`

## Command anchors

```bash
make lint-fast
go test ./... -count=1
make test-contracts
scripts/validate_contracts.sh
make test-release-smoke
```

## Workflow rerun evidence

After changing release or docs workflow refs, rerun the affected workflow class on the branch and confirm the previous Node20 deprecation warning is gone for the upgraded refs:

```bash
gh workflow run release.yml --ref <branch>
gh workflow run docs.yml --ref <branch>
gh run watch --repo Clyra-AI/wrkr <run-id>
```

If a release-path helper still lacks a published Node24-ready upstream release, treat it as a bounded exception, document it in the same PR, and do not widen that exception set silently.

## Install-path UAT (release-candidate)

Run install-path UAT locally before cutting a release tag:

Treat `README.md`, this page, and `docs/install/minimal-dependencies.md` as the shared install and release-parity contract: Homebrew, pinned Go install, `wrkr version --json` verification, and optional secondary `@latest` convenience guidance.

```bash
# Full local gate set + source/release/homebrew-path checks
scripts/test_uat_local.sh

# Fast smoke lane used by release CI job
scripts/test_uat_local.sh --skip-global-gates

# Validate exact public install commands (brew + pinned go install) for a published tag
scripts/test_uat_local.sh --release-version v1.0.0 --brew-formula Clyra-AI/tap/wrkr
```

After any public install path, verify the installed CLI deterministically:

```bash
wrkr version --json
```

## Operational note

Consumers should verify published release checksums and provenance metadata before promotion.
Maintainers should treat changelog updates as release-gating documentation work, not an optional follow-up.
When using `wrkr verify --chain --json` as a release/promotion gate, inspect `chain.verification_mode` and `chain.authenticity_status` in addition to exit code `0`; `chain_only/unavailable` is an explicit structural-only result, not authenticated proof verification.

## Q&A

### Which checks should pass before trusting a Wrkr release?

Deterministic test gates, contract validation, Node24 runtime policy checks, and integrity outputs (checksums/provenance) should all pass before promotion.

### How do I verify artifact integrity after download?

Validate published checksums and provenance metadata against the release artifact you intend to promote.

### Do docs-site development dependency advisories affect Wrkr runtime guarantees?

Wrkr runtime guarantees are tied to the Go CLI contract surfaces. Docs-site advisories should still be tracked, and production/runtime audit gates should remain green.

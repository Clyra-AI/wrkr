---
title: "Release Integrity"
description: "Release hardening checks, reproducibility expectations, and integrity verification surfaces for Wrkr artifacts."
---

# Release Integrity

## Release checks

- Deterministic test gates in release workflow.
- Contract and scenario validation before artifact generation.
- Node24-ready action refs on the release path for all remediable workflow helpers, enforced by `make lint-fast`.
- Public docs-site Markdown is treated as untrusted input; raw HTML, unsafe attributes, and unsafe link schemes are escaped or blocked before static HTML publish.
- Docs-site production dependency advisories are release-trust inputs. High and critical advisories fail closed, and moderate advisories require an exact checked-in exception when no patched stable upstream dependency is available.
- Tag releases build candidate artifacts without publishing them, verify checksums, generate an SBOM, run Grype, sign the checksum manifest, generate and verify provenance attestations, and only then publish GitHub release assets and Homebrew tap updates.
- Exact release scanner/signing versions are pinned in CI and checked by local/CI hygiene gates.
- `CHANGELOG.md` release-note entries finalized before tag publication with `scripts/finalize_release_changelog.py`, and tag builds verify them with `scripts/validate_release_changelog.py`.
- Broad major aliases on the release/docs scanner and GitHub Pages helper path are removed. These helpers are pinned to immutable commit refs:
  - `actions/configure-pages@983d7736d9b0ae728b81ab479565c72886d7745b`
  - `actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e`
  - `anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610`
  - `anchore/scan-action@64a33b277ea7a1215a3c142735a1091341939ff5`
- Remaining release/docs action-ref exceptions are explicit in `.github/action-ref-exceptions.yaml`, owner-scoped, expiring, and reviewed during every runtime uplift.

## Command anchors

```bash
make lint-fast
python3 scripts/validate_docs_site_audit.py --repo-root . --json
python3 scripts/resolve_release_version.py --json
python3 scripts/finalize_release_changelog.py --json
python3 scripts/validate_release_changelog.py --release-version vX.Y.Z --json
go test ./... -count=1
make test-contracts
scripts/validate_contracts.sh
make test-release-smoke
```

## Docs-site trust posture

`make docs-site-check` and `npm test -- --test-name-pattern markdown` verify that hostile Markdown fixtures cannot publish raw script, unsafe attributes, malicious titles, or unsafe link schemes while safe docs features like repo-relative links, headings, code blocks, and Mermaid diagrams still render deterministically.

`make docs-site-audit-prod` is the single audit entry point for docs-site production dependencies. It runs `npm audit --omit=dev --json` through `scripts/validate_docs_site_audit.py`, then compares live advisory output against [`docs-site/security-advisory-exceptions.json`](../../docs-site/security-advisory-exceptions.json). Each exception must remain:

- owner-scoped
- expiring
- pinned to the advisory id, affected node path, direct dependency, and locked current version
- removable as soon as a patched stable upstream release clears the advisory

If an advisory disappears, the node path changes, the direct dependency version drifts, or the exception expires, the gate fails closed instead of silently approving the docs site.

## Factory profile trust posture

`python3 scripts/validate_profiles.py --repo-root . --profile wrkr --json` validates that Wrkr's Factory profile still points at current standards docs, user-facing docs paths, and high-risk review surfaces. This keeps code-review and app-audit automation aligned with the real repository layout, including the MCP detector packages, instead of relying on stale review targets.

## Workflow rerun evidence

After changing release or docs workflow refs, rerun the affected workflow class on the branch and confirm the previous Node20 deprecation warning is gone for the upgraded refs:

```bash
gh workflow run release.yml --ref <branch>
gh workflow run docs.yml --ref <branch>
gh run watch --repo Clyra-AI/wrkr <run-id>
```

If a release-path helper still lacks a published Node24-ready upstream release, treat it as a bounded exception, document it in the same PR, and do not widen that exception set silently.

## Publish sequence

For tag builds, treat release publication as the final gated step:

1. Build candidate artifacts into `dist/` without publishing them.
2. Verify checksums.
3. Generate an SBOM.
4. Run Grype against the staged artifacts.
5. Sign the checksum manifest.
6. Generate and verify provenance attestations.
7. Publish GitHub release assets and Homebrew tap updates from the verified staged set.

## Install-path UAT (release-candidate)

Run install-path UAT locally before cutting a release tag:

Treat `README.md`, this page, and `docs/install/minimal-dependencies.md` as the shared install and release-parity contract: Homebrew, pinned Go install, `wrkr version --json` verification, and optional secondary `@latest` convenience guidance.

```bash
# Full local gate set + source/release/homebrew-path checks
scripts/test_uat_local.sh

# Fast smoke lane used by release CI job
scripts/test_uat_local.sh --skip-global-gates

# Validate exact public install commands (brew + pinned go install) for a published tag
scripts/test_uat_local.sh --release-version v1.7.2 --brew-formula Clyra-AI/tap/wrkr
```

## Changelog finalization

Before tagging a release, resolve the next version from `## [Unreleased]`, then finalize the changelog and validate that the prepared versioned section matches the intended tag:

```bash
python3 scripts/resolve_release_version.py --json
python3 scripts/finalize_release_changelog.py --json
python3 scripts/validate_release_changelog.py --release-version vX.Y.Z --json
```

The finalizer promotes releasable `Unreleased` entries into `## [vX.Y.Z] - YYYY-MM-DD`, adds a hidden semver hint for CI validation, and resets `Unreleased` to the canonical empty template so the next release only considers new entries. Publish that changelog update through a short-lived release-prep PR before creating the tag; the tag workflow validates the changelog content from the tagged commit itself.

For the full changelog ownership model, planning/implementation handoff, and file/script reference, see [`docs/trust/changelog-and-release-versioning.md`](changelog-and-release-versioning.md).

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

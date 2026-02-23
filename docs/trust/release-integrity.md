---
title: "Release Integrity"
description: "Release hardening checks, reproducibility expectations, and integrity verification surfaces for Wrkr artifacts."
---

# Release Integrity

## Release checks

- Deterministic test gates in release workflow.
- Contract and scenario validation before artifact generation.
- SBOM generation and vulnerability scanning in release pipeline.

## Command anchors

```bash
go test ./... -count=1
make test-contracts
scripts/validate_contracts.sh
make test-release-smoke
```

## Install-path UAT (release-candidate)

Run install-path UAT locally before cutting a release tag:

```bash
# Full local gate set + source/release/homebrew-path checks
scripts/test_uat_local.sh

# Fast smoke lane used by release CI job
scripts/test_uat_local.sh --skip-global-gates

# Validate exact public install commands (brew + pinned go install) for a published tag
scripts/test_uat_local.sh --release-version v1.0.0 --brew-formula Clyra-AI/tap/wrkr
```

## Operational note

Consumers should verify published release checksums and provenance metadata before promotion.

## Q&A

### Which checks should pass before trusting a Wrkr release?

Deterministic test gates, contract validation, and integrity outputs (checksums/provenance) should all pass before promotion.

### How do I verify artifact integrity after download?

Validate published checksums and provenance metadata against the release artifact you intend to promote.

### Do docs-site development dependency advisories affect Wrkr runtime guarantees?

Wrkr runtime guarantees are tied to the Go CLI contract surfaces. Docs-site advisories should still be tracked, and production/runtime audit gates should remain green.

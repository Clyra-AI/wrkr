# Install With Minimal Dependencies

This page is the install contract source for environments that only have Go and standard shell tooling.

The main README landing page may show a convenience `@latest` install path. This page remains the pinned and reproducible install contract for CI, release validation, and support.

## Go-only pinned install

```bash
WRKR_VERSION="v1.0.0"
go install github.com/Clyra-AI/wrkr/cmd/wrkr@"${WRKR_VERSION}"
```

Use this path for deterministic onboarding and CI scripts that pin a known release.

## Latest release tag without `gh` or `python3`

```bash
WRKR_VERSION="$(curl -fsSL https://api.github.com/repos/Clyra-AI/wrkr/releases/latest | sed -nE 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
test -n "${WRKR_VERSION}"
go install github.com/Clyra-AI/wrkr/cmd/wrkr@"${WRKR_VERSION}"
```

This path uses `curl`, `sed`, and `head` only.

## Homebrew path

```bash
brew install Clyra-AI/tap/wrkr
```

## Release-smoke validation commands

Install commands above are validated by release UAT:

```bash
scripts/test_uat_local.sh --skip-global-gates
scripts/test_uat_local.sh --release-version v1.0.0 --skip-global-gates
scripts/test_uat_local.sh --release-version v1.0.0 --brew-formula Clyra-AI/tap/wrkr --skip-global-gates
```

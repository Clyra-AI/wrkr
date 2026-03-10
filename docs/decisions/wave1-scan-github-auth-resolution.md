# ADR: Hosted Scan GitHub Auth Resolution

Date: 2026-03-10

## Status

Accepted

## Context

Hosted `wrkr scan --repo/--org` required an explicit GitHub API base, but token resolution was inconsistent with docs and operational expectations. Public unauthenticated scans could fail on rate limiting, while the command did not consume ambient token inputs that operators commonly use in CI and local automation.

Wrkr must remain explicit and fail closed for hosted acquisition.

## Decision

- Preserve explicit hosted-source selection through `--github-api` or `WRKR_GITHUB_API_BASE`.
- Resolve hosted scan tokens in this order:
  1. `--github-token`
  2. config `auth.scan.token`
  3. `WRKR_GITHUB_TOKEN`
  4. `GITHUB_TOKEN`
- Keep GitHub rate-limit and auth failures as `runtime_failure` with exit `1`.
- Make the runtime error message explicitly point operators to the supported auth paths.
- Keep ambient env-token fallback runtime-only; `wrkr init --json` continues to report only config-persisted token state.

## Consequences

- Hosted scan onboarding is more self-serve without introducing hidden network defaults.
- Explicit flag/config precedence is preserved.
- Operators still get fail-closed behavior when auth is missing or insufficient, but the remediation path is clearer.

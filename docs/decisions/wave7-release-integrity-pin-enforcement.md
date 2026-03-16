# ADR: Wave 7 Release Integrity Pin Enforcement

Date: 2026-03-15
Status: accepted

## Context

Wrkr's public standards documentation pins exact release-integrity tool versions for `cosign`, `Syft`, and `Grype`, but the release workflow had drifted from that contract and local enforcement only hard-failed a narrower tool subset.

The launch-alignment plan requires:

- atomic alignment between normative docs and workflow implementation
- hard-fail detection of future release pin drift in local and CI gates
- preservation of deterministic release behavior without introducing hidden wrappers or hosted dependencies

## Decision

1. Keep `product/dev_guides.md` as the normative version source for release-integrity tool pins.
2. Pin the release workflow's `cosign`, `Syft`, and `Grype` versions to the documented values.
3. Extend `scripts/check_toolchain_pins.sh` and hygiene tests so release-integrity drift fails in `make lint-fast` before merge or release.
4. Keep the enforcement scope explicit and auditable rather than relying on implicit action-managed tool defaults.

## Rationale

- Release-integrity claims only build trust if docs, workflow, and enforcement agree.
- Failing fast in the local fast lane prevents release drift from becoming a late-stage discovery.
- Explicit pin checks are easier to audit than action wrappers with hidden default versions.

## Consequences

- Future release pin changes must update docs, workflow, and enforcement together.
- `make lint-fast` now blocks drift on the release-integrity subset instead of only style/lint tooling.
- Release-related docs can stay high-level while the enforced version truth remains machine-checkable in the repo.


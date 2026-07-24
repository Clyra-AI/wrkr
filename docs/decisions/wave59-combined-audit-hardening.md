# Wave 59: Combined audit hardening

Status: Accepted  
Date: 2026-07-23

## Context

The combined repository code review and application-readiness audit identified four release-blocking gaps:

1. A repository-local transaction journal could be supplied by an untrusted clone and interpreted as recovery instructions.
2. Coverage guidance existed without numeric CI enforcement.
3. The Sprint 0 public-surface freeze receipt recorded assertions but did not execute and bind its validation evidence to the tested source.
4. First-value scan and evidence command envelopes retained more repeated enterprise detail than operators needed.

The same audit found a stale Go version in the Factory profile pointer. The repository and Factory profile must have one enforceable toolchain contract.

## Decision

Wrkr adopts these controls in one patch wave:

- Transaction recovery journals move outside repositories into the operating system's private user cache. Journals are keyed and content-bound to the canonical state path, constrained to regular owner-private files, identity-checked while opened, and validated for unique canonical artifact paths captured under the state lease before recovery. Legacy repository-local journals are never replayed and fail closed with exit `8`.
- `make test-coverage` enforces an 85% aggregate core target and 75% per-package target in pull request, main, release, and full pre-push lanes. Current gaps are recorded as expiring, owner-assigned non-regression floors rather than silently waived.
- The freeze gate validates a digest of its declared source scope, directly executes allowlisted `go test` commands plus the exact-byte Action Contract fixture check, records output hashes and exit codes, and publishes a runtime receipt. Protected CI lanes require a clean worktree.
- Scan and evidence command-response previews use smaller deterministic caps while canonical state, customer-redacted BOM, and full report-evidence artifacts retain the governed detail paths.
- Toolchain pin validation includes `factory/profiles/wrkr.yaml`; the Factory submodule pointer advances to the profile revision carrying Go `1.26.5`.

## Consequences

- An interrupted operation created by a version that used repository-local journals requires operator inspection and removal of the legacy journal before rerun. Wrkr does not automatically migrate untrusted recovery instructions.
- Coverage cannot regress below the committed floor even where a package has not yet reached the target. Exceptions expire and name owners, follow-up work, and compensating validation lanes.
- Freeze evidence becomes source-bound and reproducible. Editing any declared source scope without refreshing the receipt causes the gate to fail.
- Machine consumers that relied on uncapped command-response arrays must use the canonical state or documented full evidence artifacts.

## Rollback

Rollback must preserve the security properties. A replacement journal design must remain outside the repository trust boundary or require a comparably strong authenticated provenance mechanism. Coverage and freeze gates may be replaced only by controls that enforce the same numeric, source-bound contracts in protected CI.

## Validation

- Transaction traversal, legacy-journal rejection, interrupted recovery, and JSON exit-code tests.
- Aggregate and per-package coverage enforcement in CI with tamper tests for missing, stale, and regressed exception data.
- Freeze receipt contract tests, content-digest verification, direct test execution, and runtime-receipt upload contracts.
- Enterprise-pressure size, redaction, clone-strip, scenario, contract, hardening, and CodeQL lanes.

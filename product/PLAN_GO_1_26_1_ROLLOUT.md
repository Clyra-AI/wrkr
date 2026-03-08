# PLAN Cross-Repo Go 1.26.1 Remediation: scanner-gate recovery

Date: 2026-03-08
Source of truth:
- `wrkr` run `22792249754`
- `gait` runs `22792367021`, `22792919694`
- https://go.dev/blog/go1.26
- https://pkg.go.dev/vuln/GO-2026-4600
- https://pkg.go.dev/vuln/GO-2026-4599
Scope: Any Clyra repo failing `govulncheck` while pinned to `go1.25.7`.

## Global Decisions (Locked)

- Target `Go 1.26.1` everywhere. Do not stop at `1.25.8`; it leaves the `crypto/x509` findings unresolved.
- Treat the toolchain pin as an atomic contract change: `go.mod`, CI, local toolchain files, docs, and pin-enforcement tests move together.
- Do not bypass `govulncheck`, relax severity, or path-gate the failure away.
- Preserve CLI behavior, JSON output, schemas, and exit codes. This is a toolchain-floor change, not a runtime contract redesign.

## Current Baseline (Observed)

- On March 7, 2026, `wrkr` run `22792249754` failed under `go1.25.7` during binary-mode `govulncheck`.
- On March 7, 2026, `gait` runs `22792367021` and `22792919694` failed under `go1.25.7` during binary-mode `govulncheck`.
- The observed advisories were `GO-2026-4602`, `GO-2026-4601`, `GO-2026-4600`, and `GO-2026-4599`.
- `1.25.8` removes only a subset of those findings; `1.26.1` is the first version that clears all called standard-library vulnerabilities observed in the failing runs.

## Exit Criteria

- Every affected repo has no remaining `1.25.7` or `1.25.8` pin surfaces.
- Local binary-mode `govulncheck` reports no called vulnerabilities on the built binary.
- Repo pin-enforcement tests and contract tests pass.
- The same workflow lane that failed before is green after the bump.
- User-facing docs and contributor setup docs reflect `Go 1.26.1`.

## Public API and Contract Map

- Stable surfaces:
  - CLI flags
  - JSON keys
  - schema fields
  - exit codes
  - merge-blocking workflow status names when branch protection depends on them
- Internal surfaces:
  - workflow implementation details
  - helper scripts
  - pin-enforcement tests
- Shim/deprecation path:
  - none; this is a direct minimum-toolchain raise
- Schema/versioning policy:
  - no schema version bump expected
  - contributor and CI toolchain minimums must be updated in the same change
  - machine-readable outputs remain unchanged

## Docs and OSS Readiness Baseline

- Update `CONTRIBUTING`, `README`, repo docs, or policy docs if they declare a Go version.
- Update `.tool-versions`, `mise.toml`, bootstrap scripts, devcontainers, or Dockerfiles if present.
- If the repo has governance docs like `product/dev_guides.md`, update the normative table before or with enforcement changes.
- Keep PR evidence explicit: exact commands run, exact failing workflow replaced by passing rerun.

## Recommendation Traceability

- `R1` Fix all repos failing the March 2026 stdlib advisory wave.
- `R2` Standardize on `Go 1.26.1`, not mixed patch levels.
- `R3` Preserve scanner enforcement; remediate the floor instead of weakening the gate.

## Test Matrix Wiring

- Fast lane:
  - lint
  - unit tests
  - contract and pin-enforcement checks
- Core CI lane:
  - repo-equivalent of `prepush` or full deterministic test bundle
- Acceptance lane:
  - integration/E2E suites when present
- Cross-platform lane:
  - rerun the platform that failed before
  - preserve Windows validation if the failing lane was Windows
- Risk lane:
  - `govulncheck`
  - `gosec`
  - hardening/chaos/perf lanes already defined by the repo
- Merge/release gating rule:
  - do not merge until the previously failing lane is green on the branch

## Epic W1: Runtime and Contract Correction

Objective: Remove the vulnerable Go floor and restore scanner-gated CI without changing runtime contracts.

### Story W1-S1: Confirm affected repo and failing lane signature
Priority: P0
Tasks:
- Inspect the failed workflow.
- Verify the run uses `go1.25.7`.
- Verify `govulncheck -mode=binary` is the failing gate.
- Record the workflow name, job name, and failing command.
Repo paths:
- `.github/workflows/**`
- `go.mod`
- `Makefile`
- `scripts/**`
- `.tool-versions`
- repo docs and policy docs
Run commands:
- `gh run view <run_id> --repo Clyra-AI/<repo> --log-failed | rg "govulncheck|go1\\.25\\.7|GO-2026-460"`
- `rg -n '1\\.25\\.7|1\\.25\\.8|go-version:|go-version-file: go.mod|golang 1\\.' go.mod .tool-versions .github/workflows Makefile scripts docs product`
Test requirements:
- Preserve evidence of the pre-change failing lane.
- Capture all pin surfaces before editing.
Matrix wiring:
- Fast lane metadata only
- Risk lane signature confirmation
Acceptance criteria:
- Repo is marked affected only if the failure matches the `go1.25.7 + govulncheck` pattern.
- All declared pin surfaces are enumerated before implementation begins.
Architecture constraints:
- No scanner bypass.
- No workflow rename unless status contract work is explicitly planned.
ADR required: no
TDD first failing test(s):
- Existing pin-enforcement or contract test should fail until the version bump is applied.
Cost/perf impact: low
Chaos/failure hypothesis:
- If one workflow or doc surface is missed, CI remains red or policy drifts silently.

### Story W1-S2: Apply atomic Go 1.26.1 pin uplift
Priority: P0
Tasks:
- Update `go.mod`.
- Update `.tool-versions` or equivalent local toolchain file.
- Update `setup-go` workflows.
- Update pin-enforcement scripts and tests.
- Update contributor-facing docs and policy docs.
Repo paths:
- `go.mod`
- `.tool-versions`
- `.github/workflows/**`
- `scripts/check_*pins*.sh`
- `testinfra/**`
- `CONTRIBUTING*`
- `README*`
- `docs/**`
- `product/**`
Run commands:
- `git checkout -b fix/go-1.26.1-vuln-gate`
- `rg -n '1\\.25\\.7|1\\.25\\.8' .`
Test requirements:
- Pin-enforcement tests
- Contract tests for toolchain declarations
- Workflow contract checks if present
Matrix wiring:
- Fast lane
- Core CI lane
Acceptance criteria:
- All normative and enforced pin surfaces read `1.26.1` in one branch.
- No stale `1.25.7` or `1.25.8` references remain in enforced paths.
Contract/API impact:
- Developer minimum Go version changes.
- CLI/runtime contracts do not change.
Versioning/migration impact:
- Update install/build docs to state `Go 1.26.1`.
- No schema or output migration required.
Architecture constraints:
- Keep the change thin.
- Do not mix unrelated refactors into the toolchain PR.
ADR required: no
TDD first failing test(s):
- Update the repo’s exact-pin test first, then make the repo pass it.
Cost/perf impact: low
Chaos/failure hypothesis:
- Partial pin updates create nondeterministic CI depending on which lane resolves the toolchain.

### Story W1-S3: Validate scanner recovery and lane parity
Priority: P0
Tasks:
- Rebuild the binary under `1.26.1`.
- Rerun `govulncheck`.
- Rerun the repo’s deterministic test bundles.
- Rerun the previously failing workflow.
Repo paths:
- `cmd/**`
- `Makefile`
- workflow files
- scanner scripts
Run commands:
- `go version`
- `go build -o .tmp/<bin> ./cmd/<bin>`
- `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -mode=binary .tmp/<bin>`
- `make lint`
- `make test`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Binary vulnerability scan
- Contract suite
- Previously failing lane rerun
Matrix wiring:
- Fast lane
- Core CI lane
- Cross-platform lane
- Risk lane
Acceptance criteria:
- Local `govulncheck` is clean.
- The same failing workflow turns green after the change.
- No required status or branch protection contract regresses.
Architecture constraints:
- Preserve deterministic outputs and existing status names.
ADR required: no
TDD first failing test(s):
- If the repo has workflow or pin contract tests, make them fail on old pins and pass on `1.26.1`.
Cost/perf impact: low
Chaos/failure hypothesis:
- CI caches may hide stale toolchain assumptions; rerunning the original failing lane is mandatory.

## Epic W2: Governance and Repeatability

Objective: Make the remediation repeatable across repos without re-discovering the same steps.

### Story W2-S1: Maintain a cross-repo rollout checklist
Priority: P1
Tasks:
- Track affected repos.
- Track failing workflow names and run IDs.
- Track pin surfaces updated.
- Track validation commands and final passing reruns.
Repo paths:
- internal rollout note or tracking issue
- per-repo PR descriptions
Run commands:
- `gh run list --repo Clyra-AI/<repo> --limit 20`
- `gh pr create --fill`
Test requirements:
- None beyond per-repo validation bundles.
Matrix wiring:
- None; rollout control only
Acceptance criteria:
- Every affected repo has one PR with the same target version and explicit validation evidence.
- Deviations are documented rather than improvised.
Architecture constraints:
- Keep repo-specific differences documented and bounded.
ADR required: no
TDD first failing test(s):
- n/a
Cost/perf impact: low

## Minimum-Now Sequence

1. Re-check the failing run and confirm `go1.25.7 + govulncheck`.
2. Branch: `fix/go-1.26.1-vuln-gate`.
3. Update all pin surfaces atomically.
4. Run local binary `govulncheck` on the built CLI.
5. Run fast, core, and contract suites.
6. Push and rerun the exact workflow that failed.
7. Repeat repo by repo only after the previous repo is green.

## Explicit Non-Goals

- No scanner suppression.
- No broad dependency upgrades unrelated to the Go floor.
- No workflow renames or CI redesign unless the repo is already broken beyond the toolchain issue.
- No partial `1.25.8` rollout.

## Definition of Done

- The repo no longer uses `go1.25.7` or `go1.25.8`.
- `govulncheck` passes on the built binary.
- Contract, pin, and docs surfaces agree on `Go 1.26.1`.
- The previously failing GitHub Actions run is green.
- The PR description includes exact commands run and pass/fail results.

# PLAN WRKR_NODE24_ACTION_RUNTIME: GitHub Actions Node 20 Deprecation Remediation

Date: 2026-03-18
Source of truth:
- user-provided GitHub Actions Node.js 20 deprecation notice dated 2026-03-18
- `rg -n '^\s*uses:' .github/workflows/*.yml`
- `.github/required-checks.json`
- `product/dev_guides.md`
- `product/architecture_guides.md`
Scope: Wrkr repository only. Planning artifact only. Remove Node20-backed GitHub Actions risk from active workflows without changing Wrkr CLI/runtime contracts or merge-blocking status names.

## Global Decisions (Locked)

- Treat this as a workflow and release-contract remediation, not a product-runtime redesign.
- Eliminate Node20-backed GitHub Actions usage from active repo workflows by upgrading or re-pinning to Node24-compatible action refs.
- Do not rely on `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` as the steady-state fix. It may be used only as a short-lived proving aid if an implementation story explicitly scopes it and removes it before merge.
- Preserve stable PR status names relied on by branch protection:
  - `wave-sequence`
  - `fast-lane`
  - `scan-contract`
  - `windows-smoke`
- Preserve workflow names and semantic roles unless a later contract plan explicitly authorizes renames:
  - `pr`
  - `main`
  - `nightly`
  - `release`
  - `docs`
  - `wrkr-action-ci`
  - `wrkr-sarif`
- Treat workflow YAML, local enforcement scripts, contract tests, and contributor/release docs as one atomic contract. No workflow-only or docs-only remediation PR.
- Keep CLI flags, JSON output, schema fields, proof-chain semantics, and exit codes `0..8` unchanged.
- Stories touching workflow contract, release integrity, or CI failure semantics must include `make prepush-full`.
- Reliability and release-risk stories in this plan must include `make test-hardening` and `make test-chaos`.
- Performance-sensitive stories in this plan must include `make test-perf`.
- Floating `@latest` remains prohibited. Implementation must use auditable action refs and preserve deterministic workflow behavior.

## Current Baseline (Observed)

- `git status --short --branch` was clean before generating this plan.
- `product/dev_guides.md` and `product/architecture_guides.md` were present, readable, and enforceable for testing, CI gating, determinism, contract stability, TDD, chaos, frugal architecture, and boundary governance.
- Output path validation passed:
  - requested path: `product/PLAN_NEXT.md`
  - resolved path stayed inside `/Users/tr/wrkr`
- Local workflow inventory shows active Node20-era action refs on real merge and release surfaces:
  - `actions/checkout@v4` appears in:
    - `.github/workflows/docs.yml`
    - `.github/workflows/main.yml`
    - `.github/workflows/nightly.yml`
    - `.github/workflows/pr.yml`
    - `.github/workflows/release.yml`
    - `.github/workflows/wrkr-action-ci.yml`
    - `.github/workflows/wrkr-sarif.yml`
  - `actions/setup-go@v5` appears in:
    - `.github/workflows/main.yml`
    - `.github/workflows/nightly.yml`
    - `.github/workflows/pr.yml`
    - `.github/workflows/release.yml`
    - `.github/workflows/wrkr-action-ci.yml`
    - `.github/workflows/wrkr-sarif.yml`
- Additional JavaScript actions on active repo workflows that may fall into the same Node20-to-Node24 compatibility wave include:
  - `actions/setup-python@v5`
  - `actions/setup-node@v4`
  - `actions/upload-artifact@v4`
  - `actions/configure-pages@v5`
  - `actions/upload-pages-artifact@v3`
  - `actions/deploy-pages@v4`
  - `actions/attest-build-provenance@v2`
  - `dorny/paths-filter@v3`
  - `github/codeql-action/init@v3`
  - `github/codeql-action/upload-sarif@v3`
  - `goreleaser/goreleaser-action@v6`
  - `anchore/sbom-action@v0`
  - `anchore/scan-action@v4`
  - `sigstore/cosign-installer@v3`
  - `Homebrew/actions/setup-homebrew@cced187498280712e078aaba62dc13a3e9cd80bf`
- The user-provided deprecation notice explicitly names `actions/checkout@v4` and `actions/setup-go@v5` as Node20-backed actions that GitHub Actions will force to Node24 starting June 2, 2026.
- Current required PR checks remain stable and contract-bound via `.github/required-checks.json`:
  - `fast-lane`
  - `scan-contract`
  - `wave-sequence`
  - `windows-smoke`
- Existing local enforcement is strong for tool pins and required-check contracts:
  - `scripts/check_toolchain_pins.sh`
  - `scripts/check_no_latest.sh`
  - `scripts/check_branch_protection_contract.sh`
  - `testinfra/contracts/story0_contracts_test.go`
  - `testinfra/hygiene/toolchain_pins_test.go`
- Existing enforcement does not yet hard-fail on Node20-backed GitHub Action refs or unauthorized `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` usage.
- `CONTRIBUTING.md` documents local Go/Python/Node requirements, but it does not currently explain the GitHub Actions JavaScript runtime compatibility baseline or the policy for temporary Node24 force flags.
- `docs/trust/release-integrity.md` documents release smoke, SBOM, scanning, signing, and install-path UAT, but it does not yet state that release trust depends on Node24-ready GitHub Actions refs on the release path.

## Exit Criteria

1. No active workflow in `.github/workflows/*.yml` uses a known Node20-backed action ref on PR, main, nightly, release, docs, or auxiliary contract lanes, or any approved exception is explicitly bounded and non-merge-blocking.
2. Required PR status names remain exactly:
   - `wave-sequence`
   - `fast-lane`
   - `scan-contract`
   - `windows-smoke`
3. `pr.yml`, `main.yml`, `nightly.yml`, `release.yml`, `docs.yml`, `wrkr-action-ci.yml`, and `wrkr-sarif.yml` all pass with the upgraded action set.
4. The workflow class that previously produced the Node20 deprecation warning is rerun and no longer emits the same deprecation annotation for the upgraded refs.
5. Local and CI enforcement fail deterministically if deprecated action refs or disallowed Node24 force flags are reintroduced.
6. `CONTRIBUTING.md`, `docs/trust/release-integrity.md`, and any touched policy docs describe the same implemented workflow contract.
7. Wrkr CLI behavior, JSON output, schemas, and exit codes remain unchanged.

## Public API and Contract Map

Stable/public surfaces touched by this plan:

- Required PR status checks:
  - `wave-sequence`
  - `fast-lane`
  - `scan-contract`
  - `windows-smoke`
- Release workflow identity and release-trust contract:
  - workflow name `release`
  - job name `release-artifacts`
- CLI and machine-readable product contracts:
  - CLI flags
  - JSON keys
  - schema fields
  - proof-chain behavior
  - exit codes `0..8`
- Contributor and trust docs if updated:
  - `CONTRIBUTING.md`
  - `docs/trust/release-integrity.md`

Internal surfaces expected to change:

- `.github/workflows/*.yml`
- workflow validation and hygiene scripts:
  - `scripts/check_branch_protection_contract.sh`
  - `scripts/check_no_latest.sh`
  - `scripts/check_repo_hygiene.sh`
  - new or extended GitHub Actions runtime enforcement script under `scripts/`
- workflow contract and hygiene tests:
  - `testinfra/contracts/story0_contracts_test.go`
  - `testinfra/hygiene/toolchain_pins_test.go`
  - new or extended tests under `testinfra/hygiene/`
- if normative policy language is added:
  - `product/dev_guides.md`

Shim/deprecation path:

- No CLI or schema shim is required.
- `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` is not acceptable as the steady-state repo contract.
- If a third-party action lacks a Node24-ready release, implementation must either replace it in the same wave or document a bounded exception with explicit follow-up; do not silently depend on GitHub's forced runtime switch.

Schema/versioning policy:

- No CLI schema version bump is expected.
- No JSON or proof artifact migration is expected.
- Workflow and docs contract changes move atomically with tests and enforcement.

Machine-readable error expectations:

- No new CLI error envelope or exit-code behavior is introduced.
- CI failure remains visible through existing workflow/job names and deterministic script stderr.
- Any new enforcement check must emit stable failure text naming:
  - offending workflow file
  - offending action ref
  - whether the issue is deprecated runtime use or disallowed override policy

## Docs and OSS Readiness Baseline

README first-screen contract for this plan:

- `README.md` remains product/value-first unless a public release-trust claim must be clarified for accuracy.
- Contributor CI/runtime policy belongs primarily in:
  - `CONTRIBUTING.md`
  - `docs/trust/release-integrity.md`
- Do not crowd the README first screen with maintainer-only workflow details unless public trust claims would otherwise be misleading.

Integration-first docs flow for this plan:

1. `CONTRIBUTING.md`
2. `docs/trust/release-integrity.md`
3. `README.md` only if public trust/install wording changes
4. `product/dev_guides.md` if a normative GitHub Actions runtime policy is added

Lifecycle path model that docs must preserve:

- `pull_request` remains the merge-blocking contract path.
- `main.yml` remains the post-merge continuity path.
- `nightly.yml` remains the broader risk lane.
- `release.yml` remains the release/distribution trust authority.
- `docs.yml` remains the docs deployment authority.
- Docs must describe this as a CI/release lifecycle contract, not a user-facing runtime dependency.

Docs source-of-truth mapping for this plan:

- contributor setup and CI policy: `CONTRIBUTING.md`
- release trust and install-path validation: `docs/trust/release-integrity.md`
- normative CI/process policy: `product/dev_guides.md`
- implementation truth: `.github/workflows/*.yml`

OSS trust baseline:

- Existing trust files already exist and remain the baseline:
  - `README.md`
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `.github/ISSUE_TEMPLATE/*`
  - `.github/pull_request_template.md`
- No new governance file is required unless an action replacement changes maintainer or support expectations materially.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Remove Node20-backed GitHub Action refs from active workflows | GitHub will force Node24 for JavaScript actions starting June 2, 2026; deprecated refs become release and CI risk | Workflow contract correction | Prevents CI/release breakage and future trust erosion | `W1-S01`, `W1-S02`, `W1-S03` |
| R2 | Preserve branch-protection status names and workflow semantics during the uplift | Required checks are stable contract surfaces | Contract-preserving remediation | Avoids accidental branch protection or automation regressions | `W1-S01`, `W1-S02`, `W1-S03` |
| R3 | Add hard-fail guardrails so deprecated action refs cannot re-enter | Current enforcement does not catch Node20-backed action refs | Enforcement-first governance | Prevents repeat drift and late discovery during release | `W1-S04` |
| R4 | Prefer native Node24-ready action upgrades over permanent force flags | Global force flags hide compatibility gaps instead of proving them closed | Explicit compatibility and fail-closed policy | Lower operational surprise and clearer support boundary | `W1-S02`, `W1-S03`, `W1-S04` |
| R5 | Align contributor and release-trust docs with the implemented workflow policy | Docs currently do not explain GitHub Actions JavaScript runtime baseline | Docs and trust consistency | Better maintainer onboarding and public release trust | `W2-S01` |

## Test Matrix Wiring

Fast lane:

- `make lint-fast`
- `make test-contracts`
- `go test ./testinfra/contracts -count=1`
- `go test ./testinfra/hygiene -count=1`

Core CI lane:

- `make prepush-full`
- `.github/workflows/main.yml` `core-matrix-*`

Acceptance lane:

- `.github/workflows/main.yml`:
  - `acceptance`
  - `docs-smoke`
  - `v1-acceptance`
- `scripts/run_v1_acceptance.sh --mode=main`

Cross-platform lane:

- `.github/workflows/pr.yml` `windows-smoke`
- `.github/workflows/main.yml` `core-matrix-macos-latest`
- `.github/workflows/main.yml` `core-matrix-windows-latest`

Risk lane:

- `.github/workflows/nightly.yml` `risk-lane`
- `.github/workflows/release.yml` `release-artifacts` for release-facing workflow changes
- `make test-hardening`
- `make test-chaos`
- `make test-perf`

Merge/release gating rule:

- Do not merge until `wave-sequence`, `fast-lane`, `scan-contract`, and `windows-smoke` are green.
- Do not merge workflow-runtime remediation until the affected workflow class has been rerun on-branch and no longer emits the Node20 deprecation annotation for the upgraded refs.
- Release/docs workflow changes do not ship without a green rerun of `release.yml` and, when touched, `docs.yml`.

## Epic W1: Workflow Contract and Node24 Action Runtime Remediation

Objective: Remove Node20-backed GitHub Actions risk from all active workflow classes while preserving required status names, release semantics, and deterministic enforcement.

### Story W1-S01: Confirm affected workflow inventory and deprecation signature
Priority: P0
Tasks:
- Capture a full `uses:` inventory across `.github/workflows/*.yml`.
- Classify each action surface by workflow class:
  - merge-blocking PR
  - post-merge main
  - nightly risk
  - release/distribution
  - docs deployment
  - auxiliary/manual
- Record which actions are directly named in the deprecation notice and which additional JS actions are likely part of the same runtime-risk wave.
- Freeze the stable contract surfaces that must not change:
  - required PR status names
  - workflow names
  - release job name
- Identify any third-party actions that may require replacement rather than simple version uplift.
Repo paths:
- `.github/workflows/*.yml`
- `.github/required-checks.json`
- `scripts/check_branch_protection_contract.sh`
- `testinfra/contracts/story0_contracts_test.go`
- `testinfra/hygiene/`
Run commands:
- `rg -n '^\s*uses:' .github/workflows/*.yml`
- `cat .github/required-checks.json`
- `scripts/check_branch_protection_contract.sh`
- `go test ./testinfra/contracts -count=1`
- `gh run list --repo Clyra-AI/wrkr --limit 20`
Test requirements:
- Preserve evidence of the pre-change workflow inventory.
- Add or update a failing hygiene/contract test that encodes the known deprecated refs before editing workflow YAML.
- Keep required-check and workflow-name contract tests green after the inventory baseline is frozen.
Matrix wiring:
- Fast lane: contract metadata and failing-test-first inventory work
- Core CI lane: metadata only
- Acceptance lane: none
- Cross-platform lane: n/a
- Risk lane: warning signature evidence only
Acceptance criteria:
- Every workflow file and `uses:` surface is inventoried.
- Stable required PR checks and release workflow identity are explicitly frozen.
- Any action that needs replacement rather than upgrade is identified before implementation starts.
Architecture constraints:
- Treat workflow YAML and branch protection as contract surfaces, not incidental config.
- No workflow rename or status-name changes in this story.
- Keep inventory work thin and evidence-first.
ADR required: no
TDD first failing test(s):
- Add a hygiene/contract fixture that fails when `actions/checkout@v4` or `actions/setup-go@v5` remain on protected workflow surfaces without an approved exception.
Cost/perf impact: low
Chaos/failure hypothesis:
- If one workflow file or action surface is missed, the repo will appear remediated on core PR lanes while still carrying latent release/docs/nightly Node20 risk.

### Story W1-S02: Upgrade merge-blocking and mainline workflows to Node24-ready action refs
Priority: P0
Dependencies:
- `W1-S01`
Tasks:
- Upgrade or re-pin deprecated action refs in:
  - `.github/workflows/pr.yml`
  - `.github/workflows/main.yml`
  - `.github/workflows/nightly.yml`
  - `.github/workflows/wrkr-action-ci.yml`
  - `.github/workflows/wrkr-sarif.yml`
- Validate action surfaces that influence merge-blocking and core CI behavior:
  - `actions/checkout`
  - `actions/setup-go`
  - `actions/setup-python`
  - `actions/setup-node`
  - `actions/upload-artifact`
  - `dorny/paths-filter`
  - `github/codeql-action/*`
- Preserve:
  - job names
  - triggers
  - concurrency blocks
  - required-check mapping
- Rerun required PR checks and at least one main/nightly-equivalent validation on the upgraded branch.
Repo paths:
- `.github/workflows/pr.yml`
- `.github/workflows/main.yml`
- `.github/workflows/nightly.yml`
- `.github/workflows/wrkr-action-ci.yml`
- `.github/workflows/wrkr-sarif.yml`
- `.github/required-checks.json`
- `scripts/check_branch_protection_contract.sh`
- `testinfra/contracts/story0_contracts_test.go`
- `testinfra/hygiene/`
Run commands:
- `make lint-fast`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-perf`
- `gh run list --repo Clyra-AI/wrkr --workflow pr --limit 10`
- `gh run watch --repo Clyra-AI/wrkr <run-id>`
- `gh workflow run nightly.yml --ref <branch>`
- `gh run watch --repo Clyra-AI/wrkr <nightly-run-id>`
Test requirements:
- workflow contract tests
- hygiene checks for deprecated action refs and override policy
- branch protection contract tests
- deterministic failure-message checks for any new enforcement script
- rerun of merge-blocking PR checks plus a nightly-equivalent lane
Matrix wiring:
- Fast lane: `wave-sequence`, `fast-lane`, `scan-contract`
- Core CI lane: `main` `core-matrix-*`
- Acceptance lane: `main` `acceptance`, `v1-acceptance`
- Cross-platform lane: `windows-smoke`, `core-matrix-macos-latest`, `core-matrix-windows-latest`
- Risk lane: `nightly` `risk-lane`, `make test-hardening`, `make test-chaos`, `make test-perf`
Acceptance criteria:
- No deprecated action refs remain on merge-blocking, mainline, nightly, action-contract, or SARIF workflow surfaces.
- Required PR status names are unchanged.
- Rerun PR and main/nightly validations complete without the same Node20 deprecation annotation on upgraded refs.
Contract/API impact:
- Stable workflow status names and workflow semantics remain unchanged.
- No CLI or schema impact.
Architecture constraints:
- Preserve fail-closed gates and exact workflow purposes.
- Prefer direct Node24-ready upgrades over temporary force flags.
- Keep validation logic side-effect-free and deterministic.
ADR required: no
TDD first failing test(s):
- Extend hygiene/contract tests to fail on old refs in `pr.yml`, `main.yml`, `nightly.yml`, `wrkr-action-ci.yml`, and `wrkr-sarif.yml` before editing the workflow files.
Cost/perf impact: low
Chaos/failure hypothesis:
- An action upgrade may alter path-filter, artifact, or setup semantics differently across Linux/macOS/Windows and only surface after merge if the cross-platform lanes are not rerun.

### Story W1-S03: Upgrade release and docs/distribution workflows to Node24-ready action refs
Priority: P0
Dependencies:
- `W1-S01`
Tasks:
- Upgrade or re-pin deprecated action refs in:
  - `.github/workflows/release.yml`
  - `.github/workflows/docs.yml`
- Validate third-party and release-trust action surfaces:
  - `actions/setup-python`
  - `actions/setup-node`
  - `actions/upload-artifact`
  - `actions/configure-pages`
  - `actions/upload-pages-artifact`
  - `actions/deploy-pages`
  - `goreleaser/goreleaser-action`
  - `anchore/sbom-action`
  - `anchore/scan-action`
  - `sigstore/cosign-installer`
  - `actions/attest-build-provenance`
  - `Homebrew/actions/setup-homebrew`
- Preserve release and docs workflow semantics:
  - `release-artifacts` job purpose
  - release smoke/install-path parity
  - provenance/signing/SBOM/vulnerability scan sequence
  - GitHub Pages deployment flow
- Rerun `release.yml` and `docs.yml` on the branch and inspect annotations/logs for lingering Node20 deprecation warnings.
Repo paths:
- `.github/workflows/release.yml`
- `.github/workflows/docs.yml`
- `docs/trust/release-integrity.md`
- `CONTRIBUTING.md`
- `scripts/test_uat_local.sh`
- `Makefile`
- `testinfra/contracts/`
- `testinfra/hygiene/`
Run commands:
- `make lint-fast`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-perf`
- `make test-release-smoke`
- `scripts/test_uat_local.sh --skip-global-gates`
- `gh workflow run docs.yml --ref <branch>`
- `gh workflow run release.yml --ref <branch>`
- `gh run watch --repo Clyra-AI/wrkr <run-id>`
Test requirements:
- release smoke and install-path UAT
- workflow contract and hygiene tests
- deterministic release helper behavior
- rerun of docs and release workflows with annotation inspection
- docs consistency checks if release-trust docs change
Matrix wiring:
- Fast lane: `fast-lane`, `scan-contract`
- Core CI lane: `main` `docs-smoke`
- Acceptance lane: `main` `v1-acceptance`
- Cross-platform lane: rerun `windows-smoke` if release helper or install-path behavior changes
- Risk lane: `release` `release-artifacts`, `nightly` `risk-lane`, `make test-hardening`, `make test-chaos`, `make test-perf`
Acceptance criteria:
- `release.yml` and `docs.yml` no longer use deprecated Node20-backed action refs.
- Branch reruns of release/docs flows pass without the same Node20 deprecation annotation.
- Release signing, provenance, SBOM, vulnerability scanning, and install-path parity semantics remain intact.
Contract/API impact:
- Release workflow identity and install-path trust contract remain stable.
- No CLI or schema impact.
Architecture constraints:
- Do not weaken release gates, signing, scanning, or docs deployment behavior.
- Keep workflow behavior deterministic and auditable.
- If a third-party action needs replacement, preserve equivalent side-effect semantics and document the rationale in the same PR.
ADR required: no
TDD first failing test(s):
- Extend hygiene/contract tests to fail on old refs in `release.yml` and `docs.yml` before editing the workflow files.
Cost/perf impact: low
Chaos/failure hypothesis:
- A release/docs action upgrade can silently change auth, artifact paths, or page deploy behavior and only surface during release or docs publication if those workflows are not rerun directly.

### Story W1-S04: Add hard-fail enforcement for GitHub Actions JavaScript runtime compatibility
Priority: P0
Dependencies:
- `W1-S01`
Tasks:
- Add or extend a deterministic repo check that flags:
  - known Node20-backed action refs
  - unapproved `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`
  - unapproved `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION`
- Wire the check into the existing fast governance path:
  - `make lint-fast`
  - repo hygiene script chain
- Add test fixtures covering:
  - blocked deprecated refs
  - approved clean refs
  - blocked steady-state force flags
  - any explicit bounded exception mechanism if needed
- Ensure failure output is stable and names the offending workflow path and action ref.
Repo paths:
- `scripts/`
- `Makefile`
- `testinfra/hygiene/`
- `testinfra/contracts/`
- `product/dev_guides.md`
Run commands:
- `make lint-fast`
- `go test ./testinfra/hygiene -count=1`
- `go test ./testinfra/contracts -count=1`
- `make prepush-full`
Test requirements:
- deterministic allow/block fixtures
- reason-string stability checks
- parser behavior tests against representative workflow YAML
- required-check contract tests proving enforcement does not change status names
Matrix wiring:
- Fast lane: `fast-lane`, `scan-contract`
- Core CI lane: `make prepush-full`
- Acceptance lane: none beyond green PR/main flows
- Cross-platform lane: `windows-smoke`
- Risk lane: `nightly` `risk-lane`
Acceptance criteria:
- Repo fails before merge when deprecated action refs or disallowed force flags are introduced.
- Enforcement messages are deterministic and actionable.
- Existing required-check and release-contract tests remain green.
Architecture constraints:
- Prefer structured parsing over brittle regex-only validation for workflow semantics.
- Keep the enforcement surface thin, explicit, and side-effect-free.
- Do not add hidden network dependency or stateful caching to hygiene checks.
ADR required: no
TDD first failing test(s):
- Add blocked fixtures for `actions/checkout@v4`, `actions/setup-go@v5`, and a workflow file containing `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` before implementing the enforcement check.
Cost/perf impact: low
Chaos/failure hypothesis:
- Without hard-fail enforcement, future workflow edits can silently reintroduce deprecated refs and the repo will rediscover the problem only during release or external GitHub platform cutover.

## Epic W2: Docs and Maintainer Repeatability

Objective: Keep contributor and release-trust documentation aligned with the new workflow-runtime contract so maintainers do not reintroduce deprecated action behavior.

### Story W2-S01: Update contributor, release-trust, and normative policy docs for Node24 workflow readiness
Priority: P1
Dependencies:
- `W1-S02`
- `W1-S03`
- `W1-S04`
Tasks:
- Update `CONTRIBUTING.md` with the GitHub Actions JavaScript runtime compatibility baseline and the distinction between:
  - local Node toolchain for docs-site
  - GitHub Actions JavaScript runtime for CI workflows
- Update `docs/trust/release-integrity.md` so release trust claims explicitly assume a Node24-ready action set on the release path.
- If needed, extend `product/dev_guides.md` with a normative rule covering:
  - GitHub Actions JavaScript runtime compatibility
  - update procedure for JS actions when GitHub deprecates a runtime
  - policy for temporary force flags
- Add exact validation commands and rerun expectations to the touched docs.
Repo paths:
- `CONTRIBUTING.md`
- `docs/trust/release-integrity.md`
- `product/dev_guides.md`
- `README.md` only if public release-trust copy must be corrected
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `make docs-site-install`
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`
- `make lint-fast`
Test requirements:
- docs consistency checks
- storyline/smoke checks
- docs source-of-truth mapping checks when policy and docs both change
- README first-screen checks if README copy changes
Matrix wiring:
- Fast lane: docs consistency + `make lint-fast`
- Core CI lane: `main` `docs-smoke`
- Acceptance lane: n/a unless docs-site user flow changes materially
- Cross-platform lane: n/a
- Risk lane: none beyond existing release/docs validation
Acceptance criteria:
- Contributor, trust, and normative policy docs describe the same implemented Node24-ready workflow contract.
- Docs distinguish local Node contribution requirements from GitHub Actions JavaScript runtime policy.
- No touched doc contradicts the actual workflow YAML or enforcement rules.
Architecture constraints:
- Docs cannot promise compatibility that workflow YAML and tests do not enforce.
- Keep public trust wording precise and scoped to implemented behavior.
ADR required: no
TDD first failing test(s):
- Update docs consistency/storyline expectations before editing the prose so the doc contract goes red first.
Cost/perf impact: low
Chaos/failure hypothesis:
- If docs lag the workflow contract, maintainers may reintroduce temporary force flags or stale action majors under the false assumption that the repo still permits them.

## Minimum-Now Sequence

1. Reconfirm the Node20 deprecation signature and freeze the affected workflow/action inventory.
2. Add the failing hygiene/contract test(s) for deprecated action refs and disallowed force flags.
3. Upgrade merge-blocking and mainline workflows (`pr.yml`, `main.yml`, `nightly.yml`, `wrkr-action-ci.yml`, `wrkr-sarif.yml`).
4. Upgrade release/docs workflows (`release.yml`, `docs.yml`) and preserve release/deploy semantics.
5. Rerun required PR checks, main/nightly validation, and branch-triggered or workflow-dispatch release/docs lanes until the deprecation annotation is gone.
6. Wire permanent enforcement into the fast governance path.
7. Update contributor/release-trust/normative docs and rerun docs validation.

## Explicit Non-Goals

- No CLI feature work, schema evolution, or exit-code changes.
- No workflow rename, required-check rename, or branch-protection redesign.
- No permanent repo-wide use of `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`.
- No unrelated CI redesign, toolchain refresh, or release-pipeline simplification outside the Node20 remediation scope.
- No weakening of SBOM, vulnerability scanning, signing, provenance, or install-path UAT gates.

## Definition of Done

- All active workflow surfaces in `.github/workflows/*.yml` are on Node24-compatible action refs or an explicitly bounded exception path.
- `wave-sequence`, `fast-lane`, `scan-contract`, and `windows-smoke` remain unchanged and green.
- The workflow class that previously emitted the Node20 deprecation warning has been rerun and no longer emits that warning for the upgraded refs.
- `release.yml` and `docs.yml` reruns are green after the uplift.
- A hard-fail local/CI enforcement check prevents deprecated action refs or disallowed force flags from re-entering.
- `CONTRIBUTING.md`, `docs/trust/release-integrity.md`, and any touched policy docs match the implemented workflow/runtime contract.
- Wrkr CLI behavior, JSON output, schemas, and exit codes are unchanged.

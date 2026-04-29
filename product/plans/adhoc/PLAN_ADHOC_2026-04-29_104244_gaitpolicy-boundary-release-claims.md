# Adhoc Plan: Gait Policy Boundary and Release Claims

Date: 2026-04-29
Profile: `wrkr`
Slug: `gaitpolicy-boundary-release-claims`
Recommendation source: user-provided full `app-audit` no-go report covering a release-blocking `.gait/*.yaml` symlink escape, current LVP claim drift around GitHub App install discovery, required-check documentation drift, stale Go-version references, and post-fix release gate requirements.

All local checkout paths from the recommendation source are normalized to repo-relative paths. Story repo paths below resolve from the active checkout root.

## Global Decisions (Locked)

- Wrkr remains the See product only. This plan does not implement Axym or Gait product features except shared `Clyra-AI/proof` interoperability contracts.
- Scan, detection, risk, proof, verify, regress, and release-gate behavior stays deterministic and non-generative. No LLM calls are allowed in runtime paths.
- Zero scan-data egress by default remains a hard security contract. Detector reads must stay bounded to the selected scan root unless a future explicit, documented, opt-in source mode changes that contract.
- Root-escaping symlinked policy/config files must surface deterministic `parse_error.kind=unsafe_path` diagnostics and must not leak external file contents or resolved machine-local paths.
- Gait policy support is a static repository posture signal. This plan does not add Gait runtime enforcement or Gait product behavior.
- GitHub App install inventory is future/additive platform scope unless an implementation story explicitly adds org-level API detection, token handling, deterministic fixtures, and docs.
- Public JSON, proof, report, state, schema, exit-code, and changelog contracts remain additive unless a versioned migration is planned.
- Product docs are treated as release governance. Claims about current LVP scope, required checks, and toolchain pins must match executable behavior.
- Every behavior-changing story starts with failing tests that reproduce the observed audit finding before implementation.

## Current Baseline (Observed)

- Full `app-audit` verdict was `No-go` because `.gait/*.yaml` can escape the selected repo root through symlinks.
- `core/detect/gaitpolicy/detector.go` globs `.gait/*.yaml`, then `mergePolicyFile` reads the joined path with `os.ReadFile`.
- `core/detect/parse.go` already exposes `ReadFileWithinRoot`, `OpenFileWithinRoot`, and `WalkFilesWithParseErrors`, which resolve symlinks and map root escapes to `unsafe_path`.
- Many detectors already emit structured `parse_error` findings for unsafe symlinked config files; gait policy does not yet follow that pattern.
- `core/detect/skills/detector.go` calls `gaitpolicy.LoadBlockedTools` before scanning skills, so changing gait policy parsing must preserve skills detector behavior and avoid turning an unsafe policy file into a scan-wide runtime failure.
- The audit repro scan exited `0` and emitted `.gait/external.yaml` as repo-local policy evidence instead of `unsafe_path`.
- Public docs promise root-bounded local scans in `README.md`, `docs/commands/scan.md`, and `docs/trust/security-and-privacy.md`.
- `product/wrkr.md` current scope says GitHub App install inventory is a future/non-default platform signal, and `docs/positioning.md` says Wrkr is not a GitHub App inventory product in OSS default mode.
- `product/wrkr.md` LVP functional requirements still claim "Detect GitHub App installations with AI-related scopes" as current discovery scope.
- `.github/required-checks.json` declares four required checks: `fast-lane`, `scan-contract`, `wave-sequence`, and `windows-smoke`.
- `product/dev_guides.md` currently lists only `fast-lane` and `windows-smoke` in the current required-check section.
- `go.mod` pins Go `1.26.2`, while `product/PLAN_v1.md` still references Go `1.26.1`.
- Audit validation already passed for `make build`, `make lint-fast`, `make test-fast`, `make test-docs-consistency`, and `make test-scenarios`.
- Full `make prepush-full`, CodeQL, docs-site build/checks, release smoke/UAT, and release acceptance were not run in the audit.

## Exit Criteria

- `.gait/*.yaml`, `.gait/policy.yaml`, `.gait/policies.yaml`, and `gait.yaml` reads are routed through root-bounded helpers or stricter typed parse helpers.
- Root-escaping gait policy symlinks emit deterministic `parse_error` findings with `parse_error.kind=unsafe_path`, repo-relative logical paths, and no external file content.
- Gait policy parse failures do not abort unrelated skill scanning when the failure can be represented as a deterministic finding.
- The audit repro shape no longer emits `.gait/external.yaml` as valid repo-local `gait_policy` evidence.
- Tests cover regular in-root policy files, in-root symlinks, external symlinks, dangling symlinks, malformed YAML, and deterministic finding order.
- Product docs either remove GitHub App install discovery from current LVP wording or explicitly move it to future/additive platform scope with no ambiguity.
- Required-check docs match `.github/required-checks.json`, and stale literal Go-version references are aligned with the repo pin policy.
- Post-fix release readiness gates are run and recorded: `make prepush-full`, `make test-release-smoke`, `scripts/run_v1_acceptance.sh --mode=release`, docs-site gates, and CI/CodeQL.
- `CHANGELOG.md` under `## [Unreleased]` contains operator-facing entries for security and docs/governance changes that affect public trust surfaces.

## Public API and Contract Map

- CLI flags and exits:
  - Existing `--json`, `--explain`, and `--quiet` behavior remains stable.
  - Existing exit codes `0,1,2,3,4,5,6,7,8` remain stable.
  - A gait policy symlink escape must not become a broad runtime failure when the scan can emit a deterministic parse-error finding.
- Finding and JSON surfaces:
  - `finding_type=parse_error` remains the public diagnostic shape for unsafe detector reads.
  - `parse_error.kind=unsafe_path` remains the stable reason code for root-escaping symlinks.
  - `parse_error.path` and finding `location` stay repo-relative. Do not serialize resolved external targets.
  - Valid in-root gait policies continue to emit `tool_config` findings with `tool_type=gait_policy`.
- Proof and risk surfaces:
  - Parse-error findings remain finding-only posture/bookkeeping signals and must not become lifecycle identities.
  - Risk scoring continues to treat parse errors as explicit quality/security signals without creating raw-source reads in risk/proof layers.
- Detection boundaries:
  - Source boundary semantics live in `core/detect/parse.go` and detector helpers.
  - Gait policy parsing stays inside `core/detect/gaitpolicy`.
  - Skills may consume blocked-tool policy data, but skills detection must not own gait policy filesystem safety.
- Documentation and governance surfaces:
  - `product/wrkr.md`, `docs/positioning.md`, `product/dev_guides.md`, `product/PLAN_v1.md`, `README.md`, and `docs/trust/security-and-privacy.md` are public or normative trust surfaces.
  - `.github/required-checks.json` is the executable source of truth for current required PR checks.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/trust/security-and-privacy.md`
  - `docs/trust/deterministic-guarantees.md` if root-bound wording needs clarification
  - `docs/positioning.md`
  - `product/wrkr.md`
  - `product/dev_guides.md`
  - `product/PLAN_v1.md`
  - `CHANGELOG.md`
- Docs must answer directly:
  - How does Wrkr handle `.gait/*.yaml` policy files that are symlinks outside the selected scan root?
  - Is GitHub App install detection part of current OSS default LVP scope?
  - Which PR checks are currently required for Wrkr?
  - Which file is the source of truth for the current Go floor/pin?
  - Which release gates must run after the P0 boundary fix?
- Docs parity gates:
  - `scripts/check_docs_cli_parity.sh`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/run_docs_smoke.sh`
  - `make test-docs-consistency`
  - docs-site install/lint/build/check commands when release readiness is being closed

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage |
|---|---:|---|
| 1. Fix `.gait/*.yaml` root escape by routing reads through safe helpers or typed parse helpers | P0 | Story 1.1 |
| 2. Emit deterministic `unsafe_path` for gait policy symlink escapes without reading external contents | P0 | Story 1.1 |
| 3. Add symlink fixtures for `.gait/*.yaml` and direct gait policy paths | P0 | Story 1.1 |
| 4. Preserve skills detector behavior where `LoadBlockedTools` is consumed | P0 | Story 1.1 |
| 5. Reconcile GitHub App install discovery claims with current LVP scope | P1 | Story 2.1 |
| 6. Align required-check documentation with `.github/required-checks.json` | P2 | Story 2.2 |
| 7. Align stale literal Go-version references with repo policy | P2 | Story 2.2 |
| 8. Run release gates after fixes and record the remaining launch posture | P0 | Story 3.1 |

## Test Matrix Wiring

- Fast lane: focused Go detector tests plus `make lint-fast` and `make test-fast`.
- Core CI lane: `make test-contracts`, targeted CLI JSON/parse-error contract tests, and docs governance checks for required-check and scope wording.
- Acceptance lane: `make test-scenarios`, `scripts/validate_scenarios.sh`, and `scripts/run_v1_acceptance.sh --mode=release` after P0 and P1 fixes.
- Cross-platform lane: Windows smoke plus symlink tests with deterministic platform guards or deterministic skip behavior where OS privileges differ.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make prepush-full` for root-boundary and release-readiness work.
- Release/UAT lane: `make test-release-smoke`, docs-site install/lint/build/check, CodeQL, and `bash scripts/test_uat_local.sh` when cutting a release candidate.
- Gating rule: no story is complete until declared lanes are green, first failing regression tests are present, docs and changelog entries are synchronized, and repeated scan fixtures are byte-stable except explicit timestamp/version fields.

## Minimum-Now Sequence

- Wave 1 - P0 source-boundary correctness:
  - Story 1.1: fix gait policy root-bound reads and unsafe-path diagnostics.
- Wave 2 - P1/P2 product and governance claim reconciliation:
  - Story 2.1: reconcile GitHub App install discovery scope.
  - Story 2.2: align required-check and Go-version governance docs.
- Wave 3 - Release readiness closure:
  - Story 3.1: rerun release gates and capture launch posture after fixes.

## Explicit Non-Goals

- No implementation of Axym or Gait product features.
- No Gait runtime enforcement, gateway behavior, or policy decision execution in Wrkr.
- No live GitHub App inventory unless a separate implementation story adds an explicit org API source, token model, deterministic fixtures, and docs.
- No LLM-based parsing, scoring, summarization, or remediation generation.
- No default network enrichment or scan-data exfiltration.
- No broad detector rewrite outside the gait policy boundary unless tests prove a shared helper change is required.
- No public schema or exit-code breaking change.
- No bypass of branch protection, CodeQL, release signing, provenance, or required-check controls.

## Definition of Done

- The P0 audit repro fails before implementation and passes after implementation with `parse_error.kind=unsafe_path`.
- External gait policy symlink contents are never read, surfaced, counted as blocked tools, or emitted as valid policy evidence.
- `gaitpolicy.LoadBlockedTools` or its replacement has an explicit parse-error contract used by both the gait policy detector and skills detector.
- Valid in-root gait policies continue to produce deterministic blocked-tool counts and skill ceiling behavior.
- Product scope docs no longer claim current GitHub App install inventory while positioning docs call it future/non-default.
- `product/dev_guides.md`, `product/PLAN_v1.md`, and executable check declarations agree on required checks and toolchain source of truth.
- Required commands for each story are run and recorded in the implementation PR.
- Release readiness gates are run after fixes, with any remaining blockers documented as release blockers rather than silent assumptions.
- Final review includes a repo-wide search proving no committed plan, doc, or public artifact contains developer-specific absolute checkout paths.

## Epic 1: Gait Policy Source-Boundary Safety

Objective: close the release-blocking `.gait/*.yaml` symlink escape while preserving deterministic scan output and skills detector policy consumption.

### Story 1.1: Make gait policy reads root-bounded and fail closed

Priority: P0
Recommendation coverage: 1, 2, 3, 4
Strategic direction: Gait policy discovery should use the same source-boundary contract as other structured detectors: parse what is inside the selected repo root, emit deterministic parse diagnostics for unsafe paths, and never read external content.
Expected benefit: Restores Wrkr's zero-exfiltration and proof correctness guarantees for policy files and removes the audit no-go blocker.

Tasks:
- Add a failing unit test in `core/detect/gaitpolicy` that creates `.gait/external.yaml` as a symlink to a file outside the scan root and asserts the detector emits one `parse_error` finding with `parse_error.kind=unsafe_path`.
- Add companion tests for `.gait/policy.yaml`, `.gait/policies.yaml`, `gait.yaml`, regular `.gait/*.yaml`, in-root symlinks, dangling symlinks, malformed YAML, and deterministic sort order.
- Replace direct `os.ReadFile` in `mergePolicyFile` with `detect.ReadFileWithinRoot` or a typed YAML parse helper built on that safe read path.
- Refactor `LoadBlockedTools` so callers can distinguish valid policy files, blocked tools, and parse diagnostics without converting representable unsafe paths into scan-wide runtime errors.
- Update `Detector.Detect` to append parse-error findings for unsafe or malformed gait policy files while still emitting valid `gait_policy` findings for safe policy files.
- Update `core/detect/skills/detector.go` integration if the gait policy loader API changes, preserving blocked-tool ceiling behavior for valid policy files and ignoring unsafe policy contents.
- Add or update CLI/scan contract coverage proving the audit repro exits successfully, includes `parse_error.kind=unsafe_path`, and does not include external blocked-tool values or external file content.
- Add a scenario fixture or focused e2e fixture for the `.gait/*.yaml` symlink escape if existing detector tests do not cover scan aggregation and JSON output.
- Update security/privacy docs only if the implementation changes existing public wording for root-bounded detector reads.
- Add an Unreleased changelog entry under `Security`.

Repo paths:
- `core/detect/gaitpolicy/detector.go`
- `core/detect/gaitpolicy/detector_test.go`
- `core/detect/skills/detector.go`
- `core/detect/skills/detector_test.go`
- `core/detect/parse.go`
- `core/cli/scan_partial_errors_test.go`
- `internal/e2e/source/source_e2e_test.go`
- `scenarios/wrkr/`
- `docs/trust/security-and-privacy.md`
- `docs/commands/scan.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/gaitpolicy -count=1`
- `go test ./core/detect/skills -run 'Test.*Gait|Test.*Policy|Test.*Unsafe|Test.*Symlink' -count=1`
- `go test ./core/cli -run 'Test.*Unsafe|Test.*Parse|Test.*Gait' -count=1`
- `go test ./internal/e2e/source -run 'Test.*Unsafe|Test.*Symlink|Test.*Gait' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`
- `make test-chaos`
- `make lint-fast`
- `make test-fast`

Test requirements:
- TDD unit test reproducing the audit escape through `.gait/*.yaml`.
- Detector tests for direct policy paths and globbed policy paths.
- Integration test proving skills detection still honors safe blocked-tool policy and does not read unsafe policy contents.
- CLI JSON test asserting `finding_type=parse_error`, `tool_type=gait_policy`, `location=.gait/external.yaml`, and `parse_error.kind=unsafe_path`.
- Negative assertion proving no external file content, external resolved path, or external blocked tool appears in findings, scan quality, proof events, or logs.
- Repeated-run determinism test for finding order and parse-error payload.

Matrix wiring:
- Fast lane: focused `core/detect/gaitpolicy`, `core/detect/skills`, `core/cli` tests plus `make lint-fast`.
- Core CI lane: `make test-contracts` and `make test-fast`.
- Acceptance lane: `make test-scenarios` plus focused e2e source-boundary tests.
- Cross-platform lane: Windows smoke with deterministic symlink skip or creation behavior where privileges differ.
- Risk lane: `make test-hardening` and `make test-chaos`.
- Release/UAT lane: include this story in `make prepush-full` before release candidate validation.

Acceptance criteria:
- The audit repro emits deterministic `unsafe_path` instead of valid `.gait/external.yaml` policy evidence.
- Safe gait policies still produce the same blocked-tool counts and `gait_policy` findings as before.
- Unsafe gait policy contents never affect skill risk, blocked-tool ceilings, proof records, scan quality, or reports.
- Scan output remains stable across repeated runs on the same fixture.
- Docs and changelog reflect the security fix if public wording changes.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Reject root-escaping Gait policy symlinks as deterministic `unsafe_path` parse diagnostics instead of reading or emitting external policy files as repository evidence.
Semver marker override: [semver:patch]
Contract/API impact: Additive finding behavior for unsafe gait policy inputs; CLI flags, exit codes, and schema keys remain stable.
Versioning/migration impact: No schema migration. Existing consumers that handle `parse_error.kind=unsafe_path` continue to work; scans may now include a parse-error finding where unsafe policy files were previously misclassified.
Architecture constraints: Preserve Source and Detection boundaries; root safety stays in `core/detect` helpers and detector code; risk/proof layers must not perform raw filesystem reads.
ADR required: no
TDD first failing test(s): `go test ./core/detect/gaitpolicy -run TestDetectRejectsExternalGaitPolicySymlink -count=1`
Cost/perf impact: low
Chaos/failure hypothesis: If a policy file is dangling, permission-denied, malformed, or root-escaping, scan emits a stable parse diagnostic and continues processing safe files without reading outside the selected root.

## Epic 2: Product Claim and Governance Alignment

Objective: remove release-trust drift between shipped behavior, product claims, required checks, and toolchain policy.

### Story 2.1: Reconcile GitHub App install discovery scope

Priority: P1
Recommendation coverage: 5
Strategic direction: Current LVP claims should describe what Wrkr actually ships by default; future platform signals should stay visible as roadmap scope without weakening buyer trust.
Expected benefit: Prevents evaluators and auditors from expecting current GitHub App install inventory that the OSS default path does not yet provide.

Tasks:
- Update `product/wrkr.md` Functional Requirements so GitHub App install detection is no longer stated as current LVP default scope unless it is implemented in the same PR.
- Keep or move GitHub App install inventory wording under future/additive platform signals, consistent with the scope language near the discovery surface tables.
- Verify `docs/positioning.md` still says Wrkr is not a GitHub App inventory product in OSS default mode.
- Search `README.md`, `docs/`, `docs-site/public/llms.txt`, and `docs-site/public/llm/` for contradictory GitHub App install claims and align wording.
- If maintainers choose implementation instead of wording removal, split this story into a separate implementation plan covering GitHub API source acquisition, token prerequisites, deterministic fixtures, API error mapping, rate-limit behavior, JSON fields, docs, and tests before merging.
- Add an Unreleased changelog entry under `Changed`.

Repo paths:
- `product/wrkr.md`
- `docs/positioning.md`
- `README.md`
- `docs/`
- `docs-site/public/llms.txt`
- `docs-site/public/llm/`
- `CHANGELOG.md`

Run commands:
- `rg -n "GitHub App|App install|installed app|org settings" README.md docs docs-site product`
- `make test-docs-consistency`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `make lint-fast`

Test requirements:
- Docs consistency check proving current-scope docs and positioning docs agree.
- Search-based guard in an existing docs/governance test if one already enforces current/future scope language.
- Manual review of product and positioning docs to ensure GitHub App install inventory appears only as future/additive scope unless implemented.

Matrix wiring:
- Fast lane: docs checks plus `make lint-fast`.
- Core CI lane: docs consistency and storyline checks.
- Acceptance lane: no scenario change required for wording-only reconciliation.
- Cross-platform lane: no platform-specific behavior.
- Risk lane: no hardening lane required unless implementation is chosen instead of docs reconciliation.
- Release/UAT lane: include the reconciled docs in release acceptance review.

Acceptance criteria:
- No current LVP or default OSS scan wording claims GitHub App install detection as shipped behavior.
- Future/additive platform scope remains visible and consistent.
- Docs and product PRD agree with `docs/positioning.md`.
- Changelog records the public claim correction.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Clarify that GitHub App install inventory is future/additive platform scope, not part of the current default OSS scan path.
Semver marker override: none
Contract/API impact: Documentation and product-scope contract only; no CLI, JSON, exit-code, or schema change.
Versioning/migration impact: No migration. Buyer-facing and contributor-facing scope language changes for release trust.
Architecture constraints: Do not add network/API scanning in a docs-only fix; any future implementation must stay behind the Source boundary and explicit hosted prerequisites.
ADR required: no
TDD first failing test(s): Existing docs consistency/storyline checks plus a targeted search proving current-scope GitHub App install claims are gone.
Cost/perf impact: low
Chaos/failure hypothesis: If a future implementation is chosen instead, GitHub API unavailable, unauthorized, or rate-limited states must fail closed with deterministic error classes and no partial unmarked claims.

### Story 2.2: Align required-check and Go-version governance docs

Priority: P2
Recommendation coverage: 6, 7
Strategic direction: Normative docs should point to executable sources of truth and avoid stale duplicated toolchain or required-check claims.
Expected benefit: Maintainers, contributors, and auditors see the same release governance contract that CI enforces.

Tasks:
- Update `product/dev_guides.md` current required-check section to list `fast-lane`, `scan-contract`, `wave-sequence`, and `windows-smoke`, or state that `.github/required-checks.json` is the source of truth and include the current list from that file.
- Update any scripts/tests if they encode the old two-check set.
- Replace stale `product/PLAN_v1.md` Go `1.26.1` references with source-of-truth wording that points to `go.mod`, or align the literal with `go.mod` only if the plan intentionally keeps a historical snapshot.
- Search product and docs surfaces for stale Go version claims and reconcile with `go.mod` and `product/dev_guides.md`.
- Add or update governance tests if existing tests do not catch required-check drift.
- Add an Unreleased changelog entry under `Changed`.

Repo paths:
- `product/dev_guides.md`
- `product/PLAN_v1.md`
- `.github/required-checks.json`
- `scripts/check_branch_protection_contract.sh`
- `testinfra/contracts/story0_contracts_test.go`
- `README.md`
- `CONTRIBUTING.md`
- `CHANGELOG.md`

Run commands:
- `rg -n "fast-lane|scan-contract|wave-sequence|windows-smoke|required checks|required PR checks" product docs README.md CONTRIBUTING.md .github scripts testinfra`
- `rg -n "1\\.26\\.1|1\\.26\\.2|Current pin|Go \\`1\\." product docs README.md CONTRIBUTING.md go.mod .tool-versions`
- `go test ./testinfra/contracts -run 'Test.*Branch|Test.*Required|Test.*Toolchain|Test.*Go' -count=1`
- `scripts/check_branch_protection_contract.sh`
- `scripts/check_toolchain_pins.sh`
- `make test-docs-consistency`
- `make lint-fast`

Test requirements:
- Required-check contract test passes with the four-check set from `.github/required-checks.json`.
- Toolchain pin check passes with `go.mod` as the Go source of truth.
- Docs consistency checks pass after wording changes.
- Search output shows no stale two-check-only or old Go-pin claim in normative current-state docs.

Matrix wiring:
- Fast lane: `make lint-fast`, docs consistency, and focused contract tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: no scenario change required.
- Cross-platform lane: no platform-specific behavior.
- Risk lane: no chaos/hardening lane required for docs-only governance alignment.
- Release/UAT lane: release readiness review consumes the corrected governance docs.

Acceptance criteria:
- Required-check documentation matches `.github/required-checks.json`.
- Stale Go-version claims are removed or aligned with the explicit source-of-truth policy.
- Existing contract scripts/tests still pass and protect against future drift.
- Changelog records the governance-doc correction.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Align required-check and Go toolchain governance docs with the executable branch-protection and `go.mod` sources of truth.
Semver marker override: none
Contract/API impact: Documentation/governance contract only; no CLI, JSON, exit-code, or schema change.
Versioning/migration impact: No runtime migration. Contributor expectations for required checks and toolchain source of truth are clarified.
Architecture constraints: Keep enforcement in existing scripts and `testinfra/contracts`; docs must not become a divergent authority from executable checks.
ADR required: no
TDD first failing test(s): Existing branch-protection/toolchain contract tests should fail if docs or check declarations drift.
Cost/perf impact: low
Chaos/failure hypothesis: If required-check docs drift again, branch-protection contract checks should fail before release planning treats the repo as ready.

## Epic 3: Release Gate Closure

Objective: prove the no-go blocker is closed and capture any remaining release blockers with concrete evidence.

### Story 3.1: Run post-fix release readiness gates and record launch posture

Priority: P0
Recommendation coverage: 8
Strategic direction: A no-go audit should close with executable release evidence, not with assumptions from narrower fast gates.
Expected benefit: Maintainers get a clean go/no-go handoff after the P0 boundary fix and P1/P2 docs reconciliation.

Tasks:
- After Stories 1.1, 2.1, and 2.2 land, run the full local release readiness gate set from the active profile.
- Run docs-site gates so product/positioning/required-check changes are verified in published docs surfaces.
- Run CodeQL through the repo-supported command or CI workflow if local `make codeql` is unavailable.
- Run release smoke and release acceptance commands against the fixed branch or release candidate.
- Capture command results in the implementation PR and release handoff notes, including exact failures, skipped checks, and owner/blocker status.
- If any release gate fails, classify it as repo-fixable, external/policy, or environment-only; do not mark release ready until repo-fixable blockers are addressed.
- Do not cut a release tag as part of this story unless the release workflow is explicitly invoked by maintainers after gates pass.

Repo paths:
- `product/plans/adhoc/PLAN_ADHOC_2026-04-29_104244_gaitpolicy-boundary-release-claims.md`
- `CHANGELOG.md`
- `docs/trust/release-integrity.md`
- `.github/workflows/`
- `scripts/`
- `docs-site/`

Run commands:
- `make prepush-full`
- `make test-release-smoke`
- `scripts/run_v1_acceptance.sh --mode=release`
- `make docs-site-install`
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`
- `scripts/run_docs_smoke.sh`
- `make codeql`
- `bash scripts/test_uat_local.sh`

Test requirements:
- Full profile final gate passes after P0/P1/P2 fixes.
- Release smoke proves build artifacts, checksum, SBOM, vulnerability scan, signing/provenance expectations, and install-path parity remain intact.
- Release acceptance verifies the V1 scorecard after the security fix.
- Docs-site gates prove changed docs render and remain link/check clean.
- CodeQL either passes or has an explicit external/policy blocker recorded.

Matrix wiring:
- Fast lane: already covered by earlier stories; rerun `make lint-fast` only if final gate fails and a narrow fix is needed.
- Core CI lane: `make prepush-full` includes contract and deterministic behavior coverage.
- Acceptance lane: `scripts/run_v1_acceptance.sh --mode=release` and `make test-release-smoke`.
- Cross-platform lane: rely on required `windows-smoke` in CI and record its status.
- Risk lane: profile final gate plus CodeQL, hardening, chaos, and release smoke coverage.
- Release/UAT lane: docs-site gates and `bash scripts/test_uat_local.sh` with the intended release version environment when available.

Acceptance criteria:
- Release handoff says either `Go` with all required evidence or `No-go` with exact remaining blocker owners.
- No repo-fixable P0/P1 release blockers remain unplanned.
- Command results include enough detail for an implementer or release owner to reproduce the same gate set.
- No release tag is cut before the gates pass.

Changelog impact: not required
Changelog section: none
Draft changelog entry: none
Semver marker override: none
Contract/API impact: Validation-only story; no CLI, JSON, exit-code, schema, or docs contract change unless failures require follow-up fixes.
Versioning/migration impact: No migration. Release readiness evidence may inform the next semver decision through existing changelog markers from prior stories.
Architecture constraints: Use the active profile commands; do not invent alternate release gates or bypass required signing/provenance/security controls.
ADR required: no
TDD first failing test(s): Not applicable for validation-only work; failures from `make prepush-full`, release smoke, release acceptance, docs-site gates, CodeQL, or UAT become the next failing tests.
Cost/perf impact: medium
Chaos/failure hypothesis: If a gate fails because the P0 boundary fix introduced nondeterminism, unsafe reads, or release-integrity drift, the release remains blocked until a focused hotfix restores the profile gate.

# Adhoc Plan: Release Boundary and Fail-Closed Hardening

Date: 2026-04-28
Profile: `wrkr`
Slug: `release-boundary-failclosed`
Recommendation source: user-provided code-review findings covering release publish ordering, scan-root symlink escapes, skill frontmatter fail-open parsing, and nondeterministic local Go package discovery.

All local checkout paths from the recommendation source are normalized to repo-relative paths. Story repo paths below resolve from the active checkout root.

## Global Decisions (Locked)

- Wrkr remains the See product only. This plan does not implement Axym or Gait features except shared `Clyra-AI/proof` interoperability.
- Scan, detection, risk, proof, regress, verify, and release-gate behavior stays deterministic and non-generative. No LLM calls are allowed in runtime paths.
- Zero data exfiltration and source-root ownership remain hard contracts. A scan path must not read repo-declared symlinks that resolve outside the selected repo root unless an explicit, documented, fail-closed exception is introduced later.
- Ambiguous high-risk detection inputs fail closed with stable parse/error metadata rather than silently downgrading risk.
- Release publication must happen only after build artifacts pass checksum, SBOM, vulnerability scan, signature, provenance, and in-pipeline verification gates.
- Workflow, Makefile, and validation behavior are executable governance contracts. Any changed command semantics must update the corresponding contract tests and docs in the same implementation PR.
- Public JSON, proof, state, report, schema, exit-code, and changelog contracts remain additive unless an explicit versioned migration is planned.
- Every story in this plan starts with failing tests that reproduce the observed review finding before implementation.

## Current Baseline (Observed)

- `.github/workflows/release.yml` runs `goreleaser release --clean` for tag builds before later checksum verification, SBOM generation, Grype scan, cosign signing, and provenance attestation.
- `.goreleaser.yaml` contains release publication configuration, including Homebrew tap publishing, so tag release execution can publish before later integrity gates complete.
- `product/dev_guides.md` requires release artifact publication only after acceptance, checksum, SBOM, vulnerability scan, signing, provenance, and verification gates pass.
- `core/detect/parse.go` exposes `WalkFilesWithOptions`, which returns walked file paths without centrally rejecting symlinked file escapes.
- `core/detect/parse.go` already contains `ReadFileWithinRoot`, which resolves symlinks and rejects paths outside the scan root with `unsafe_path`.
- `core/detect/skills/detector.go` walks `.agents/skills/**/SKILL.md` and reads matched files directly. A symlinked skill file resolving outside the repo can be scanned and emitted as an in-repo finding.
- Other walk-based detector paths use the same risky shape: walk or glob, then direct `os.ReadFile`.
- Skill frontmatter parsing in `core/detect/skills/detector.go` ignores YAML decode errors and treats malformed `allowed-tools` frontmatter as no allowed tools.
- `Makefile` uses `PKGS := ./...` and `go test ./...`, which can include ignored generated docs dependencies such as `docs-site/node_modules/**` when they exist locally.
- Existing fast gates passed during review, but the local package set included a Go package under ignored `docs-site/node_modules`.

## Exit Criteria

- Tag releases build candidate artifacts without publishing them, run all integrity gates, verify the gated artifacts in-pipeline, and only then publish GitHub release assets, release notes, and Homebrew tap changes.
- A workflow contract test proves release publication steps occur after checksum, SBOM, vulnerability scan, signing, provenance, and verification steps.
- All walk-based detector file reads either go through `ReadFileWithinRoot` or a stricter central helper that rejects symlink escapes before detector parsing.
- Symlink escape fixtures for skills, Cursor rules, prompt/channel files, WebMCP files, dependency manifests, workflow/identity files, and non-human identity files are rejected or emitted as deterministic `unsafe_path` parse errors without reading external contents.
- Malformed skill frontmatter emits structured parse-error metadata and cannot produce a low-risk "zero tools" finding when structured config is invalid.
- Go validation commands use a deterministic package list that excludes ignored/generated docs artifacts, including `docs-site/node_modules`, `docs-site/.next`, `.tmp`, and `.wrkr`.
- `make lint-fast`, `make test-fast`, `make test-contracts`, `make test-scenarios`, `make test-hardening`, and `make test-chaos` pass for the affected work.
- Release-facing work also passes `make prepush-full`, `make test-release-smoke`, and `scripts/run_v1_acceptance.sh --mode=release` before tagging.
- `CHANGELOG.md` under `## [Unreleased]` contains operator-facing entries for each implementation PR that changes release integrity, security posture, or contributor validation behavior.

## Public API and Contract Map

- CLI flags and exits:
  - Existing `--json`, `--explain`, and `--quiet` behavior remains stable.
  - Existing exit codes `0,1,2,3,4,5,6,7,8` remain stable.
  - Symlink escape or unsafe detector path handling should map to existing unsafe/parse surfaces. Default CLI behavior must remain deterministic and machine-readable.
- Artifact and finding keys:
  - Existing finding identity and proof record fields remain stable.
  - If detector-level parse errors are added to walked-file findings, use existing `parse_error.kind`, `parse_error.message`, and stable reason-code conventions where available.
  - Do not serialize external resolved symlink targets into public findings by default; preserve logical repo-relative locations and safe reason metadata.
- Release/governance surfaces:
  - `.github/workflows/release.yml`
  - `.goreleaser.yaml`
  - `docs/trust/release-integrity.md`
  - `product/dev_guides.md` only if normative wording needs clarification.
  - `testinfra/contracts` and `testinfra/hygiene` workflow contract tests.
- Detection boundaries:
  - Detection: `core/detect/*`
  - Source boundary semantics: selected scan root ownership and safe path resolution.
  - Risk/proof consumers must receive deterministic findings; they must not perform raw filesystem reads to compensate for detector uncertainty.
- Validation surfaces:
  - `Makefile`
  - package-list helper script or make variable used by local and CI gates.
  - hygiene tests proving ignored/generated paths are excluded.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `docs/trust/release-integrity.md`
  - `docs/trust/security-and-privacy.md`
  - `docs/trust/deterministic-guarantees.md`
  - `docs/failure_taxonomy_exit_codes.md` if parse/unsafe reason wording changes.
  - `README.md` or `CONTRIBUTING.md` only if validation command usage changes for contributors.
  - `CHANGELOG.md`
- Docs must answer directly:
  - Are release artifacts published before or after security and provenance checks?
  - How does Wrkr treat repo files that are symlinks outside the selected scan root?
  - What happens when a structured skill frontmatter block is malformed?
  - Which local validation commands are deterministic after docs-site dependencies are installed?
- Docs parity gates:
  - `scripts/check_docs_cli_parity.sh`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/run_docs_smoke.sh`
  - `make test-docs-consistency`

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage |
|---|---:|---|
| 1. Move release publication after all integrity gates | P0 | Story 1.1 |
| 2. Add workflow contract coverage for publish-after-verify ordering | P0 | Story 1.1 |
| 3. Reject symlinked walked files that resolve outside the scan root | P0 | Story 2.1 |
| 4. Migrate direct-read walk-based detectors to safe root-bound reads | P0 | Story 2.2 |
| 5. Add detector regression fixtures for external symlink escapes | P0 | Story 2.2 |
| 6. Make malformed skill frontmatter fail closed with parse-error metadata | P0 | Story 3.1 |
| 7. Make Go package discovery deterministic and exclude ignored generated docs artifacts | P1 | Story 4.1 |

## Test Matrix Wiring

- Fast lane: focused Go unit tests plus `make lint-fast` and `make test-fast`.
- Core CI lane: `make test-contracts`, targeted `go test` packages for detection and hygiene, schema/golden checks when public finding fields change.
- Acceptance lane: `make test-scenarios`, `scripts/validate_scenarios.sh`, and targeted scenario fixtures for scan-root and release-governance behavior.
- Cross-platform lane: Windows smoke plus path/symlink coverage where OS semantics differ; symlink tests must either run with proper platform guards or assert deterministic skip reasons.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf` when filesystem safety or hot-path package discovery changes.
- Release/UAT lane: `make prepush-full`, `make test-release-smoke`, `scripts/run_v1_acceptance.sh --mode=release`, `bash scripts/test_uat_local.sh` for release-facing changes.
- Gating rule: no story is complete until declared lanes are green, the first failing regression test is present, changed docs and changelog entries are synchronized, and repeated fixture runs produce byte-stable output except explicit timestamp/version fields.

## Minimum-Now Sequence

- Wave 1 - P0 release integrity:
  - Story 1.1 publish-after-verification release workflow.
- Wave 2 - P0 source-boundary safety:
  - Story 2.1 central walked-file safe-read contract.
  - Story 2.2 detector migration and symlink escape regression matrix.
- Wave 3 - P0 parser fail-closed behavior:
  - Story 3.1 malformed skill frontmatter parse-error handling.
- Wave 4 - P1 validation determinism:
  - Story 4.1 deterministic Go package discovery for local and CI gates.

## Explicit Non-Goals

- No new product feature outside Wrkr discovery, risk, proof, release, or validation governance.
- No LLM-based parsing, scoring, summarization, or remediation generation.
- No live network probing for detector validation.
- No broad raw source-content scanning expansion.
- No breaking removal of existing finding, proof, state, or schema fields without a versioned migration plan.
- No bypass of GitHub branch protection or release signing/provenance controls.
- No cleanup or filesystem mutation outside Wrkr-managed temporary/test paths.

## Definition of Done

- Every story includes a failing regression test that reproduces the reviewed failure mode.
- All detector file reads that can be reached from walked or globbed paths are covered by safe-root tests.
- Release workflow tests fail if any publish-capable step appears before integrity verification.
- Malformed structured input tests assert parse-error metadata, stable reason codes, and non-low-risk behavior when risky grants are undecidable.
- Local and CI package discovery use the same deterministic package list.
- Docs and changelog entries are updated in the same implementation PR where behavior or governance changes.
- `make lint-fast`, `make test-fast`, and relevant focused package tests pass for each story.
- P0 security/release stories run `make test-contracts`, `make test-scenarios`, `make test-hardening`, and `make test-chaos` as declared.
- Release-facing work runs `make prepush-full` or a documented profile-approved equivalent with the same release contract coverage before tagging.
- Final review includes a repo-wide search proving no committed plan, doc, or public artifact contains developer-specific absolute checkout paths.

## Epic 1: Release Integrity Publication Ordering

Objective: make release publication impossible until all artifact integrity gates have passed.

### Story 1.1: Publish release artifacts only after verification gates

Priority: P0
Recommendation coverage: 1, 2
Strategic direction: Release pipelines should stage artifacts, verify them, and only then publish public assets and downstream package metadata.
Expected benefit: Prevents failed vulnerability, signing, provenance, or checksum gates from leaving public artifacts or Homebrew tap updates behind.

Tasks:
- Add a workflow contract test under `testinfra/contracts` or `testinfra/hygiene` that fails when any publish-capable GoReleaser invocation or release/upload action precedes checksum, SBOM, vulnerability scan, signing, provenance, and verification steps.
- Change `.github/workflows/release.yml` so tag builds first create local candidate artifacts without publishing.
- Ensure checksum verification, SBOM generation, Grype scan, cosign signing, provenance attestation, and in-pipeline verification run against the same staged artifact set that will be published.
- Move the publish-capable GoReleaser/release step to the final gated stage, or split publishing into an explicit final command that cannot run until prior steps succeed.
- Preserve snapshot behavior for non-tag/manual dry-run paths without publishing public artifacts.
- Update `docs/trust/release-integrity.md` to document the build, verify, sign, attest, publish sequence.
- Add an Unreleased changelog entry under `Security`.

Repo paths:
- `.github/workflows/release.yml`
- `.goreleaser.yaml`
- `testinfra/contracts/story0_contracts_test.go`
- `testinfra/hygiene/toolchain_pins_test.go`
- `docs/trust/release-integrity.md`
- `CHANGELOG.md`

Run commands:
- `go test ./testinfra/contracts -run 'Test.*Release|Test.*Workflow' -count=1`
- `go test ./testinfra/hygiene -run 'Test.*Release|Test.*Toolchain' -count=1`
- `make test-contracts`
- `make test-release-smoke`
- `scripts/run_v1_acceptance.sh --mode=release`
- `make prepush-full`

Test requirements:
- TDD workflow-order test that fails on the current `goreleaser release --clean` placement.
- Contract fixture covering tag and snapshot paths.
- Release smoke verifying generated archives, checksums, SBOM, signing, provenance, and install-path parity.
- Docs consistency check proving release-integrity docs mention the post-gate publication order.

Matrix wiring:
- Fast lane: targeted workflow contract tests plus `make lint-fast`.
- Core CI lane: `make test-contracts`.
- Acceptance lane: release acceptance subset through `scripts/run_v1_acceptance.sh --mode=release`.
- Cross-platform lane: keep existing Windows smoke unaffected; release artifact matrix remains Linux-hosted unless release policy changes.
- Risk lane: `make test-hardening` if workflow changes affect signing, provenance, or scanner setup.
- Release/UAT lane: `make test-release-smoke`, `make prepush-full`, and `bash scripts/test_uat_local.sh` before a real tag.

Acceptance criteria:
- A failed Grype, cosign, checksum, or provenance step cannot publish GitHub release assets, release notes, or Homebrew tap changes.
- The workflow contract test fails if a publish-capable step is moved above verification.
- Snapshot builds remain non-publishing.
- Release docs and changelog reflect the corrected order.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Prevent release artifacts and Homebrew tap updates from publishing until checksum, SBOM, vulnerability scan, signing, provenance, and verification gates pass.
Semver marker override: [semver:patch]
Contract/API impact: Release workflow contract and OSS trust posture change; CLI JSON/exits unchanged.
Versioning/migration impact: No artifact schema migration. Release operators must use the updated workflow sequence for future tags.
Architecture constraints: Preserve immutable build and supply-chain integrity requirements from `product/dev_guides.md`; do not move release policy/sign/verify logic outside authoritative workflow and tested scripts.
ADR required: no
TDD first failing test(s): Workflow-order contract test showing current tag release publishes before post-build integrity gates.
Cost/perf impact: low
Chaos/failure hypothesis: If any post-build gate fails, the release job exits before publication and leaves no public asset/tap mutation.

## Epic 2: Source Boundary and Detector Safe Reads

Objective: ensure static discovery never reads outside the selected repo root through symlinked walked files.

### Story 2.1: Centralize safe walked-file handling

Priority: P0
Recommendation coverage: 3
Strategic direction: The detector framework should make safe-root handling the default path, so individual detectors cannot accidentally follow external symlinks.
Expected benefit: Preserves zero-exfiltration and proof correctness by preventing external files from being emitted as repo-local evidence.

Tasks:
- Add failing tests in `core/detect` for a walked file symlink that resolves outside the scan root.
- Extend `WalkFilesWithOptions` or add a sibling helper that resolves candidate files and rejects symlink escapes before detectors parse them.
- Preserve deterministic ordering and existing ignore/hidden-directory behavior.
- Return stable parse-error metadata or exclusion behavior for unsafe paths, with no raw external resolved target serialized by default.
- Document the helper contract so new detectors use the safe API.
- Update any existing tests that intentionally exercise symlink behavior to assert the new fail-closed contract.

Repo paths:
- `core/detect/parse.go`
- `core/detect/parse_test.go`
- `core/detect/testdata/`
- `product/architecture_guides.md` only if source-boundary wording needs clarification
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect -run 'Test.*Walk|Test.*Symlink|Test.*ReadFileWithinRoot' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make lint-fast`

Test requirements:
- Unit tests for in-root regular files, in-root symlinks, external symlink files, broken symlinks, hidden directories, and deterministic sort order.
- Hardening test proving external file contents are never read or surfaced in output.
- Cross-platform handling for symlink privilege differences with deterministic skip or fixture behavior.

Matrix wiring:
- Fast lane: `go test ./core/detect ...` plus `make lint-fast`.
- Core CI lane: `make test-contracts`.
- Acceptance lane: targeted scan fixture once migrated detector tests exist.
- Cross-platform lane: Windows path/symlink coverage with deterministic platform behavior.
- Risk lane: `make test-hardening` and `make test-chaos`.

Acceptance criteria:
- Walked external symlink files are rejected before detector-specific parsing.
- Existing safe direct-read tests continue to pass.
- Returned findings or parse errors are stable, sorted, and do not leak external absolute paths.
- New detector APIs make unsafe direct reads visible in code review and tests.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Reject symlinked detector inputs that resolve outside the selected scan root to preserve source-boundary and proof-record integrity.
Semver marker override: [semver:patch]
Contract/API impact: Detection behavior changes for unsafe symlinked repo files; public CLI shape remains compatible unless existing parse-error fields are added.
Versioning/migration impact: No schema migration expected if existing parse-error shape is reused; otherwise add optional fields only.
Architecture constraints: Detection boundary must own parsing while respecting Source boundary semantics; Risk and Proof emission must consume detector output rather than reading raw files.
ADR required: yes
TDD first failing test(s): `TestWalkFilesWithOptionsRejectsExternalSymlinkedFile` reproducing a symlinked `SKILL.md` or generic walked file outside root.
Cost/perf impact: low to medium, depending on symlink resolution per walked file.
Chaos/failure hypothesis: If symlink resolution fails, detection emits a stable unsafe-path/parse-error result and continues deterministically without reading file contents.

### Story 2.2: Migrate walk-based detectors and add symlink escape regressions

Priority: P0
Recommendation coverage: 4, 5
Strategic direction: Detector ownership should be explicit: every walked or globbed path is parsed only after root-bound safety checks.
Expected benefit: Closes the same source-boundary bug across high-risk AI tooling surfaces instead of fixing only the reproduced skill case.

Tasks:
- Inventory all detector paths that combine walking/globbing with direct `os.ReadFile`.
- Migrate skill, prompt/channel, Cursor rules, dependency manifest, WebMCP, workflow, and non-human identity reads to the safe helper.
- Add fixture tests for each migrated detector using external symlinked files with sentinel content that must not appear in findings, proof records, JSON stdout, or logs.
- Verify normal in-root detections are unchanged for representative fixtures.
- Add a lightweight static/hygiene check or targeted test that flags new detector direct reads reachable from walked paths.
- Update security/privacy docs if user-facing symlink behavior is documented there.

Repo paths:
- `core/detect/skills/detector.go`
- `core/detect/skills/detector_test.go`
- `core/detect/promptchannel/detector.go`
- `core/detect/promptchannel/detector_test.go`
- `core/detect/cursor/detector.go`
- `core/detect/cursor/detector_test.go`
- `core/detect/dependency/detector.go`
- `core/detect/dependency/detector_test.go`
- `core/detect/webmcp/detector.go`
- `core/detect/webmcp/detector_test.go`
- `core/detect/nonhumanidentity/detector.go`
- `core/detect/nonhumanidentity/detector_test.go`
- `testinfra/hygiene/`
- `docs/trust/security-and-privacy.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/skills ./core/detect/promptchannel ./core/detect/cursor ./core/detect/dependency ./core/detect/webmcp ./core/detect/nonhumanidentity -run 'Test.*Symlink|Test.*External|Test.*Detect' -count=1`
- `go test ./testinfra/hygiene -run 'Test.*Detector|Test.*ReadFile' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`

Test requirements:
- Detector-specific symlink escape regressions for every migrated surface.
- Sentinel-leak assertions across JSON scan output and proof/state artifacts where the detector emits findings.
- Golden/fixture updates only when output changes intentionally.
- Scenario coverage for mixed-org fixture behavior after safe-read migration.

Matrix wiring:
- Fast lane: focused detector package tests and `make test-fast`.
- Core CI lane: `make test-contracts`.
- Acceptance lane: `make test-scenarios` and `scripts/validate_scenarios.sh`.
- Cross-platform lane: Windows smoke plus platform-aware symlink tests.
- Risk lane: `make test-hardening` and `make test-chaos`.

Acceptance criteria:
- The reproduced external symlinked `.agents/skills/.../SKILL.md` case no longer reads external content or emits it as in-repo evidence.
- All migrated detectors preserve valid in-root detections.
- Sentinel external content is absent from scan JSON, state, proof, reports, and logs in the regression fixtures.
- A future detector direct-read regression is caught by test or hygiene coverage.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Harden walked detector inputs so symlinked files outside the selected repo root cannot be read or recorded as repo-local evidence.
Semver marker override: [semver:patch]
Contract/API impact: Public findings may include deterministic unsafe-path parse errors for unsafe symlinked inputs; no breaking CLI shape change.
Versioning/migration impact: Optional parse-error fields only if needed; existing baselines with unsafe symlink findings may drift and should be treated as security-corrected drift.
Architecture constraints: Preserve Detection, Risk, and Proof emission boundaries. Do not let downstream risk/proof code re-open source files.
ADR required: no
TDD first failing test(s): Detector-level tests for external symlinked skill, Cursor rule, prompt file, dependency manifest, WebMCP declaration, and identity/workflow input.
Cost/perf impact: medium for large repos if every candidate resolves symlinks; include perf lane if helper adds measurable overhead.
Chaos/failure hypothesis: Broken, cyclic, or permission-denied symlink paths produce stable unsafe/parse results without panics or external content reads.

## Epic 3: Skill Parser Fail-Closed Semantics

Objective: prevent malformed structured skill metadata from hiding risky tool grants.

### Story 3.1: Emit parse errors for malformed skill frontmatter

Priority: P0
Recommendation coverage: 6
Strategic direction: Structured YAML parsing failures in high-risk skill metadata should be visible and risk-bearing rather than silently interpreted as empty configuration.
Expected benefit: Operators see malformed or ambiguous skill grants as actionable findings, and risk scoring cannot be suppressed by invalid syntax.

Tasks:
- Add a failing unit test for malformed `allowed-tools` frontmatter such as `allowed-tools: [`.
- Change `parseAllowedTools` to return structured parse-error metadata when frontmatter exists but YAML decoding fails.
- Keep absent frontmatter behavior distinct from invalid frontmatter behavior.
- Ensure malformed skill findings are not emitted as low risk with `allowed_tools_count=0`.
- Add reason-code stability coverage for the parse error.
- Update docs only if skill parsing behavior is documented in user-facing command or trust docs.
- Add an Unreleased changelog entry under `Security`.

Repo paths:
- `core/detect/skills/detector.go`
- `core/detect/skills/detector_test.go`
- `schemas/v1/findings/` if parse-error schema examples need optional field coverage
- `docs/trust/security-and-privacy.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/detect/skills -run 'Test.*Frontmatter|Test.*AllowedTools|Test.*ParseError' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-scenarios`
- `make lint-fast`

Test requirements:
- Unit tests for absent frontmatter, valid empty frontmatter, valid `allowed-tools`, malformed YAML, and malformed high-risk grants.
- Contract/golden coverage when finding JSON shape or parse-error details change.
- Deterministic severity and reason-code assertions.

Matrix wiring:
- Fast lane: `go test ./core/detect/skills ...` plus `make test-fast`.
- Core CI lane: `make test-contracts`.
- Acceptance lane: scenario fixture if skill findings are represented in scenario contracts.
- Cross-platform lane: no special platform behavior expected.
- Risk lane: `make test-hardening`.

Acceptance criteria:
- Malformed structured frontmatter emits parse-error metadata.
- Invalid `allowed-tools` cannot be counted as zero tools with low severity.
- Existing valid skill findings and allowed-tool extraction remain stable.
- Contract fixtures and docs/changelog are synchronized where public output changes.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Treat malformed skill frontmatter as an actionable parse error so invalid `allowed-tools` metadata cannot silently downgrade skill risk.
Semver marker override: [semver:patch]
Contract/API impact: Finding details for malformed skill files become stricter and may include parse-error metadata; CLI command shape and exits unchanged.
Versioning/migration impact: Additive finding metadata only. Existing baselines with malformed skills may report corrected drift.
Architecture constraints: Use `gopkg.in/yaml.v3` consistently for structured config parsing; keep parser logic deterministic and detector-local.
ADR required: no
TDD first failing test(s): `TestSkillDetectorMalformedAllowedToolsFrontmatterEmitsParseError`.
Cost/perf impact: low
Chaos/failure hypothesis: Invalid or partial frontmatter produces a stable parse-error finding and does not panic, skip the file silently, or infer no risk.

## Epic 4: Deterministic Local Validation Hygiene

Objective: make Go validation commands independent of ignored generated docs-site dependencies.

### Story 4.1: Exclude ignored generated artifacts from Go package discovery

Priority: P1
Recommendation coverage: 7
Strategic direction: Local and CI gates should validate tracked Wrkr Go packages, not transient packages installed by documentation tooling.
Expected benefit: Contributors get reproducible fast-gate results whether or not `docs-site/node_modules` exists locally.

Tasks:
- Add a failing hygiene test that demonstrates the current package list can include ignored `docs-site/node_modules` Go packages.
- Introduce a deterministic package-list helper or Makefile expression that excludes ignored/generated directories such as `docs-site/node_modules`, `docs-site/.next`, `.tmp`, and `.wrkr`.
- Wire `lint-fast`, `test-fast`, and any dependent Go validation targets to the deterministic package list.
- Preserve docs-site Node workflows for docs-only checks; do not remove or vendor docs dependencies.
- Update `CONTRIBUTING.md` or local validation docs if contributor commands or expectations change.
- Add an Unreleased changelog entry under `Fixed` if contributor validation behavior is documented as part of OSS governance.

Repo paths:
- `Makefile`
- `scripts/` if a package-list helper is added
- `testinfra/hygiene/`
- `CONTRIBUTING.md`
- `docs/trust/deterministic-guarantees.md`
- `CHANGELOG.md`

Run commands:
- `go test ./testinfra/hygiene -run 'Test.*Package|Test.*GoList|Test.*Generated' -count=1`
- `make lint-fast`
- `make test-fast`
- `make test-contracts`
- `make prepush`

Test requirements:
- Hygiene test with a fixture or temporary ignored generated directory containing a Go package.
- Assertion that package discovery excludes `docs-site/node_modules`, `docs-site/.next`, `.tmp`, and `.wrkr`.
- Command-level verification that `make test-fast` no longer reports generated docs-site packages.

Matrix wiring:
- Fast lane: `make lint-fast` and `make test-fast`.
- Core CI lane: `make test-contracts` and package-list hygiene test.
- Acceptance lane: not required beyond preserving scenario validation.
- Cross-platform lane: Windows smoke should use the same deterministic package list.
- Risk lane: `make test-perf` only if package-list helper adds measurable overhead.

Acceptance criteria:
- `go list` used by Makefile-backed validation excludes ignored/generated docs artifacts.
- Clean CI and a local checkout with installed docs dependencies validate the same tracked Wrkr package set.
- Existing Go package tests still run.
- Contributor docs and changelog reflect any changed validation behavior.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Keep Go validation commands focused on tracked Wrkr packages so ignored docs-site dependency installs do not affect local fast-gate results.
Semver marker override: [semver:patch]
Contract/API impact: Contributor validation contract changes; CLI runtime output unchanged.
Versioning/migration impact: No runtime migration. Contributors may need to rerun `make lint-fast` or `make test-fast` after pulling the package-list update.
Architecture constraints: Node remains docs/UI only and must not enter core Go validation scope.
ADR required: no
TDD first failing test(s): Hygiene test that creates an ignored generated Go package and proves the validation package list excludes it.
Cost/perf impact: low
Chaos/failure hypothesis: If ignored generated directories exist, validation still uses the tracked package list and does not fail or pass based on transient dependencies.

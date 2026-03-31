# PLAN NEXT: Contract Hardening and Boundary Safety

Date: 2026-03-31
Source of truth: user-provided 2026-03-31 full-repo code-review findings, `AGENTS.md`, `product/dev_guides.md`, `product/architecture_guides.md`, `docs/commands/scan.md`, `docs/commands/evidence.md`, `docs/commands/campaign.md`, `docs/extensions/detectors.md`
Scope: Wrkr repository only. Planning artifact only. Convert the four reproduced P1 findings into an execution-ready backlog plan that preserves Wrkr's deterministic, offline-first, fail-closed contract line.

This plan is execution-first: every story includes concrete repo paths, commands, tests, lane wiring, acceptance criteria, changelog intent, and architecture constraints.

---

## Global Decisions (Locked)

- This file is planning-only. No implementation work is in scope for this artifact.
- The four reproduced P1 findings are minimum-now release blockers. No lower-priority polish may displace them.
- Preserve Wrkr's v1 stable surfaces: offline-first defaults, deterministic `--json` outputs, exit codes `0..8`, proof-chain contracts, and schema stability unless a story explicitly proves a version bump is unavoidable.
- Marker-name-only trust is not acceptable on destructive filesystem paths. Managed-directory reuse must be bound to stronger provenance than a predictable marker filename and static contents.
- The authoritative scan commit point must be all-or-nothing across snapshot, lifecycle chain, proof chain/attestation, manifest, and explicitly requested sidecar artifacts. A failed scan must not advance only part of that set.
- `wrkr campaign aggregate` accepts only complete `wrkr scan --json` artifacts. Accepting arbitrary `status=ok` JSON is treated as a contract bug, not a supported compatibility surface.
- Repo-local extension detectors remain additive finding sources only unless an explicit, documented contract promotes them into authoritative tool/identity surfaces. Undocumented implicit promotion is blocked.
- Thin orchestration stays in `core/cli/*`; proof/state/persistence logic stays in focused packages. Shared safety helpers may be introduced, but they must not collapse the source, detection, identity, risk, proof, and evidence boundaries.
- Stories touching architecture/risk/adapter/failure semantics must include `make prepush-full`.
- Reliability and fault-tolerance stories must include `make test-hardening` and `make test-chaos`.
- Docs, trust pages, and changelog updates ship in the same PR as the contract/runtime change they describe.

---

## Current Baseline (Observed)

- Preconditions validated:
  - `product/dev_guides.md` exists and is readable.
  - `product/architecture_guides.md` exists and is readable.
  - `/Users/tr/wrkr/product/PLAN_NEXT.md` resolves inside the repository and is writable.
- Standards guides contain the enforceable rules required by this skill:
  - testing and CI gating via `make prepush`, `make prepush-full`, `make test-risk-lane`, `scripts/validate_scenarios.sh`, and `scripts/run_v1_acceptance.sh --mode=local`
  - determinism and contract stability via `testinfra/contracts`, `testinfra/hygiene`, scenario fixtures, and docs parity/storyline checks
  - architecture, TDD, frugal governance, and chaos requirements via `product/architecture_guides.md`
- Repository baseline is otherwise healthy:
  - `git status --short` is clean before writing this plan
  - `go test ./...` passed during the code review
  - command anchors exercised successfully in temp workspaces: `wrkr scan --json`, `wrkr verify --chain --json`, `wrkr regress init --json`, `wrkr regress run --json`
- Reproduced release-blocking gaps:
  - evidence output ownership can be spoofed by a forged `.wrkr-evidence-managed` marker, causing unrelated files in the selected output directory to be deleted
  - `scan` can exit `1` after a late artifact failure while still leaving `state.json`, `proof-chain.json`, and `wrkr-manifest.yaml` updated
  - `campaign aggregate` accepts non-scan JSON such as `wrkr version --json` and emits a bogus campaign artifact
  - repo-local extension descriptors can synthesize authoritative tool/identity surfaces (`agent_privilege_map`, `action_paths`, and downstream regress/proof state)
- Current documentation already promises stronger behavior than the runtime enforces:
  - `docs/commands/evidence.md` describes fail-closed managed output ownership
  - `docs/commands/campaign.md` says campaign aggregation accepts complete scan artifacts only
  - `docs/extensions/detectors.md` says extension findings do not bypass built-in detector/risk/proof boundaries

---

## Exit Criteria

1. Destructive managed-directory reuse is provenance-gated, not marker-name-only, across the touched ownership surfaces. Spoofed markers, symlink markers, directory markers, and unrelated non-empty directories fail closed.
2. `wrkr scan` publishes snapshot, lifecycle, proof, manifest, and requested sidecar artifacts as a transactional unit; a late failure leaves the prior generation intact and does not expose mixed artifacts.
3. `wrkr campaign aggregate` rejects non-scan JSON and malformed scan artifacts with stable `invalid_input` behavior while continuing to accept complete scan artifacts.
4. Extension findings no longer create authoritative tool, identity, action-path, or regress state unless a future explicit contract says so. Raw findings and risk ranking remain available.
5. Docs, trust pages, changelog guidance, and regression tests are aligned with the corrected semantics in the same change set.
6. All required fast, core, acceptance, cross-platform, and risk lanes declared below are green.

---

## Public API and Contract Map

Stable/public surfaces touched by this plan:

- `wrkr evidence --frameworks ... --output <dir> --json`
- `wrkr scan ... --state <path> --report-md --sarif --json --json-path`
- scan-owned sidecar artifact behavior documented around state, proof, and manifest adjacency
- `wrkr campaign aggregate --input-glob <glob> --json`
- exit-code and error-envelope behavior for `invalid_input`, `runtime_failure`, and `unsafe_operation_blocked`
- repository-local extension detector contract at `.wrkr/detectors/extensions.json`
- command/trust docs:
  - `docs/commands/scan.md`
  - `docs/commands/evidence.md`
  - `docs/commands/campaign.md`
  - `docs/extensions/detectors.md`
  - `docs/state_lifecycle.md`
  - relevant `docs/trust/*` pages

Internal surfaces expected to change:

- `core/evidence/stage.go`
- `core/evidence/evidence.go`
- `core/cli/scan.go`
- `core/cli/managed_artifacts.go`
- `core/cli/jsonmode.go`
- `core/cli/report_artifacts.go`
- `core/cli/campaign.go`
- `core/model/identity_bearing.go`
- supporting tests under `core/*_test.go`, `internal/e2e/*`, `internal/scenarios/*`, and `testinfra/contracts/*`

Shim and deprecation path:

- No CLI flags are removed in this plan.
- No schema version bump is assumed by default.
- Campaign input validation becomes stricter within the current contract line. Previously accepted non-scan JSON is treated as invalid input from this point forward.
- Extension findings remain in `findings`, `ranked_findings`, and raw scan evidence. Their undocumented promotion into authoritative state is removed. If future users need authoritative extension promotion, introduce it as an explicit descriptor contract with migration notes, not as an implicit default.
- Managed-directory provenance changes must include a safe compatibility path for already legitimate Wrkr-managed directories. Migration may be one-time and internal, but it must not silently authorize unrelated directories that only mimic marker contents.

Schema/versioning policy:

- Preserve current scan/report/evidence/campaign output keys and exit codes.
- Prefer additive internal metadata and stricter validators over user-visible schema changes.
- If an explicit future extension-promotion field is introduced, it must be additive, documented, schema-validated, and default to non-authoritative behavior.

Machine-readable error expectations:

- Ownership/provenance violations continue to return `unsafe_operation_blocked` with exit `8`.
- Invalid campaign inputs continue to return `invalid_input` with exit `6`.
- Transactional scan failures continue to return `runtime_failure` or `invalid_input` according to the failing step, but must leave managed artifacts untouched on failure.
- No story may convert these failure classes into warnings or partial successes.

---

## Docs and OSS Readiness Baseline

README first-screen contract:

- Wrkr remains an open-source deterministic scanner for AI tooling posture and proof artifacts.
- Do not imply runtime observation, live enforcement, or control-plane behavior.
- Quickstart remains integration-first: scan, report, evidence, verify.

Integration-first docs flow:

- `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
- `wrkr report --state ./.wrkr/last-scan.json --json`
- `wrkr evidence --frameworks eu-ai-act,soc2 --state ./.wrkr/last-scan.json --json`
- `wrkr verify --chain --state ./.wrkr/last-scan.json --json`

Lifecycle path model:

- scan and source acquisition
- deterministic findings, inventory, identity, and risk shaping
- authoritative state/proof/manifest publish
- report, campaign, evidence, and verify read from committed state only

Docs source-of-truth mapping:

- command contracts: `docs/commands/*.md`
- lifecycle and artifact semantics: `docs/state_lifecycle.md`
- extension contract: `docs/extensions/detectors.md`
- trust posture and compatibility language: `docs/trust/*.md`
- public overview and install parity: `README.md`, `docs/install/minimal-dependencies.md`

OSS trust baseline:

- `CHANGELOG.md` must be updated for every story marked `Changelog impact: required`
- `SECURITY.md` remains aligned when public safety posture or operator expectations change
- `CONTRIBUTING.md` remains the contributor-facing policy source if workflow expectations shift
- issue and PR templates are unaffected unless implementation changes maintainer expectations; otherwise leave unchanged

---

## Recommendation Traceability

| Recommendation | Why now | Strategic direction | Expected moat / benefit | Story IDs |
|---|---|---|---|---|
| Replace forgeable marker-file trust on destructive output paths | Prevent local data destruction and meet fail-closed ownership rules | Hard safety boundary for managed artifacts | Safer OSS adoption and higher operator trust in local execution | `SAFE-01`, `DOCS-01` |
| Make scan publication transactional across state, proof, manifest, and late artifacts | Eliminate mixed-generation authoritative state after failed scans | Deterministic state commit semantics | Stronger CI/operator reliability and proof integrity confidence | `SAFE-02`, `DOCS-01` |
| Reject non-scan JSON in campaign aggregation | Restore campaign input contract and prevent bogus summaries | Contract-first machine-readable validation | Safer automation and cleaner downstream posture reporting | `CONTRACT-01`, `DOCS-01` |
| Stop extension findings from entering authoritative surfaces by default | Block false identities, proof records, and regress drift | Preserve core-authority boundaries | Lower noise, more trustworthy proof/regress outputs, less fork pressure | `BOUNDARY-01`, `DOCS-01` |

---

## Test Matrix Wiring

Lane definitions:

- Fast lane: `make lint-fast`, targeted `go test` for touched packages, and narrow docs parity checks when public wording moves.
- Core CI lane: `make prepush` plus `make prepush-full` for architecture/risk/failure stories.
- Acceptance lane: `make test-contracts`, `make test-scenarios`, and targeted e2e coverage for the changed command surfaces.
- Cross-platform lane: `windows-smoke` plus any touched Go tests that are expected to remain platform-safe.
- Risk lane: `make test-risk-lane`; for reliability/failure stories, explicitly include `make test-hardening` and `make test-chaos`.

Story-to-lane map:

| Story | Fast | Core CI | Acceptance | Cross-platform | Risk |
|---|---|---|---|---|---|
| `SAFE-01` | Yes | Yes | Yes | Yes | Yes |
| `SAFE-02` | Yes | Yes | Yes | Yes | Yes |
| `CONTRACT-01` | Yes | Yes | Yes | Yes | No |
| `BOUNDARY-01` | Yes | Yes | Yes | Yes | Yes |
| `DOCS-01` | Yes | Yes | Yes | No | No |

Merge/release gating rule:

- Any story with `Core CI lane: required` must not merge unless `make prepush-full` passes locally and the equivalent CI lanes are green.
- Any story with `Risk lane: required` must also keep `make test-risk-lane` green.
- Release tags remain blocked on the existing release workflow, but these stories must keep release-path docs, contracts, and binary validation consistent with the current pinned toolchain and scanner regime.

---

## Epic WRKR-HARDEN-1: Managed Artifact Safety and Transactional Publishing

Objective: remove destructive marker spoofing and mixed-generation scan state by hardening ownership validation and atomic publication semantics before any later contract fixes land.

### Story SAFE-01: Replace marker-name-only trust with provenance-gated managed artifact ownership
Priority: P0
Tasks:
- Design a provenance model for Wrkr-managed directories that is stronger than marker filename plus static contents and is compatible with the current state-directory layout.
- Implement the new ownership gate first on evidence output directories, then apply the same safety rule to the equivalent scan-owned managed roots touched by this review if they share the same destructive trust pattern.
- Preserve current fail-closed rejections for symlink markers, directory markers, non-empty unmanaged directories, and root-escaping path tricks.
- Add compatibility handling for already legitimate Wrkr-managed directories so users can rerun commands without manual cleanup, while forged legacy markers remain blocked.
- Add deterministic tests for spoofed markers, symlink markers, directory markers, mismatched provenance, valid managed reruns, and publish rollback after failed stage promotion.
Repo paths:
- `core/evidence/stage.go`
- `core/evidence/evidence.go`
- `core/cli/scan_helpers.go`
- `core/source/org/checkpoint.go`
- `core/evidence/evidence_test.go`
- `internal/scenarios/permission_failure_surfacing_scenario_test.go`
- `docs/commands/evidence.md`
- `docs/state_lifecycle.md`
Run commands:
- `go test ./core/evidence ./core/source/org ./core/cli -count=1`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- gate/policy/fail-closed fixtures for `non-empty + non-managed => fail`
- marker trust tests proving marker must be a regular file and that symlink/directory markers fail
- crash-safe publish tests for failed stage swap and rollback restore
- repeat-run determinism checks for valid managed reruns
- scenario coverage for unsafe local path handling
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- Evidence output reuse is denied for directories that only mimic the old marker contents.
- Legitimate Wrkr-managed output directories continue to rerun safely under the migrated provenance scheme.
- No destructive command path authorizes deletion based only on marker filename and static content.
- Public docs describe the corrected ownership semantics without weakening fail-closed guarantees.
Changelog impact: required
Changelog section: Security
Draft changelog entry: Hardened managed output and scan-owned directory ownership checks so forged marker files can no longer authorize destructive reuse of caller-selected paths.
Semver marker override: none
Contract/API impact: Public flags and exit codes stay the same; `unsafe_operation_blocked` remains the failure class for unsafe ownership reuse, but the acceptance rule becomes stricter and correct.
Versioning/migration impact: No schema bump planned. Implementation must include an explicit compatibility path for legitimate legacy managed directories and block forged legacy markers.
Architecture constraints:
- Keep ownership/provenance logic in a focused helper rather than duplicating ad hoc marker checks.
- Preserve explicit side-effect semantics in API names for validate, stage, publish, and cleanup steps.
- Do not let CLI orchestration own provenance policy; core packages remain authoritative.
- Keep extension points available for other managed-root callers without widening trust by default.
ADR required: yes
TDD first failing test(s):
- `go test ./core/evidence -run 'TestBuildEvidenceRejectsForgedLegacyMarker$|TestBuildEvidenceAcceptsMigratedManagedOutput$|TestBuildEvidenceRejectsMarkerSymlink$' -count=1`
- `go test ./core/source/org -run 'TestPrepareCheckpointRootRejectsForgedManagedRoot$' -count=1`
Cost/perf impact: low
Chaos/failure hypothesis: If a caller selects a pre-populated path that only impersonates a Wrkr-managed directory, Wrkr must abort without deleting or replacing any unrelated files.

### Story SAFE-02: Make scan publication transactional across snapshot, proof, manifest, and requested sidecars
Priority: P0
Dependencies: `SAFE-01` if the provenance helper is shared; otherwise independent
Tasks:
- Introduce a scan-owned managed-artifact transaction helper that can snapshot, stage, and roll back the full authoritative artifact set.
- Convert `wrkr scan` publication order so snapshot, lifecycle chain, proof chain/attestation, manifest, `--json-path`, `--report-md`, and `--sarif` are committed as one managed generation.
- Ensure late failures in report, SARIF, or JSON-path publication leave the previous generation untouched and do not expose mixed outputs.
- Align scan-side transaction handling with the rollback discipline already used by manual identity transitions.
- Add deterministic tests for late artifact failure, prior-generation preservation, repeat-run byte stability, and no duplicate lifecycle/proof side effects after retry.
Repo paths:
- `core/cli/scan.go`
- `core/cli/managed_artifacts.go`
- `core/cli/jsonmode.go`
- `core/cli/report_artifacts.go`
- `core/cli/scan_*_test.go`
- `internal/e2e/cli_contract/cli_contract_e2e_test.go`
- `docs/commands/scan.md`
- `docs/state_lifecycle.md`
Run commands:
- `go test ./core/cli ./internal/e2e/cli_contract ./internal/e2e/verify -count=1`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- CLI help/usage and `--json` stability tests
- machine-readable error-envelope checks for late artifact failures
- lifecycle tests proving prior generation survives a failed late write
- crash-safe and atomic-write tests for transactional publish
- deterministic repeat-run tests for state/proof/manifest bundles
- contract tests proving invalid artifact paths do not mutate managed state
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- A failed late artifact write leaves the prior snapshot, proof chain, lifecycle chain, and manifest unchanged.
- Successful scans publish a single coherent generation across all requested managed artifacts.
- Retrying after a failed late write does not duplicate lifecycle or proof records.
- Public scan docs no longer claim semantics the runtime does not enforce.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Made scan artifact publication transactional so failed late writes no longer leave mixed state, proof, and manifest generations on disk.
Semver marker override: none
Contract/API impact: No flag or schema changes are planned; the contract change is stricter state-safety under existing exit-code and error-envelope behavior.
Versioning/migration impact: No version bump planned. Existing artifact locations remain stable; only commit ordering and rollback behavior change.
Architecture constraints:
- Keep transaction orchestration thin in `core/cli/scan.go`; snapshot/rollback mechanics belong in focused helpers.
- Preserve explicit `validate`, `stage`, `publish`, and `rollback` semantics rather than hidden side effects.
- Maintain cancellation and timeout propagation through staged publish paths.
- Do not special-case optional sidecars in ways that weaken the authoritative commit rule.
ADR required: yes
TDD first failing test(s):
- `go test ./core/cli -run 'TestScanLateReportFailureRollsBackManagedArtifacts$|TestScanLateSARIFFailureRollsBackManagedArtifacts$|TestScanJSONPathFailureLeavesPreviousGenerationUntouched$' -count=1`
- `go test ./internal/e2e/cli_contract -run 'TestE2EScanTransactionalPublish$' -count=1`
Cost/perf impact: medium
Chaos/failure hypothesis: If scan succeeds through snapshot/proof generation but fails while writing a requested sidecar artifact, Wrkr must exit non-zero and leave the previous managed generation intact.

---

## Epic WRKR-HARDEN-2: Contract Input and Authoritative Boundary Enforcement

Objective: close the machine-readable ingestion and extension-boundary leaks so only real scan artifacts and real authoritative tool surfaces can influence campaign, lifecycle, proof, and regress behavior.

### Story CONTRACT-01: Enforce complete scan-artifact validation in `campaign aggregate`
Priority: P0
Tasks:
- Define the minimum scan-artifact contract required by campaign aggregation and validate it before summarization.
- Reject non-scan JSON, malformed scan JSON, and incomplete scan JSON with stable `invalid_input` behavior.
- Keep acceptance of complete scan artifacts unchanged.
- Add contract and e2e tests that explicitly use `wrkr version --json`, `wrkr report --json`, and degraded scan artifacts as negative inputs.
- Update campaign docs to align with the enforced validator rather than best-effort assumptions.
Repo paths:
- `core/cli/campaign.go`
- `core/cli/campaign_test.go`
- `internal/e2e/campaign/campaign_e2e_test.go`
- `testinfra/contracts/story24_contracts_test.go`
- `docs/commands/campaign.md`
Run commands:
- `go test ./core/cli ./internal/e2e/campaign ./testinfra/contracts -count=1`
- `make prepush-full`
- `make test-contracts`
- `make test-scenarios`
Test requirements:
- CLI `--json` and exit-code contract tests
- machine-readable error-envelope checks for invalid non-scan inputs
- compatibility tests that complete scan artifacts still aggregate successfully
- fixture/golden updates for rejected malformed inputs where applicable
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: not required
Acceptance criteria:
- `wrkr campaign aggregate --input-glob <version-json>` exits `6` with `invalid_input`.
- Complete scan artifacts continue to aggregate successfully with deterministic ordering.
- Incomplete or degraded scan artifacts remain rejected.
- Campaign docs now describe enforced validation rather than best-effort interpretation.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: `wrkr campaign aggregate` now rejects non-scan JSON and incomplete artifacts with stable `invalid_input` errors instead of summarizing them as posture evidence.
Semver marker override: none
Contract/API impact: Tightens the existing public input contract for campaign aggregation without changing flags or success-envelope shape.
Versioning/migration impact: No version bump planned. Consumers relying on accidental acceptance of non-scan JSON must migrate to passing real `wrkr scan --json` artifacts.
Architecture constraints:
- Keep the validator as a focused contract-check helper rather than mixing validation and aggregation.
- Preserve symmetric semantics: parse and validate before summarize.
- Do not add network or external dependency lookups to infer missing fields.
ADR required: no
TDD first failing test(s):
- `go test ./core/cli -run 'TestCampaignAggregateRejectsVersionEnvelope$|TestCampaignAggregateRejectsReportEnvelope$|TestCampaignAggregateRejectsMalformedScanArtifact$' -count=1`
- `go test ./internal/e2e/campaign -run 'TestCampaignAggregateRequiresRealScanArtifacts$' -count=1`
Cost/perf impact: low
Chaos/failure hypothesis: If the input glob accidentally matches a non-scan JSON file, campaign aggregation must fail deterministically before any summary artifact is emitted.

### Story BOUNDARY-01: Keep extension findings out of authoritative tool, identity, and regress surfaces by default
Priority: P0
Tasks:
- Remove the implicit rule that any extension finding with a non-excluded `tool_type` is inventory-bearing and identity-bearing.
- Preserve extension findings in raw `findings` and risk outputs unless a future explicit contract promotes them.
- Add regression tests showing extension-only repositories do not emit tool records, manifest identities, `agent_privilege_map`, `action_paths`, or regress drift by default.
- Decide and document the future extension-promotion path as an explicit follow-up contract, not a hidden default.
- Update extension and scan docs to match the corrected behavior.
Repo paths:
- `core/model/identity_bearing.go`
- `core/model/identity_bearing_test.go`
- `core/aggregate/inventory/inventory_test.go`
- `core/regress/regress_test.go`
- `core/cli/scan_observed_tools_test.go`
- `core/cli/scan_agent_context_test.go`
- `docs/extensions/detectors.md`
- `docs/commands/scan.md`
Run commands:
- `go test ./core/model ./core/aggregate/inventory ./core/regress ./core/cli -count=1`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-scenarios`
Test requirements:
- deterministic classifier fixtures for identity-bearing vs non-identity-bearing findings
- regress drift tests proving extension-only repos do not create false tool state
- CLI and scan contract tests showing extension findings stay visible in `findings` but absent from authoritative surfaces
- docs parity checks for corrected extension semantics
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- Extension findings remain visible in scan findings and risk ranking.
- Extension-only repos no longer create tool identities, privilege-map rows, action paths, or regress baseline entries by default.
- Docs stop claiming extension findings are additive while runtime still promotes them into authoritative state.
- Future authoritative extension support is explicitly deferred or separately versioned.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Repo-local extension detectors now stay on additive finding surfaces by default and no longer create implicit tool identities, action paths, or regress state.
Semver marker override: none
Contract/API impact: Narrows authoritative-surface behavior to match documented boundaries while preserving raw extension findings.
Versioning/migration impact: No schema bump planned. Consumers that depended on undocumented extension-generated identities must migrate to raw findings until a future explicit promotion contract exists.
Architecture constraints:
- Keep authoritative-surface classification centralized and explicit.
- Do not let detector-local logic decide lifecycle or regress authority by itself.
- Preserve room for a future explicit extension point without reintroducing silent promotion.
- Avoid boundary leakage from detection straight into identity or regress.
ADR required: yes
TDD first failing test(s):
- `go test ./core/model -run 'TestIsIdentityBearingFindingExtensionDefaultsToFalse$|TestIsInventoryBearingFindingExtensionDefaultsToFalse$' -count=1`
- `go test ./core/cli -run 'TestScanExtensionFindingDoesNotEmitAuthoritativeSurfaces$' -count=1`
- `go test ./core/regress -run 'TestExtensionOnlyFindingDoesNotCreateDriftReason$' -count=1`
Cost/perf impact: low
Chaos/failure hypothesis: If a repository adds a custom extension descriptor with an arbitrary `tool_type`, Wrkr must not let that finding create approval gaps, tool identities, or regress drift without an explicit future promotion contract.

---

## Epic WRKR-HARDEN-3: Docs, Changelog, and Acceptance Lock-In

Objective: codify the corrected semantics in user-facing docs, trust guidance, changelog language, and durable regression suites after the runtime behavior is fixed.

### Story DOCS-01: Align docs, changelog, and executable regression coverage with the hardened runtime
Priority: P1
Dependencies: `SAFE-01`, `SAFE-02`, `CONTRACT-01`, `BOUNDARY-01`
Tasks:
- Update command docs, trust pages, and lifecycle docs so ownership gating, transactional scan publication, campaign input validation, and extension-boundary semantics all match runtime behavior.
- Add or update scenario, e2e, and contract tests that lock in the four reproduced regressions from the review.
- Update `CHANGELOG.md` `## [Unreleased]` with operator-facing entries that reflect the corrected safety and contract behavior.
- Review README/install/trust wording to ensure no page promises weaker or stronger semantics than the implemented runtime.
- Verify docs-site parity for any touched command/trust pages.
Repo paths:
- `docs/commands/scan.md`
- `docs/commands/evidence.md`
- `docs/commands/campaign.md`
- `docs/extensions/detectors.md`
- `docs/state_lifecycle.md`
- `docs/trust/compatibility-and-versioning.md`
- `docs/trust/contracts-and-schemas.md`
- `CHANGELOG.md`
- `internal/scenarios/*`
- `testinfra/contracts/*`
- `docs-site/src/lib/docs.ts`
- `docs-site/src/lib/markdown.ts`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `make docs-site-build`
- `make docs-site-check`
- `make test-contracts`
- `make test-scenarios`
- `scripts/run_v1_acceptance.sh --mode=local`
Test requirements:
- docs consistency, storyline, and smoke checks
- README first-screen and integration-first flow checks for touched flows
- scenario and contract updates for the four reproduced regressions
- changelog and OSS trust surface verification where touched
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: not required
- Risk lane: not required
Acceptance criteria:
- Public docs and trust pages no longer contradict runtime semantics for the four blocker areas.
- `CHANGELOG.md` contains operator-facing entries for the user-visible behavior changes.
- Scenario and contract tests fail if any of the four corrected regressions reappear.
- Docs-site and command docs remain in sync.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Updated scan, evidence, campaign, and extension-detector docs plus regression coverage to match the hardened contract and boundary behavior.
Semver marker override: none
Contract/API impact: No new runtime contract is introduced here; this story aligns the public documentation and regression suite with the implemented fixes.
Versioning/migration impact: No version bump planned. This story documents migration expectations already declared in the runtime stories.
Architecture constraints:
- Keep docs as executable contract companions to the runtime.
- Do not move normative behavior into docs without matching enforcement in code and tests.
- Preserve README first-screen positioning inside Wrkr's static posture boundary.
ADR required: no
TDD first failing test(s):
- `go test ./testinfra/contracts -run 'TestCampaignContractRejectsNonScanInputs|TestScanContractLateArtifactFailureDoesNotMutateManagedState' -count=1`
- `go test ./internal/scenarios -run 'TestExtensionFindingStaysNonAuthoritative|TestEvidenceRejectsForgedManagedOutput' -count=1 -tags=scenario`
- `make test-docs-consistency`
Cost/perf impact: low
Chaos/failure hypothesis: If a future change reintroduces one of these boundary or ownership regressions, docs parity and executable regression suites must fail before release.

---

## Minimum-Now Sequence

Wave 1:

- `SAFE-01` to close destructive ownership spoofing and establish the shared provenance rule.
- `SAFE-02` to make scan publication atomic once managed-artifact safety primitives are in place.

Wave 2:

- `CONTRACT-01` to enforce real scan-artifact validation for campaign aggregation.
- `BOUNDARY-01` to remove extension findings from authoritative state by default.

Wave 3:

- `DOCS-01` after Waves 1 and 2 settle the runtime semantics, so docs, changelog, and executable regressions lock the final behavior rather than intermediate drafts.

Parallelization notes:

- `CONTRACT-01` and `BOUNDARY-01` can run in parallel after Wave 1 because their write scopes are largely disjoint.
- `DOCS-01` must follow the runtime stories so wording and golden expectations are anchored to shipped behavior.

---

## Explicit Non-Goals

- No new dashboard, web control plane, or hosted runtime scope.
- No expansion of detector coverage beyond what is needed to fix the extension-boundary leak.
- No new proof-record types, schema version bumps, or exit-code renumbering unless a later implementation proves them unavoidable and ships a migration plan.
- No unrelated CI workflow renames, packaging changes, or toolchain pin updates unless directly required by these fixes.
- No runtime observation or enforcement features; Wrkr remains in the See boundary.

---

## Definition of Done

- Every recommendation above maps to at least one completed story and all required lanes for those stories are green.
- Acceptance criteria are proven by deterministic tests or docs/build gates, not by manual narrative alone.
- Public docs, trust pages, and changelog entries match the implemented semantics in the same PR.
- `make prepush-full` is green for every architecture/failure-semantics story.
- Reliability stories also keep `make test-hardening` and `make test-chaos` green.
- No story weakens offline-first defaults, fail-closed behavior, proof integrity, schema stability, or exit-code stability.
- Follow-on implementation can start from this file without guessing story order, test scope, or changelog intent.

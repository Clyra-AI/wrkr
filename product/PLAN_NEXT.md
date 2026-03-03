# PLAN NEXT: Wrkr Runtime Contract Hardening and OSS Readiness

Date: 2026-03-03
Source of truth: user-provided required changes (items 1-27), `product/dev_guides.md`, `product/architecture_guides.md`, `AGENTS.md`
Scope: Wrkr OSS CLI only. Planning artifact only; no implementation in this document.

This plan is execution-ready and dependency-ordered. It uses two strict waves:
- Wave 1: runtime/contract/reliability correctness
- Wave 2: docs/DX/OSS/governance consistency

## Global Decisions (Locked)

- Runtime correctness and contract safety are merge-blocking and always precede docs/governance polish.
- Exit code contract remains stable (`0..8` per `product/dev_guides.md`) unless explicitly versioned.
- Scan behavior must be deterministic and fail-closed for ambiguous high-risk conditions.
- Partial-result mode is required: non-fatal detector/repo errors are surfaced without discarding completed findings.
- Timeout and cancellation must propagate through acquisition, detection, and long-running operations via context.
- Retry semantics must honor upstream rate-limit contracts (`Retry-After`/reset windows) and use bounded jittered backoff.
- Source connector degradation must be bounded (threshold + cooldown), with explicit partial-result reporting.
- Architecture boundaries remain mandatory: Source -> Detection -> Aggregation -> Identity -> Risk -> Proof -> Compliance.
- Go remains authoritative for policy/signing/verification logic; wrappers/adapters remain thin.
- Contract evolution is additive-first: new fields/envelopes before breaking changes, with migration guidance.
- Machine-readable failure semantics are mandatory for JSON mode (stable code/class envelope + retryability hints where applicable).
- Two-wave execution is hard-gated: Wave 2 stories cannot begin until Wave 1 story criteria and lanes are green.

## Current Baseline (Observed)

Repository snapshot (2026-03-03):

- `core/cli/scan.go` is large (762 LOC) and currently carries multiple responsibilities.
- `core/source/github/connector.go` (358 LOC) contains retry-sensitive external acquisition behavior.
- `core/detect/detect.go` is central detector orchestration with detector-level contract implications.
- JSON mode detection exists as `wantsJSONOutput` in `core/cli/root.go`; command surfaces call into same package helper but ownership is not in a dedicated shared CLI utility.
- No first-class `wrkr version` / `wrkr --version` command surface exists today.
- Install docs rely on `gh`/`python3` fallback for latest tag resolution in README Go-install path.
- `CONTRIBUTING.md` is minimal and does not yet encode contributor workflow complexity.
- Community health gaps remain:
  - missing `CODE_OF_CONDUCT.md`
  - missing `CHANGELOG.md`
  - missing `.github/ISSUE_TEMPLATE/*`
  - missing `.github/pull_request_template.md`
- `product/PLAN_NEXT.md` did not previously exist.

## Exit Criteria

The plan is complete only when all are true:

1. Scan does not abort on first non-fatal detector error; findings and structured detector/repo errors are both returned.
2. `wrkr scan --timeout <duration>` enforces deadline deterministically with documented JSON and exit behavior.
3. Ctrl-C cancellation stops acquisition/detection promptly without stuck in-flight work.
4. GitHub connector retries honor 429 rate-limit windows and apply bounded jittered backoff for retryable errors.
5. Connector degradation handling is bounded (threshold/cooldown) with explicit partial-result output.
6. Silent detector failures (`nil, nil` on real I/O/permission/corruption issues) are removed; failures are surfaced with stable codes/context.
7. Scan command responsibilities are decomposed into focused units; orchestrator remains thin and testable.
8. JSON error-mode detection is centralized and consistently tested across commands.
9. `wrkr version` and `wrkr --version` are available with human and JSON output contracts.
10. Install path supports minimal environments without mandatory `gh`/`python3` while preserving pinned install options.
11. State/baseline/evidence lifecycle and canonical paths are documented once and linked from quickstart/commands.
12. `wrkr fix` behavior contract (planning/mutations/optional PR effects) is explicit and consistent in help + docs.
13. Custom detector extension point is documented, deterministic, schema-validated, and covered by E2E tests.
14. Explicit compatibility/versioning policy is published and tied to CI contract enforcement.
15. goja rationale and AST-only guardrails are documented; tests block runtime eval regressions.
16. Contributor workflow, Go-only path, docs-source-of-truth flow, and CI lane map are explicit in docs.
17. OSS governance baseline files/templates are present and linked.
18. Governance policies for `product/` and `.agents/skills/` visibility are explicit and enforced by repository content.
19. Cross-repo README contract is defined and Wrkr README conforms, with tracked follow-up for Proof/Gait.
20. Wave gates pass with no JSON/exit-code contract regressions:
- `make prepush-full`
- `make test-contracts`
- `make test-scenarios`
- `make test-docs-consistency`
- `make docs-site-install && make docs-site-lint && make docs-site-build && make docs-site-check`

## Public API and Contract Map

Stable/public surfaces (must remain compatible unless explicitly versioned):
- CLI commands and flags under `core/cli/*` (`scan`, `fix`, `report`, `evidence`, `verify`, `regress`, etc.)
- JSON output envelopes and reason/error codes in `--json` mode
- Exit code contract (`0..8`)
- State/evidence artifact schemas in `schemas/v1`

Internal surfaces (refactor-safe, non-public API):
- `core/detect/*` detector internals and registration internals
- `core/source/*` connector internals
- internal orchestration helpers and non-exported package functions

Planned additive contract changes:
- Scan JSON envelope extension for structured partial-result detector/repo errors
- Machine-readable timeout/cancellation/degradation error classes
- Optional SARIF output format alongside existing native artifacts
- `version` command output envelope

Deprecation/shim policy for this plan:
- Additive fields first; no removal/rename of existing required JSON keys without migration path.
- If behavior changes, dual-reader compatibility and contract tests are required in the same PR.

## Docs and OSS Readiness Baseline

README first-screen baseline:
- One-liner, positioning, install, quickstart already present, but minimal-dependency install path and clearer side-effect docs are required.

Integration-before-internals baseline:
- Command docs exist but state-lifecycle and docs source-of-truth need explicit canonical mapping.

Governance baseline:
- Present: `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`
- Missing: `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, issue templates, PR template

Cross-project clarity baseline:
- README contains Clyra/Axym/Gait references and standalone note; requires concise trust/support section with clearer governance positioning.

## Recommendation Traceability

| Item | Requirement | Planned Coverage |
|---|---|---|
| 1 | Keep scans running on detector failures (partial-results mode) | Story 0.1 |
| 2 | Add scan-level timeout (`--timeout`) | Story 0.2 |
| 3 | Wire cancellation end-to-end (Ctrl-C) | Story 0.2 |
| 4 | Honor GitHub rate-limit semantics in retry logic | Story 0.3 |
| 5 | Circuit-breaker style degradation handling | Story 0.3 |
| 6 | Remove silent detector failures (`nil, nil`) | Story 0.1 |
| 7 | Decompose scan command by responsibility | Story 1.1 |
| 8 | Centralize JSON error-mode detection | Story 1.1 |
| 9 | Add `wrkr version` / `wrkr --version` | Story 1.2 |
| 10 | Harden install UX (minimal dependencies) | Story 2.1 |
| 11 | Clarify state-file lifecycle and canonical paths | Story 2.2 |
| 12 | Make `wrkr fix` behavior explicit | Story 2.3 |
| 13 | Add custom detector extension point | Story 1.3 |
| 14 | Publish explicit schema/versioning policy | Story 1.4 |
| 15 | Document goja rationale and enforce guardrails | Story 1.5 |
| 16 | Expand CONTRIBUTING workflow | Story 3.1 |
| 17 | Make Node requirement optional for Go-only contributors | Story 3.1 |
| 18 | Clarify Clyra/Axym/Gait context and standalone positioning | Story 2.4 |
| 19 | Clarify docs source-of-truth (`docs/` vs `docs-site`) | Story 2.4 |
| 20 | Add issue and PR templates | Story 3.2 |
| 21 | Add `CODE_OF_CONDUCT.md` | Story 3.3 |
| 22 | Add `CHANGELOG.md` with process | Story 3.3 |
| 23 | Decide public-content policy for `product/` docs | Story 3.4 |
| 24 | Decide exposure policy for `.agents/skills/` | Story 3.4 |
| 25 | Standardize README flow across 3 repos | Story 3.5 |
| 26 | SARIF output + GitHub Action distribution | Story 1.6 |
| 27 | Two PR waves with strict gates | Global Decisions, Minimum-Now Sequence, Exit Criteria |

## Test Matrix Wiring

Lane definitions:
- Fast lane: `make lint-fast`, targeted unit checks, contract smoke.
- Core CI lane: deterministic unit/integration/e2e for touched packages.
- Acceptance lane: scenario/operator-path acceptance checks.
- Cross-platform lane: Linux/macOS/Windows-safe command/path behavior.
- Risk lane: hardening/chaos/perf/contract suites for high-risk changes.
- Gating rule: merge/release blocks on required lane failures.

Story-to-lane mapping:

| Story | Fast | Core CI | Acceptance | Cross-platform | Risk |
|---|---|---|---|---|---|
| 0.1 | Yes | Yes | Yes | Yes | Yes |
| 0.2 | Yes | Yes | Yes | Yes | Yes |
| 0.3 | Yes | Yes | Yes | Yes | Yes |
| 1.1 | Yes | Yes | Yes | Yes | Yes |
| 1.2 | Yes | Yes | Yes | Yes | No |
| 1.3 | Yes | Yes | Yes | Yes | Yes |
| 1.4 | Yes | Yes | Yes | Yes | Yes |
| 1.5 | Yes | Yes | Yes | Yes | Yes |
| 1.6 | Yes | Yes | Yes | Yes | Yes |
| 2.1 | Yes | Yes | Yes | Yes | No |
| 2.2 | Yes | Yes | Yes | Yes | No |
| 2.3 | Yes | Yes | Yes | Yes | No |
| 2.4 | Yes | Yes | Yes | Yes | No |
| 3.1 | Yes | Yes | No | Yes | No |
| 3.2 | Yes | Yes | No | No | No |
| 3.3 | Yes | Yes | No | No | No |
| 3.4 | Yes | Yes | No | No | No |
| 3.5 | Yes | Yes | Yes | Yes | No |

Gating rule:
- Wave 1 stories (`0.*`, `1.*`) must be complete and green before starting any Wave 2 story (`2.*`, `3.*`).
- A story is complete only when all mapped lanes are green with command evidence.

## Epic 0: Wave 1 Runtime Reliability and Partial-Result Safety

Objective: prevent scan abort cascades, bound runtime behavior, and make detector/source failures visible and deterministic.

### Story 0.1: Partial-Result Detector Error Envelope and Silent-Failure Removal
Priority: P0
Tasks:
- Add detector/repo scoped error capture in `core/detect/detect.go` and detector output model.
- Extend scan JSON envelope in `core/cli/scan.go` to include structured partial-result detector errors.
- Audit detectors for silent `nil, nil` on real stat/walk/permission/corruption errors; convert to surfaced findings/errors with stable codes.
- Add deterministic ordering for surfaced detector errors.
Repo paths:
- `core/detect/detect.go`
- `core/detect/*/detector.go`
- `core/cli/scan.go`
- `core/cli/*_test.go`
Run commands:
- `go test ./core/detect/... -count=1`
- `go test ./core/cli -run Scan -count=1`
- `make test-contracts`
- `make test-scenarios`
Test requirements:
- Tier 1 unit tests for per-detector error aggregation and ordering.
- Tier 2 integration tests for mixed-success detector runs.
- Tier 3 CLI tests for scan JSON envelope with findings + detector errors.
- Tier 9 contract tests for JSON shape/additive compatibility.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (Fast + targeted Core), Main (Core + Acceptance), Nightly (Risk).
Acceptance criteria:
- Non-fatal detector errors do not abort scan.
- Findings from completed repos are preserved when later repos/detectors fail.
- JSON output includes deterministic, structured detector error list.
- Silent permission/mount/corruption failures are surfaced with stable code/class/context.
Contract/API impact:
- Additive scan JSON fields for partial-result errors; no removal of existing keys.
Versioning/migration impact:
- Additive-only; no schema major bump.
Architecture constraints:
- Detection layer emits structured errors; CLI layer formats output only.
- No boundary leakage from CLI into detector internals.
ADR required: yes
TDD first failing test(s):
- `TestScanContinuesOnDetectorError`
- `TestDetectorPermissionErrorIsSurfaced`
Cost/perf impact: low
Chaos/failure hypothesis:
- Inject detector filesystem permission errors mid-scan; expected deterministic partial-result output with non-stuck completion.
Dependencies:
- None.
Risks:
- Contract drift if JSON envelope changes are not covered in Tier 9 tests.

### Story 0.2: Scan Timeout and End-to-End Cancellation Propagation
Priority: P0
Tasks:
- Add `--timeout` flag to `wrkr scan` and enforce with `context.WithTimeout` in `core/cli/scan.go`.
- Add signal-aware context in `cmd/wrkr/main.go` and propagate cancellation into acquisition/detector loops/connectors.
- Ensure cancellation/deadline errors map to stable machine-readable error classes in JSON mode.
- Document timeout/cancel behavior and exit semantics in docs and README.
Repo paths:
- `cmd/wrkr/main.go`
- `core/cli/scan.go`
- `core/detect/detect.go`
- `core/source/*`
- `docs/commands/scan.md`
- `README.md`
Run commands:
- `go test ./core/cli -run Scan -count=1`
- `go test ./core/source/... -count=1`
- `go test ./... -run Integration -count=1`
- `make test-contracts`
Test requirements:
- Tier 1 unit tests for timeout flag parsing and context wiring.
- Tier 2 integration tests for context cancel propagation.
- Tier 3 CLI tests for timeout deadline behavior and JSON error envelope.
- Tier 5 hardening tests for cancellation during in-flight acquisition.
- Tier 9 tests for exit-code and JSON error class stability.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (Fast + targeted Core), Main (Core + Acceptance + Tier 9), Nightly (Tier 5).
Acceptance criteria:
- `wrkr scan --timeout 10m` exits deterministically on deadline with documented behavior.
- Ctrl-C cancels promptly without hanging goroutines/workers.
- Timeout/cancel output is machine-readable and stable in `--json` mode.
Contract/API impact:
- New `--timeout` scan flag; additive error classes for timeout/cancel.
Versioning/migration impact:
- Additive-only command/JSON updates.
Architecture constraints:
- Context propagation from entrypoint to source/detect is mandatory.
- No ad-hoc timeout handling in leaf components without parent context.
ADR required: yes
TDD first failing test(s):
- `TestScanTimeoutDeadlineExceeded`
- `TestScanCancellationStopsAcquisitionAndDetection`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Inject slow source and long detector operations; expected deadline/cancel termination with bounded completion time.
Dependencies:
- Story 0.1 recommended first for consistent error envelope behavior.
Risks:
- Incomplete context propagation can leave latent hangs.

### Story 0.3: Rate-Limit Correct Retry Semantics and Circuit-Breaker Degradation
Priority: P0
Tasks:
- Update GitHub connector retry logic to honor `Retry-After` and reset windows for 429.
- Implement bounded jittered backoff for retryable 5xx/network failures.
- Add circuit-breaker style consecutive-failure threshold + cooldown in connector.
- Surface degraded mode/partial termination explicitly in scan error/report envelope.
Repo paths:
- `core/source/github/connector.go`
- `core/source/github/connector_test.go`
- `core/cli/scan.go`
Run commands:
- `go test ./core/source/github -count=1`
- `go test ./core/cli -run Scan -count=1`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- Tier 1 retry/backoff/circuit unit tests with deterministic clocks.
- Tier 2 integration tests for prolonged outage behavior.
- Tier 5 hardening tests for bounded failure under repeated upstream errors.
- Tier 6 chaos tests for alternating 429/5xx faults.
- Tier 9 contract tests for degraded partial-result reporting.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (Fast + Core), Main (Core + Acceptance), Nightly (Risk).
Acceptance criteria:
- 429 behavior honors server-declared wait semantics.
- Retry behavior for retryable failures is jittered but bounded.
- Prolonged outage triggers bounded degradation behavior with explicit partial-result output.
Contract/API impact:
- Additive degraded-mode metadata in JSON scan output (if needed).
Versioning/migration impact:
- Additive-only envelope updates.
Architecture constraints:
- Connector owns retry/circuit policy; CLI only maps surfaced states.
ADR required: yes
TDD first failing test(s):
- `TestConnectorHonorsRetryAfter429`
- `TestConnectorCircuitBreakerCooldown`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Simulate sustained 429/5xx responses; expected bounded retries and explicit degraded result classification.
Dependencies:
- Story 0.2 for context cancellation interaction.
Risks:
- Non-deterministic timing in tests without controlled clock abstractions.

## Epic 1: Wave 1 Contract Surfaces, Boundary Hygiene, and Distribution

Objective: tighten command contracts, improve architecture boundaries, and unlock ecosystem distribution without breaking existing contracts.

### Story 1.1: Decompose Scan Command and Centralize JSON Error-Mode Utility
Priority: P1
Tasks:
- Split `core/cli/scan.go` into focused modules (orchestration, flag parsing, persistence, report output, policy/profile eval).
- Keep top-level orchestrator thin and explicit in side effects.
- Move JSON mode detection logic from `root.go` into shared CLI helper used across commands.
- Add coverage for `--json`, `--json=true/false`, malformed bool values, and command parity.
Repo paths:
- `core/cli/scan.go`
- `core/cli/scan_*.go`
- `core/cli/root.go`
- `core/cli/jsonmode.go` (new)
- `core/cli/*_test.go`
Run commands:
- `go test ./core/cli -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 1 unit tests for shared JSON mode parser.
- Tier 2 module-level integration tests for decomposed scan units.
- Tier 3 CLI parity tests across commands.
- Tier 9 contract tests for unchanged JSON/exit behavior.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (Fast + Core), Main (Core + Acceptance + Tier 9), Nightly (Risk if perf-sensitive).
Acceptance criteria:
- Scan orchestrator is thin, responsibilities are split, and isolated tests exist.
- One shared implementation handles JSON mode detection consistently.
- No JSON/exit-code contract regressions.
Contract/API impact:
- No intended public contract change.
Versioning/migration impact:
- None.
Architecture constraints:
- Explicit boundaries between orchestration, persistence, rendering, and policy evaluation.
ADR required: yes
TDD first failing test(s):
- `TestSharedJSONModeParsingCases`
- `TestScanOrchestratorDelegatesResponsibilities`
Cost/perf impact: low
Chaos/failure hypothesis:
- Inject malformed JSON mode flag variants during command parsing; expected deterministic validation behavior.
Dependencies:
- Story 0.* should be merged first.
Risks:
- Refactor may accidentally alter command side effects without contract tests.

### Story 1.2: Add First-Class Version Command Surface
Priority: P1
Tasks:
- Add `wrkr version` subcommand and `wrkr --version` handling.
- Provide human and JSON outputs with stable fields.
- Update root help/README/docs command index.
- Add contract tests for output shape and exit behavior.
Repo paths:
- `core/cli/root.go`
- `core/cli/version.go` (new)
- `core/cli/root_test.go`
- `docs/commands/index.md`
- `README.md`
Run commands:
- `go test ./core/cli -run Version -count=1`
- `make test-docs-consistency`
- `make test-contracts`
Test requirements:
- Tier 1 unit tests for version formatter.
- Tier 3 CLI tests for command and flag forms.
- Tier 9 output key/exit contract tests.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR (Fast + Core), Main (Core + Acceptance + docs consistency).
Acceptance criteria:
- `wrkr version` and `wrkr --version` both succeed.
- JSON output is deterministic and documented.
Contract/API impact:
- New additive command surface.
Versioning/migration impact:
- Additive-only.
Architecture constraints:
- Version retrieval must not introduce runtime network dependencies.
ADR required: no
TDD first failing test(s):
- `TestVersionCommandHumanAndJSON`
- `TestRootVersionFlag`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required (low-risk command-surface addition).
Dependencies:
- Story 1.1 for shared JSON mode utility.
Risks:
- Help/docs drift if command index not updated in same PR.

### Story 1.3: Custom Detector Extension Point with Deterministic Ordering
Priority: P1
Tasks:
- Define extension contract (plugin/file-based registry) and validation rules.
- Enforce deterministic ordering and failure semantics for extension detectors.
- Add schema validation for extension descriptor/config.
- Add E2E scenario fixtures showing extension detector execution.
Repo paths:
- `core/detect/*`
- `core/detect/defaults/defaults.go`
- `schemas/v1/*` (if extension descriptor schema added)
- `docs/extensions/detectors.md` (new)
- `internal/scenarios/*`
Run commands:
- `go test ./core/detect/... -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-adapter-parity`
Test requirements:
- Tier 1 unit tests for extension loading/ordering/validation.
- Tier 2 integration tests for extension + built-in detector composition.
- Tier 4 acceptance scenario for enterprise extension flow.
- Tier 9 contract tests for extension schema compatibility.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (Fast + Core), Main (Core + Acceptance), Nightly (Risk).
Acceptance criteria:
- Extension path is documented and deterministic.
- Invalid extensions fail with stable machine-readable errors.
- E2E test covers extension execution path.
Contract/API impact:
- New extension contract surface and optional schema.
Versioning/migration impact:
- Additive extension surface; no break to built-in detectors.
Architecture constraints:
- Core detection engine remains authoritative; extension adapters cannot bypass policy/signing boundaries.
ADR required: yes
TDD first failing test(s):
- `TestExtensionRegistryDeterministicOrdering`
- `TestInvalidExtensionDescriptorFailsClosed`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Inject malformed/slow extension definitions; expected bounded failure and deterministic ordering.
Dependencies:
- Story 0.1 error surfacing model.
Risks:
- Inadequate sandboxing model for extensions if contract is underspecified.

### Story 1.4: Compatibility and Versioning Policy with CI Enforcement
Priority: P1
Tasks:
- Publish compatibility/versioning policy docs (additive vs breaking, v2 trigger, migration guidance).
- Publish compatibility matrix and consumer guidance.
- Add CI contract checks that fail on undocumented breaking contract changes.
Repo paths:
- `docs/trust/compatibility-and-versioning.md` (new)
- `docs/contracts/compatibility_matrix.md` (new)
- `testinfra/contracts/*`
- `scripts/validate_contracts.sh`
Run commands:
- `make test-contracts`
- `scripts/validate_contracts.sh`
- `make prepush-full`
Test requirements:
- Tier 9 contract tests for schema/JSON key/exit behavior compatibility.
- Tier 11 scenario checks for representative compatibility transitions.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (Fast + Tier 9 subset), Main (full Tier 9/11), Release (contract freeze gate).
Acceptance criteria:
- Policy docs exist and are linked from README/docs index.
- CI fails when compatibility policy is violated without explicit versioned migration handling.
Contract/API impact:
- No immediate runtime change; governance contract clarified and enforced.
Versioning/migration impact:
- Defines future policy behavior; no immediate schema bump.
Architecture constraints:
- Compatibility enforcement lives in contract tests/scripts, not ad-hoc reviewer convention.
ADR required: no
TDD first failing test(s):
- `TestContractPolicyFailsOnUndocumentedBreakingChange`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required (governance/contract enforcement story).
Dependencies:
- None.
Risks:
- Overly strict rule set could block valid additive changes if not tuned.

### Story 1.5: goja Dependency Rationale and AST-Only Guardrails
Priority: P1
Tasks:
- Document rationale for goja usage in threat/architecture docs.
- Codify AST-parse-only intent in implementation and tests.
- Add tests/policy checks blocking runtime eval execution regressions.
Repo paths:
- `core/detect/webmcp/*`
- `docs/architecture/*`
- `docs/trust/*`
- `testinfra/contracts/*`
Run commands:
- `go test ./core/detect/webmcp -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 1 unit tests for parser behavior and disallowed eval paths.
- Tier 9 contract/policy checks preventing runtime execution drift.
- Tier 5 hardening checks for malicious JS fixtures.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (Fast + Core), Main (Core + Risk subset), Nightly (hardening).
Acceptance criteria:
- Documentation clearly states goja scope and constraints.
- Tests fail if runtime eval execution path is introduced.
Contract/API impact:
- No public API change.
Versioning/migration impact:
- None.
Architecture constraints:
- Parser-only semantics are invariant for WebMCP detection.
ADR required: yes
TDD first failing test(s):
- `TestWebMCPParserRejectsRuntimeEvalPath`
Cost/perf impact: low
Chaos/failure hypothesis:
- Fuzz malformed JS payloads; expected parse-safe failure without runtime execution.
Dependencies:
- None.
Risks:
- False confidence if tests do not cover all evaluator entry points.

### Story 1.6: SARIF Output and GitHub Action Distribution
Priority: P1
Tasks:
- Add SARIF output mode mapping Wrkr findings to SARIF schema.
- Add GitHub Action packaging path for scan + SARIF publication.
- Ensure native proof outputs remain unchanged and primary contract remains intact.
- Add docs for SARIF usage and GitHub Security tab integration.
Repo paths:
- `core/export/*` or `core/cli/*` (SARIF emitter path)
- `action/*`
- `.github/workflows/*`
- `docs/commands/*`
- `README.md`
Run commands:
- `go test ./core/... -count=1`
- `make test-contracts`
- `make test-release-smoke`
- `make test-docs-consistency`
Test requirements:
- Tier 1 unit tests for SARIF transformation.
- Tier 3 CLI tests for SARIF output switch.
- Tier 9 schema/output compatibility checks for SARIF envelopes.
- Tier 12 interoperability checks where action/release contracts are touched.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (Fast + Core), Main (Core + Acceptance), Release (integrity + smoke).
Acceptance criteria:
- Wrkr emits valid SARIF for supported finding classes.
- GitHub Action path is documented and release-smoke validated.
- Existing proof and JSON contracts remain compatible.
Contract/API impact:
- Additive output format; no break to existing JSON/proof contracts.
Versioning/migration impact:
- Additive-only.
Architecture constraints:
- Distribution packaging must not alter core risk/proof decision logic.
ADR required: yes
TDD first failing test(s):
- `TestSARIFEmitterValidatesAgainstSchema`
- `TestScanSARIFModeDoesNotAlterNativeOutput`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Simulate action upload/report failure; expected fail-closed publish behavior without corrupting scan outputs.
Dependencies:
- Story 1.4 for compatibility policy checks.
Risks:
- SARIF mapping ambiguity for non-standard finding classes.

## Epic 2: Wave 2 Docs and DX Contract Clarity

Objective: make operator behavior and integration surfaces explicit, reproducible, and troubleshooting-first.

### Story 2.1: Minimal-Dependency Install UX Hardening
Priority: P1
Tasks:
- Add install path that does not require `gh`/`python3` for latest-tag resolution.
- Keep pinned install options documented.
- Add release smoke checks for clean Go-only environments.
Repo paths:
- `README.md`
- `docs/install/*` (new or existing)
- `scripts/test_uat_local.sh`
Run commands:
- `scripts/test_uat_local.sh --release-version v1.0.0 --skip-global-gates`
- `make test-docs-consistency`
Test requirements:
- Tier 4 acceptance checks for install copy-paste paths.
- Tier 10 UAT checks for source/go/brew install flows.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: Main + Release.
Acceptance criteria:
- Documented install works in clean Go environment without mandatory `gh`/`python3`.
- Pinned install path remains available and validated.
Contract/API impact:
- No runtime API change; install contract/documentation updates.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep install logic deterministic and tool-minimal.
ADR required: no
TDD first failing test(s):
- `TestInstallDocsSmokeGoOnlyPath`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required (docs/distribution workflow story).
Dependencies:
- Story 1.2 (version command) preferred.
Risks:
- Release smoke may pass locally but fail in constrained CI if assumptions persist.

### Story 2.2: Canonical State Lifecycle Documentation
Priority: P1
Tasks:
- Add canonical lifecycle doc with table/diagram for state/baseline/evidence artifacts.
- Link lifecycle doc from quickstart and command docs.
- Normalize `.wrkr` vs `.tmp` examples.
Repo paths:
- `docs/state_lifecycle.md` (new)
- `README.md`
- `docs/commands/*.md`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
Test requirements:
- Tier 4 docs storyline checks for lifecycle path consistency.
- Tier 9 docs contract checks for required tokens/sections.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR + Main.
Acceptance criteria:
- One canonical lifecycle source is documented and linked.
- Command docs and quickstart align on canonical paths.
Contract/API impact:
- No runtime API change.
Versioning/migration impact:
- None.
Architecture constraints:
- Documentation reflects actual command read/write behavior only.
ADR required: no
TDD first failing test(s):
- `TestDocsLifecyclePathConsistency`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required (docs story).
Dependencies:
- None.
Risks:
- Drift if docs are updated without command behavior checks.

### Story 2.3: Explicit `wrkr fix` Side-Effect Contract
Priority: P1
Tasks:
- Rewrite `wrkr fix` description in README/docs/help text with explicit behavior contract:
  - planning outputs
  - file mutation behavior
  - optional PR actions and prerequisites
- Ensure docs/help text matches implementation and JSON output.
Repo paths:
- `README.md`
- `docs/commands/fix.md`
- `core/cli/root.go`
- `core/cli/fix.go` (if help text wired there)
Run commands:
- `go test ./core/cli -run Fix -count=1`
- `make test-docs-consistency`
Test requirements:
- Tier 3 CLI help contract tests.
- Tier 4 docs storyline checks for fix workflow.
- Tier 9 docs/CLI parity checks.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR + Main.
Acceptance criteria:
- Two-sentence explicit behavior contract appears consistently in README/help/docs.
- Docs/help no longer imply opaque side effects.
Contract/API impact:
- Documentation/help contract clarifies existing side effects.
Versioning/migration impact:
- None.
Architecture constraints:
- Side-effect semantics must remain explicit and auditable.
ADR required: no
TDD first failing test(s):
- `TestFixHelpMatchesBehaviorContract`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required (docs/help contract story).
Dependencies:
- None.
Risks:
- Misalignment if implementation changes without docs update.

### Story 2.4: Positioning Trust Section and Docs Source-of-Truth Map
Priority: P1
Tasks:
- Add concise trust/positioning section clarifying Wrkr standalone usage and Clyra/Axym/Gait relationship.
- Add explicit docs source-of-truth map: where to edit and required validation commands.
- Add FAQ entry for standalone vs ecosystem dependency questions.
Repo paths:
- `README.md`
- `docs/faq.md`
- `CONTRIBUTING.md`
- `docs/map.md` (new or existing map page)
Run commands:
- `make test-docs-consistency`
- `make docs-site-install && make docs-site-lint && make docs-site-build && make docs-site-check`
Test requirements:
- Tier 4 docs acceptance checks for required trust/source-of-truth sections.
- Tier 9 docs consistency checks across repo docs and docs-site.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR + Main + Release docs gate.
Acceptance criteria:
- README/FAQ clearly state standalone usage and related projects.
- Docs contribution path is explicit: "edit here, validate with these commands".
Contract/API impact:
- No runtime API change.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep source-of-truth mapping explicit and stable.
ADR required: no
TDD first failing test(s):
- `TestDocsSourceOfTruthSectionsPresent`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required (docs/governance story).
Dependencies:
- Story 2.2 preferred.
Risks:
- Multi-surface docs drift if source map not enforced in CI.

## Epic 3: Wave 2 OSS Governance and Contributor Systemization

Objective: raise public OSS trust baseline and contributor throughput with explicit governance contracts.

### Story 3.1: Expand CONTRIBUTING Workflow and Go-Only Contributor Path
Priority: P1
Tasks:
- Expand `CONTRIBUTING.md` with setup, targeted test commands, detector authoring guidance, determinism expectations, PR process, and CI lane map.
- Split required vs optional toolchains; document Go-only contribution path without default Node requirement.
Repo paths:
- `CONTRIBUTING.md`
- `Makefile` (guidance references only if needed)
- `docs/contributing/*` (optional)
Run commands:
- `make lint-fast`
- `make test-fast`
- `make test-docs-consistency`
Test requirements:
- Tier 9 docs contract checks for required contributor sections and command accuracy.
Matrix wiring:
- Lanes: Fast, Core CI, Cross-platform.
- Pipeline placement: PR + Main.
Acceptance criteria:
- New contributor can execute focused Go-only workflow without Node stack.
- Optional docs-site path is explicit and separate.
Contract/API impact:
- No runtime API change.
Versioning/migration impact:
- None.
Architecture constraints:
- Contributor guidance must reflect actual lane gates and deterministic expectations.
ADR required: no
TDD first failing test(s):
- `TestContributingContainsRequiredWorkflowSections`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required (contributor-doc story).
Dependencies:
- None.
Risks:
- Documentation quality degrades if commands are not validated in CI.

### Story 3.2: Add Issue and PR Templates with Contract/Test Prompts
Priority: P1
Tasks:
- Add structured issue templates for bug/feature/docs.
- Add PR template requiring contract impact, tests, and lane evidence.
- Link templates from contributing docs.
Repo paths:
- `.github/ISSUE_TEMPLATE/*`
- `.github/pull_request_template.md`
- `CONTRIBUTING.md`
Run commands:
- `make lint-fast`
- `make test-docs-consistency`
Test requirements:
- Tier 9 hygiene tests for presence/required template fields.
Matrix wiring:
- Lanes: Fast, Core CI.
- Pipeline placement: PR + Main.
Acceptance criteria:
- New issue/PR forms guide reproducible, high-signal submissions.
- Template prompts include contract/test expectations.
Contract/API impact:
- No runtime API change.
Versioning/migration impact:
- None.
Architecture constraints:
- Governance templates must reinforce contract-first review behavior.
ADR required: no
TDD first failing test(s):
- `TestCommunityTemplatesPresentAndStructured`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required.
Dependencies:
- None.
Risks:
- Low.

### Story 3.3: Community Health Baseline (`CODE_OF_CONDUCT` + `CHANGELOG`)
Priority: P2
Tasks:
- Add `CODE_OF_CONDUCT.md` and link from README/community section.
- Add `CHANGELOG.md` format + maintenance process and release linkage.
- Update release docs to include changelog update expectation.
Repo paths:
- `CODE_OF_CONDUCT.md` (new)
- `CHANGELOG.md` (new)
- `README.md`
- `docs/release/*`
Run commands:
- `make test-docs-consistency`
Test requirements:
- Tier 9 docs/hygiene checks for required governance files and links.
Matrix wiring:
- Lanes: Fast, Core CI.
- Pipeline placement: PR + Main + Release doc gate.
Acceptance criteria:
- Both files exist and are linked from README/docs.
- Changelog maintenance process is explicit and release-linked.
Contract/API impact:
- No runtime API change.
Versioning/migration impact:
- None.
Architecture constraints:
- Governance docs remain aligned with release process reality.
ADR required: no
TDD first failing test(s):
- `TestCommunityHealthFilesAndLinks`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required.
Dependencies:
- None.
Risks:
- Low.

### Story 3.4: Governance Policy for `product/` and `.agents/skills/` Exposure
Priority: P2
Tasks:
- Define policy for planning/audit content in `product/` (public vs redacted vs private).
- Define policy for `.agents/skills/` exposure (transparency artifact vs restricted operational detail).
- Add enforcement guidance and directory notices; reconcile repository content to chosen policy.
Repo paths:
- `docs/governance/content-visibility.md` (new)
- `product/*` (policy-driven updates as needed)
- `.agents/skills/README.md` or policy notice (new)
- `README.md` / `CONTRIBUTING.md`
Run commands:
- `make test-docs-consistency`
- `make lint-fast`
Test requirements:
- Tier 9 governance-doc checks for explicit policy statements and directory references.
Matrix wiring:
- Lanes: Fast, Core CI.
- Pipeline placement: PR + Main.
Acceptance criteria:
- Both policies are explicit and linked.
- Repository content/state aligns with documented policy.
Contract/API impact:
- No runtime API change.
Versioning/migration impact:
- None.
Architecture constraints:
- Governance policy must not weaken runtime security contracts.
ADR required: no
TDD first failing test(s):
- `TestGovernancePolicyDocsPresent`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required.
Dependencies:
- Story 3.1 recommended.
Risks:
- Organizational alignment needed before enforcement.

### Story 3.5: Cross-Repo README Contract Standardization (Wrkr-first)
Priority: P2
Tasks:
- Define shared README contract sections (install, first 10 minutes, integration, command surface, governance/support links).
- Align Wrkr README to the contract in this repo.
- Record tracked external follow-ups for Proof/Gait alignment with owner and due date.
Repo paths:
- `docs/contracts/readme_contract.md` (new)
- `README.md`
- `docs/roadmap/cross-repo-readme-alignment.md` (new)
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
Test requirements:
- Tier 9 docs contract checks for required README sections.
- Tier 4 docs storyline checks for first-10-minutes flow.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR + Main.
Acceptance criteria:
- Wrkr README follows shared contract.
- External repo alignment work is explicitly tracked (owner + dates) and linkable.
Contract/API impact:
- No runtime API change.
Versioning/migration impact:
- None.
Architecture constraints:
- README contract reflects runtime boundaries and deterministic command behavior.
ADR required: no
TDD first failing test(s):
- `TestReadmeContractSectionsPresent`
Cost/perf impact: low
Chaos/failure hypothesis:
- Not required.
Dependencies:
- Story 2.4 recommended.
Risks:
- Cross-repo dependency outside this repo’s direct merge control.

## Minimum-Now Sequence

Phase 0 (Week 1): Wave 1/P0 runtime safety foundation
- Story 0.1
- Story 0.2
- Story 0.3
Gate:
- `make prepush-full`
- `make test-contracts`
- `make test-scenarios`

Phase 1 (Week 2): Wave 1 contract/boundary quality
- Story 1.1
- Story 1.2
- Story 1.3
- Story 1.4
- Story 1.5
Gate:
- `make prepush-full`
- `make test-risk-lane`

Phase 2 (Week 3): Wave 1 distribution completion
- Story 1.6
Gate:
- `make prepush-full`
- `make test-release-smoke`
- `make test-contracts`

Wave 1 hard gate before Wave 2:
- All `0.*` and `1.*` stories are complete and all mapped lanes are green.
- No JSON key removals, exit-code changes, or undocumented compatibility breaks.

Phase 3 (Week 4): Wave 2 docs/DX clarity
- Story 2.1
- Story 2.2
- Story 2.3
- Story 2.4
Gate:
- `make test-docs-consistency`
- `make docs-site-install && make docs-site-lint && make docs-site-build && make docs-site-check`

Phase 4 (Week 5): Wave 2 OSS/governance closure
- Story 3.1
- Story 3.2
- Story 3.3
- Story 3.4
- Story 3.5
Gate:
- `make lint-fast`
- `make test-docs-consistency`

Release readiness gate:
- `make prepush-full`
- `make test-contracts`
- `make test-scenarios`
- `make test-docs-consistency`
- `make docs-site-install && make docs-site-lint && make docs-site-build && make docs-site-check`

## Explicit Non-Goals

- No Axym or Gait runtime feature implementation in Wrkr.
- No hosted backend introduction for core scan/risk/proof paths.
- No schema v2 rollout in this plan unless explicitly triggered by approved compatibility policy.
- No relaxation of fail-closed behavior for ambiguous high-risk paths.
- No replacement of native proof artifacts; SARIF is additive distribution output only.
- No broad refactor outside story scope.

## Definition of Done

A story is done only when all are true:

- Acceptance criteria are met with command evidence.
- Required tests for the story work type are added/updated and passing.
- Required lane mapping is satisfied in the designated pipeline(s).
- Contract/API impact and migration implications are documented and reflected in tests.
- Docs/help are updated in the same change for user-visible behavior changes.
- Architecture constraints are respected; ADR included when marked required.
- Determinism/fail-closed guarantees are preserved.

Plan completion requires:
- All stories complete or explicitly marked blocked/deferred with owner and unblock path.
- All Exit Criteria met.
- Wave 1 hard gate satisfied before any Wave 2 completion claims.

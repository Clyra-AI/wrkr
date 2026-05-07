# Adhoc Plan: Scan Progress UX

Date: 2026-05-07
Profile: `wrkr`
Slug: `scan-progress-ux`
Recommendation source: user-provided plan-only recommendations for adding a visible, informative progress bar during `wrkr scan` so users can distinguish long-running scans from stuck scans.

All paths in this plan are repo-relative. This is a planning artifact only; it does not implement scan progress behavior.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product. Progress UI must observe scan state; it must not change detector output, risk scoring, proof records, source acquisition behavior, or artifact contents except for explicit additive status fields.
- `stdout` remains reserved for command output contracts. Final scan JSON, human explain output, and existing CLI completion text must not be polluted by progress rendering.
- Progress rendering writes to `stderr` only and is suppressed by `--quiet`.
- Existing machine-readable progress lines emitted during `--json` org/path scans are compatibility surface and must remain available unless the user explicitly chooses a different progress mode.
- User-visible progress must be TTY-aware: animated bar for interactive terminals, plain newline milestones for non-TTY human output, structured events for automation, and no ANSI/control characters when terminal capability is unknown.
- Progress percent is an operator UX estimate, not evidence. It must not be used in risk, proof, compliance, regress, or policy logic.
- Detector-level progress can expose detector names and counters, but it must not introduce nondeterminism, parallelism changes, file reads, network calls, or secret serialization.
- Status sidecar changes are additive and backward-compatible. Old status files must continue to load as `unknown` or `completed` exactly as today.
- Resume, timeout, cancellation, rollback, and partial-result paths must flush progress cleanly before any final error envelope or footer is emitted.
- Documentation and changelog updates are required because this changes visible CLI behavior and adds user-facing scan UX contracts.

## Current Baseline (Observed)

- `core/cli/scan.go` creates a `scanProgressReporter` with `newScanProgressReporter(*jsonOut && !*quiet && anyTargetUsesProgress(targets), stderr)`, so progress currently streams only for selected JSON scans and only for org/path targets.
- `core/cli/scan_progress.go` already receives source acquisition, repo discovery, repo materialization, retry, cooldown, resume, phase, and complete events.
- `core/source/local/local.go` already emits path discovery and per-repo discovery progress through a source-layer progress interface.
- `core/source/org` already has acquisition and resume tests proving source progress events can be observed before command completion.
- `core/cli/scan_status.go` and `core/state/scan_status.go` already maintain a scan status sidecar with status, phase, repo counters, phase timings, artifact paths, source privacy, and partial-result state.
- `core/cli/scan_progress_test.go` protects current progress behavior: progress stays on `stderr`, JSON stays clean on `stdout`, `--quiet` suppresses progress, progress is visible before completion, retries are surfaced, and progress flushes on error.
- Detector execution currently runs through `core/detect/detect.go` without detector-level progress callbacks, so the detector phase can appear quiet after source acquisition completes.
- `docs/commands/scan.md` documents existing stderr progress events for `--json` hosted org and local path scans, plus `wrkr scan status` for background inspection.

## Exit Criteria

- Interactive `wrkr scan` users see a concise progress bar or equivalent live status during long org/path scans without needing `--json`.
- Non-interactive users get deterministic plain progress lines only when progress is enabled and never receive terminal control sequences.
- `--json` output remains byte-clean on `stdout`; existing progress event tests continue to pass or are intentionally updated under an explicit compatibility story.
- `--quiet` suppresses all non-error progress output.
- `wrkr scan status --state <path> --json` exposes additive progress fields suitable for background monitoring.
- Source acquisition, detector execution, analysis, and artifact commit phases all produce visible liveness signals.
- Long phases emit heartbeat updates with elapsed time so users can tell Wrkr is still running.
- Failure, interruption, timeout, cancellation, and rollback paths end with a clean final progress/footer line and preserve existing exit-code/error-envelope semantics.
- Docs and changelog explain progress modes, TTY behavior, JSON safety, quiet behavior, status sidecar monitoring, and large-org usage.

## Public API and Contract Map

- `wrkr scan`
  - Add `--progress <auto|bar|plain|events|none>` or an equivalent explicitly named flag.
  - Default `auto` selects a safe renderer from output mode and terminal capability.
  - `bar` renders a single updating line to `stderr` only when terminal capability supports it; otherwise it degrades to `plain` with an explanatory first line or validation error, as decided in Story 1.1.
  - `plain` emits newline-delimited human-readable milestones to `stderr`.
  - `events` preserves machine-oriented `progress target=... event=...` lines on `stderr`.
  - `none` disables progress output and is equivalent to progress suppression without muting errors.
  - `--quiet` overrides progress mode and suppresses progress output.
- `wrkr scan --json`
  - `stdout` remains the final JSON payload only.
  - Existing event-style progress on `stderr` remains compatible by default unless Story 1.1 deliberately chooses `auto` semantics that preserve `events` for JSON mode.
  - `--json-path` remains byte-identical to `stdout` when both are requested.
- `wrkr scan status --json`
  - Additive fields may include `progress_percent`, `progress_message`, `last_progress_at`, `elapsed_seconds`, `phase_progress`, `repo_progress`, and `detector_progress`.
  - Existing fields remain optional-compatible and old status files remain readable.
- `state.ScanStatus`
  - Additive JSON fields only; no required migration for existing sidecars.
- `detect.Options`
  - Add optional progress reporter callback/interface for detector lifecycle events.
  - Detector output, errors, ordering, and findings remain deterministic.
- Exit codes and error envelopes
  - Existing exit code meanings remain unchanged.
  - Progress render errors must not mask scan runtime, policy/schema, invalid input, dependency, or unsafe-operation exits.
- Docs and changelog
  - `docs/commands/scan.md`, generated CLI help expectations, and `CHANGELOG.md` must reflect the new flag and behavior.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `docs/commands/scan.md`
  - `README.md` if quickstart examples should demonstrate progress defaults
  - `docs/examples/security-team.md` if large-org command examples mention foreground/background monitoring
  - `docs/examples/operator-playbooks.md` if operator scan runbooks mention progress and status
  - `CHANGELOG.md`
- Docs must answer directly:
  - When does Wrkr show an animated progress bar?
  - How can CI keep output stable?
  - Where does progress render when `--json` is used?
  - How does `--quiet` interact with progress?
  - How can a background scan be inspected with `wrkr scan status`?
  - What does the percent mean, and why is it an estimate rather than an evidence field?
  - What should a user do when a progress footer says the scan was interrupted or partial?
- Required docs/trust gates:
  - `scripts/check_docs_cli_parity.sh`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/run_docs_smoke.sh`
  - `make test-docs-consistency`

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage |
|---|---:|---|
| 1. Scan Progress UX Contract | P0 | Story 1.1 |
| 2. Unified Progress Model | P0 | Story 1.2 |
| 3. TTY Progress Bar Renderer | P0 | Story 2.1 |
| 4. Heartbeat For Long Phases | P0 | Story 2.2 |
| 5. Detector-Phase Detail | P1 | Story 3.1 |
| 6. Status Sidecar Progress Fields | P1 | Story 1.2 |
| 7. Failure And Completion Footer | P0 | Story 2.3 |
| 8. Contract Tests And Docs | P0 | Stories 1.1, 1.2, 2.1, 2.2, 2.3, 3.1, 4.1 |

## Test Matrix Wiring

- Fast lane:
  - Focused unit tests for progress mode parsing, renderer selection, progress model percentage math, terminal capability fallbacks, plain/event output formatting, and footer generation.
  - `go test ./core/cli -run 'TestScan.*Progress|TestScanStatus' -count=1`
  - `make lint-fast`
- Core CI lane:
  - `make test-fast`
  - `make test-contracts`
  - CLI contract tests for `--json`, `--json-path`, `--quiet`, `--explain`, progress modes, exit codes, and status JSON compatibility.
- Acceptance lane:
  - `make test-scenarios`
  - `scripts/validate_scenarios.sh`
  - Scenario-tagged scan flows where long source acquisition, detector execution, cancellation, and partial-result paths produce stable progress/status behavior.
- Cross-platform lane:
  - Ensure Windows smoke does not receive unsupported terminal control sequences.
  - Keep path rendering and footer artifact paths path-separator neutral.
  - Verify non-TTY output is deterministic across Linux, macOS, and Windows.
- Risk lane:
  - `make test-hardening` for unsafe artifact/rollback paths with progress enabled.
  - `make test-chaos` for cancellation, timeout, interrupted scan, status sidecar write failures, and source cleanup failure.
  - `make test-perf` to bound heartbeat/renderer overhead on large org/path scans.
- Gating rule:
  - No story is complete until progress output stays off `stdout`, JSON payload bytes remain stable, `--quiet` suppresses progress, old scan status sidecars load, docs match CLI help, and no progress field is consumed by risk/proof/compliance logic.

## Minimum-Now Sequence

- Wave 1 - Contract and state model:
  - Story 1.1: define the `scan` progress mode contract and CLI parsing behavior.
  - Story 1.2: create the shared progress model and additive status sidecar fields.
- Wave 2 - Human-visible liveness:
  - Story 2.1: add TTY-aware progress rendering with plain/event fallbacks.
  - Story 2.2: add heartbeat updates for long phases.
  - Story 2.3: harden failure, interruption, timeout, and completion footer behavior.
- Wave 3 - Detector depth:
  - Story 3.1: add detector-phase progress callbacks without changing detector semantics.
- Wave 4 - Docs and release contract:
  - Story 4.1: synchronize docs, changelog, CLI help, examples, and contract tests.

## Explicit Non-Goals

- No changes to detector findings, risk scores, proof records, report summaries, evidence bundles, compliance mappings, or regress baselines except additive scan status fields.
- No LLM calls, telemetry upload, hosted progress service, daemon mode, background worker manager, or external UI.
- No live endpoint probing or runtime source execution to estimate progress.
- No raw secret names or values in progress messages beyond existing safe repo/target labels.
- No breaking removal of existing `progress target=... event=...` stderr lines for JSON scans without a versioned compatibility decision.
- No use of progress percent as a policy, proof, risk, or compliance input.
- No broad scan pipeline rewrite. Reuse existing progress and status seams unless a story identifies a specific missing callback.

## Definition of Done

- The generated implementation plan can be handed to `plan-implement` without additional discovery.
- Each story has failing tests identified before implementation tasks.
- CLI progress behavior is additive, documented, deterministic, and compatible with automation.
- All changed command flags, docs, and changelog entries agree.
- Focused CLI progress tests, docs parity checks, and relevant risk lanes pass.
- A final manual smoke transcript can show interactive progress, non-TTY plain output, JSON-clean output, quiet suppression, status sidecar inspection, and failure footer behavior.

## Stories

### Story 1.1: Scan Progress Mode Contract

Priority: P0

Tasks:

- Add a `wrkr scan` progress mode contract centered on `--progress <auto|bar|plain|events|none>` or a final equivalent naming decision.
- Define default `auto` behavior for interactive human scans, JSON scans, non-TTY scans, and quiet scans.
- Preserve existing `--json` progress events on `stderr` unless the selected explicit mode changes them.
- Add invalid-mode handling with the existing JSON error envelope and `invalid_input` exit behavior.
- Update scan usage text and CLI contract tests before renderer implementation.

Repo paths:

- `core/cli/scan.go`
- `core/cli/scan_helpers.go`
- `core/cli/scan_progress.go`
- `core/cli/scan_progress_test.go`
- `docs/commands/scan.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/cli -run 'TestScan.*Progress|TestScanUsage|TestScanJSON' -count=1`
- `make lint-fast`

Test requirements:

- TDD first failing tests must cover valid progress mode parsing, invalid mode rejection, `--quiet` override, JSON stdout cleanliness, and existing JSON event compatibility.
- Include tests for `--json --json-path` byte identity with progress enabled.

Matrix wiring:

- Fast lane: focused `core/cli` progress and usage tests.
- Core CI lane: CLI contract tests for JSON, quiet, usage, and invalid-input envelopes.
- Cross-platform lane: mode parsing and non-TTY fallbacks must not depend on terminal-specific behavior.

Acceptance criteria:

- `wrkr scan --progress nonsense --json` fails with `invalid_input` and clean JSON error semantics.
- `wrkr scan --json` still emits final JSON on `stdout` only.
- `wrkr scan --json --quiet` emits no progress lines.
- Existing progress-event tests are still meaningful and either unchanged or updated with a clear compatibility assertion.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added an explicit scan progress mode contract so operators can choose automatic, bar, plain, event, or disabled progress output without breaking JSON consumers.
Semver marker override: [semver:minor]
Contract/API impact: Adds a user-facing `scan` flag and documents default progress semantics.
Versioning/migration impact: Additive CLI behavior; no saved-state migration required.
Architecture constraints: Keep progress in the CLI/status boundary and do not feed progress mode into Source, Detection, Risk, Proof emission, or Compliance mapping/evidence output semantics.
ADR required: no
TDD first failing test(s): `TestScanProgressModeRejectsInvalidValue`, `TestScanProgressAutoKeepsJSONStdoutClean`, `TestScanQuietSuppressesAllProgressModes`.
Cost/perf impact: low
Chaos/failure hypothesis: Invalid or conflicting progress modes must fail before scan-managed artifact mutation and must not leave partial state.

### Story 1.2: Shared Progress Model And Status Fields

Priority: P0

Tasks:

- Introduce one internal progress state model for phase, repo totals, completed repos, failed repos, detector totals, completed detectors, retries, cooldowns, elapsed time, latest message, and estimated percentage.
- Map existing scan phases to stable weighted progress bands: source acquisition, detectors, analysis, artifact commit, and terminal completion.
- Persist additive status sidecar fields such as `progress_percent`, `progress_message`, `last_progress_at`, `elapsed_seconds`, `phase_progress`, `repo_progress`, and `detector_progress`.
- Keep old status sidecars readable and avoid adding required fields to existing state contracts.
- Ensure progress status writes remain best-effort only when appropriate and do not mask the primary scan error.

Repo paths:

- `core/cli/scan_progress.go`
- `core/cli/scan_status.go`
- `core/state/scan_status.go`
- `core/cli/scan_progress_test.go`
- `core/cli/scan_resume_test.go`

Run commands:

- `go test ./core/cli -run 'TestScan.*Progress|TestScanStatus|TestScanResume' -count=1`
- `go test ./core/state -run 'Test.*ScanStatus' -count=1`
- `make test-contracts`

Test requirements:

- TDD first failing tests must cover deterministic phase percentage mapping, status JSON additive fields, old status sidecar compatibility, resume progress counts, and progress state after interrupted scans.
- Verify that `progress_percent` never decreases during a normal successful scan except when explicitly resetting for a new run.

Matrix wiring:

- Fast lane: progress model and state sidecar unit tests.
- Core CI lane: saved-state/status JSON compatibility tests.
- Risk lane: interrupted scan and partial-result status behavior through chaos/hardening lanes.

Acceptance criteria:

- `wrkr scan status --state <path> --json` includes additive progress fields during active scans.
- Existing state snapshots without status sidecars still report `completed` or `unknown` as today.
- Interrupted scans report partial state, last phase, and the latest progress message.
- Progress percentage and messages are absent from risk/proof/compliance payload derivation.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added progress metadata to the scan status sidecar so background scans can be inspected without tailing logs.
Semver marker override: [semver:minor]
Contract/API impact: Adds optional JSON fields to `wrkr scan status --json` and the scan status sidecar.
Versioning/migration impact: Additive status schema update; old sidecars and absent fields remain accepted.
Architecture constraints: State/status owns operational progress observability only; Risk, Proof emission, and Compliance mapping/evidence output must not consume these fields.
ADR required: no
TDD first failing test(s): `TestScanStatusIncludesProgressFieldsDuringRun`, `TestScanStatusLoadsLegacySidecarWithoutProgress`, `TestScanProgressPercentMonotonicSuccessfulRun`.
Cost/perf impact: low
Chaos/failure hypothesis: Status sidecar write failure during progress update must preserve the primary scan failure and must not corrupt the final status file.

### Story 2.1: TTY-Aware Progress Bar And Plain Renderer

Priority: P0

Tasks:

- Add a renderer abstraction that consumes the shared progress model and writes to `stderr`.
- Implement `bar` rendering as a single updating line for interactive terminals.
- Implement `plain` rendering as deterministic newline milestones for non-TTY output.
- Keep `events` rendering compatible with existing `progress target=... event=...` lines.
- Detect terminal capability conservatively and avoid ANSI/control characters for `TERM=dumb`, non-TTY writers, `NO_COLOR`, and Windows terminals without safe support.
- Flush a newline before normal scan success text, explain output, JSON error envelopes, and failure footers.

Repo paths:

- `core/cli/scan_progress.go`
- `core/cli/scan_progress_render.go`
- `core/cli/scan.go`
- `core/cli/scan_progress_test.go`
- `cmd/wrkr/main_test.go`

Run commands:

- `go test ./core/cli -run 'TestScan.*Progress|TestScanExplain|TestScanJSON' -count=1`
- `go test ./cmd/wrkr -count=1`
- `make test-fast`

Test requirements:

- TDD first failing tests must cover TTY bar output, non-TTY plain output, no progress on `stdout`, final newline flush, `NO_COLOR`, `TERM=dumb`, and `--quiet`.
- Use fake terminal writers or injected terminal capability checks rather than relying on the developer's terminal.

Matrix wiring:

- Fast lane: renderer unit tests and CLI integration tests.
- Core CI lane: full CLI contract around JSON/explain/quiet behavior.
- Cross-platform lane: Windows smoke ensures no unsupported terminal sequences leak into non-TTY logs.

Acceptance criteria:

- Interactive scans show a compact live progress line with phase, percent, repo counts, failures, and elapsed time.
- Non-TTY scans use stable newline progress when progress is enabled.
- `--json` payloads and `--json-path` payloads remain clean and byte-identical.
- Renderer finalization leaves terminal output readable after success or failure.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a TTY-aware scan progress renderer with animated bar output for interactive runs and plain progress milestones for logs.
Semver marker override: [semver:minor]
Contract/API impact: Adds visible human CLI output behavior on `stderr`; `stdout` contracts remain unchanged.
Versioning/migration impact: No data migration; renderer is additive and mode-controlled.
Architecture constraints: CLI renderer must remain a presentation layer over scan progress state and must not drive scan execution.
ADR required: no
TDD first failing test(s): `TestScanProgressBarRendersOnTTYStderr`, `TestScanProgressPlainRendererForNonTTY`, `TestScanProgressFlushesNewlineBeforeExplain`.
Cost/perf impact: low
Chaos/failure hypothesis: Renderer write errors must not panic or hide scan completion/failure status.

### Story 2.2: Heartbeat Updates For Long Phases

Priority: P0

Tasks:

- Add a context-bound heartbeat ticker for enabled progress renderers.
- Refresh elapsed time and current phase every bounded interval while a scan is active.
- Pause or annotate heartbeat during retry/cooldown so users can distinguish waiting from a dead scan.
- Stop heartbeat cleanly on success, failure, timeout, cancellation, and panic-safe deferred cleanup paths.
- Make heartbeat interval testable through injected clock/ticker seams to avoid slow tests.

Repo paths:

- `core/cli/scan.go`
- `core/cli/scan_progress.go`
- `core/cli/scan_progress_render.go`
- `core/cli/scan_progress_test.go`
- `core/source/org/acquire_resume_test.go`

Run commands:

- `go test ./core/cli -run 'TestScan.*Heartbeat|TestScan.*Progress|TestScanStatusReportsInterruptedPartialPhase' -count=1`
- `go test ./core/source/org -run 'Test.*Progress|Test.*Resume' -count=1`
- `make test-chaos`

Test requirements:

- TDD first failing tests must prove heartbeat output appears before long blocked source acquisition completes, appears during detector phase when no detector detail has fired, and stops after cancellation.
- Tests must avoid real multi-second sleeps by using fake tickers or short injected intervals.

Matrix wiring:

- Fast lane: heartbeat unit and focused CLI tests.
- Acceptance lane: long-running org/path scan scenario with observable progress before completion.
- Risk lane: cancellation, timeout, and interrupted scan chaos coverage.

Acceptance criteria:

- A long source acquisition or detector phase produces visible elapsed-time refreshes.
- Cooldown/retry waits show wait context instead of appearing frozen.
- Canceled or timed-out scans do not leave goroutines writing after command return.
- Heartbeat does not alter scan results, ordering, or artifacts.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added heartbeat progress updates for long-running scan phases, retries, and cooldown waits.
Semver marker override: [semver:minor]
Contract/API impact: Adds repeated progress updates on `stderr` when progress is enabled.
Versioning/migration impact: No migration required.
Architecture constraints: Heartbeat observes context and progress state only; it must not trigger detector/source work or external calls.
ADR required: no
TDD first failing test(s): `TestScanProgressHeartbeatVisibleBeforeLongSourceCompletion`, `TestScanProgressHeartbeatStopsAfterCancellation`, `TestScanProgressCooldownHeartbeatShowsWait`.
Cost/perf impact: low to medium
Chaos/failure hypothesis: Heartbeat goroutine leaks under timeout/cancel would degrade long CI runs; tests must prove cleanup.

### Story 2.3: Failure, Interruption, And Completion Footers

Priority: P0

Tasks:

- Standardize final progress footer output for success, runtime failure, policy/schema failure, invalid input after scan start, timeout, cancellation, source cleanup failure, and rollback failure.
- Include status, current phase, last successful phase, partial-result marker, repo/detector counts, elapsed time, artifact paths, and resume hint when applicable.
- Reuse existing `scanStatusTracker.Footer()` semantics where possible and improve them through the shared progress model.
- Ensure final footer renders after progress bar newline cleanup and before or after error envelopes according to current CLI contract.
- Keep `--quiet` suppression and JSON error behavior intact.

Repo paths:

- `core/cli/scan.go`
- `core/cli/scan_status.go`
- `core/cli/scan_progress.go`
- `core/cli/scan_progress_render.go`
- `core/cli/scan_progress_test.go`
- `core/cli/scan_resume_test.go`

Run commands:

- `go test ./core/cli -run 'TestScan.*Progress.*Error|TestScanStatusReportsInterruptedPartialPhase|TestScanResume' -count=1`
- `make test-hardening`
- `make test-chaos`

Test requirements:

- TDD first failing tests must cover progress footer after policy violation, runtime failure, cancellation, timeout, source cleanup failure, and successful artifact commit.
- Verify no duplicate or malformed footer appears when progress is disabled.

Matrix wiring:

- Fast lane: focused failure/footer tests.
- Core CI lane: error envelope and exit-code contract tests.
- Risk lane: rollback, unsafe path, source cleanup, and interrupted scan hardening/chaos tests.

Acceptance criteria:

- Every scan that started progress finalizes progress output cleanly.
- Failure footer gives enough operator context to know whether to rerun, resume, or inspect status.
- Error envelopes remain parseable in JSON mode.
- Existing exit codes are unchanged.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Improved scan completion and failure footers so interrupted or partial scans explain the last phase, progress state, and next inspection path.
Semver marker override: [semver:minor]
Contract/API impact: Changes human-facing stderr/footer text while preserving exit codes and JSON error envelopes.
Versioning/migration impact: No migration required.
Architecture constraints: Footer text is CLI/operator guidance only and must not alter saved scan state beyond already-defined status fields.
ADR required: no
TDD first failing test(s): `TestScanProgressFooterAfterPolicyViolation`, `TestScanProgressFooterAfterTimeout`, `TestScanProgressFooterIncludesResumeHintForInterruptedOrgScan`.
Cost/perf impact: low
Chaos/failure hypothesis: Failure while finalizing progress must not hide the original scan failure or emit corrupt mixed output.

### Story 3.1: Detector-Phase Progress Detail

Priority: P1

Tasks:

- Add an optional detector progress callback/interface to `detect.Options`.
- Have the detector registry emit deterministic detector start, complete, and error events with stable detector IDs/names and counts.
- Update the shared progress model and renderers to show detector totals, active detector label, and detector completion count.
- Keep detector ordering, findings, detector errors, and scan quality output stable.
- Add tests proving detector progress is observable without changing detector outputs.

Repo paths:

- `core/detect/detect.go`
- `core/detect/defaults`
- `core/cli/scan.go`
- `core/cli/scan_progress.go`
- `core/cli/scan_progress_test.go`
- `internal/testutil/detectors/harness.go`

Run commands:

- `go test ./core/detect ./core/cli -run 'Test.*Detector.*Progress|TestScan.*Progress' -count=1`
- `go test ./internal/testutil/detectors -count=1`
- `make test-fast`
- `make test-perf`

Test requirements:

- TDD first failing tests must prove detector start/complete events are emitted in deterministic order and final scan JSON remains unchanged aside from explicitly planned status fields.
- Include tests where a detector returns an error and progress records completed/error counts without swallowing the detector error.

Matrix wiring:

- Fast lane: detector registry and CLI progress tests.
- Core CI lane: detector output compatibility and CLI JSON cleanliness.
- Risk lane: performance lane to bound callback overhead across broad detector sets.

Acceptance criteria:

- Detector phase no longer appears silent during long runs when progress is enabled.
- Progress can identify the active detector group without exposing secrets or raw file contents.
- Detector progress callback absence preserves existing detector behavior.
- Detector progress does not introduce nondeterministic ordering.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added detector-phase progress detail so long scans can show which detector group is active without changing scan findings.
Semver marker override: [semver:minor]
Contract/API impact: Adds optional internal detector progress callbacks and visible stderr progress detail.
Versioning/migration impact: No migration required.
Architecture constraints: Detection owns detector lifecycle events; CLI owns rendering; Risk and Proof emission must not consume progress callbacks.
ADR required: no
TDD first failing test(s): `TestDetectorRegistryEmitsProgressInStableOrder`, `TestScanProgressShowsDetectorPhaseDetail`, `TestDetectorProgressDoesNotChangeFindings`.
Cost/perf impact: medium
Chaos/failure hypothesis: Detector callback panic or write failure must not corrupt detector results; callback paths should be guarded or kept non-panicking.

### Story 4.1: Docs, Changelog, And Contract Validation

Priority: P0

Tasks:

- Update `docs/commands/scan.md` with progress mode syntax, defaults, JSON safety, quiet behavior, TTY/non-TTY behavior, heartbeat semantics, scan status fields, and long-org examples.
- Update `CHANGELOG.md` under `[Unreleased]` with the user-visible scan progress behavior.
- Update any CLI docs parity fixtures or help snapshots required by current docs gates.
- Add operator examples for foreground scans and background scans inspected through `wrkr scan status`.
- Run lightweight docs and contract validation after implementation stories land.

Repo paths:

- `docs/commands/scan.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `README.md`
- `CHANGELOG.md`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`

Run commands:

- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
- `make test-docs-consistency`
- `make prepush-full`

Test requirements:

- TDD first failing tests or docs checks must detect missing `--progress` help/docs parity and stale scan examples.
- Docs smoke must cover at least one JSON-safe scan command and one background status inspection command.

Matrix wiring:

- Fast lane: docs parity check when help text changes.
- Core CI lane: command docs consistency and scan contract tests.
- Acceptance lane: large-org/operator examples stay copy-pasteable or explicitly marked as environment-dependent.
- Gating rule: docs and changelog must ship in the same PR as public CLI progress behavior.

Acceptance criteria:

- Users can discover progress behavior from scan docs and CLI help.
- Docs clearly state progress writes to `stderr` and `stdout` remains clean for JSON.
- Changelog includes operator-facing progress summary and semver marker as required.
- Docs gates pass.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Documented scan progress modes, terminal behavior, heartbeat updates, and scan status progress fields for long-running scans.
Semver marker override: [semver:minor]
Contract/API impact: Documentation and CLI help become the public contract for progress behavior.
Versioning/migration impact: No migration required.
Architecture constraints: Docs must not claim telemetry, daemon, enforcement, or proof behavior that Wrkr does not implement.
ADR required: no
TDD first failing test(s): `scripts/check_docs_cli_parity.sh` must fail until scan docs and help both mention the final progress flag/modes.
Cost/perf impact: low
Chaos/failure hypothesis: Inaccurate docs could cause CI users to parse progress from `stdout`; docs must repeatedly anchor progress on `stderr`.

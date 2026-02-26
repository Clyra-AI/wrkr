# PLAN Polish: Root CLI Discoverability + Evidence Artifact Parity

Date: 2026-02-26
Source of truth:
- `product/dev_guides.md`
- `product/architecture_guides.md`
Scope:
- Improve root CLI discoverability without breaking CLI contracts.
- Add deterministic `inventory.yaml` evidence artifact parity while preserving existing JSON outputs.
- Align docs/contracts to implemented behavior.

## Global Decisions (Locked)
- Deterministic, offline-first, fail-closed behavior remains non-negotiable.
- Exit-code and `--json` contracts are API surface and must remain stable.
- No architecture boundary collapse; changes stay in CLI/evidence/doc contract layers.
- TDD is required: failing tests first, then implementation, then refactor.
- Evidence artifact changes require contract and determinism validation.
- Required gates are enforced by scope:
  - CLI contract scope: `make prepush` + targeted contract tests.
  - Evidence contract scope: `make prepush-full` + contract/scenario coverage.

## Current Baseline (Observed)
- Root help discoverability is limited:
  - `wrkr --help` prints only root flags (`-json`, `-quiet`, `-explain`) and no subcommand catalog.
  - `wrkr help` is treated as unknown command and returns `invalid_input`/exit `6`.
  - Code path: `core/cli/root.go` uses flag-style root parser and no `help` alias.
- Evidence output is JSON-first in implementation:
  - `core/evidence/evidence.go` writes `inventory.json` and `inventory-snapshot.json`.
  - No emitted `inventory.yaml` in evidence bundle output.
- Documentation drift exists:
  - `product/wrkr.md` references `inventory.yaml` output while implementation currently does not emit it.

## Exit Criteria
- `wrkr --help` includes a deterministic command catalog and usage examples for major subcommands.
- `wrkr help` works as alias behavior (root help by default; `wrkr help <command>` delegates to subcommand help) with stable exits.
- Evidence bundle emits `inventory.yaml` in addition to existing JSON artifacts.
- JSON evidence outputs remain unchanged and backward-compatible.
- Evidence manifest/signature verification remains green after artifact addition.
- Docs and examples reflect true behavior for help/discoverability and evidence artifacts.
- Required matrix lanes pass and no contract regressions are introduced.

## Recommendation Traceability
- R1: Root CLI discoverability weak (`wrkr --help` lacks subcommands; `wrkr help` unsupported).
  - Mapped to: `EPIC-CLI-001 / Story CLI-001`, `EPIC-CLI-001 / Story CLI-002`.
- R2: Evidence output JSON-centric; `inventory.yaml` missing in implementation.
  - Mapped to: `EPIC-EVID-001 / Story EVID-001`, `EPIC-EVID-001 / Story EVID-002`.

## Test Matrix Wiring
- Fast lane:
  - Lint + unit + CLI contract slices.
  - Commands: `make lint-fast`, `make test-fast`.
- Core CI lane:
  - Full deterministic Go test sweep + contract checks.
  - Commands: `make prepush`.
- Acceptance lane:
  - Scenario/acceptance flows that validate user-facing CLI/evidence behavior.
  - Commands: `make test-scenarios`, `go test ./internal/acceptance -count=1`.
- Cross-platform lane:
  - Verify CLI help/evidence behavior on Linux/macOS/Windows CI matrix.
  - Commands: existing `main` workflow matrix jobs.
- Risk lane:
  - For evidence artifact and output-dir safety behaviors.
  - Commands: `make prepush-full`, `make test-hardening`, `make test-chaos`, `make test-contracts`.
- Merge/release gating rule:
  - Do not merge unless Fast + Core + required PR checks are green.
  - For evidence-contract stories, require Risk lane green in the same PR.

## EPIC-CLI-001: Root CLI Discoverability Contract
Objective:
- Make root help self-discoverable and support ergonomic `help` entrypoints without breaking exit-code/JSON contracts.

### Story CLI-001: Add deterministic root command catalog to `wrkr --help`
Priority:
- P0
Tasks:
- Add deterministic root help text section listing supported subcommands and one-line purpose.
- Include short usage/examples block for common workflows (`scan`, `score`, `evidence`, `verify`, `regress`).
- Keep current flag help available and stable.
- Add tests that lock help text anchors and ordering.
Repo paths:
- `core/cli/root.go`
- `core/cli/root_test.go`
- `docs/commands/*.md` (if command catalog wording is mirrored)
Run commands:
- `go test ./core/cli -run 'TestRunHelpReturnsExit0|TestRunRootHelpListsCommands' -count=1`
- `make prepush`
Test requirements:
- CLI behavior tests: help/usage tests for root output.
- `--json` stability tests to confirm non-help behavior unchanged.
- Exit-code contract tests for `--help` (still `0`).
Matrix wiring:
- Fast lane, Core CI lane, Cross-platform lane.
Acceptance criteria:
- `wrkr --help` output includes subcommand list and usage anchors deterministically.
- Existing root flags remain present and descriptions unchanged unless intentionally updated.
- No exit-code regressions in existing CLI contract tests.
Architecture constraints:
- Contract-first CLI interface; preserve deterministic output ordering.
- No change to scan/risk/proof execution semantics.
ADR required: yes
TDD first failing test(s):
- `TestRunRootHelpListsCommands` (new; fails before implementation)
- `TestRunHelpReturnsExit0` (update with stricter assertions)
Cost/perf impact: low
Chaos/failure hypothesis:
- If help rendering code encounters unknown command metadata, CLI still returns deterministic help and exit `0` (no panic path).
Dependencies:
- None
Risks:
- Help text churn causing brittle tests; mitigate via anchor-based assertions and stable ordering.

### Story CLI-002: Support `wrkr help` and `wrkr help <subcommand>` aliases
Priority:
- P0
Tasks:
- Implement `help` alias routing in root parser.
- `wrkr help` should match root help behavior.
- `wrkr help <cmd>` should delegate to `<cmd> --help` semantics.
- Preserve unknown-command handling and JSON error envelopes outside help paths.
Repo paths:
- `core/cli/root.go`
- `core/cli/root_test.go`
Run commands:
- `go test ./core/cli -run 'TestRunHelpAlias|TestRunHelpSubcommandAlias|TestRunUnknownCommandReturnsExit6' -count=1`
- `make prepush`
Test requirements:
- CLI behavior changes: alias help tests and subcommand delegation tests.
- Exit-code contract tests (`help` paths return `0`; invalid commands remain `6`).
- JSON error envelope stability tests for non-help invalid paths.
Matrix wiring:
- Fast lane, Core CI lane, Cross-platform lane.
Acceptance criteria:
- `wrkr help` returns root help, exit `0`.
- `wrkr help scan` returns scan help, exit `0`.
- Unknown command behavior remains unchanged for non-help invocation.
Architecture constraints:
- Contract-first CLI interface; preserve existing machine-readable error envelope behavior.
ADR required: yes
TDD first failing test(s):
- `TestRunHelpAliasReturnsExit0`
- `TestRunHelpSubcommandAliasReturnsExit0`
Cost/perf impact: low
Chaos/failure hypothesis:
- Invalid delegated subcommand under help path must fail predictably with deterministic `invalid_input` classification.
Dependencies:
- CLI-001 recommended first (shared help formatter).
Risks:
- Parser precedence ambiguities between root flags and help alias.

## EPIC-EVID-001: Evidence Inventory Artifact Parity
Objective:
- Emit deterministic YAML inventory artifact in evidence bundles while preserving existing JSON artifact and proof integrity contracts.

### Story EVID-001: Emit `inventory.yaml` alongside existing inventory JSON artifacts
Priority:
- P0
Tasks:
- Add deterministic YAML write path for inventory snapshot in evidence build.
- Keep `inventory.json` and `inventory-snapshot.json` unchanged for backward compatibility.
- Ensure YAML serialization order is deterministic and byte-stable across runs.
- Include `inventory.yaml` in manifest/signature flow automatically.
Repo paths:
- `core/evidence/evidence.go`
- `core/evidence/evidence_test.go`
- `core/cli/root_test.go` (evidence command e2e expectations)
- `testinfra/contracts` (artifact contract tests if needed)
Run commands:
- `go test ./core/evidence -run 'TestBuildEvidenceBundle|TestBuildEvidenceInventoryYAMLDeterministic' -count=1`
- `go test ./core/cli -run TestVerifyAndEvidenceCommands -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Schema/artifact tests: bundle artifact presence + compatibility assertions.
- Determinism tests: repeat-run byte-stability for `inventory.yaml`.
- Contract tests: manifest includes new file and verify path remains intact.
- Marker/output safety retention tests (non-empty non-managed directory still fails; marker trust remains enforced).
Matrix wiring:
- Core CI lane, Acceptance lane, Cross-platform lane, Risk lane.
Acceptance criteria:
- Evidence output directory contains `inventory.yaml`, `inventory.json`, `inventory-snapshot.json`.
- Manifest/signature verification continues to pass with new file included.
- No regressions in existing evidence JSON payload keys.
Architecture constraints:
- Offline deterministic evidence generation preserved.
- Fail-closed output-dir safety and integrity verification preserved.
ADR required: yes
TDD first failing test(s):
- `TestBuildEvidenceBundleIncludesInventoryYAML`
- `TestBuildEvidenceInventoryYAMLByteStableAcrossRuns`
Cost/perf impact: low
Chaos/failure hypothesis:
- If YAML write fails (permission/full disk), evidence build fails closed with deterministic error classification and no partial-success status.
Dependencies:
- None
Risks:
- Non-deterministic YAML field order; mitigate with canonical struct-driven encoding and byte-stability tests.

### Story EVID-002: Align docs/contracts to help and evidence artifact reality
Priority:
- P1
Tasks:
- Update product and command docs to reflect root help discoverability behavior and `help` alias.
- Update docs where inventory artifact list currently implies/omits YAML inconsistently.
- Refresh examples with exact expected artifact set and output snippets.
- Add or update docs consistency checks/goldens as needed.
Repo paths:
- `product/wrkr.md`
- `product/dev_guides.md` (only sections that currently drift from implementation intent)
- `docs/commands/evidence.md`
- `docs/commands/scan.md` (if artifact references appear)
- `docs/examples/*` (as needed)
Run commands:
- `make test-docs-consistency`
- `make lint-fast`
- `make prepush`
Test requirements:
- Docs consistency checks for command flags, artifacts, and exit-code references.
- Storyline/smoke doc checks for updated user flows.
Matrix wiring:
- Fast lane, Core CI lane.
Acceptance criteria:
- All touched docs match implemented help and evidence artifact behavior.
- Docs consistency gate passes with no stale key/artifact references.
Architecture constraints:
- Documentation is treated as executable contract and updated in the same PR as behavior changes.
ADR required: no
TDD first failing test(s):
- Docs consistency test/golden that fails on stale artifact/help references.
Cost/perf impact: low
Chaos/failure hypothesis:
- N/A (documentation-only story, no runtime behavior introduced).
Dependencies:
- CLI-001, CLI-002, EVID-001.
Risks:
- Partial docs updates leaving contradictory examples; mitigate with repo-wide consistency scan.

## Minimum-Now Sequence
1. CLI-001 (root help catalog) to establish discoverability baseline.
2. CLI-002 (help alias routing) to complete command entry ergonomics.
3. EVID-001 (inventory.yaml artifact parity) with contract/determinism gates.
4. EVID-002 (docs/contract alignment) after behavior lands.

## Explicit Non-Goals
- No redesign of command taxonomy beyond discoverability/help aliases.
- No migration from flag parser to external CLI framework.
- No changes to risk scoring, detection logic, or proof-chain model.
- No deprecation/removal of existing JSON evidence artifacts.

## Definition of Done
- All stories implemented with TDD evidence (failing tests first) captured in PR notes.
- Required lanes pass per story wiring and plan-level matrix.
- CLI contracts preserved: stable exits and `--json` machine-readable behavior.
- Evidence bundle contracts preserved and extended deterministically with `inventory.yaml`.
- Docs updated in the same PR set as behavior changes.
- No unresolved P0/P1 review findings remain at merge time.

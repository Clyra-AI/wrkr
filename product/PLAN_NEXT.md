# PLAN WRKR_PERSONAL_HYGIENE: Developer Machine Hygiene to Org-Ready Proof

Date: 2026-03-09  
Source of truth: user-provided recommended items for this run, `product/dev_guides.md`, `product/architecture_guides.md`, `AGENTS.md`, current repo baseline  
Scope: Wrkr repository only. Planning artifact only; no implementation in this document.

## Global Decisions (Locked)

- Lead the next Wrkr release with the developer angle first: personal machine hygiene (`wrkr scan --my-setup`, `wrkr mcp-list`, `wrkr inventory --diff`) becomes the first-screen contract, while org scanning remains a first-class security workflow.
- Preserve Wrkr’s deterministic, offline-first, fail-closed core. `scan --my-setup` must work locally by default and must never exfiltrate host data or require network access.
- Preserve architecture boundaries: Source -> Detection -> Aggregation -> Identity -> Risk -> Proof emission -> Compliance/evidence output. Local-machine support must be added as a new source/detection flow, not as ad hoc CLI logic.
- Preserve existing CLI/API contracts:
  - keep `scan --path`, `scan --org`, `scan --repo`, `export`, `evidence`, `verify`, and `regress`
  - keep stable `--json` envelope and exit code taxonomy (`0..8`)
  - add new commands/flags additively only
- Treat `scan --github-org` as an additive alias over existing `scan --org`, not a replacement.
- Treat `inventory` as a developer-facing compatibility wrapper over existing inventory export/regression primitives. `export --format inventory` remains supported and documented.
- `mcp-list` is discovery and privilege mapping only. It must not perform vulnerability scanning, package exploitation checks, or live MCP endpoint probing. Discovery/interoperability notes may reference Snyk and Gait, but Wrkr stays in the See boundary.
- Secret handling remains presence-only and class-only. Local environment scanning may identify configured key names/categories and privilege implications, but must never emit secret values.
- Optional Gait trust-registry overlay is allowed only as a local read-only enrichment. Missing Gait files/tools must degrade explicitly in output (`trust_status: unavailable`) and must not block Wrkr commands.
- Compliance rollups are additive summaries built from existing proof/compliance mappings; do not break current evidence bundle schema or framework coverage semantics.
- Delivery wave order is locked:
  - Wave 1: target contract expansion and local-machine discovery foundation
  - Wave 2: developer command surfaces (`mcp-list`, `inventory`, `inventory --diff`)
  - Wave 3: compliance rollups and evidence/proof packaging
  - Wave 4: README, docs, OSS hygiene, and positioning reframe
  - Wave 5: thin self-serve web bootstrap only
- Thin self-serve web scanning may be planned only as a read-only bootstrap shell after Waves 1-4 are locked. No dashboard-first scope in this plan.
- Every runtime/boundary/risk story must wire `make prepush-full`. Reliability-sensitive local machine scanning and trust overlay stories must also wire `make test-hardening` and `make test-chaos`.

## Current Baseline (Observed)

- `core/cli/root.go` exposes `scan`, `export`, `report`, `score`, `verify`, `evidence`, `regress`, `fix`, and related commands. There is no `inventory` command and no `mcp-list` command today.
- `core/cli/scan.go` already supports `--path`, `--repo`, and `--org`; there is no `--my-setup` mode and no `--github-org` alias.
- `core/cli/export.go` already emits machine-readable inventory via `wrkr export --format inventory --json`. This should be reused rather than replaced.
- `core/cli/regress.go` already provides deterministic baseline/drift mechanics that can power `inventory --diff`.
- `docs/commands/scan.md` and `README.md` are currently repo/org/path posture-first. They do not lead with a personal-machine workflow or MCP quick-reference UX.
- `docs-site/next.config.mjs` uses `output: 'export'`; the current docs-site is static-export oriented and has no GitHub OAuth/bootstrap flow today.
- Agent inventory is already present in scan contracts (`inventory.agents` appears in `docs/commands/scan.md` and tests). This plan should not re-plan generic phase-1.5 agent detection from scratch; it should surface and package existing org/agent signals more effectively.
- Current docs already position Wrkr and Gait together, but they do not yet frame Wrkr as “npm audit for AI tools/MCP servers” or show concrete personal setup examples.
- OSS trust files already exist at repo root: `CONTRIBUTING.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `README.md`, and `LICENSE`.
- Current CI and local gate baseline is compatible with this plan:
  - fast local gate: `make prepush`
  - full architecture gate: `make prepush-full`
  - contract gate: `make test-contracts`
  - scenario gate: `make test-scenarios`
  - reliability gates: `make test-hardening`, `make test-chaos`
  - docs consistency/storyline gates: `make test-docs-consistency`, `make test-docs-storyline`

## Exit Criteria

1. `wrkr scan --my-setup --json` deterministically inventories supported local AI tools, MCP configs, local agent project markers, and environment key presence classes without emitting raw secrets.
2. `wrkr mcp-list` emits a stable machine-readable and human-readable MCP quick-reference view with transport, privilege surface, and optional trust overlay fields.
3. `wrkr inventory` emits a stable machine-readable inventory contract, and `wrkr inventory --diff` deterministically reports added/removed/changed entities relative to a baseline.
4. Existing `wrkr export --format inventory --json` and `wrkr regress` contracts remain valid and documented as compatibility surfaces.
5. `wrkr scan --github-org` exists as an additive alias for org scanning without breaking existing `scan --org` automation.
6. Scan/report/evidence outputs expose additive compliance rollups by framework/control/article without changing existing exit codes or removing current JSON keys.
7. Personal setup and org scan outputs can both produce signed proof/evidence artifacts that remain verifiable via existing `wrkr verify --chain --json` contract.
8. README, command docs, examples, and docs-site first-screen flow lead with the developer hygiene narrative while still covering the security-team posture/compliance path.
9. Thin web scanner scope, if implemented, remains a read-only bootstrap shell that hands off to existing Wrkr org scan contracts and does not introduce dashboard-first core scope.
10. All changed surfaces are covered by deterministic contract tests, scenario coverage where applicable, docs parity checks, and required CI matrix wiring.

## Public API and Contract Map

Stable/public surfaces:
- `wrkr scan --path|--repo|--org --json`
- `wrkr export --format inventory|appendix --json`
- `wrkr regress init|run --json`
- `wrkr evidence --frameworks ... --json`
- `wrkr verify --chain --json`
- Current scan/report/evidence exit codes and machine-readable error envelopes
- Current top-level scan JSON keys and additive v1 schema policy

New stable/public surfaces introduced by this plan:
- `wrkr scan --my-setup`
- `wrkr scan --github-org <org>` as alias for `scan --org <org>`
- `wrkr inventory [--diff] [--baseline <path>]`
- `wrkr mcp-list`
- Additive `compliance_summary` / `control_mappings`-style summary sections in scan/report/evidence outputs

Internal surfaces:
- New local-machine source package(s) for workstation discovery
- New local detection package(s) for host config/env classification
- Optional Gait trust overlay adapter
- Inventory diff projection helpers built on existing export/regress internals
- Docs-site bootstrap shell and auth handoff scaffolding

Shim/deprecation path:
- `export --format inventory` remains stable and supported; `inventory` initially wraps the same builder and only adds ergonomic affordances like `--diff`.
- `scan --org` remains stable; `scan --github-org` is an additive alias and docs-friendly spelling.
- `regress` remains the underlying deterministic diff engine; `inventory --diff` should call into it rather than fork logic.
- Existing `report` and `evidence` output keys stay intact; compliance rollups are additive only.

Schema/versioning policy:
- Remain on v1 schemas.
- New machine-readable fields must be additive and optional unless deterministic empty/default values are required by contract.
- No renames/removals of existing required keys in scan/export/evidence payloads.
- If the thin web bootstrap introduces any server-facing payload contract, it must be explicitly versioned and isolated from core CLI schemas.

Machine-readable error expectations:
- Conflicting target flags (`--my-setup` plus `--path`/`--repo`/`--org`) return `invalid_input` (exit `6`).
- Unsupported or unreadable local config roots that are optional degrade explicitly in output; they do not silently disappear.
- Unsafe local read paths or invalid trust overlay references fail closed with stable error classes.
- Missing GitHub acquisition dependencies for org scan remain `dependency_missing` (exit `7`).
- Missing optional Gait trust registry must not become a hard dependency failure.

## Docs and OSS Readiness Baseline

README first-screen contract:
- Current README is strong on deterministic org/path scanning and evidence, but it does not lead with the developer-machine problem.
- This plan moves the first screen to:
  - install
  - `scan --my-setup`
  - `mcp-list`
  - `scan --github-org`
  - `inventory --diff`
- Security-team positioning remains, but moves below the developer-first story.

Integration-first docs flow:
- New docs must explain “what do I run first?” before internal architecture or taxonomy.
- Command docs for new surfaces must include copy-paste examples and stable JSON keys before implementation details.

Lifecycle path model:
- Keep Wrkr’s current lifecycle state model intact.
- Personal setup inventory should not invent a separate lifecycle machine; it should enrich discovery posture, not fork identity semantics.

Docs source-of-truth:
- README: product entry contract
- `docs/commands/*`: command/flag/JSON/exit-code contract
- `docs/examples/*`: narrative examples and adoption flows
- `docs/contracts/readme_contract.md`: README structural contract
- `docs-site/`: public docs shell and future thin web bootstrap shell

OSS trust baseline:
- Root baseline files already exist.
- This plan keeps trust-file changes minimal and focused on externally visible behavior, support expectations, and install/discovery clarity.
- If web bootstrap scope adds hosted behavior, maintainer/support expectations must be made explicit in docs and security policy links.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | `wrkr scan --my-setup` personal machine scan | Create immediate “what’s on my machine?” moment | Developer-bottom-up PLG | Faster first value and higher individual adoption | W1-S01, W1-S02 |
| R2 | Personal inventory + diff | Make posture trackable over time | Ongoing hygiene loop | Habit formation and drift visibility | W1-S04 |
| R3 | `wrkr mcp-list` quick reference | Show MCP posture fast without full scan archaeology | Fast operator UX | Clearer day-1 value and lower friction | W1-S03 |
| R4 | Discovery, not vulnerability scanning | Avoid scope confusion and competitive overlap | Product boundary clarity | Stronger positioning with less promise risk | W2-S08 |
| R5 | `scan --github-org` org workflow | Make org posture story obvious in CLI/README | Security-team usability | Lower onboarding friction for CISOs | W1-S01, W2-S07, W2-S08 |
| R6 | Surface agent/org posture in org scans | Keep top-down security story complete | Security posture continuity | Better enterprise relevance | W1-S05, W1-S06 |
| R7 | Compliance mapping output in scan/report | Turn findings into audit-ready summaries | Compliance leverage | Stronger buyer and auditor value | W1-S05 |
| R8 | Evidence bundle as signed proof artifact | Preserve audit handoff story | Proof-first differentiation | Portable, verifiable evidence moat | W1-S06 |
| R9 | Developer-first README and examples | Reframe Wrkr from org-only to dual-use | PLG messaging shift | Better conversion from install to activation | W2-S07, W2-S08 |
| R10 | Gait interoperability and Snyk boundary docs | Make product edges explicit | Ecosystem positioning | Lower confusion, higher trust | W1-S03, W2-S08 |
| R11 | Thin self-serve web scanner | Show HN/demo-ready org onboarding path | Distribution UX | Higher reach without changing core runtime | W2-S09 |

## Test Matrix Wiring

Fast lane:
- `make lint-fast`
- `make test-fast`

Core CI lane:
- `make prepush`
- `make test-contracts`
- targeted package tests for touched command/source/detection packages

Acceptance lane:
- `make test-scenarios`
- `scripts/run_v1_acceptance.sh --mode=local`
- add new outside-in personal setup fixture scenarios where applicable

Cross-platform lane:
- `windows-smoke`
- path/home-directory/env handling contract tests on Linux/macOS/Windows

Risk lane:
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-perf` for stories that materially increase local file traversal or docs-site server/runtime cost

Merge/release gating rule:
- Wave 1 must pass Fast + Core CI + Acceptance + Cross-platform + Risk lanes before Wave 2 starts.
- Wave 2 must pass Fast + Core CI + Acceptance + Cross-platform + Risk lanes before Wave 3 starts.
- Wave 3 must pass Fast + Core CI + Acceptance + Cross-platform + Risk lanes before Wave 4 starts.
- Wave 4 must pass Fast + docs consistency/storyline gates before Wave 5 starts.
- Wave 5 must pass Fast + Core CI + Cross-platform + Risk lanes plus docs-site build/smoke gates.
- No merge is allowed with `--json` drift, exit-code drift, or docs/CLI parity failures unless explicitly versioned and approved.

## Epic W1-E1 (Wave 1): Personal Machine Discovery Foundation

Objective: add the deterministic, offline-first personal-machine source mode and target contract needed for all later developer-facing flows without breaking current `scan`, `export`, or `regress` contracts.

### Story W1-S01: Add `scan --my-setup` and `scan --github-org` target contract expansion
Priority: P0
Tasks:
- Add additive scan target flags:
  - `--my-setup`
  - `--github-org` as alias to existing `--org`
- Define and document mutual exclusion rules across `--my-setup`, `--path`, `--repo`, `--org`, and `--github-org`.
- Add deterministic target metadata to scan output so personal vs repo/org scans are machine-distinguishable without breaking current top-level keys.
- Keep org/repo acquisition failure semantics unchanged and keep `--my-setup` local-only by default.
Repo paths:
- `core/cli/scan.go`
- `core/cli/root.go`
- `core/state/*`
- `docs/commands/scan.md`
- `README.md`
- `core/cli/root_test.go`
- `core/cli/*scan*_test.go`
Run commands:
- `go test ./core/cli -count=1`
- `go run ./cmd/wrkr scan --my-setup --json --quiet`
- `go run ./cmd/wrkr scan --github-org acme --github-api https://api.github.com --json`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- CLI help/usage tests for new flags.
- `--json` stability tests for target selection and machine-readable error envelopes.
- Exit-code contract tests for conflicting target combinations.
- Deterministic target metadata fixture tests.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- `scan --my-setup` is accepted as a single-source mode and rejects mixed target combinations with exit `6`.
- `scan --github-org` behaves identically to `scan --org` for output and exit semantics.
- Existing `scan --org` and `scan --path` automation remains green without output regressions.
Contract/API impact:
- Additive CLI flag expansion on `scan`; preserve current exit codes and top-level JSON envelope.
Versioning/migration impact:
- No schema major bump; only additive target metadata fields if needed.
Architecture constraints:
- Keep target selection in CLI orchestration only.
- Introduce local-machine source entry point under Source boundary rather than direct filesystem crawling in CLI.
- Preserve cancellation/timeout propagation for target acquisition flow.
ADR required: yes
TDD first failing test(s):
- `TestScanRejectsMixedMySetupAndPathTargets`
- `TestScanGitHubOrgAliasMatchesOrgContract`
Cost/perf impact: low
Chaos/failure hypothesis:
- If local target roots are partially unreadable, scan emits deterministic non-secret detector/source errors and stays fail-closed on unsafe reads.
Dependencies:
- none

### Story W1-S02: Implement deterministic local-machine source and workstation detectors
Priority: P0
Tasks:
- Add new local-machine source package that enumerates supported config roots deterministically:
  - home-directory config roots for Cursor, Claude, Codex, VS Code/Copilot, MCP declarations, agent projects
  - environment-variable allowlist for API key presence classification
- Implement structured detectors for:
  - installed/configured AI tools
  - MCP server definitions and privilege-bearing config
  - local agent project markers
  - environment key presence classes and risk hints
- Normalize findings so raw secret values and raw connection strings are never emitted.
- Add privilege mapping for local-only findings such as filesystem scope, database endpoints, Slack/channel posting, and production-target hints where parsable.
Repo paths:
- `core/source/localsetup/*`
- `core/detect/workstation/*`
- `core/detect/mcp/*`
- `core/detect/mcpgateway/*`
- `core/model/finding.go`
- `schemas/v1/findings/*`
- `schemas/v1/inventory/*`
- `internal/scenarios/*`
- `scenarios/wrkr/my-setup/*`
Run commands:
- `go test ./core/source/... ./core/detect/... -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go run ./cmd/wrkr scan --my-setup --json --quiet`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- Structured parser tests for local config formats (JSON/YAML/TOML).
- Privacy contract tests proving no raw secret value is emitted.
- Deterministic inventory/finding ordering tests for home directory and env enumeration.
- Fail-closed undecidable-path tests for unreadable directories, symlink traps, and malformed configs.
- Scenario fixtures for realistic local setup examples, including production-risk MCP configs.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- A fixed machine fixture produces byte-stable findings and inventory across repeated runs.
- Environment results identify key presence by normalized key family only.
- MCP privilege findings show explainable privilege surfaces without active probing.
- Unsupported or unreadable roots are surfaced explicitly and deterministically.
Contract/API impact:
- Additive scan finding/inventory fields for local-machine context and privilege hints.
Versioning/migration impact:
- Stay on v1 schemas with additive fields only.
Architecture constraints:
- Source package enumerates candidate inputs; detectors parse structured content; aggregation/risk remain separate.
- Avoid regex-only parsing for structured configs.
- No network or remote calls in default local-machine scan path.
ADR required: yes
TDD first failing test(s):
- `TestMySetupScan_RedactsEnvironmentSecrets`
- `TestMySetupScan_DeterministicOrderingAcrossHomeRoots`
Cost/perf impact: medium
Chaos/failure hypothesis:
- If home-directory traversal encounters symlink loops or permission-denied folders, scan exits or degrades deterministically without partial secret exposure or hidden skips.
Dependencies:
- W1-S01
Risks:
- Home-directory and env modeling can create noise if allowlists are too broad; keep fixtures and confidence thresholds conservative.

## Epic W1-E2 (Wave 2): Developer Command Surfaces

Objective: expose the new local-machine posture model through stable, ergonomic command surfaces after the source and detection foundation is locked.

### Story W1-S03: Add `wrkr mcp-list` with optional Gait trust overlay
Priority: P0
Tasks:
- Add new top-level `mcp-list` command with human-readable and `--json` output.
- Project existing local/repo MCP findings into a stable MCP server catalog:
  - server name
  - transport type
  - requested permissions / privilege surface
  - trust status
  - concise risk note
- Add optional local-only overlay that reads Gait trust registry state when present and marks server trust status without making Gait a hard dependency.
- Add explicit docs note that Wrkr inventories/configures MCP posture and does not replace vulnerability scanners.
Repo paths:
- `core/cli/mcp_list.go`
- `core/cli/root.go`
- `core/report/mcp_list.go`
- `core/detect/mcp/*`
- `core/detect/mcpgateway/*`
- `docs/commands/mcp-list.md`
- `docs/faq.md`
- `core/cli/*mcp*_test.go`
Run commands:
- `go test ./core/cli ./core/report ./core/detect/mcp ./core/detect/mcpgateway -count=1`
- `go run ./cmd/wrkr mcp-list --json`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- CLI help/usage tests.
- Stable JSON contract tests for field ordering and absence/presence of trust overlay metadata.
- Wrapper error-mapping tests for missing/unreadable optional Gait inputs.
- Deterministic allow/block/degrade tests for trust overlay states.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- `mcp-list --json` produces deterministic rows for the same fixture input.
- Missing Gait trust registry yields `trust_status: unavailable` rather than command failure.
- Human-readable output is a concise quick-reference card, not a verbose report.
- Docs clearly distinguish discovery from vulnerability assessment and reference Snyk/Gait appropriately.
Contract/API impact:
- New public CLI command and JSON schema surface.
Versioning/migration impact:
- Additive only; no impact on existing scan/export/evidence schemas.
Architecture constraints:
- Command should consume catalog/projection helpers, not reimplement detector logic.
- Keep optional trust overlay behind a thin adapter boundary.
- Explicitly separate discovery data from trust overlay metadata.
ADR required: yes
TDD first failing test(s):
- `TestMCPListJSON_StableRowsAndTrustStatus`
- `TestMCPListWithoutGait_DegradesExplicitly`
Cost/perf impact: low
Chaos/failure hypothesis:
- If the trust overlay file is malformed or unreadable, Wrkr still lists MCP servers with deterministic `trust_status: unavailable` and machine-readable warning context.
Dependencies:
- W1-S02

### Story W1-S04: Add `wrkr inventory` and deterministic `inventory --diff`
Priority: P0
Tasks:
- Add new top-level `inventory` command that wraps current inventory export primitives.
- Add `inventory --diff` over deterministic baseline comparison using existing regress/diff logic rather than bespoke comparison code.
- Define baseline file/default path semantics for developer hygiene workflows.
- Keep `export --format inventory` and `regress` fully supported and document the relationship between commands.
Repo paths:
- `core/cli/inventory.go`
- `core/cli/root.go`
- `core/export/inventory/*`
- `core/regress/*`
- `docs/commands/inventory.md`
- `docs/commands/export.md`
- `docs/commands/regress.md`
- `core/cli/*inventory*_test.go`
Run commands:
- `go test ./core/cli ./core/export/inventory ./core/regress -count=1`
- `go run ./cmd/wrkr inventory --json`
- `go run ./cmd/wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --json`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- CLI help/usage tests.
- `--json` stability tests for inventory and diff payloads.
- Exit-code contract tests for missing baseline / invalid baseline shape.
- Compatibility tests proving `inventory` output matches `export --format inventory` for equivalent state.
- Deterministic drift reason tests for added/removed/changed MCP servers, tools, and key-presence classes.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- `inventory --json` produces a stable inventory payload equivalent to the underlying export contract.
- `inventory --diff` deterministically identifies additions/removals/permission changes between two fixed baselines.
- Existing `export` and `regress` workflows remain valid and documented as compatibility surfaces.
Contract/API impact:
- New public CLI command; additive wrapper over existing stable JSON builders and drift semantics.
Versioning/migration impact:
- No schema major bump; diff payload uses additive v1-compatible envelope.
Architecture constraints:
- Reuse export/regress boundaries; do not duplicate inventory serialization or diff semantics in CLI.
- Keep diff engine deterministic and side-effect-free.
- Preserve symmetric API semantics between raw inventory export and diff mode.
ADR required: yes
TDD first failing test(s):
- `TestInventoryCommand_MatchesInventoryExportContract`
- `TestInventoryDiff_ReportsAddedRemovedChangedDeterministically`
Cost/perf impact: low
Chaos/failure hypothesis:
- If baseline file is malformed or stale, command fails with a stable machine-readable error instead of producing ambiguous diff results.
Dependencies:
- W1-S02

## Epic W1-E3 (Wave 3): Compliance Rollups and Evidence Packaging

Objective: make Wrkr’s top-down security story explicit in scan/report/evidence outputs after the personal-machine and command contracts are stable.

### Story W1-S05: Add additive compliance summary sections to scan and report outputs
Priority: P0
Tasks:
- Reuse existing compliance mappings to emit deterministic rollups by framework/control/article in scan and report outputs.
- Add explain-mode rendering so human-readable summaries can say things like “12 findings map to SOC 2 CC6.1”.
- Ensure summaries work for both personal setup and org/repo scans where mappings exist.
- Keep current report keys intact and add compliance sections additively.
Repo paths:
- `core/compliance/*`
- `core/cli/scan.go`
- `core/cli/report.go`
- `core/report/*`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `core/cli/report_contract_test.go`
- `core/cli/root_test.go`
Run commands:
- `go test ./core/compliance ./core/cli ./core/report -count=1`
- `go run ./cmd/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
- `go run ./cmd/wrkr report --state ./.wrkr/last-scan.json --json`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- Schema/contract tests for additive compliance summary keys.
- Golden fixture updates for scan/report JSON.
- Deterministic mapping aggregation tests and ordering checks.
- Scenario tests proving summary counts stay stable on fixed fixtures.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Scan and report JSON include deterministic compliance rollups without removing existing fields.
- Repeated runs on fixed fixtures emit identical framework/control counts.
- Human-readable docs/examples match tested JSON terminology.
Contract/API impact:
- Additive public JSON fields for scan/report.
Versioning/migration impact:
- v1 additive fields only; no breaking changes.
Architecture constraints:
- Compliance mapping logic remains in compliance/evidence layer, not in detectors or CLI.
- Keep stable framework IDs and reason-code semantics.
- Preserve explicit side-effect naming between summarize/build/export paths.
ADR required: yes
TDD first failing test(s):
- `TestScanJSON_EmitsComplianceSummaryAdditively`
- `TestReportJSON_EmitsDeterministicControlRollups`
Cost/perf impact: low
Chaos/failure hypothesis:
- If a mapping file is missing or invalid, Wrkr fails closed with stable policy/schema behavior instead of silently emitting partial compliance numbers.
Dependencies:
- W1-S02

### Story W1-S06: Extend proof/evidence artifacts for personal setup and org posture bundles
Priority: P0
Tasks:
- Ensure `scan --my-setup` writes proof records and state artifacts that remain compatible with existing evidence and verify flows.
- Add additive evidence bundle artifacts for:
  - personal inventory snapshot
  - compliance summary snapshot
  - MCP catalog snapshot when present
- Keep existing proof record type conventions and chain verification semantics intact.
- Add evidence docs showing auditor handoff for org scans and local handoff for personal hygiene baselines.
Repo paths:
- `core/evidence/*`
- `core/proofemit/*`
- `core/proofmap/*`
- `core/verify/*`
- `docs/commands/evidence.md`
- `docs/commands/verify.md`
- `core/evidence/*test.go`
- `internal/scenarios/*`
Run commands:
- `go test ./core/evidence ./core/proofemit ./core/proofmap ./core/verify -count=1`
- `go run ./cmd/wrkr evidence --frameworks soc2 --json`
- `go run ./cmd/wrkr verify --chain --json`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- Schema/artifact compatibility tests for new evidence files.
- Byte-stability repeat-run tests for personal and org evidence bundles.
- Canonicalization/digest and chain verification tests.
- Scenario tests covering both personal and org evidence generation paths.
Matrix wiring:
- Fast, Core CI, Acceptance, Cross-platform, Risk
Acceptance criteria:
- Personal setup scans can produce verifiable proof/evidence artifacts without changing existing verify semantics.
- Evidence bundles contain deterministic machine-readable inventory and compliance summary artifacts.
- Existing evidence consumers remain compatible.
Contract/API impact:
- Additive evidence artifact surface; existing proof verify contract remains stable.
Versioning/migration impact:
- No proof record type rename/removal; additive artifact files only.
Architecture constraints:
- Proof emission remains authoritative in Go core.
- Evidence packaging reuses existing proof primitives and chain semantics.
- No web/UI-specific evidence generation logic leaks into core runtime.
ADR required: yes
TDD first failing test(s):
- `TestEvidenceBuild_IncludesPersonalInventoryArtifactDeterministically`
- `TestVerifyChain_PersonalSetupBundleRemainsCompatible`
Cost/perf impact: medium
Chaos/failure hypothesis:
- If evidence output directory is unsafe or partially populated, Wrkr fails closed using existing unsafe-output semantics and does not emit half-written artifacts.
Dependencies:
- W1-S04
- W1-S05

## Epic W2-E1 (Wave 4): Developer-First README and Docs Reframe

Objective: reposition Wrkr around the developer “holy shit” moment first after runtime/API surfaces are settled, while preserving the security-team and compliance story lower in the funnel.

### Story W2-S07: Rewrite README first screen and quickstart around personal machine hygiene
Priority: P1
Tasks:
- Replace current hero and top quickstart with the developer-first contract:
  - install
  - `wrkr scan --my-setup`
  - `wrkr mcp-list`
  - `wrkr scan --github-org`
  - `wrkr inventory --diff`
- Add a concrete personal setup output example showing surprising but realistic privilege findings.
- Preserve lower-page sections for security-team posture, evidence, and Gait relationship.
- Update root help examples/documentation references if needed for command discoverability.
Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/contracts/readme_contract.md`
- `docs/map.md`
- `core/cli/root.go`
- `core/cli/root_test.go`
Run commands:
- `go test ./core/cli -count=1`
- `make test-docs-consistency`
- `make test-docs-storyline`
- `docs-site-install`
- `docs-site-build`
Test requirements:
- README first-screen checks.
- Docs consistency checks for renamed/additive commands and examples.
- Storyline/smoke checks for first-run developer flow.
- Help/usage tests if examples or command catalog text changes.
Matrix wiring:
- Fast, Core CI
Acceptance criteria:
- README first screen reflects the developer-machine narrative before the org/audit narrative.
- Examples are copy-pasteable and aligned with tested command surfaces.
- Docs/CLI parity checks stay green.
Contract/API impact:
- Documentation-only unless root help/example text changes.
Architecture constraints:
- Docs must remain integration-first and contract-accurate.
- Do not overstate runtime enforcement or vulnerability scanning scope.
ADR required: no
TDD first failing test(s):
- `TestRootHelpListsInventoryAndMCPListExamples`
- docs storyline check for developer-first quickstart
Cost/perf impact: low
Dependencies:
- W1-S01
- W1-S03
- W1-S04

### Story W2-S08: Publish command docs and positioning pages for developer and security personas
Priority: P1
Tasks:
- Add/refresh docs for:
  - `docs/commands/mcp-list.md`
  - `docs/commands/inventory.md`
  - `docs/commands/scan.md` developer/org examples
  - security-team posture/compliance examples
  - Gait interoperability notes
  - Snyk/vuln-scanning boundary notes
- Add separate persona examples:
  - developer personal hygiene
  - security team org inventory and compliance handoff
- Update FAQ and positioning pages to make the discovery-versus-vulnerability boundary explicit.
Repo paths:
- `docs/commands/scan.md`
- `docs/commands/mcp-list.md`
- `docs/commands/inventory.md`
- `docs/commands/evidence.md`
- `docs/examples/personal-hygiene.md`
- `docs/examples/security-team.md`
- `docs/faq.md`
- `docs/positioning.md`
- `README.md`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `docs-site-install`
- `docs-site-lint`
- `docs-site-build`
- `docs-site-check`
Test requirements:
- Docs consistency checks.
- Storyline/smoke checks for changed user flows.
- README/docs source-of-truth mapping checks when both repo docs and docs-site nav are touched.
- Version/install discoverability checks where command surface changes are referenced.
Matrix wiring:
- Fast, Core CI
Acceptance criteria:
- New commands and examples are fully documented with stable `--json` expectations.
- Docs explicitly say Wrkr inventories/configures MCP posture and does not assess server vulnerabilities.
- Gait interoperability is framed as inventory vs enforcement, not as a hard prerequisite.
Contract/API impact:
- Documentation-only unless command docs expose new public JSON fields from Wave 1.
Architecture constraints:
- Docs must mirror tested CLI semantics and fail-closed behavior.
- Keep integration-before-internals order in command docs.
ADR required: no
TDD first failing test(s):
- docs parity check for `mcp-list` and `inventory`
- docs storyline check for personal hygiene flow
Cost/perf impact: low
Dependencies:
- W1-S03
- W1-S04
- W1-S05
- W1-S06

## Epic W2-E2 (Wave 5): Thin Self-Serve Web Bootstrap

Objective: create a minimal distribution shell that lets a user connect GitHub and trigger/read a Wrkr org scan quickly, without turning Wrkr into a dashboard-first product, only after the CLI/docs contract is settled.

### Story W2-S09: Add thin web scanner/bootstrap shell for read-only org scanning
Priority: P2
Tasks:
- Produce ADR for hosting model change required by current static docs-site baseline.
- Add a minimal docs-site `/scan` bootstrap flow that:
  - explains the 60-second org scan value proposition
  - initiates read-only GitHub OAuth or equivalent bootstrap handshake
  - hands off to existing Wrkr org scan/action contracts
  - renders returned machine-readable summary artifact, not a persistent dashboard
- Keep Go CLI authoritative for scan/risk/proof; Node/Next code remains a thin adoption/distribution layer only.
- Add privacy/security copy and explicit “read-only, no runtime enforcement” messaging.
Repo paths:
- `docs-site/src/app/*`
- `docs-site/src/lib/*`
- `docs-site/package.json`
- `docs-site/next.config.mjs`
- `docs-site/README.md`
- `.github/workflows/*`
- `docs/positioning.md`
- `README.md`
Run commands:
- `docs-site-install`
- `docs-site-lint`
- `docs-site-build`
- `docs-site-check`
- `make test-docs-consistency`
- `make test-perf`
- `make prepush-full`
Test requirements:
- Docs-site smoke tests for bootstrap flow.
- Failure-path tests for denied auth, missing callback state, and unavailable scan backend/handoff.
- Wrapper error-mapping tests if a thin adapter/service contract is introduced.
- README/docs parity checks for hosted bootstrap copy.
Matrix wiring:
- Fast, Core CI, Cross-platform, Risk
Acceptance criteria:
- A user can reach a read-only org scan bootstrap flow from the docs-site without encountering dashboard-only dead ends.
- The bootstrap shell produces or renders a deterministic Wrkr summary artifact tied to existing org scan contracts.
- The flow clearly states its boundaries and does not duplicate core runtime logic in Node.
Contract/API impact:
- Potential new thin web bootstrap payload contract; must be versioned and isolated from CLI schemas if introduced.
Versioning/migration impact:
- If docs-site hosting/export mode changes, document the migration and release/deploy expectations explicitly.
Architecture constraints:
- No dashboard-first scope.
- Go core remains authoritative for scanning, risk, proof, and evidence logic.
- Thin orchestration only in web layer; explicit timeout/cancellation semantics for long-running handoff flows.
- Extension points should reduce enterprise fork pressure if self-hosted bootstrap variants are needed later.
ADR required: yes
TDD first failing test(s):
- docs-site bootstrap smoke test with mocked GitHub auth callback
- adapter test for scan kickoff error mapping
Cost/perf impact: medium
Chaos/failure hypothesis:
- If auth callback or scan kickoff fails, the shell must present deterministic retry/error states and must not create hidden partial org scans or ambiguous success UX.
Dependencies:
- W2-S07
- W2-S08
Risks:
- Current static-export docs-site is incompatible with full OAuth callback handling; hosting mode change must be explicit and tightly scoped.

## Minimum-Now Sequence

1. Wave 1: W1-S01, W1-S02
2. Wave 2: W1-S03, W1-S04
3. Wave 3: W1-S05, W1-S06
4. Wave 4: W2-S07, W2-S08
5. Wave 5: W2-S09

Parallelization notes:
- Within Wave 1, W1-S02 starts immediately after W1-S01 target-contract locking.
- Within Wave 2, W1-S03 and W1-S04 can overlap once W1-S02 lands stable local inventory primitives.
- Within Wave 3, W1-S05 can start first; W1-S06 follows once inventory/diff/compliance payload shapes are stable.
- Within Wave 4, W2-S07 can start before W2-S08, but both should stay behind locked Wave 3 command/output contracts.
- Wave 5 must not start before Waves 1-4 are green and the docs-site hosting/ADR decision is explicitly accepted.

## Explicit Non-Goals

- No vulnerability scanning of MCP servers, agent packages, or developer workstations.
- No raw secret extraction or raw credential materialization in any output.
- No runtime enforcement, request interception, or tool blocking; that remains Gait’s boundary.
- No rich multi-tenant dashboard, analytics portal, or long-lived SaaS control plane in this plan.
- No breaking removal of `scan --org`, `export --format inventory`, `regress`, or current v1 JSON schemas.
- No LLM-based local machine interpretation in scan/risk/proof paths.

## Definition of Done

- Every recommendation in the traceability table maps to at least one implemented story or an explicit additive compatibility shim.
- Every story has real repo paths, concrete run commands, deterministic acceptance criteria, and matrix wiring.
- CLI changes preserve stable `--json` and exit-code behavior, with help/usage coverage and machine-readable error envelope tests.
- Schema/artifact changes remain additive under v1 and are covered by contract/golden compatibility tests.
- Reliability-sensitive local scan and trust-overlay stories pass `make test-hardening` and `make test-chaos`.
- Docs updates ship in the same PRs as command/contract changes and pass docs parity/storyline checks.
- README first-screen contract, integration-first docs flow, and OSS trust baseline remain explicit and accurate.
- Waves 1-4 complete in order before Wave 5 distribution/bootstrap work begins.

# PLAN WRKR_FIRST_OFFER_GOVERN_FIRST: Customer-Ready Bounded AI Action Exposure Assessment

Date: 2026-03-30
Source of truth:
- user-provided "Wrkr First-Offer Work Items" dated 2026-03-30
- `AGENTS.md`
- `product/dev_guides.md`
- `product/architecture_guides.md`
- `product/wrkr.md`
- `Makefile`
- `README.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/cli/scan.go`
- `core/cli/scan_progress.go`
- `core/detect/parse.go`
- `core/owners/owners.go`
- `core/report/activation.go`
- `core/report/build.go`
- `core/report/types.go`
- `core/risk/action_paths.go`
- `core/risk/risk.go`
- `internal/scenarios`
- `scenarios/wrkr`
- `testinfra/contracts`
Scope: Wrkr repository only. Planning artifact only. Align the shipped product to the first prospect offer: find bounded AI-connected software-delivery action paths, rank the riskiest ones first, emit offline-verifiable proof, recommend what to control first, and stay usable on real customer repos and larger org scans. Runtime provenance, live action observation, and control-layer enforcement remain out of scope.

## Global Decisions (Locked)

- This file is planning-only. No implementation work is in scope for this artifact.
- The first-offer product claim is static posture plus offline-verifiable proof for bounded software-delivery AI action paths. It is not runtime provenance, live action observation, selective gating, or enforcement.
- Raw findings, inventory records, proof records, exit codes, and existing `attack_paths` surfaces stay intact unless a story explicitly adds an additive field. Govern-first sharpening happens in `activation`, `action_paths`, `action_path_to_control_first`, assessment-specific report summaries, and ranking order only.
- Add an additive `assessment` profile for bounded customer scans instead of mutating the semantics of existing `baseline|standard|strict` profiles.
- The `assessment` profile may narrow or downweight only govern-first prioritization surfaces. It must not delete or mutate raw findings, proof records, or machine-readable evidence emitted for the same scan input.
- `action_paths[*].path_id` remains an opaque deterministic lowercase hex identifier. The exact hash inputs may evolve to improve uniqueness, but repeat-run stability and uniqueness are mandatory.
- `recommended_action` remains a stable four-value enum: `inventory`, `approval`, `proof`, `control`.
- `--json` stdout is a hard contract. Hosted/org progress is allowed only on stderr and must never pollute stdout JSON or `--json-path` byte identity.
- Real-world regression checks must use frozen deterministic fixtures or materialized subset snapshots under repo control; no CI step may depend on live external repo state.
- Thin orchestration stays in `core/cli/*`. Deterministic correlation belongs in `core/aggregate/*`, path ranking and grouping in `core/risk/*`, ownership logic in `core/owners/*`, detector error surfacing in `core/detect/*`, and rendering/template logic in `core/report/*`.
- Stories that touch architecture boundaries, risk logic, report contracts, adapters, or failure semantics must run `make prepush-full`.
- Reliability, retry, progress, resume, or failure-surfacing stories must also run `make test-hardening` and `make test-chaos`.
- Performance-sensitive stories that add grouping, ranking, or broader scenario coverage must run `make test-perf`.
- Public docs, CLI help, markdown reports, and templates must stay explicit about Wrkr's claim boundary: what was found, what can write, what should be reviewed first, and what proof artifacts were produced.
- Wave ordering is dependency-driven. Contract/runtime correctness ships before later docs polish, OSS trust wording, and broader CISO-friendly summaries.

## Current Baseline (Observed)

- Preconditions validated:
  - `product/dev_guides.md` exists and is readable
  - `product/architecture_guides.md` exists and is readable
  - output path resolves inside `/Users/tr/wrkr`
  - repository worktree was clean before the plan rewrite
- Required repo gates already exist and are enforceable:
  - `make prepush`
  - `make prepush-full`
  - `make test-risk-lane`
  - `make test-hardening`
  - `make test-chaos`
  - `make test-perf`
  - `scripts/run_v1_acceptance.sh --mode=local`
- `docs/commands/scan.md` and `docs/commands/report.md` already treat `action_paths`, `action_path_to_control_first`, delivery-chain metadata, ownership metadata, execution-identity metadata, and `recommended_action` as public machine-readable surfaces.
- `core/risk/action_paths.go` already emits govern-first projections, but `actionPathID` currently hashes only `agent_id`, `org`, first repo, location, and `recommended_action`, which leaves duplicate/collision risk when repeated privilege-map entries differ on omitted dimensions.
- `core/report/types.go` and `core/report/build.go` already expose `ActionPaths`, `ActionPathToControlFirst`, and `Activation`, but the summary remains finding-first through `TopRisks` and section ordering instead of prospect-offer-first.
- `core/cli/scan_progress.go` buffers progress lines in memory and only writes them on `Flush()`, so long org scans do not look live while the scan is still running.
- `core/detect/parse.go` already provides error-bearing helpers, but priority detectors still rely on `FileExists`, `DirExists`, or direct `os.ReadFile`, so permission/stat failures are not surfaced consistently.
- Existing scenario and contract coverage gives a strong starting harness:
  - `internal/scenarios/action_path_to_control_first_scenario_test.go`
  - `internal/scenarios/delivery_chain_correlation_scenario_test.go`
  - `internal/scenarios/approval_gap_modeling_scenario_test.go`
  - `internal/scenarios/ownership_quality_scenario_test.go`
  - `internal/scenarios/identity_to_action_path_scenario_test.go`
  - `internal/scenarios/nonhuman_identity_inventory_scenario_test.go`
  - `internal/scenarios/permission_failure_surfacing_scenario_test.go`
  - `testinfra/contracts/story1_contracts_test.go`
  - `core/cli/report_contract_test.go`
- Current scan docs only advertise `--profile baseline|standard|strict`; there is no bounded assessment-specific profile or report mode today.
- User-provided real-scan feedback shows the remaining offer gap clearly:
  - duplicate `action_paths` rows weaken trust
  - top summaries are still dominated by generic `secret_presence` findings
  - many paths collapse to `recommended_action=approval`
  - sample/test/vendor noise overwhelms govern-first output on real repos
  - top paths often land on fallback ownership or `execution_identity_status=unknown`

## Exit Criteria

1. `action_paths` are unique and deterministic for a given scan input: `len(action_paths) == len(unique(path_id))`, `path_id` repeat-runs are byte-stable, and duplicate privilege-map inputs do not emit duplicate action rows.
2. When AI action paths are present, top scan/report/readout surfaces lead with those paths before generic `secret_presence` findings, while raw findings remain available unchanged.
3. `recommended_action` deterministically spans all four values (`inventory|approval|proof|control`) across scenario fixtures, and top-ranked paths land in the expected class.
4. `wrkr scan --profile assessment --json` sharpens govern-first output for sample-heavy, test-heavy, vendored, and generated-noise repos without mutating raw findings, proof chains, or exit codes.
5. Hosted/org scans emit progress, retry, cooldown, resume, and completion lines to stderr during execution rather than only at completion.
6. Permission and stat failures from priority detectors surface in JSON and explain-mode as incomplete-visibility signals instead of silent omission.
7. Customer-facing report/readout layers lead with governable path counts, write-capable path counts, production-target-backed path counts, top path to control first, top identity-backed path, and proof artifact location.
8. Ownership weakness and non-human identity weakness are first-class surfaces: `ownerless_exposure`, `identity_exposure_summary`, `identity_to_review_first`, and `identity_to_revoke_first` are additive, deterministic, and contract-tested.
9. `action_paths[*]` expose richer semantics (`business_state_surface`, shared-identity / standing-privilege heuristics), and `exposure_groups` collapse repetitive path rows without removing raw `action_paths`.
10. README, command docs, templates, and generated summaries never imply runtime provenance, live observation, or enforcement, and those wording guarantees are enforced by docs/template contracts.
11. Real-world scenario packs and report-usefulness contracts stay green in CI and fail whenever AI-path-present output regresses back to generic finding-first readouts.

## Public API and Contract Map

Stable/public surfaces today:

- `wrkr scan --json`
- `wrkr report --json`
- `wrkr report --md`
- `wrkr report --pdf`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- Public scan/report JSON keys already documented for:
  - `findings`
  - `ranked_findings`
  - `top_findings`
  - `attack_paths`
  - `top_attack_paths`
  - `action_paths`
  - `action_path_to_control_first`
  - `activation`
  - `inventory`
  - `profile`
- `recommended_action` stays a stable enum surface.
- Hosted/org progress stays an operator-only stderr side channel when `--json` is set. Stdout JSON and `--json-path` must remain byte-identical.

Planned additive surfaces in this plan:

- `scan --profile assessment`
- report/summary additive `assessment_summary` for path-centric customer readouts
- additive report/summary fields:
  - `identity_exposure_summary`
  - `identity_to_review_first`
  - `identity_to_revoke_first`
  - `ownerless_exposure`
  - `exposure_groups`
- additive `action_paths[*]` fields:
  - `business_state_surface`
  - `shared_execution_identity`
  - `standing_privilege`

Internal implementation surfaces expected to change:

- `core/aggregate/inventory/*`
- `core/aggregate/privilegebudget/*`
- `core/cli/scan.go`
- `core/cli/scan_progress.go`
- `core/detect/*`
- `core/owners/*`
- `core/report/*`
- `core/risk/*`
- `internal/scenarios/*`
- `testinfra/contracts/*`

Shim and deprecation path:

- `attack_paths`, `top_attack_paths`, `findings`, `ranked_findings`, and `top_findings` remain available; no removal or rename is allowed in this plan.
- Existing `baseline|standard|strict` profile semantics remain unchanged. `assessment` is additive.
- Existing report templates remain valid. Assessment-specific summary facts are additive within the current report pipeline; if a dedicated template alias becomes necessary later, it must be additive rather than a replacement.
- `path_id` remains opaque. Downstream consumers must not parse business meaning from it.

Schema and versioning policy:

- No proof-record type changes in this plan. `scan_finding` and `risk_assessment` remain the proof primitives.
- JSON and markdown/pdf report additions must be additive only.
- No exit-code changes are allowed.
- Raw findings remain unchanged under the new bounded assessment mode; only govern-first ranking/projection layers may narrow.
- Any fixture or golden that pins exact `path_id` values must be updated together with the uniqueness hardening change.

Machine-readable error expectations:

- Permission/stat failures must emit visible parse/detector errors and incomplete-visibility hints in JSON / explain output.
- Ambiguous high-risk conditions fail closed; Wrkr must not invent ownership, execution identity, or production-write claims when evidence is missing.
- Noise suppression under `assessment` must never hide raw evidence; it only narrows customer-facing prioritization surfaces.

## Docs and OSS Readiness Baseline

README first-screen contract:

- Lead with the first-offer promise: bounded AI-connected software-delivery action paths, risky ones first, offline-verifiable proof, and what to control first.
- Keep first-screen examples evaluator-safe and org-scan-safe.
- Preserve the existing local/offline fallback story.
- Do not lead with runtime provenance, live observation, or enforcement claims.

Integration-first docs flow:

- Evaluator quickstart after this plan lands:
  - `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile assessment --json`
  - `wrkr report --state ./.wrkr/last-scan.json --md --md-path ./.tmp/assessment.md --template operator --json`
  - `wrkr evidence --frameworks eu-ai-act,soc2 --state ./.wrkr/last-scan.json --output ./.tmp/evidence --json`
  - `wrkr verify --chain --state ./.wrkr/last-scan.json --json`
- Security-team org flow after this plan lands:
  - `wrkr scan --github-org <org> --github-api https://api.github.com --profile assessment --json --json-path ./.wrkr/scan.json`
  - `wrkr report --state ./.wrkr/last-scan.json --md --md-path ./.wrkr/assessment.md --template operator --json`
- `wrkr report` remains a saved-state renderer. It does not become a live observation surface.

Lifecycle path model:

- The assessment narrative is still static and file-based:
  - discovery
  - privilege and delivery-path correlation
  - govern-first ranking
  - offline proof generation
  - deterministic review recommendations
- No story in this plan may change that model into runtime observation or enforcement.

Docs source-of-truth mapping:

- Product promise: `product/wrkr.md`
- First-screen operator copy: `README.md`
- Scan contract and examples: `docs/commands/scan.md`
- Report contract and examples: `docs/commands/report.md`
- Operator/customer flow: `docs/examples/security-team.md`, `docs/examples/operator-playbooks.md`
- Static trust boundary: `README.md`, `docs/commands/scan.md`, `docs/commands/report.md`

OSS trust baseline:

- `CHANGELOG.md` must be updated for every story marked `Changelog impact: required`.
- Public behavior changes that affect command help, report wording, or support expectations must keep `CONTRIBUTING.md` and `SECURITY.md` aligned when applicable.
- No story may weaken the repo's deterministic/offline-first trust posture.

## Recommendation Traceability

| # | Recommendation | Strategic direction / moat | Story IDs |
|---|---|---|---|
| 1 | Fix duplicate `action_paths` | Contract correctness and trust in govern-first output | `FO-01`, `FO-14` |
| 2 | Make output path-first, not finding-first | Customer-ready prioritization around risky AI paths | `FO-04`, `FO-15` |
| 3 | Make `recommended_action` useful | Decision-ready next steps instead of blunt approval-only output | `FO-05` |
| 4 | Add a bounded assessment profile | Sharper customer readout without losing raw evidence | `FO-06`, `FO-14` |
| 5 | Add an AI-first report mode for scans | First-offer packaging for customer readouts | `FO-07`, `FO-08` |
| 6 | Make org-scan progress actually live | Operator trust and usability on long org scans | `FO-02` |
| 7 | Normalize stat/permission-failure surfacing | Honest completeness signaling when visibility is partial | `FO-03` |
| 8 | Improve ownership quality in govern-first surfaces | Clearer control targets and stronger governance story | `FO-09` |
| 9 | Improve execution-identity usefulness | Actor-centric actionability on top risky paths | `FO-10` |
| 10 | Add `identity_exposure_summary` | Cleaner non-human identity wedge for CISOs | `FO-10` |
| 11 | Add `identity_to_review_first` / `identity_to_revoke_first` | Concrete actor review and revocation priorities | `FO-11` |
| 12 | Add `shared_execution_identity` / `standing_privilege` heuristics | Strong durable-risk storyline for reused identities | `FO-11` |
| 13 | Add `ownerless_exposure` headline metrics | Explicit top-line ownership pain statement | `FO-09` |
| 14 | Add `business_state_surface` classification | Differentiate code change from real-system change | `FO-12` |
| 15 | Add clustered `exposure_groups` | Collapse repetitive path rows into executive-ready groupings | `FO-13` |
| 16 | Add real-world noise scenarios | Keep the product sharp on realistic repos, not only synthetic fixtures | `FO-14` |
| 17 | Add report-usefulness contracts | GTM/readout quality becomes a test gate, not a hope | `FO-04`, `FO-15` |
| 18 | Keep claim boundaries explicit in reports and docs | Preserve trust by staying inside Wrkr's static-proof boundary | `FO-08` |

## Test Matrix Wiring

| Lane | Purpose | Commands / Evidence |
|---|---|---|
| Fast lane | Author feedback and required PR quick signal | `make lint-fast`; targeted `go test ... -count=1`; `make build` |
| Core CI lane | Full contract, CLI, architecture, and failure-semantic gate | `make prepush`; `make prepush-full` for risk/CLI/architecture/failure changes |
| Acceptance lane | Outside-in scenarios, contracts, and evaluator scorecard | `make test-contracts`; `make test-scenarios`; `scripts/run_v1_acceptance.sh --mode=local` |
| Cross-platform lane | Windows and cross-platform CLI safety | required `windows-smoke` workflow plus any targeted Go tests that must stay Windows-safe |
| Risk lane | Ranking, profile, ownership, identity, and report hardening | `make test-risk-lane`; targeted scenario/contract/golden updates |

Merge and release gating rule:

- Required PR checks remain exactly `fast-lane` and `windows-smoke`.
- Stories marked with `Core CI lane: required` must not merge unless `make prepush-full` passes locally and the equivalent CI lanes are green.
- Stories marked with `Risk lane: required` must also pass `make test-risk-lane`.
- Docs/CLI/report wording stories must pass `make test-docs-consistency` and `make test-docs-storyline`.
- No story may merge with failing scenario, contract, or docs parity tests.

## Epic WRKR-FO-EPIC-1: Contract Correctness and Operator Trust Foundation

Objective: make the govern-first substrate believable before re-ranking or packaging it. This epic fixes duplicate paths, makes org progress live, and ensures incomplete detector visibility is surfaced honestly.

### Story FO-01: Deduplicate action paths and harden path identity
Priority: P0
Tasks:
- Dedupe privilege-budget-to-action-path projection so repeated findings for the same govern-first path emit exactly one action row.
- Expand `actionPathID` inputs to include the identity dimensions needed to avoid collisions while keeping the output opaque and deterministic.
- Keep `action_path_to_control_first` selection tied to the deduped action-path set.
- Freeze a deterministic agent-ecosystem-subset regression fixture so the duplicate-path bug is testable without live network dependency.
Repo paths:
- `core/aggregate/privilegebudget/budget.go`
- `core/risk/action_paths.go`
- `core/risk/action_paths_test.go`
- `internal/scenarios`
- `scenarios/wrkr`
- `testinfra/contracts`
Run commands:
- `go test ./core/aggregate/privilegebudget ./core/risk -count=1`
- `go test ./testinfra/contracts -count=1`
- `go test ./internal/scenarios -run 'TestActionPathToControlFirstScenario|TestDeliveryChainCorrelationScenario' -count=1 -tags=scenario`
- `make prepush-full`
Test requirements:
- contract assertion that `len(action_paths) == len(unique(path_id))`
- repeated-finding fixture that previously emitted duplicate rows
- byte-stable repeat-run assertion for deduped `path_id`
- frozen real-world regression fixture based on the scanned agent-ecosystem subset
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- repeated findings for the same govern-first path yield one `action_paths` row and one unique `path_id`
- `action_path_to_control_first.path.path_id` always references a row present in `action_paths`
- no raw findings, proof records, or inventory rows are deleted to achieve dedupe
- repeat runs against the same fixture produce identical `path_id` values and ordering
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Deduplicated govern-first `action_paths` so each deterministic action path emits one unique `path_id` row per scan.
Semver marker override: none
Contract/API impact: `action_paths[*].path_id` remains an opaque hex string; exact hash inputs change to improve uniqueness and determinism.
Versioning/migration impact: No schema version bump; update contract goldens or fixtures that pin exact `path_id` values.
Architecture constraints:
- keep dedupe logic at the privilege-budget/action-path projection boundary
- preserve raw findings, inventory, and proof emission unchanged
- deterministic ordering must remain explicit after dedupe
ADR required: no
TDD first failing test(s):
- `core/risk/action_paths_test.go`: duplicate privilege-map entries still emit one path
- `testinfra/contracts`: `action_paths` unique `path_id` invariant
Cost/perf impact: low
Chaos/failure hypothesis: If mixed repo scans emit repeated or partially-correlated privilege-map entries, Wrkr must collapse them deterministically into one govern-first path instead of duplicating customer-visible action rows.

### Story FO-02: Stream org-scan progress to stderr during execution
Priority: P0
Tasks:
- Replace buffered progress accumulation with immediate event emission to stderr.
- Emit repo discovery, materialization, retry, cooldown, resume, and completion lines as the scan advances.
- Preserve `--json` stdout contract and `--json-path` byte identity while progress streams live on stderr.
- Add tests that prove progress is observable before command completion.
Repo paths:
- `core/cli/scan_progress.go`
- `core/cli/scan.go`
- `core/cli/scan_progress_test.go`
- `core/cli/scan_resume_test.go`
Run commands:
- `go test ./core/cli -run 'TestScanProgress|TestScanResume' -count=1`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- progress tests that assert lines appear before command completion
- retry/cooldown/resume tests that keep stdout JSON clean
- cancellation and interrupted-run coverage for org resume
- smoke path for multi-repo org/path scans
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- org-scan progress lines appear on stderr while the command is still executing
- stdout remains reserved for final JSON when `--json` is enabled
- `--quiet` still suppresses progress lines
- retry, cooldown, resume, and completion events remain deterministic and parseable
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Org scans now stream deterministic progress events to stderr during execution while preserving stdout JSON contracts.
Semver marker override: none
Contract/API impact: stderr progress becomes truly live; stdout JSON and `--json-path` contracts remain unchanged.
Versioning/migration impact: No schema migration.
Architecture constraints:
- keep progress emission as thin CLI orchestration
- do not leak scan state mutation into report/risk layers
- cancellation and timeout behavior must propagate without buffering surprises
ADR required: no
TDD first failing test(s):
- `core/cli/scan_progress_test.go`: progress lines visible before completion
- `core/cli/scan_resume_test.go`: resume emits live progress without corrupting JSON
Cost/perf impact: low
Chaos/failure hypothesis: Under retries, cooldowns, resume, and cancellation, Wrkr must keep operator progress live on stderr and never contaminate stdout JSON or deadlock on buffered output.

### Story FO-03: Normalize stat and permission failure surfacing across priority detectors
Priority: P0
Tasks:
- Replace remaining bool-only existence checks and direct `os.ReadFile` paths in priority detectors with error-bearing helper calls where scan completeness matters.
- Standardize detector behavior so permission denied, unsafe path, and stat failures surface as parse/detector errors instead of silent absence.
- Add explain-mode messaging for incomplete visibility when detector access failed.
- Keep secret values scrubbed and fail closed for unsafe root-escaping paths.
Repo paths:
- `core/detect/parse.go`
- `core/detect/agentframework/detector.go`
- `core/detect/agentcustom/detector.go`
- `core/detect/ciagent/detector.go`
- `core/detect/compiledaction/detector.go`
- `core/detect/workstation/detector.go`
- `internal/scenarios/permission_failure_surfacing_scenario_test.go`
Run commands:
- `go test ./core/detect/... -count=1`
- `go test ./internal/scenarios -run 'TestPermissionFailureSurfacingScenario' -count=1 -tags=scenario`
- `go test ./core/cli -run 'TestScanPartialErrors' -count=1`
- `make prepush-full`
Test requirements:
- permission-denied fixtures producing visible parse/detector errors in JSON
- explain-mode messaging that calls out incomplete visibility
- unsafe-path regression tests for root-escaping symlinked files
- deterministic failure-shape assertions across priority detectors
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- the listed priority detectors surface permission/stat failures through parse or detector errors rather than silently dropping evidence
- explain-mode mentions incomplete visibility when relevant
- secret values remain scrubbed even when read attempts fail
- unsafe or root-escaping paths still fail closed
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Priority detectors now surface permission and stat failures consistently in scan output so incomplete visibility is explicit.
Semver marker override: none
Contract/API impact: additive incomplete-visibility errors and warnings become more consistent; no exit-code changes.
Versioning/migration impact: No schema migration; contract goldens update for additive error details.
Architecture constraints:
- centralize file-read semantics in `core/detect/parse.go`
- keep detector packages focused on structured parsing, not bespoke filesystem policy
- preserve fail-closed unsafe-path handling
ADR required: no
TDD first failing test(s):
- `internal/scenarios/permission_failure_surfacing_scenario_test.go`: permission-denied paths are visible in JSON
- detector unit tests for parse-error propagation from helper APIs
Cost/perf impact: low
Chaos/failure hypothesis: If filesystem access is partially denied during a scan, Wrkr must say visibility is incomplete instead of pretending the repo was clean.

## Epic WRKR-FO-EPIC-2: Govern-First Prioritization and Bounded Assessment

Objective: move the customer-visible output from generic finding-first security summaries to bounded AI action-path prioritization without mutating raw evidence.

### Story FO-04: Make ranking and activation path-first when AI action paths exist
Priority: P1
Tasks:
- Re-rank report and scan summary surfaces so `action_paths` and `action_path_to_control_first` lead when govern-first paths exist.
- Downrank generic workflow secret findings unless they directly support a top AI action path.
- Keep `findings`, `ranked_findings`, and `top_findings` available unchanged for operators and automation.
- Add report-usefulness assertions that fail when AI-path-present scenarios still lead with generic `secret_presence`.
Repo paths:
- `core/risk/risk.go`
- `core/report/build.go`
- `core/report/activation.go`
- `core/report/report_test.go`
- `core/cli/report_contract_test.go`
- `testinfra/contracts`
- `internal/scenarios`
Run commands:
- `go test ./core/risk ./core/report ./core/cli -count=1`
- `go test ./testinfra/contracts -count=1`
- `go test ./internal/scenarios -run 'TestActionPathToControlFirstScenario|TestDeliveryChainCorrelationScenario' -count=1 -tags=scenario`
- `make test-risk-lane`
Test requirements:
- report contracts where AI paths exist and top summary lines reference them before generic `secret_presence`
- scenario fixtures proving AI-path-first ranking
- stable ordering tests for equal-score path cases
- usefulness contracts that fail on secret-dominated summaries when AI paths are present
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- customer-visible summary ordering leads with govern-first paths whenever they exist
- generic secret findings remain present but no longer dominate top summary/readout layers without path linkage
- `action_path_to_control_first` is aligned with the top-ranked govern-first path story
- tie-breaking remains deterministic
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Scan and report summaries now prioritize govern-first AI action paths ahead of generic supporting findings when risky paths are present.
Semver marker override: none
Contract/API impact: ranking and summary emphasis change; raw finding surfaces remain available and unchanged.
Versioning/migration impact: No schema migration; contract goldens update for deterministic ranking order changes.
Architecture constraints:
- keep ranking logic in `core/risk` and summary projection in `core/report`
- do not mutate raw findings to achieve customer-ready ordering
- keep tie-break rules explicit and testable
ADR required: no
TDD first failing test(s):
- `core/report/report_test.go`: top summary lines lead with AI paths when present
- `testinfra/contracts`: AI-path-present scenarios fail if top content is generic secret-first
Cost/perf impact: low
Chaos/failure hypothesis: When both AI paths and generic support findings are present, Wrkr must still surface the govern-first path first instead of reverting to noisy generic headlines.
Dependencies:
- `FO-01`

### Story FO-05: Make `recommended_action` a real decision surface
Priority: P1
Tasks:
- Rework `recommended_action` derivation so `inventory`, `approval`, `proof`, and `control` are all meaningfully reachable.
- Base the decision on write capability, delivery-chain status, deployment status, ownership quality, credential access, approval-gap type, and execution-identity confidence.
- Keep the enum stable while improving deterministic class boundaries.
- Add fixtures that explicitly exercise all four recommendation classes.
Repo paths:
- `core/risk/action_paths.go`
- `core/risk/action_paths_test.go`
- `internal/scenarios`
- `testinfra/contracts`
Run commands:
- `go test ./core/risk -count=1`
- `go test ./internal/scenarios -run 'TestApprovalGapModelingScenario|TestDeliveryChainCorrelationScenario|TestIdentityToActionPathScenario' -count=1 -tags=scenario`
- `go test ./testinfra/contracts -count=1`
- `make test-risk-lane`
Test requirements:
- scenario fixtures that deterministically produce all four recommendation classes
- contract tests on `action_paths[*].recommended_action`
- stable priority-order tests across equal-risk paths
- rationale coverage for approval-gap type and identity confidence
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- all four `recommended_action` values are reachable in deterministic fixtures
- top risky paths no longer collapse to `approval` by default
- the recommendation reflects delivery-chain, production, identity, and ownership context
- public enum values remain unchanged
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Govern-first `recommended_action` output now differentiates inventory, approval, proof, and control based on path context instead of collapsing most paths to approval.
Semver marker override: none
Contract/API impact: stable enum, changed classification logic.
Versioning/migration impact: No schema migration; update contract and scenario goldens for new class distribution.
Architecture constraints:
- keep recommendation derivation deterministic and local to `core/risk/action_paths.go`
- do not leak report wording rules into risk classification
- preserve stable enum values
ADR required: no
TDD first failing test(s):
- `core/risk/action_paths_test.go`: four deterministic recommendation classes
- scenario tests covering each class and the correct priority ordering
Cost/perf impact: low
Chaos/failure hypothesis: If ownership or identity evidence is weak, Wrkr must still choose the right next action deterministically instead of collapsing the path into a generic approval bucket.
Dependencies:
- `FO-01`

### Story FO-06: Add additive `assessment` profile for bounded customer scans
Priority: P1
Tasks:
- Add `assessment` as an additive scan profile with deterministic weighting/filter behavior for govern-first surfaces.
- Downweight or exclude `examples/`, `tests/`, `.venv/`, generated/vendor-like paths, and non-production-like sample content from `activation`, `action_paths`, and top report/readout layers only.
- Keep raw findings, inventory evidence, proof records, and explain output intact.
- Make the same bounded profile available to report building via saved scan state.
Repo paths:
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/cli/scan.go`
- `core/risk/action_paths.go`
- `core/report/build.go`
- `docs/commands/scan.md`
- `internal/scenarios`
- `testinfra/contracts`
Run commands:
- `go test ./core/aggregate/... ./core/risk ./core/report ./core/cli -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./testinfra/contracts -count=1`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make prepush-full`
Test requirements:
- scenario fixtures for sample-heavy, test-heavy, and vendored noise repos
- comparison tests proving govern-first output sharpens while raw findings remain unchanged
- CLI help/usage tests for the additive profile
- contract tests for saved-state report behavior under `profile=assessment`
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- `scan --profile assessment` is accepted and documented
- bounded assessment suppresses noise only in govern-first surfaces, not in raw findings or proof data
- saved-state report output respects the bounded profile
- deterministic output remains stable across repeat runs
Changelog impact: required
Changelog section: Added
Draft changelog entry: Added an `assessment` scan profile that sharpens govern-first action-path output for customer readouts while keeping raw findings and proof artifacts unchanged.
Semver marker override: [semver:minor]
Contract/API impact: additive new profile value; existing profile semantics remain unchanged.
Versioning/migration impact: No schema migration; CLI docs/help and profile contract tests must be updated in the same change.
Architecture constraints:
- isolate noise classification in aggregation/risk projection helpers
- keep scan CLI orchestration thin
- do not let the profile mutate proof emission or raw finding collection
ADR required: no
TDD first failing test(s):
- CLI contract test for `--profile assessment`
- scenario comparison test proving raw findings stability with sharper govern-first surfaces
Cost/perf impact: medium
Chaos/failure hypothesis: In sample-heavy or vendored repos, Wrkr must narrow customer-readout noise without losing the underlying evidence operators still need.
Dependencies:
- `FO-01`
- `FO-04`
- `FO-05`

## Epic WRKR-FO-EPIC-3: Customer-Ready Assessment Report and Claim Boundary

Objective: turn the improved govern-first substrate into a customer-facing readout that says what matters first, what to control first, and nothing beyond Wrkr's static-proof boundary.

### Story FO-07: Add AI-first assessment summary to report output
Priority: P1
Tasks:
- Add an additive `assessment_summary` block and markdown/template rendering that lead with governable AI path count, write-capable path count, production-target-backed path count, top path to govern first, top execution-identity-backed path, and offline proof artifact path.
- Make the operator report read path-centric for customer scans while keeping existing report templates valid.
- Ensure `action_paths`, `action_path_to_control_first`, and assessment headline facts are aligned.
- Add comparison fixtures against the existing operator report using the agent-ecosystem subset regression fixture.
Repo paths:
- `core/report/build.go`
- `core/report/types.go`
- `core/report/templates`
- `core/report/render_markdown.go`
- `core/cli/report.go`
- `docs/commands/report.md`
- `internal/scenarios`
- `testinfra/contracts`
Run commands:
- `go test ./core/report ./core/cli -count=1`
- `go test ./testinfra/contracts -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `make test-docs-consistency`
- `make prepush-full`
Test requirements:
- contract tests for additive `assessment_summary`
- markdown/template golden updates for AI-first readouts
- comparison tests against current operator report using the frozen agent-ecosystem subset
- JSON stability tests proving existing fields still exist
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- assessment-oriented reports lead with path-centric counts and top control recommendation
- `assessment_summary` is additive and deterministic
- proof artifact path is surfaced without implying live observation
- existing report consumers still receive prior fields unchanged
Changelog impact: required
Changelog section: Added
Draft changelog entry: Added an AI-first assessment summary to report output so customer readouts lead with governable paths, top control targets, and offline proof location.
Semver marker override: [semver:minor]
Contract/API impact: additive report summary fields and template content; existing keys remain.
Versioning/migration impact: No schema migration; markdown/PDF goldens and report docs update in the same change.
Architecture constraints:
- keep render-neutral summary construction in `core/report/build.go`
- templates render precomputed facts instead of recomputing ranking logic
- preserve deterministic markdown and PDF generation
ADR required: no
TDD first failing test(s):
- `core/report/report_test.go`: `assessment_summary` is present and path-centric
- `core/cli/report_contract_test.go`: top-level report payload keeps prior fields and adds the new summary block
Cost/perf impact: low
Chaos/failure hypothesis: If path data is present but some identity or proof metadata is missing, the assessment summary must degrade honestly without reverting to generic finding-first wording.
Dependencies:
- `FO-04`
- `FO-05`
- `FO-06`

### Story FO-08: Lock report and docs wording to Wrkr's static posture boundary
Priority: P1
Tasks:
- Audit report summary wording, templates, README, and scan/report command docs for drift into runtime provenance, live observation, or control-layer enforcement claims.
- Update operator/customer readout language so it says what Wrkr found, what can write, what should be reviewed first, and what proof artifacts were generated.
- Add wording contracts and docs consistency checks that fail if templates or docs overclaim.
- Keep the first-offer story explicit in README and command docs.
Repo paths:
- `core/report/build.go`
- `core/report/templates`
- `README.md`
- `docs/commands/report.md`
- `docs/commands/scan.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `testinfra/contracts`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `go test ./core/report ./core/cli ./testinfra/contracts -count=1`
- `make prepush-full`
Test requirements:
- wording contracts for templates and summaries
- docs parity and storyline checks
- README first-screen checks for bounded first-offer promise
- report/template tests that reject runtime observation or enforcement language
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: not required
Acceptance criteria:
- no touched doc, template, or generated summary implies runtime `what actually happened`
- no touched surface implies selective gating or enforcement
- README and command docs clearly state the bounded assessment promise
- docs and templates stay aligned with actual runtime behavior
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Clarified scan and report wording so Wrkr's customer-facing output stays explicitly scoped to static posture, risky paths, and offline-verifiable proof.
Semver marker override: none
Contract/API impact: wording-only on public docs/template surfaces; no schema change.
Versioning/migration impact: No migration.
Architecture constraints:
- treat docs and templates as executable contract surfaces
- keep wording enforcement close to docs/template tests rather than ad hoc review
- do not change runtime semantics to fit copy
ADR required: no
TDD first failing test(s):
- docs/template contract that fails on banned runtime or enforcement wording
- README first-screen contract test for bounded first-offer promise
Cost/perf impact: low
Chaos/failure hypothesis: If future copy drifts into runtime or enforcement claims, docs/template contracts must fail before merge rather than rely on manual review.
Dependencies:
- `FO-07`

## Epic WRKR-FO-EPIC-4: Ownership and Identity Action Targets

Objective: make the top risky paths answer the natural buyer question: who owns this, which non-human identity backs it, and what actor should we review or revoke first.

### Story FO-09: Elevate ownership quality and ownerless exposure in govern-first surfaces
Priority: P2
Tasks:
- Use `owner_source` and `ownership_status` directly in ranking and summary wording.
- Add additive `ownerless_exposure` summary counts for explicit owner, inferred owner, unresolved owner, and multi-repo conflict owner.
- Prefer `needs owner clarification` messaging when ownership is weak instead of silently accepting fallback owners.
- Ensure ownership weakness can raise a path in govern-first prioritization.
Repo paths:
- `core/owners/owners.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/report/build.go`
- `core/report/activation.go`
- `internal/scenarios/ownership_quality_scenario_test.go`
- `testinfra/contracts`
Run commands:
- `go test ./core/owners ./core/aggregate/inventory ./core/aggregate/privilegebudget ./core/report -count=1`
- `go test ./internal/scenarios -run 'TestOwnershipQualityScenario' -count=1 -tags=scenario`
- `go test ./testinfra/contracts -count=1`
- `make test-risk-lane`
Test requirements:
- fixtures with explicit, inferred, unresolved, and multi-repo-conflict ownership
- report assertions that ownership quality changes wording and priority
- contract tests for additive `ownerless_exposure`
- stable ordering tests when ownership quality is the differentiator
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- top govern-first surfaces clearly distinguish explicit, inferred, unresolved, and conflicting ownership
- unresolved ownership can elevate a risky path and produces `needs owner clarification` messaging
- `ownerless_exposure` is additive and deterministic
- fallback ownership is no longer treated as equally strong as explicit ownership
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Govern-first summaries now highlight ownership quality and ownerless exposure so unresolved or conflicting ownership is explicit in top action paths.
Semver marker override: none
Contract/API impact: additive ownership summary fields and ranking emphasis.
Versioning/migration impact: No schema migration; update report and contract goldens for new ownership wording and counts.
Architecture constraints:
- keep ownership resolution authoritative in `core/owners`
- use aggregation/risk layers for ranking, not ad hoc report-only overrides
- do not fabricate strong ownership from weak evidence
ADR required: no
TDD first failing test(s):
- `internal/scenarios/ownership_quality_scenario_test.go`: weak ownership changes wording and priority
- contract test for `ownerless_exposure` summary counts
Cost/perf impact: low
Chaos/failure hypothesis: If CODEOWNERS or repo provenance are ambiguous, Wrkr must say ownership is weak and prioritize clarification instead of inventing confidence.
Dependencies:
- `FO-04`
- `FO-06`

### Story FO-10: Improve execution-identity correlation and add `identity_exposure_summary`
Priority: P2
Tasks:
- Tighten static matching between workflow-backed non-human identity evidence and top action paths using repo, workflow, and location context.
- Reduce avoidable `execution_identity_status=unknown` while preserving honest ambiguity when correlation is insufficient.
- Add additive `identity_exposure_summary` counts for total non-human identities observed, identities backing write-capable paths, identities backing deploy-capable paths, identities with unresolved ownership, and identities with unknown execution correlation.
- Surface the summary in report/readout layers next to govern-first path output.
Repo paths:
- `core/detect/nonhumanidentity/detector.go`
- `core/risk/action_paths.go`
- `core/report/build.go`
- `core/report/types.go`
- `core/aggregate/inventory/inventory.go`
- `internal/scenarios/identity_to_action_path_scenario_test.go`
- `internal/scenarios/nonhuman_identity_inventory_scenario_test.go`
- `testinfra/contracts`
Run commands:
- `go test ./core/detect/nonhumanidentity ./core/risk ./core/report ./core/aggregate/inventory -count=1`
- `go test ./internal/scenarios -run 'TestIdentityToActionPathScenario|TestNonHumanIdentityInventoryScenario' -count=1 -tags=scenario`
- `go test ./testinfra/contracts -count=1`
- `make test-risk-lane`
Test requirements:
- fixtures where GitHub App, bot, or service-account evidence maps to top-ranked paths
- report/state contracts for `identity_exposure_summary`
- additive execution-identity field assertions on top govern-first paths
- stable ambiguity tests when correlation is still insufficient
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- top risky paths resolve more non-human identities when evidence exists
- `execution_identity_status=unknown` remains only when correlation is genuinely ambiguous
- `identity_exposure_summary` is additive and deterministic
- report/readout layers surface identity-backed path counts and weak-correlation counts
Changelog impact: required
Changelog section: Added
Draft changelog entry: Added identity exposure summaries and improved correlation between top govern-first paths and non-human execution identities.
Semver marker override: [semver:minor]
Contract/API impact: additive summary fields and improved execution-identity correlation on existing path objects.
Versioning/migration impact: No schema migration; update path/report contract goldens for additive identity fields.
Architecture constraints:
- keep identity evidence collection in detection/inventory layers
- keep final path correlation deterministic in `core/risk`
- preserve ambiguous outcomes instead of overfitting weak matches
ADR required: no
TDD first failing test(s):
- `internal/scenarios/identity_to_action_path_scenario_test.go`: path maps to the right identity when evidence exists
- contract test for `identity_exposure_summary`
Cost/perf impact: medium
Chaos/failure hypothesis: If workflow identity evidence is partial or ambiguous, Wrkr must reduce avoidable unknowns without inventing false positive identity matches.
Dependencies:
- `FO-05`
- `FO-07`

### Story FO-11: Rank identities to review or revoke first and flag standing privilege reuse
Priority: P2
Tasks:
- Add deterministic ranking logic for `identity_to_review_first` and `identity_to_revoke_first`.
- Score identities by write-capable path count, deploy/db/admin path count, unknown-to-security count, unresolved ownership, and ambiguous execution correlation.
- Add `shared_execution_identity` and `standing_privilege` heuristics for identities reused across repos, workflows, or risky paths.
- Surface those identity-first actions in report/readout layers without removing raw path detail.
Repo paths:
- `core/risk`
- `core/detect/nonhumanidentity/detector.go`
- `core/report/build.go`
- `core/report/types.go`
- `internal/scenarios`
- `testinfra/contracts`
Run commands:
- `go test ./core/risk ./core/detect/nonhumanidentity ./core/report -count=1`
- `go test ./internal/scenarios -run 'TestIdentityToActionPathScenario|TestNonHumanIdentityInventoryScenario' -count=1 -tags=scenario`
- `go test ./testinfra/contracts -count=1`
- `make test-risk-lane`
Test requirements:
- scenarios where one identity clearly ranks above others for review or revocation
- stable ordering tests for equal-score ties
- fixtures where one bot/app/service account spans multiple risky repos or paths
- summary/report assertions for shared-identity exposure flags
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- report/readout layers expose deterministic `identity_to_review_first` and `identity_to_revoke_first`
- reused high-risk identities are flagged with additive shared/standing-privilege heuristics
- tie-breaking is stable and documented
- raw `action_paths` remain available for drill-down
Changelog impact: required
Changelog section: Added
Draft changelog entry: Added identity-first review and revoke recommendations plus shared-identity standing-privilege signals for reused risky execution identities.
Semver marker override: [semver:minor]
Contract/API impact: additive identity-first action targets and heuristics.
Versioning/migration impact: No schema migration; update report and contract goldens for additive identity ranking fields.
Architecture constraints:
- keep identity ranking logic inside `core/risk`
- do not duplicate path ranking logic in report templates
- heuristic flags must be evidence-backed and deterministic
ADR required: no
TDD first failing test(s):
- risk/report test proving one identity ranks first for review/revocation
- stable tie-order test for equal-score identities
Cost/perf impact: medium
Chaos/failure hypothesis: When one non-human identity quietly backs too many risky paths, Wrkr must say so deterministically instead of burying that exposure in individual path rows.
Dependencies:
- `FO-10`

## Epic WRKR-FO-EPIC-5: Better Path Semantics and Grouped Exposures

Objective: make path output say what kind of state can change and collapse repetitive rows into higher-level exposure groups that are easier to review with customers.

### Story FO-12: Add `business_state_surface` classification to action paths
Priority: P2
Tasks:
- Classify action paths by the kind of state they can change: `code`, `deploy`, `db`, `ticketing`, `admin_api`, `saas_write`, `workflow_control`.
- Extend workflow capability and MCP-derived evidence only as needed to support those classes deterministically.
- Add the field to `action_paths` and make it usable in report/readout wording.
- Keep classification explainable and tied to concrete static evidence.
Repo paths:
- `core/risk/action_paths.go`
- `core/detect/workflowcap/analyze.go`
- `core/detect/mcp/detector.go`
- `core/risk/action_paths_test.go`
- `internal/scenarios`
- `testinfra/contracts`
Run commands:
- `go test ./core/detect/workflowcap ./core/detect/mcp ./core/risk -count=1`
- `go test ./internal/scenarios -run 'TestWorkflowCapabilitiesScenario' -count=1 -tags=scenario`
- `go test ./testinfra/contracts -count=1`
- `make test-risk-lane`
Test requirements:
- fixture coverage for each classified surface
- report assertions surfacing non-code state changes clearly
- additive contract tests for `business_state_surface`
- stable precedence tests when a path qualifies for multiple surfaces
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- each requested surface class is emitted by at least one deterministic fixture
- action paths clearly distinguish code-only paths from deploy/db/admin/ticketing/SaaS-write paths
- classification remains additive and explainable
- precedence is stable when multiple signals are present
Changelog impact: required
Changelog section: Added
Draft changelog entry: Action paths now classify the business state they can change so deploy, database, admin, and other non-code write paths are explicit.
Semver marker override: [semver:minor]
Contract/API impact: additive `business_state_surface` field on action paths.
Versioning/migration impact: No schema migration; contract goldens update for additive path field.
Architecture constraints:
- keep surface classification in risk logic using detector-provided evidence
- avoid regex-only or report-only inference
- preserve explainability from capability evidence to final class
ADR required: no
TDD first failing test(s):
- `core/risk/action_paths_test.go`: each business-state surface class is reachable
- scenario test for non-code state changes in top report output
Cost/perf impact: medium
Chaos/failure hypothesis: If a path can modify non-code business state, Wrkr must classify that deterministically instead of leaving customer messaging stuck at generic write access.
Dependencies:
- `FO-05`

### Story FO-13: Add grouped `exposure_groups` on top of raw action paths
Priority: P2
Tasks:
- Add deterministic grouping logic that clusters repetitive `action_paths` by repo, framework/tool, execution identity, delivery-chain status, and business-state surface.
- Expose grouped objects as additive `exposure_groups` without removing raw `action_paths`.
- Make report output able to summarize grouped exposures before drilling into path rows.
- Keep ordering and group IDs stable for equal-input runs.
Repo paths:
- `core/risk`
- `core/report/build.go`
- `core/report/types.go`
- `core/cli/report.go`
- `internal/scenarios`
- `testinfra/contracts`
Run commands:
- `go test ./core/risk ./core/report ./core/cli -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./testinfra/contracts -count=1`
- `make prepush-full`
- `make test-perf`
Test requirements:
- scenario outputs showing repetitive paths collapsed into stable groups
- additive contract tests for `exposure_groups`
- stable group-ordering tests for equal-score ties
- perf checks ensuring grouping does not regress large org scans materially
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- repetitive path rows collapse into stable `exposure_groups`
- raw `action_paths` remain unchanged and available for detail
- group ordering is deterministic
- grouping overhead stays inside accepted perf budgets
Changelog impact: required
Changelog section: Added
Draft changelog entry: Added grouped exposure summaries on top of raw action paths so repeated risky paths can be reviewed as stable clusters.
Semver marker override: [semver:minor]
Contract/API impact: additive `exposure_groups` surface in report/readout payloads.
Versioning/migration impact: No schema migration; contract and report goldens update for additive group objects.
Architecture constraints:
- grouping logic belongs in `core/risk`, not templates
- raw path detail stays authoritative
- ordering and group identity must be explicit and deterministic
ADR required: no
TDD first failing test(s):
- risk/report test proving repetitive paths collapse into one stable exposure group
- perf regression test for grouping on larger fixture sets
Cost/perf impact: medium
Chaos/failure hypothesis: If many similar risky paths exist across a repo or identity, Wrkr must summarize them into stable groups without hiding the underlying evidence.
Dependencies:
- `FO-12`

## Epic WRKR-FO-EPIC-6: Real-World Regression Harness

Objective: turn the first-offer quality bar into executable evidence so realistic noise, duplicate paths, and weak summaries fail automatically before release.

### Story FO-14: Add real-world first-offer scenario packs
Priority: P2
Tasks:
- Create scenario packs for sample-heavy repos, test-heavy repos, vendored `.venv` noise, mixed MCP plus workflows plus agents, mixed ownership quality, and duplicated-path regressions.
- Freeze any real-world-inspired subset used for regression into deterministic repo-local fixtures or snapshot state.
- Wire new scenarios into the coverage map and acceptance harness.
- Use these scenarios as the baseline for `assessment` profile and dedupe correctness checks.
Repo paths:
- `scenarios/wrkr`
- `internal/scenarios`
- `internal/scenarios/coverage_map.json`
- `testinfra/contracts`
Run commands:
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./testinfra/contracts -count=1`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make test-perf`
Test requirements:
- scenario CLI goldens for each new pack
- coverage-map updates for new scenario intent
- deterministic snapshot fixtures for real-world-inspired subsets
- comparison coverage for standard vs assessment profile outputs
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- all requested real-world noise and duplication classes have deterministic scenario coverage
- no scenario depends on live network state
- scenario goldens clearly show the first-offer sharpened govern-first outputs
- coverage map and validation scripts stay green
Changelog impact: not required
Changelog section: none
Semver marker override: none
Architecture constraints:
- scenarios remain outside-in fixtures, not implementation-specific unit tests
- frozen subsets must preserve determinism and repo portability
- scenario packs should reflect customer reality without widening product scope
ADR required: no
TDD first failing test(s):
- new scenario contracts for sample-heavy, test-heavy, vendored, mixed-identity, and duplicate-path cases
- coverage map assertions for the new scenario packs
Cost/perf impact: medium
Chaos/failure hypothesis: If realistic repos contain lots of sample, test, or vendor noise, the scenario harness must catch any regression that reintroduces noisy govern-first output.
Dependencies:
- `FO-01`
- `FO-06`

### Story FO-15: Add report-usefulness contracts for AI-path-first output
Priority: P2
Tasks:
- Add contract tests that fail when top report lines are dominated by generic workflow secret findings while AI action paths are present.
- Add golden report outputs for AI-path-present scenarios and assert `action_path_to_control_first` points at the expected govern-first path.
- Wire usefulness assertions through `core/cli`, `core/report`, and `testinfra/contracts`.
- Keep the check focused on prioritization quality, not on brittle prose matching alone.
Repo paths:
- `testinfra/contracts`
- `core/cli`
- `core/report`
- `internal/scenarios`
- `docs/commands/report.md`
Run commands:
- `go test ./testinfra/contracts ./core/cli ./core/report -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make test-docs-consistency`
- `make prepush-full`
Test requirements:
- golden report outputs for AI-path-present scenarios
- assertions on top summary content and `action_path_to_control_first`
- contract tests that reject secret-dominated summaries when AI paths exist
- docs/report checks ensuring examples stay aligned with the sharpened output
Matrix wiring:
- Fast lane: required
- Core CI lane: required
- Acceptance lane: required
- Cross-platform lane: required
- Risk lane: required
Acceptance criteria:
- usefulness contracts fail when AI-path-present output regresses to generic finding-first summaries
- `action_path_to_control_first` stays aligned with report headline facts
- report goldens are stable and deterministic
- docs examples reflect the same prioritization order the runtime emits
Changelog impact: not required
Changelog section: none
Semver marker override: none
Architecture constraints:
- usefulness checks should validate structured report facts first and prose second
- keep contracts deterministic and resilient to incidental copy edits
- do not hide regressions behind overly broad golden updates
ADR required: no
TDD first failing test(s):
- contract test that fails when AI paths exist but generic secret findings lead the report
- golden test for `action_path_to_control_first` alignment
Cost/perf impact: low
Chaos/failure hypothesis: If later ranking or report changes drift back toward noisy generic findings, usefulness contracts must fail before customer output regresses.
Dependencies:
- `FO-04`
- `FO-07`
- `FO-14`

## Minimum-Now Sequence

Wave 1: contract correctness and live operator trust

- `FO-01` Deduplicate action paths and harden path identity
- `FO-02` Stream org-scan progress to stderr during execution
- `FO-03` Normalize stat and permission failure surfacing across priority detectors

Wave 2: govern-first prioritization and bounded customer assessment

- `FO-04` Make ranking and activation path-first when AI action paths exist
- `FO-05` Make `recommended_action` a real decision surface
- `FO-06` Add additive `assessment` profile for bounded customer scans

Wave 3: customer-facing readout and claim boundary lock

- `FO-07` Add AI-first assessment summary to report output
- `FO-08` Lock report and docs wording to Wrkr's static posture boundary

Wave 4: ownership and identity actionability

- `FO-09` Elevate ownership quality and ownerless exposure in govern-first surfaces
- `FO-10` Improve execution-identity correlation and add `identity_exposure_summary`
- `FO-11` Rank identities to review or revoke first and flag standing privilege reuse

Wave 5: better path semantics and grouped exposure review

- `FO-12` Add `business_state_surface` classification to action paths
- `FO-13` Add grouped `exposure_groups` on top of raw action paths

Wave 6: regression lock-in for realistic customer output

- `FO-14` Add real-world first-offer scenario packs
- `FO-15` Add report-usefulness contracts for AI-path-first output

Minimum-now first-offer ship point:

- After Waves 1 through 3 are green, Wrkr is aligned to the shortest-path first offer from the recommendation set:
  - deduped paths
  - live-feeling org UX
  - honest partial-visibility surfacing
  - path-first prioritization
  - meaningful `recommended_action`
  - bounded assessment profile
  - AI-first readout with claim boundaries locked

Broader CISO-strengthening work:

- Waves 4 through 6 deepen ownership, identity, business-state, grouping, and regression hardness without widening Wrkr into runtime provenance or enforcement.

## Explicit Non-Goals

- Runtime provenance, live action observation, or claims about what actually happened
- Selective gating, approval enforcement, or control-layer execution
- Any LLM or remote inference in scan, risk, or proof paths
- Mutation of raw findings to achieve customer-ready summaries
- Removal or renaming of existing `findings`, `attack_paths`, or `action_paths` surfaces
- Dashboard-first, managed-service-first, or browser-only scope
- Package/server vulnerability scanning beyond Wrkr's existing static posture role
- Unpinned or live-network-dependent regression fixtures in CI

## Definition of Done

- Every recommendation in the input set maps to at least one implemented story and a green acceptance signal.
- All stories preserve deterministic, offline-first, fail-closed behavior and keep proof-record contracts intact.
- Every story marked `Changelog impact: required` lands with `CHANGELOG.md` updated under `## [Unreleased]`.
- CLI/help/docs/report wording changes ship in the same PR as runtime changes.
- `make prepush-full` is green for architecture/risk/CLI/failure-semantic stories.
- `make test-risk-lane` is green for ranking, profile, ownership, identity, grouping, and report usefulness stories.
- `make test-docs-consistency` and `make test-docs-storyline` are green for docs/template/report wording stories.
- Acceptance and scenario goldens prove:
  - unique deterministic `action_paths`
  - AI-path-first summaries
  - useful `recommended_action`
  - bounded `assessment` profile noise suppression with raw findings unchanged
  - explicit ownership and identity weakness
  - stable grouped exposure semantics
- README, docs, and generated reports stay inside Wrkr's static-posture and offline-proof claim boundary.
- Merge-required checks remain `fast-lane` and `windows-smoke`, and no story merges with broken contract, scenario, docs, or cross-platform signals.

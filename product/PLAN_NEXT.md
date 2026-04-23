# PLAN NEXT: OSS Launch Activation, Evaluator Framing, And Audit Handoff

Date: 2026-04-23

Source of truth:
- User-provided post-audit recommendations captured on 2026-04-23.
- `AGENTS.md`.
- `product/wrkr.md`.
- `product/dev_guides.md`.
- `product/architecture_guides.md`.

Scope:
- Wrkr only.
- Planning only. No implementation is included in this plan.
- Convert the audit recommendations into an execution-ready backlog focused on first-run activation, evaluator-safe launch framing, and a clearer buyer/GRC handoff path.
- Preserve deterministic, offline-first, fail-closed, file-based behavior and existing exit-code classes.

## Global Decisions (Locked)

- No P0 or P1 release blocker was identified by the audit. This plan addresses the highest-leverage launch risks that remain after a technically green baseline.
- Preserve Wrkr’s product boundary: static discovery, posture, proof, verification, and regress only. No runtime enforcement, dashboard-first scope, or hosted control-plane dependency is introduced here.
- Preserve deterministic and offline-first defaults. Any onboarding improvement must guide operators toward explicit commands; it must not auto-select a target, mutate config unexpectedly, or create hidden network dependencies.
- Preserve exit-code stability and machine-readable error taxonomy in `core/cli/root.go`. Any CLI change in this plan is additive guidance only unless explicitly called out.
- Favor additive contract changes over new commands. Reuse `scan`, `init`, `report`, `evidence`, and `verify` before introducing new top-level surfaces.
- Treat docs as executable contract. Any CLI/help/JSON change in this plan must ship with doc updates in the same PR and pass docs parity/storyline checks.
- Follow red-green-refactor for all runtime and contract stories. Every story below names the first failing test(s).
- Contract/runtime stories land before launch-copy and onboarding-copy stories. Later docs waves must not describe fields or flows that earlier waves have not shipped.
- Use `--json` in all command examples that are part of the contract or automation story.
- Keep OSS trust surfaces aligned. `README.md`, `docs/`, and `CHANGELOG.md` move together when the user-visible launch story changes.

## Current Baseline (Observed)

- Wrkr’s shipped model is coherent and implemented: deterministic static discovery, ranked posture/risk, proof artifacts, explicit verification, and regress gating, with runtime enforcement clearly out of scope.
- The audit found no release-blocking runtime or security defect. `go build -o /tmp/wrkr-audit-bin ./cmd/wrkr` and `go test ./... -count=1` both passed during the audit run.
- Clean-machine onboarding is still colder than it should be. On a machine with no config, `HOME=/tmp/wrkr-empty-home /tmp/wrkr-audit-bin scan --json` returned exit `6` with `error.code=invalid_input` and message `no target provided and no usable config default target`.
- Hosted org posture is already the recommended first path in launch copy, but it requires explicit GitHub API and token setup.
- The evaluator-safe scenario does work end to end, but it intentionally looks risky:
  - `scan --path ./scenarios/wrkr/scan-mixed-org/repos --json` produced `131` findings, `19` tools, `19` agents, one warning, and posture score `56.74` with grade `F`.
  - `evidence --frameworks eu-ai-act,soc2 --json` returned `eu-ai-act=33.33` and `soc2=0` with the correct `coverage_note` that this is an evidence gap rather than unsupported framework parsing.
  - `verify --chain --json` returned `chain.intact=true`.
- `wrkr report` already exposes strong downstream handoff surfaces:
  - templates `audit`, `ciso`, `appsec`, `platform`, and `customer-draft`
  - Markdown/PDF/evidence JSON/CSV backlog artifact paths
  - saved-state, static-only posture language
- Buyer/GRC value exists today, but it is distributed across command docs and examples rather than promoted as a first-class operator-to-auditor lane.
- The docs already contain the correct “low coverage means evidence gap” concept, but the explanation is not front-loaded enough in the first-screen launch story.

## Exit Criteria

- A clean-machine `wrkr scan --json` failure with no target remains fail-closed and exit-stable (`6`, `invalid_input`) but now returns deterministic next-step guidance for:
  - hosted org setup via `wrkr init`
  - evaluator-safe `--path` scanning
  - developer-machine `--my-setup`
- `wrkr --help` and `wrkr scan --help` show the same three first-value paths with copy-pasteable examples.
- `wrkr report --json` and `wrkr evidence --json` provide additive deterministic handoff guidance that helps operators produce buyer/GRC-ready artifact sets without inventing new runtime behavior.
- README, quickstart, FAQ, positioning, security-team docs, operator playbooks, and integration checklist all align on:
  - hosted-org-first when prerequisites are ready
  - evaluator-safe fallback when they are not
  - `--my-setup` as secondary developer hygiene
  - risky evaluator outputs being expected and useful
  - low/zero first-run coverage being evidence-state gaps, not unsupported framework parsing
- Launch-facing docs promote the buyer/GRC handoff lane using the existing `report`, `evidence`, and `verify` surfaces.
- All stories below have passing lane coverage, updated changelog intent, and no contract drift between docs and runtime.

## Public API and Contract Map

Stable public surfaces to preserve:
- CLI commands: `init`, `scan`, `report`, `evidence`, `verify`, `regress`.
- Exit-code contract in `core/cli/root.go`.
- Stable `--json` error envelope shape rooted at `error.code`, `error.message`, and `error.exit_code`.
- Stable `report --json` and `evidence --json` success envelopes and existing keys such as `artifact_paths`, `framework_coverage`, and `coverage_note`.
- Published docs surfaces:
  - `README.md`
  - `docs/examples/quickstart.md`
  - `docs/examples/security-team.md`
  - `docs/examples/operator-playbooks.md`
  - `docs/commands/`
  - `docs/positioning.md`
  - `docs/faq.md`
  - `docs/integration_checklist.md`

Planned additive contract changes:
- `wrkr scan --json` missing-target failure may add additive guidance fields under the existing error envelope, led by `error.next_steps[]`.
- `wrkr report --json` may add additive top-level `next_steps[]` for operator-to-auditor handoff sequencing.
- `wrkr evidence --json` may add additive top-level `next_steps[]` for bundle handoff and proof verification sequencing.
- Human help/usage output for `wrkr` and `wrkr scan` may add or reorder examples, but existing command names, flags, and exit codes remain stable.

Internal surfaces likely touched:
- `core/cli/root.go`
- `core/cli/scan.go`
- `core/cli/init.go`
- `core/cli/report.go`
- `core/cli/evidence.go`
- `core/cli/`
- `internal/e2e/cli_contract/`
- `internal/acceptance/`
- `docs/`
- `README.md`
- `CHANGELOG.md`

Shim/deprecation path:
- No shim is required. The plan relies on additive guidance fields and docs alignment only.
- No command is deprecated.
- No exit code or existing JSON key is removed.

Schema/versioning policy:
- Additive-only JSON evolution. No schema-major change is planned.
- Existing automation that ignores unknown JSON fields remains compatible.
- Docs/examples must state that new guidance fields are advisory and do not replace code-based branching on exit class or stable required keys.

Machine-readable error expectations:
- Missing-target `scan --json` remains exit `6`, `error.code=invalid_input`, with additive guidance only.
- Hosted dependency gaps remain exit `7`, `error.code=dependency_missing`; this plan must not blur that distinction.
- `report --json` and `evidence --json` remain exit `0` on success; any additive `next_steps[]` must not imply runtime observation or control-layer enforcement.
- `coverage_note` remains the canonical machine-readable explanation of low/zero evidence coverage.

## Docs and OSS Readiness Baseline

- README first-screen contract must answer:
  - what Wrkr is
  - who it is for
  - where it sits in the See -> Prove -> Control sequence
  - what the three first-value entry points are
- Integration-first docs flow for this plan:
  - hosted org posture: `init -> scan -> report -> evidence -> verify -> regress`
  - evaluator-safe fallback: `scan --path -> report -> evidence -> verify -> regress`
  - developer hygiene: `scan --my-setup -> mcp-list -> inventory diff`
- Lifecycle path model remains canonical in `docs/state_lifecycle.md`. This plan does not change lifecycle semantics; it only needs cross-links to keep onboarding and handoff guidance grounded in the same artifact model.
- Docs source of truth for this scope:
  - `README.md`
  - `docs/README.md`
  - `docs/examples/quickstart.md`
  - `docs/examples/security-team.md`
  - `docs/examples/operator-playbooks.md`
  - `docs/commands/scan.md`
  - `docs/commands/init.md`
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/failure_taxonomy_exit_codes.md`
  - `docs/positioning.md`
  - `docs/faq.md`
  - `docs/integration_checklist.md`
  - `docs/state_lifecycle.md`
  - `CHANGELOG.md`
- OSS trust baseline files to verify when touched:
  - `README.md`
  - `CHANGELOG.md`
  - `SECURITY.md` only if operator-facing safety promises need wording changes
- `docs-site/` is not in scope for this minimum-now plan unless repo docs prove insufficient during implementation review.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Planned stories |
|---|---|---|---|---|---|
| R1 | Make the clean-machine first run more welcoming without weakening fail-closed behavior | The current `scan --json` no-target failure is accurate but not self-guiding | Turn missing-target failure into explicit operator guidance, not implicit behavior | Faster self-serve activation, lower evaluator drop-off, clearer PLG entry path | W1-S1, W2-S1 |
| R2 | Reframe the evaluator-safe scenario so risky outputs read as proof of detection rather than product immaturity | The shipped sample path intentionally yields high-risk posture and sparse coverage | Front-load explanation of “risky by design” and “coverage is evidence-state” in launch copy | Stronger first impression, lower messaging confusion, better demo repeatability | W2-S1 |
| R3 | Make the buyer/GRC handoff lane easier to discover and execute using existing artifacts | Artifact quality is already strong, but the path is runner-led and fragmented | Promote report/evidence/verify as a deliberate handoff flow before adding new surfaces | Better conversion from operator output to buyer-readable proof packets | W1-S2, W2-S2 |

## Test Matrix Wiring

Fast lane:
- `make lint-fast`
- Targeted package tests for touched CLI/runtime packages
- `scripts/check_docs_cli_parity.sh` for CLI/help/command-doc changes
- `scripts/check_docs_consistency.sh` for doc-surface changes

Core CI lane:
- `make prepush`
- `go test ./internal/e2e/cli_contract -count=1`
- `go test ./testinfra/contracts -count=1`
- `scripts/check_docs_storyline.sh`
- `scripts/run_docs_smoke.sh`

Acceptance lane:
- `scripts/run_v1_acceptance.sh --mode=local` when report/evidence/user-flow output changes
- `go test ./internal/acceptance -count=1` when templates, artifacts, or launch-facing flows change materially
- `go test ./internal/scenarios -count=1 -tags=scenario` when scenario-backed onboarding or expectation language depends on scenario outputs

Cross-platform lane:
- Preserve `windows-smoke`
- No story in this plan may introduce OS-specific onboarding behavior
- If example paths require shell-specific handling, docs must keep POSIX examples copy-pasteable and avoid Windows-hostile assumptions in contract text

Risk lane:
- `make test-contracts` for all additive JSON/help/CLI contract changes
- `make prepush-full` only if implementation expands beyond additive guidance into failure semantics, boundary changes, or new network/default behavior
- `make test-hardening` and `make test-chaos` are not expected for this plan unless a story grows into state, filesystem, retry, or fail-closed policy behavior

Merge/release gating rule:
- Wave 1 must merge before Wave 2 docs that depend on new runtime guidance fields.
- No story is done until its changelog intent, doc updates, and matrix lanes are green together.
- If implementation scope grows from additive guidance into failure-mode changes, promote the story to the full risk lane before merge.

## Wave 1: Contract-Safe Activation And Handoff

### Epic W1-E1: Zero-Config First-Run Guidance

Objective:
- Make Wrkr’s first failure on a clean machine self-serve and deterministic, without weakening explicit-target requirements or changing exit taxonomy.

### Story W1-S1: Add Deterministic Missing-Target Next Steps To `scan`

Priority:
- P1

First value outcome:
- A new user who runs `wrkr scan --json` without setup gets actionable next steps instead of a dead-end error.

Time-to-value target:
- Under 2 minutes from first failed command to one successful follow-up command.

Activation signal:
- User reruns one of the suggested commands successfully after receiving the missing-target error.

Repeat usage signal:
- User returns to a config-backed hosted scan or reruns the evaluator-safe path with saved-state artifacts.

Expansion path:
- Individual evaluator -> team operator -> org posture flow.

Friction removed:
- The user no longer has to infer the correct first command from scattered docs after the first failure.

Tasks:
- Define one deterministic, copy-pasteable next-step set for the missing-target case:
  - hosted org setup via `wrkr init --non-interactive --org ... --github-api ... --json`
  - evaluator-safe fallback via `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
  - developer-machine hygiene via `wrkr scan --my-setup --json`
- Add additive `error.next_steps[]` guidance to the existing missing-target `scan --json` envelope without changing `error.code`, `error.message`, or `error.exit_code`.
- Align `wrkr --help` and `wrkr scan --help` examples with the same three entry points.
- Update command and failure-taxonomy docs so automation guidance and human help stay consistent.

Repo paths:
- `core/cli/scan.go`
- `core/cli/root.go`
- `core/cli/root_test.go`
- `core/cli/jsonmode_test.go`
- `core/cli/scan_contract_fix_test.go`
- `docs/commands/scan.md`
- `docs/commands/init.md`
- `docs/failure_taxonomy_exit_codes.md`
- `docs/faq.md`
- `CHANGELOG.md`

Run commands:
- `HOME="$(mktemp -d)" go run ./cmd/wrkr scan --json`
- `go run ./cmd/wrkr --help`
- `go run ./cmd/wrkr scan --help`
- `go test ./core/cli ./cmd/wrkr -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `go test ./testinfra/contracts -count=1`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `make prepush`

Test requirements:
- Help/usage tests for root and `scan`.
- `--json` stability tests for the missing-target error envelope.
- Exit-code contract tests proving the error remains exit `6`.
- Machine-readable error-envelope tests that validate additive `error.next_steps[]`.
- Docs parity tests for changed command docs and help output.

Matrix wiring:
- Fast lane: `go test ./core/cli ./cmd/wrkr -count=1`, `scripts/check_docs_cli_parity.sh`.
- Core CI lane: `make prepush`, `go test ./internal/e2e/cli_contract -count=1`, `go test ./testinfra/contracts -count=1`.
- Acceptance lane: `go test ./internal/scenarios -count=1 -tags=scenario` only if scenario command examples or expected-first-output guidance changes materially.
- Cross-platform lane: preserve `windows-smoke`; no shell-only contract wording.
- Risk lane: `make test-contracts`; escalate to `make prepush-full` only if failure semantics change beyond additive guidance.

Acceptance criteria:
- `wrkr scan --json` with no target and no config still exits `6` with `error.code=invalid_input`.
- The same response now includes deterministic `error.next_steps[]` entries for hosted org, evaluator-safe, and `--my-setup`.
- `wrkr --help` and `wrkr scan --help` surface the same three first-value entry points.
- The command does not mutate config, state, or network behavior as part of the guidance change.

Changelog impact: required

Changelog section: Changed

Draft changelog entry: Improved the no-target `wrkr scan` experience with deterministic next-step guidance for hosted org setup, evaluator-safe fallback scanning, and local-machine hygiene while preserving existing exit codes.

Semver marker override: none

Contract/API impact:
- Additive `error.next_steps[]` guidance for one existing `scan --json` invalid-input class plus updated human help examples.

Versioning/migration impact:
- No schema version bump. Existing consumers remain compatible if they ignore unknown fields.

Architecture constraints:
- Keep orchestration thin in `core/cli`.
- Do not infer or auto-select scan targets.
- Preserve explicit side-effect semantics and fail-closed behavior.
- Keep guidance strings deterministic and local; no network lookups or environment probing beyond what already exists.

ADR required: yes

TDD first failing test(s):
- `TestScanNoTargetJSONIncludesNextSteps`
- `TestRootHelpShowsHostedEvaluatorAndMySetupPaths`

Cost/perf impact: low

Chaos/failure hypothesis:
- If guidance generation fails or config is absent, Wrkr must still return the existing invalid-input failure class and must not partially emit success-like output or mutate any artifact.

### Epic W1-E2: Artifact-Led Audit Handoff Guidance

Objective:
- Make the operator-to-buyer/GRC handoff easier to discover by promoting existing report/evidence/verify artifacts in machine-readable and doc-guided flows.

### Story W1-S2: Add Additive Handoff Guidance To `report` And `evidence`

Priority:
- P2

First value outcome:
- An operator who already has saved scan state can immediately tell which artifact sequence to generate and hand off.

Time-to-value target:
- Under 5 minutes from saved scan state to a buyer/GRC-ready artifact packet.

Activation signal:
- User generates report/evidence artifacts and follows the suggested verify/handoff sequence.

Repeat usage signal:
- The same operator reuses the handoff flow in CI or during repeat scans.

Expansion path:
- Individual operator artifact generation -> team review packet -> buyer/GRC handoff.

Friction removed:
- The user no longer has to reconstruct the handoff lane from separate report, evidence, and verify docs.

Tasks:
- Add additive top-level `next_steps[]` to `wrkr report --json` and `wrkr evidence --json` that point users toward the existing handoff sequence.
- Ensure the guidance references existing artifact outputs only:
  - report templates and artifact paths
  - evidence bundle output
  - `wrkr verify --chain --json`
- Keep the change additive; do not introduce a new command or runtime dependency.
- Update report/evidence command docs and operator-facing examples to use the same sequence.

Repo paths:
- `core/cli/report.go`
- `core/cli/evidence.go`
- `core/cli/report_contract_test.go`
- `core/cli/jsonmode_test.go`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `docs/integration_checklist.md`
- `CHANGELOG.md`

Run commands:
- `go run ./cmd/wrkr report --template audit --md --md-path ./.tmp/audit-summary.md --pdf --pdf-path ./.tmp/audit-summary.pdf --evidence-json --evidence-json-path ./.tmp/report-evidence.json --csv-backlog --csv-backlog-path ./.tmp/control-backlog.csv --state ./.wrkr/last-scan.json --json`
- `go run ./cmd/wrkr evidence --frameworks eu-ai-act,soc2 --state ./.wrkr/last-scan.json --output ./.tmp/evidence --json`
- `go run ./cmd/wrkr verify --chain --state ./.wrkr/last-scan.json --json`
- `go test ./core/cli ./core/report ./core/evidence -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `go test ./internal/acceptance -count=1`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `make prepush`

Test requirements:
- `--json` stability tests for additive `next_steps[]` in `report` and `evidence`.
- Contract tests proving existing keys and exit codes remain unchanged.
- Acceptance coverage for report/evidence artifact flows when new guidance references those artifacts.
- Docs parity tests for updated command docs and example flows.

Matrix wiring:
- Fast lane: `go test ./core/cli ./core/report ./core/evidence -count=1`, `scripts/check_docs_cli_parity.sh`.
- Core CI lane: `make prepush`, `go test ./internal/e2e/cli_contract -count=1`, `go test ./testinfra/contracts -count=1`.
- Acceptance lane: `scripts/run_v1_acceptance.sh --mode=local`, `go test ./internal/acceptance -count=1`.
- Cross-platform lane: preserve `windows-smoke`; artifact guidance must remain platform-neutral.
- Risk lane: `make test-contracts`; promote to `make prepush-full` only if implementation changes success/failure semantics instead of adding guidance.

Acceptance criteria:
- `wrkr report --json` includes deterministic `next_steps[]` that point to the current handoff sequence and reference generated artifact paths where applicable.
- `wrkr evidence --json` includes deterministic `next_steps[]` that point to `verify --chain` and downstream handoff steps.
- Existing JSON keys such as `artifact_paths`, `framework_coverage`, and `coverage_note` remain stable.
- Updated security-team and operator playbook docs use the same artifact-led sequence.

Changelog impact: required

Changelog section: Changed

Draft changelog entry: Added deterministic handoff guidance to `wrkr report --json` and `wrkr evidence --json` so operators can move from saved scan state to buyer- and audit-ready artifacts more directly.

Semver marker override: none

Contract/API impact:
- Additive top-level `next_steps[]` for successful `report --json` and `evidence --json` responses.

Versioning/migration impact:
- No schema version bump. Existing consumers remain compatible if they ignore unknown fields.

Architecture constraints:
- Keep CLI wrappers thin and reuse existing report/evidence outputs.
- Do not introduce a new orchestration command or cloud dependency.
- Keep guidance purely additive and deterministic.
- Do not imply runtime observation or control-layer behavior in success guidance text.

ADR required: yes

TDD first failing test(s):
- `TestReportJSONIncludesDeterministicNextSteps`
- `TestEvidenceJSONIncludesVerifyNextSteps`

Cost/perf impact: low

Chaos/failure hypothesis:
- Guidance generation must never mask a real report/evidence failure or emit handoff instructions for artifacts that were not actually produced.

## Wave 2: Launch Storyline And OSS Readiness

### Epic W2-E1: Evaluator-Safe Narrative Alignment

Objective:
- Make the public launch copy explain why the evaluator-safe path looks risky and why low first-run coverage is expected, so the first-run story feels intentional rather than confusing.

### Story W2-S1: Reframe README, Quickstart, Positioning, And FAQ Around The Three Entry Paths

Priority:
- P2

First value outcome:
- A new evaluator understands which path to run first and how to interpret the first results before leaving the first-screen docs.

Time-to-value target:
- Under 3 minutes from landing on README or quickstart to selecting the correct first path.

Activation signal:
- User chooses one of the documented entry paths without needing external clarification.

Repeat usage signal:
- User returns from evaluator-safe flow to hosted org posture after prerequisites are configured.

Expansion path:
- README/quickstart evaluator -> hosted org runner -> CI and audit workflows.

Friction removed:
- The user no longer has to infer that the scenario is intentionally risky or that low coverage is an evidence-state signal.

Tasks:
- Rewrite README first-screen copy to distinguish clearly between:
  - hosted org posture
  - evaluator-safe `--path` fallback
  - `--my-setup` developer hygiene
- Front-load the explanation that the shipped evaluator-safe repo-set is intentionally risky and demonstrates detection/ranking rather than “good posture.”
- Move the “low/zero first-run coverage means evidence gap” explanation earlier in the quickstart and FAQ journey.
- Keep wording aligned with product scope: static posture only, no runtime enforcement, no dashboard-first claim.

Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/positioning.md`
- `docs/faq.md`
- `docs/README.md`
- `CHANGELOG.md`

Run commands:
- `go run ./cmd/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
- `go run ./cmd/wrkr evidence --frameworks eu-ai-act,soc2 --state ./.wrkr/last-scan.json --json`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
- `make prepush`

Test requirements:
- Docs consistency checks.
- Storyline/smoke checks for onboarding flow changes.
- README first-screen checks for what/who/integration/quickstart clarity.
- Docs source-of-truth mapping checks because multiple onboarding docs change together.

Matrix wiring:
- Fast lane: `scripts/check_docs_consistency.sh`.
- Core CI lane: `make prepush`, `scripts/check_docs_storyline.sh`, `scripts/run_docs_smoke.sh`.
- Acceptance lane: not required by default; add `go test ./internal/scenarios -count=1 -tags=scenario` if scenario-backed claims or expected-output wording need fixture verification.
- Cross-platform lane: preserve `windows-smoke`; avoid shell-specific first-screen examples that are not portable.
- Risk lane: not required unless implementation spills into CLI contract behavior.

Acceptance criteria:
- README first-screen explicitly answers which users should start with hosted org, evaluator-safe `--path`, and `--my-setup`.
- Quickstart and FAQ explain that the evaluator-safe sample is risky by design and that low/zero coverage is an evidence gap.
- Positioning continues to state that Wrkr is static posture, not runtime control.
- Docs storyline and smoke checks pass.

Changelog impact: required

Changelog section: Changed

Draft changelog entry: Clarified the public launch docs to distinguish hosted org posture from evaluator-safe and local-machine fallback paths and to explain risky sample outputs and low first-run evidence coverage more directly.

Semver marker override: none

Contract/API impact:
- No runtime contract change. User-facing docs and examples only.

Architecture constraints:
- Preserve product boundary language from `product/wrkr.md`.
- Keep onboarding guidance self-serve and deterministic.
- Do not introduce dashboard-first, runtime-observation, or hosted-control-plane claims.

ADR required: no

TDD first failing test(s):
- `scripts/check_docs_storyline.sh`
- `scripts/run_docs_smoke.sh`

Cost/perf impact: low

Chaos/failure hypothesis:
- N/A for docs-only scope; primary failure mode is docs drift, which must be caught by docs consistency/storyline/smoke gates.

### Epic W2-E2: Buyer/GRC Playbooks And Integration-First Docs

Objective:
- Promote the existing artifact-led handoff lane so operators can move from technical scan state to buyer/GRC-ready packets without guesswork or new product scope.

### Story W2-S2: Align Security-Team, Operator, And Integration Docs On The Audit Handoff Flow

Priority:
- P2

First value outcome:
- An operator can follow one documented flow from scan state to an artifact packet suitable for buyer, GRC, or audit review.

Time-to-value target:
- Under 10 minutes from saved scan state to generated audit/ciso/customer-ready artifacts.

Activation signal:
- User generates report, evidence, and verify outputs using the documented handoff flow.

Repeat usage signal:
- The flow is reused in CI, launch demos, and repeated customer-style reviews.

Expansion path:
- Security/platform runner -> internal stakeholder review -> buyer/GRC handoff -> CI adoption.

Friction removed:
- Handoff no longer depends on piecing together commands from separate command reference pages.

Tasks:
- Promote one copy-pasteable artifact-led handoff flow across:
  - `docs/examples/security-team.md`
  - `docs/examples/operator-playbooks.md`
  - `docs/integration_checklist.md`
- Explicitly show the buyer/GRC-ready artifact set:
  - audit or ciso Markdown/PDF
  - evidence JSON and/or bundle
  - CSV backlog when appropriate
  - proof-chain verification
- Clarify what the operator runs versus what the buyer/GRC consumer reads.
- Keep the story integration-first and CLI-led; do not introduce new dashboards or parallel docs taxonomies.

Repo paths:
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `docs/integration_checklist.md`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `docs/README.md`
- `CHANGELOG.md`

Run commands:
- `go run ./cmd/wrkr report --template ciso --md --md-path ./.tmp/ciso.md --pdf --pdf-path ./.tmp/ciso.pdf --evidence-json --evidence-json-path ./.tmp/report-evidence.json --csv-backlog --csv-backlog-path ./.tmp/control-backlog.csv --state ./.wrkr/last-scan.json --json`
- `go run ./cmd/wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.tmp/evidence --json`
- `go run ./cmd/wrkr verify --chain --state ./.wrkr/last-scan.json --json`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
- `scripts/run_v1_acceptance.sh --mode=local`
- `go test ./internal/acceptance -count=1`
- `make prepush`

Test requirements:
- Docs consistency and storyline checks.
- Docs smoke for updated example flows.
- Acceptance validation when report artifact examples or handoff packet expectations change materially.
- Integration-before-internals guidance checks for updated CI/adoption docs.

Matrix wiring:
- Fast lane: `scripts/check_docs_consistency.sh`.
- Core CI lane: `make prepush`, `scripts/check_docs_storyline.sh`, `scripts/run_docs_smoke.sh`.
- Acceptance lane: `scripts/run_v1_acceptance.sh --mode=local`, `go test ./internal/acceptance -count=1` when report packet examples or templates are updated materially.
- Cross-platform lane: preserve `windows-smoke`; keep artifact paths and command examples platform-neutral.
- Risk lane: not required unless implementation changes CLI contracts beyond the additive guidance already planned in Wave 1.

Acceptance criteria:
- Security-team and operator playbooks share one explicit artifact-led handoff path.
- Integration checklist includes the same handoff lane after deterministic scan/report/evidence/verify steps.
- The docs clearly distinguish operator actions from buyer/GRC-consumable outputs.
- No docs in this story assume dashboards, live observation, or runtime control.

Changelog impact: required

Changelog section: Changed

Draft changelog entry: Aligned the security-team, operator, and integration docs around a single artifact-led handoff path for audit, buyer, and GRC use using existing report, evidence, and verification outputs.

Semver marker override: none

Contract/API impact:
- No additional runtime contract change beyond the additive guidance introduced in Wave 1; docs consume and explain existing and newly additive fields.

Architecture constraints:
- Keep adoption guidance integration-first and CLI-led.
- Reuse existing templates and artifacts before expanding surface area.
- Preserve offline-first and file-based evidence positioning.

ADR required: no

TDD first failing test(s):
- `scripts/check_docs_storyline.sh`
- `scripts/run_docs_smoke.sh`

Cost/perf impact: low

Chaos/failure hypothesis:
- N/A for docs-only scope; primary failure mode is contradictory handoff guidance across docs surfaces, which docs gates must catch.

## Minimum-Now Sequence

1. Deliver W1-S1 first so the clean-machine no-target path becomes self-serve without changing fail-closed behavior.
2. Deliver W1-S2 next so the operator-to-auditor handoff becomes machine-discoverable in the runtime surfaces that already exist.
3. Land W2-S1 once Wave 1 contract surfaces are fixed so first-screen launch copy can point to shipped behavior, not planned behavior.
4. Finish with W2-S2 to align playbooks and integration docs on the same artifact-led handoff path.

If scope must be reduced for the next near-term release, the minimum useful subset is:
- W1-S1
- W2-S1

That subset fixes the biggest evaluator/activation confusion while keeping later buyer/GRC flow sharpening as a follow-on patch wave.

## Explicit Non-Goals

- No new dashboard, browser-first onboarding surface, or hosted control plane.
- No new top-level CLI command for handoff orchestration.
- No change to exit-code classes or fail-closed dependency semantics.
- No runtime observation or enforcement feature work.
- No schema-major version bump.
- No docs-site expansion unless repo docs prove insufficient during implementation review.

## Definition of Done

- Every audit recommendation in this plan maps to at least one delivered story.
- All shipped runtime changes are additive, deterministic, and validated with CLI contract tests.
- All user-visible runtime changes update docs and changelog in the same PR.
- README first-screen, quickstart, FAQ, security-team docs, operator playbooks, and integration checklist tell one consistent story.
- Report/evidence handoff guidance remains artifact-led, offline-first, and explicit about proof verification.
- All required matrix lanes for each story are green.
- No story weakens fail-closed behavior, explicit-target requirements, or the static-posture product boundary.

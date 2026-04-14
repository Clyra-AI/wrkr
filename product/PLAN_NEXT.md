# PLAN Adhoc: launch onboarding alignment, evidence framing, and hosted org activation

Date: 2026-04-14
Source of truth:
- user-provided 2026-04-14 launch audit findings and recommendations for this run
- `product/dev_guides.md`
- `product/architecture_guides.md`
Scope: Planning only for the current launch-risk follow-up backlog in Wrkr OSS. This plan converts the audit recommendations into implementation-ready waves covering onboarding taxonomy drift, low first-run evidence coverage optics, and hosted org setup friction. No implementation work is performed in this plan.

## Global Decisions (Locked)

- Treat the current repo as technically launchable. This backlog is adoption-leverage and launch-clarity work, not release-blocking defect triage.
- Preserve Wrkr's non-negotiable contracts:
  - deterministic scan/risk/proof behavior by default
  - offline-first local fallback paths
  - fail-closed behavior on ambiguous or unsafe paths
  - stable numeric exit codes and machine-readable envelopes
  - file-based, offline-verifiable proof artifacts
- Keep the product boundary truthful:
  - Wrkr remains static posture, discovery, evidence, and regress
  - no runtime enforcement, no control-plane dependency, no vuln-scanner positioning
- Canonical launch taxonomy for minimum-now OSS:
  - security/platform-led hosted org posture is the primary public path when prerequisites are available
  - evaluator-safe scenario is an explicit demo and hosted-prereq fallback path
  - developer-machine hygiene remains secondary and local
- Reduce hosted-org friction through the existing CLI/config surface only. Do not add any dashboard-first, control-plane, or background-service scope.
- Keep `framework_coverage` semantics unchanged. Improve interpretation and placement, not the underlying math.
- Any config changes must be additive and backward compatible within current config version `v1`.
- Do not expand `wrkr init` into multi-target persistence in this plan. One default target remains the locked config model.
- Runtime and contract stories must land before docs/onboarding/distribution stories that depend on them.
- Every story in this plan is user-visible or OSS-governance-visible, so every story requires a changelog decision and a `CHANGELOG.md` update during implementation.

## Current Baseline (Observed)

- The end-to-end shipped loop is real and working today:
  - `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
  - `wrkr evidence --frameworks eu-ai-act,soc2 --state <state> --output <dir> --json`
  - `wrkr verify --chain --state <state> --json`
  - `wrkr regress init/run --json`
- The audit run on the curated scenario produced:
  - `19` tools
  - `19` identities
  - `131` findings
  - posture score `56.74` (`F`)
  - profile compliance `43.75% fail`
  - `19` unknown-to-security tools
  - `3` unknown-to-security write-capable agents
- Full-repo validation succeeded in the audit run:
  - `go test ./...`
  - acceptance
  - e2e
  - integration
  - scenarios
- Public launch surfaces are split today:
  - `README.md` leads with the evaluator-safe scenario path and only then widens to the security-team org path
  - `docs/examples/quickstart.md` also foregrounds evaluator-safe scenario first
  - `docs/install/minimal-dependencies.md` recommends the scenario path as first value after install
  - `product/wrkr.md` describes Sam's workflow and AC1 as `wrkr init` -> `wrkr scan --org`
  - `docs/contracts/readme_contract.md` says the current Wrkr launch should foreground the security/platform-led org posture workflow
- Hosted org friction is real in the current contract:
  - `wrkr scan --org` and `wrkr scan --github-org` require `--github-api` or `WRKR_GITHUB_API_BASE`
  - `core/cli/init.go` only persists `default_target`, `scan-token`, and `fix-token`
  - `core/config/config.go` has no hosted acquisition config beyond tokens
  - `docs/commands/init.md` has no `--github-api` support today
- Evidence coverage explanation exists, but it is unevenly placed:
  - `docs/commands/evidence.md`
  - `docs/examples/quickstart.md`
  - `docs/faq.md`
  - `docs/positioning.md`
  already clarify that low/zero `framework_coverage` is an evidence-gap signal
  - `README.md` and the first hosted-org evidence touchpoints do not place that explanation adjacent to the first evidence command
  - `core/cli/evidence.go` emits only numeric `framework_coverage` in `--json`, with no additive interpretation fields
- Existing compliance explain/report behavior already contains the right wording:
  - `core/cli/wave3_compliance_test.go` asserts that explain output says coverage reflects only controls evidenced in current scan state and should trigger remediation/rescan
- Safety posture is strong and should not be weakened:
  - proof-chain prerequisite checks in `core/evidence/evidence.go`
  - managed-marker and staged publish safety in `core/evidence/stage.go`
  - managed-root and symlink rejection in `internal/e2e/source/source_e2e_test.go`
- Working tree baseline is clean, so follow-on implementation can start from the generated plan file without hidden unrelated edits.

## Exit Criteria

- `wrkr init` can persist hosted-org scan defaults needed for the primary launch path:
  - default org target
  - hosted GitHub API base
  - scan/fix auth profile tokens
- `wrkr scan --config <path> --json` can resolve the default org target and hosted GitHub API base from config when flags are omitted.
- Hosted source precedence is deterministic, documented, and tested.
- Missing hosted acquisition config still fails closed with the same machine-readable class and numeric exit code family; the error guidance becomes more actionable without weakening the gate.
- `wrkr evidence --json` preserves the current `framework_coverage` numbers and adds an explicit additive interpretation surface so low/zero first-run coverage is not misread as unsupported framework coverage.
- README, install docs, quickstart, security-team docs, FAQ, positioning, and PRD all use one canonical launch taxonomy:
  - org posture first when prerequisites are available
  - evaluator-safe scenario as explicit fallback/demo path
  - `--my-setup` as secondary local hygiene
- Evidence-gap guidance appears immediately adjacent to the first evidence touchpoints in first-screen docs and examples.
- Docs, CLI contract, acceptance, and release-smoke gates pass on the touched surfaces.

## Public API and Contract Map

- Stable public surfaces:
  - `wrkr init`
  - `wrkr scan`
  - `wrkr evidence`
  - `wrkr report`
  - `wrkr verify`
  - `wrkr regress`
  - exit code integers and existing error classes
  - `framework_coverage` numeric semantics
  - state/proof lifecycle rooted at `--state`
  - local fallback paths `--path` and `--my-setup`
- Additive public surfaces planned in this backlog:
  - `wrkr init --github-api <url>`
  - additive config field for hosted GitHub API base
  - additive `init --json` fields exposing hosted-source configuration state and next-step guidance
  - additive `evidence --json` coverage interpretation fields
- Internal surfaces:
  - `core/config/*`
  - `core/cli/init.go`
  - `core/cli/scan.go`
  - `core/cli/scan_helpers.go`
  - `core/cli/evidence.go`
  - docs parity/storyline/hygiene checks
- Shim and deprecation path:
  - existing explicit `--github-api` usage remains valid
  - `WRKR_GITHUB_API_BASE` remains valid
  - scenario-first evaluator flow remains supported as an explicit fallback/demo path
  - no existing flag is removed in this plan
- Schema and versioning policy:
  - remain on current CLI/state/evidence schema versions
  - config stays at version `v1`
  - config additions must be backward compatible when loading older configs
  - no JSON key removals or meaning changes for existing keys
- Machine-readable error expectations:
  - missing hosted GitHub API base after all allowed resolution sources remain exhausted -> fail closed with existing dependency-missing contract
  - missing/invalid state or proof-chain prerequisites for `evidence` remain runtime failures
  - low/zero `framework_coverage` remains success-path output, not an error-path output

## Docs and OSS Readiness Baseline

- README first-screen contract:
  - must state what Wrkr is, who the current launch is for, and which workflow to run first
  - must keep hosted prerequisites adjacent to the first hosted org example
  - must preserve explicit deterministic fallback commands before hosted setup can dead-end
- Integration-first docs flow for touched surfaces:
  - install
  - first run
  - evidence/verify
  - regress
  - only then deeper concepts
- Lifecycle path model:
  - saved scan state is the canonical handoff artifact
  - report/evidence/verify/regress are downstream of saved state
  - optional JSON/markdown/SARIF sidecars are additive, not canonical
- Docs source-of-truth expectations:
  - `docs/commands/*.md` are command contract anchors
  - `docs/examples/*.md` are workflow anchors
  - `docs/contracts/readme_contract.md` governs README first-screen behavior
  - `docs/install/minimal-dependencies.md` governs install/release parity guidance
- OSS trust baseline files for touched behavior:
  - `CHANGELOG.md` is required for every story in this plan
  - `CONTRIBUTING.md` must be checked for impact and updated only if contributor workflow meaning changes
  - `SECURITY.md` must be checked for impact and updated only if security-reporting expectations change
  - no maintainer-support promises are expanded in this plan

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story IDs |
|---|---|---|---|---|---|
| R1 | Unify the launch taxonomy so the public story stops oscillating between evaluator-safe scenario first and hosted org posture first | The current split weakens buyer confidence and makes self-serve evaluation feel inconsistent | One canonical OSS onboarding story with honest fallback paths | Sharper category wedge and lower evaluator confusion | W1-S1, W2-S1 |
| R2 | Make low/zero first-run `framework_coverage` unmistakably read as an evidence gap, not a parser/capability failure | The current math is correct, but the interpretation is not adjacent enough to first evidence touchpoints | Evidence-state clarity without changing score/coverage semantics | Higher trust in proof artifacts and better remediation follow-through | W1-S2, W2-S2 |
| R3 | Reduce hosted org setup friction on the primary path using existing CLI/config surfaces | The current primary path requires more manual setup than the smoother local/synthetic flows | Self-serve hosted-org onboarding through additive config and exact next-step guidance | Better AC1 credibility and better expansion from evaluator to team/org usage | W1-S1 |

## Test Matrix Wiring

- Fast lane:
  - targeted Go tests in `core/config`, `core/cli`, and any focused docs/hygiene checks
  - `make lint-fast`
  - docs parity/storyline checks for touched README/commands/examples
- Core CI lane:
  - `make prepush`
  - `make test-contracts`
  - targeted scenario or CLI contract suites as applicable
- Acceptance lane:
  - targeted `internal/acceptance` subtests for AC01 and AC03
  - targeted `internal/e2e/init` and CLI contract coverage for touched flows
- Cross-platform lane:
  - `windows-smoke` for any Go/config/CLI behavior change
  - avoid platform-specific path assumptions in config/init tests
- Risk lane:
  - `make prepush-full` for runtime/contract stories
  - add `make test-hardening` and `make test-chaos` only if implementation changes failure-class behavior beyond the documented hosted-source resolution and evidence-note additions
- Merge/release gating rule:
  - Wave 1 stories must land before Wave 2 docs stories that depend on them
  - no public docs story closes without docs parity/storyline/smoke coverage
  - no runtime story closes without acceptance or e2e coverage on the touched path
  - if install guidance changes, release smoke/UAT parity must be rerun before merge or release cut

## Epic W1: Hosted Org Activation Contract and Evidence Interpretation

Objective: reduce real friction on the primary security/platform launch path and make first-run evidence semantics explicit in machine-readable output, without changing Wrkr's deterministic evidence math or exit behavior.

### Story W1-S1: Persist hosted org acquisition defaults in `init` and consume them in `scan`

Priority: P1
Tasks:
- Extend persisted config with an additive hosted GitHub API base field.
- Add `--github-api` to `wrkr init` so the primary hosted-org path can be configured once.
- Keep config backward compatible and deterministic under current config version `v1`.
- Update `wrkr scan` hosted-source resolution so it can consume:
  - explicit `--github-api`
  - config-persisted hosted API base
  - `WRKR_GITHUB_API_BASE`
- Align precedence with the existing token-resolution style and document it explicitly.
- Add additive `init --json` fields that expose hosted-source configuration state and deterministic next-step guidance for the chosen target.
- Keep existing explicit `--github-api` and env-driven workflows fully valid.
- Improve missing-hosted-source guidance so a fail-closed run points users to the valid flag/config/env remedies without changing the fail-closed class.
- Update PRD, command docs, and workflow examples to reflect the new hosted-org setup contract.
Repo paths:
- `core/config/config.go`
- `core/config/config_test.go`
- `core/cli/init.go`
- `core/cli/scan.go`
- `core/cli/scan_helpers.go`
- `core/cli/root.go`
- `core/cli/root_test.go`
- `core/cli/scan_github_auth_test.go`
- `internal/e2e/init/init_e2e_test.go`
- `internal/acceptance/v1_acceptance_test.go`
- `docs/commands/init.md`
- `docs/commands/scan.md`
- `docs/examples/security-team.md`
- `docs/examples/quickstart.md`
- `docs/faq.md`
- `README.md`
- `product/wrkr.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/config ./core/cli ./internal/e2e/init -count=1`
- `go test ./internal/acceptance -count=1 -run 'TestV1AcceptanceMatrix/AC01_org_scan_flow_outputs_inventory_and_top_findings'`
- `make test-contracts`
- `make prepush-full`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
Test requirements:
- Schema/artifact changes:
  - config round-trip and byte-stability tests
  - backward-compat load tests for older config files without the new hosted field
- CLI behavior changes:
  - help/usage coverage for `init`
  - `--json` stability tests for additive `init --json` fields
  - exit-code and error-envelope tests for hosted-source resolution when config/flag/env are present or missing
- Acceptance/E2E:
  - `init` followed by hosted `scan` using config-backed API base
  - AC01 org scan flow remains green
- Docs/examples changes:
  - docs consistency checks
  - storyline checks
  - README first-screen checks for hosted prerequisites
Matrix wiring:
- Fast lane: targeted `core/config`, `core/cli`, `internal/e2e/init`, docs parity
- Core CI lane: `make prepush`, `make test-contracts`
- Acceptance lane: targeted AC01 plus `internal/e2e/init`
- Cross-platform lane: `windows-smoke`
- Risk lane: `make prepush-full`
Acceptance criteria:
- `wrkr init --non-interactive --org acme --github-api https://api.github.com --config <path> --json` succeeds and persists the hosted API base in config.
- `wrkr scan --config <path> --state <state> --json` can resolve the default org target and hosted API base without needing `--github-api` again.
- Explicit `--github-api` still overrides config when both are present.
- Existing configs without the new field still load and behave correctly.
- Hosted scans with no usable API base anywhere still fail closed with the existing dependency-missing contract family.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Added config-backed hosted GitHub API base support to `wrkr init` and `wrkr scan` so org-first onboarding can be configured once without weakening the existing fail-closed hosted-scan contract.
Semver marker override: none
Contract/API impact:
- Additive `init` flag: `--github-api`
- Additive config field for hosted GitHub API base
- Additive `init --json` fields for hosted-source config state and next-step guidance
- Additive hosted-source resolution path in `scan`
Versioning/migration impact:
- Config remains version `v1`
- Existing config files must continue to load without migration steps
- No existing JSON keys or exit codes are removed or renumbered
Architecture constraints:
- Keep hosted-source resolution in thin CLI/config orchestration; do not leak hosted-config logic into source or detector packages.
- Preserve explicit side-effect semantics in API naming and precedence handling.
- Keep cancellation and timeout propagation unchanged through hosted scan flows.
- Keep the config extension narrow enough to avoid enterprise-fork pressure for basic onboarding defaults.
ADR required: yes
TDD first failing test(s):
- `core/config/config_test.go` config round-trip with additive hosted API base
- `internal/e2e/init/init_e2e_test.go` config-backed org scan without env-provided API base
- `core/cli/scan_github_auth_test.go` precedence and missing-hosted-source failure guidance
Cost/perf impact: low
Chaos/failure hypothesis:
- If precedence is wrong, stale config could override explicit user intent or hide missing hosted prerequisites.
- If config compatibility breaks, previously initialized installs could fail before scan starts.

### Story W1-S2: Add explicit coverage interpretation to `wrkr evidence --json` without changing `framework_coverage`

Priority: P1
Tasks:
- Add additive machine-readable interpretation fields to `wrkr evidence --json` that explain what `framework_coverage` means.
- Reuse the already-shipped coverage guidance wording so CLI JSON, docs, and report/explain language stay aligned.
- Keep `framework_coverage` values and framework ordering unchanged.
- Keep success/failure classes unchanged for low/zero first-run coverage.
- Update command docs and examples to consume the new additive interpretation keys.
- Add contract tests so the new keys remain additive and deterministic.
Repo paths:
- `core/cli/evidence.go`
- `core/evidence/evidence.go`
- `core/cli/root_test.go`
- `core/cli/wave3_compliance_test.go`
- `internal/scenarios/epic4_scenario_test.go`
- `internal/acceptance/v1_acceptance_test.go`
- `docs/commands/evidence.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `docs/faq.md`
- `docs/positioning.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/cli ./core/evidence -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario -run 'TestScenarioEvidenceBundleIncludesProfileAndPosture'`
- `go test ./internal/acceptance -count=1 -run 'TestV1AcceptanceMatrix/AC03_evidence_bundle_signed_and_verifiable'`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
Test requirements:
- CLI behavior changes:
  - `--json` stability tests for additive evidence keys
  - exit-code invariants proving low/zero coverage remains a success-path result
  - machine-readable envelope tests for malformed/tampered chain prerequisites remain unchanged
- Contract changes:
  - additive JSON-key assertions only
  - determinism tests proving repeat runs emit the same coverage interpretation wording for the same state
- Scenario/spec tests:
  - evidence bundle output still carries profile/posture artifacts
  - coverage interpretation remains consistent with explain/report wording
- Docs/examples changes:
  - docs consistency checks
  - workflow docs use the same interpretation sentence as the JSON note
Matrix wiring:
- Fast lane: targeted `core/cli`, `core/evidence`, docs parity
- Core CI lane: `make prepush`, `make test-contracts`
- Acceptance lane: targeted AC03 and the scenario evidence suite
- Cross-platform lane: `windows-smoke`
- Risk lane: `make prepush-full`
Acceptance criteria:
- `wrkr evidence --frameworks eu-ai-act,soc2 --state <state> --output <dir> --json` still emits the current numeric `framework_coverage` map.
- The same JSON payload now also emits additive interpretation fields that explicitly say coverage reflects controls evidenced in the current scanned state and that low/zero first-run coverage indicates evidence gaps rather than unsupported framework parsing.
- Existing low-coverage runs still exit `0`.
- Malformed/tampered chain runs still fail with the same runtime/verification behavior they have today.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Added explicit coverage-interpretation fields to `wrkr evidence --json` so low first-run framework coverage is framed as an evidence gap rather than a parser or framework-support failure.
Semver marker override: none
Contract/API impact:
- Additive `evidence --json` output fields only
- No existing key removal or exit-code change
Versioning/migration impact:
- No schema/version bump
- Existing automation that ignores unknown JSON keys remains compatible
Architecture constraints:
- Keep interpretation logic close to CLI/report contract surfaces; do not change compliance-rollup math or proof generation.
- Preserve deterministic wording and field ordering for identical inputs.
- Avoid thresholds or heuristics that could imply unsupported new policy logic.
ADR required: yes
TDD first failing test(s):
- `core/cli/root_test.go` or a dedicated evidence JSON contract test for additive coverage interpretation fields
- `core/cli/wave3_compliance_test.go` alignment checks between explain wording and the new JSON note
- `internal/acceptance/v1_acceptance_test.go` targeted AC03 assertion for additive interpretation fields
Cost/perf impact: low
Chaos/failure hypothesis:
- If the additive note diverges from numeric coverage semantics, automation and operator trust will drift.
- If interpretation fields are emitted inconsistently across equivalent runs, the CLI JSON contract becomes noisy.

## Epic W2: Launch Taxonomy and First-Run Docs Alignment

Objective: remove the public-message split, keep the evaluator-safe fallback honest and explicit, and place evidence-gap interpretation exactly where new users first encounter it.

### Story W2-S1: Reconcile first-screen launch taxonomy across README, install docs, quickstart, security-team docs, FAQ, and PRD

Priority: P1
Tasks:
- Make one canonical launch ordering explicit across public surfaces:
  - org posture first when hosted prerequisites are ready
  - evaluator-safe scenario fallback/demo path second
  - `--my-setup` secondary local hygiene path
- Align README, install docs, quickstart, security-team docs, FAQ, positioning, and PRD so they no longer contradict one another.
- Keep the evaluator-safe scenario path prominent as a fallback, but stop presenting it as the unconditional first-screen recommendation when the launch persona is security/platform-led.
- Update any README first-screen contract checks that still encode the old story.
- Verify install-path wording and `wrkr version --json` discoverability remain intact when editing first-screen docs.
Repo paths:
- `README.md`
- `docs/install/minimal-dependencies.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/faq.md`
- `docs/positioning.md`
- `docs/contracts/readme_contract.md`
- `product/wrkr.md`
- `CHANGELOG.md`
Run commands:
- `go test ./testinfra/hygiene -count=1`
- `make test-docs-consistency`
- `make test-docs-storyline`
- `scripts/run_docs_smoke.sh`
- `scripts/test_uat_local.sh --skip-global-gates`
Test requirements:
- Docs/examples changes:
  - docs consistency checks
  - storyline/smoke checks when the user flow changes
  - README first-screen checks
  - integration-before-internals guidance checks
  - version/install discoverability checks for `wrkr version` and minimal-dependency guidance
- OSS readiness changes:
  - verify `CHANGELOG.md` updates
  - verify no additional maintainer/support-policy file change is needed
Matrix wiring:
- Fast lane: docs parity and hygiene checks
- Core CI lane: docs consistency and storyline
- Acceptance lane: not required beyond docs/storyline because no runtime behavior changes in this story
- Cross-platform lane: not required beyond existing docs smoke because no platform-sensitive runtime changes are introduced
- Risk lane: not required
Acceptance criteria:
- README, quickstart, install docs, security-team docs, FAQ, and PRD all describe the same canonical launch ordering.
- The evaluator-safe scenario path remains present and explicit, but is clearly labeled as fallback/demo rather than the canonical security/platform first path.
- Hosted prerequisites sit adjacent to the first hosted org example on the public first-screen surfaces.
- `wrkr version --json` verification remains on the first install screen.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Reconciled the public launch docs so hosted org posture is the primary first-screen path, with the evaluator-safe scenario preserved as the explicit fallback and demo flow.
Semver marker override: none
Contract/API impact:
- Docs-only clarification of existing and newly-additive runtime behavior
- No CLI or schema change in this story
Versioning/migration impact:
- None
Architecture constraints:
- Do not introduce docs claims that exceed the actual CLI/runtime contract.
- Keep README and docs examples aligned with `docs/commands/*.md` command sources of truth.
ADR required: no
TDD first failing test(s):
- `go test ./testinfra/hygiene -count=1`
- docs storyline checks that encode the first-screen ordering
Cost/perf impact: low
Chaos/failure hypothesis:
- None; docs-only story. The failure mode is contract drift between public surfaces, which must be caught by docs/hygiene checks.

### Story W2-S2: Put evidence-gap framing directly beside the first evidence touchpoints and operator handoff paths

Priority: P1
Tasks:
- Update README, quickstart, security-team docs, operator playbooks, and command docs so the first evidence touchpoints explain low/zero first-run coverage immediately.
- Mirror the additive `evidence --json` interpretation wording from W1-S2 in the docs so public copy, machine-readable output, and operator playbooks use one sentence.
- Add explicit next-step guidance near the first evidence examples:
  - review top risks
  - remediate missing controls/approvals
  - rerun scan/evidence/report
- Make sure no touched doc implies low coverage means missing parser support or missing framework support.
- Add or tighten docs/hygiene checks so this guidance stays adjacent to first evidence workflows.
Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/commands/evidence.md`
- `docs/examples/operator-playbooks.md`
- `docs/faq.md`
- `docs/positioning.md`
- `docs/intent/generate-compliance-evidence-from-scans.md`
- `CHANGELOG.md`
Run commands:
- `go test ./testinfra/hygiene -count=1`
- `make test-docs-consistency`
- `make test-docs-storyline`
- `scripts/run_docs_smoke.sh`
Test requirements:
- Docs/examples changes:
  - docs consistency checks
  - storyline/smoke checks for evidence workflow changes
  - README and quickstart checks for first evidence command adjacency
  - docs source-of-truth mapping checks when both commands and examples are touched
- API/contract lifecycle changes:
  - confirm docs examples reflect the additive `evidence --json` fields from W1-S2 exactly
Matrix wiring:
- Fast lane: docs parity and hygiene checks
- Core CI lane: docs consistency and storyline
- Acceptance lane: not required beyond docs/hygiene because runtime acceptance coverage lands in W1-S2
- Cross-platform lane: not required
- Risk lane: not required
Acceptance criteria:
- The first evidence command shown in README, quickstart, and security-team docs is immediately followed by evidence-gap interpretation and next actions.
- Operator playbooks and evidence command docs use the same wording as the shipped additive JSON note.
- No touched doc frames low/zero `framework_coverage` as parser failure or unsupported framework support.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Updated first-run evidence docs to explain low framework coverage as an evidence-state gap and to place remediation guidance directly beside the first evidence workflows.
Semver marker override: none
Contract/API impact:
- Docs-only clarification of the additive evidence JSON interpretation shipped in W1-S2
Versioning/migration impact:
- None
Architecture constraints:
- Keep docs claims strictly downstream of the shipped CLI contract.
- Do not fork wording across docs surfaces; use one stable interpretation sentence.
ADR required: no
TDD first failing test(s):
- `go test ./testinfra/hygiene -count=1`
- docs storyline checks that assert evidence-gap guidance adjacency
Cost/perf impact: low
Chaos/failure hypothesis:
- None; docs-only story. The failure mode is message drift across README, examples, and command docs.

## Minimum-Now Sequence

1. Wave 1
   - W1-S1 first. The hosted-org onboarding contract must exist before public docs can honestly foreground it.
   - W1-S2 second. The additive evidence interpretation must ship before docs can rely on it.
2. Wave 2
   - W2-S1 after W1-S1. Public first-screen docs should describe the real hosted onboarding contract, not the old split story.
   - W2-S2 after W1-S2 and W2-S1. The evidence framing should quote the shipped runtime interpretation and sit inside the canonical launch ordering.

## Explicit Non-Goals

- No dashboard, browser handoff redesign, or SaaS control plane work
- No change to risk scoring math, posture score weights, or `framework_coverage` calculation
- No new scanner surfaces, no live probing by default, and no runtime enforcement scope
- No multi-target persistence in `wrkr init`
- No package- or server-vulnerability scanning scope expansion
- No release engineering/toolchain pin work unless it is directly required by implementation of the above stories

## Definition of Done

- Every audit recommendation in this run maps to one or more completed stories in this plan.
- Runtime/contract stories land before the docs stories that describe them.
- Every story ships with:
  - explicit changelog intent
  - tests at the right level
  - matrix wiring
  - acceptance criteria proven by commands or gated checks
- Public docs, install docs, examples, and PRD no longer contradict one another on the minimum-now launch path.
- Hosted org onboarding is materially simpler through existing CLI/config surfaces and remains fail closed when prerequisites are missing.
- Evidence coverage semantics are explicit in both machine-readable output and first-run docs.
- `CHANGELOG.md` is updated in the same implementation PRs.
- If follow-on implementation with `adhoc-implement` finds additional dirty files beyond the generated plan file, scope/clean that state before proceeding on a new branch.

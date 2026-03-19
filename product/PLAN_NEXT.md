# PLAN WRKR_LAUNCH_EXPECTATION_ALIGNMENT: First-Run Evidence Semantics, Funnel Focus, and Install Trust

Date: 2026-03-19
Source of truth:
- user-provided launch audit findings dated 2026-03-19
- `product/dev_guides.md`
- `product/architecture_guides.md`
- `README.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `docs/install/minimal-dependencies.md`
- `docs/positioning.md`
- `docs/faq.md`
- `docs/contracts/readme_contract.md`
- `docs/state_lifecycle.md`
- `core/compliance/summary.go`
- `core/report/build.go`
- `core/cli/report.go`
- `testinfra/hygiene/wave2_docs_contracts_test.go`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
Scope: Wrkr repository only. Planning artifact only. Close the top three launch risks from the 2026-03-19 audit without weakening determinism, offline-first defaults, fail-closed behavior, schema stability, exit-code stability, or README/docs contract enforcement.

## Global Decisions (Locked)

- Treat this plan as contract/runtime clarity first, then docs/onboarding distribution. Earlier waves remove interpretation gaps before later waves tighten funnel copy.
- Preserve Wrkr machine-readable contracts:
  - `scan`, `report`, `evidence`, `verify`, and `version` JSON keys remain stable unless any new fields are strictly additive and optional.
  - exit codes `0..8` remain unchanged.
  - `compliance_summary` and `framework_coverage` remain stable public surfaces.
- Keep `core/cli` thin. Authoritative compliance explanation logic belongs in `core/compliance` and report section assembly belongs in `core/report`.
- Security/platform-led org posture remains the primary minimum-now launch persona. Developer hygiene remains a secondary path, and `--path` remains the explicit zero-integration fallback when hosted prerequisites are unavailable.
- Preserve README Variant B (`Wrkr Landing v2`) unless the docs contract is explicitly revised in the same PR.
- First-screen install surfaces must expose:
  - Homebrew path
  - pinned/reproducible Go path
  - `wrkr version` verification
  - convenience `@latest` only if it remains clearly secondary and contract-consistent
- No dashboard-first scope, no hosted control-plane requirements, no new network defaults, and no changes to proof-record formats or compliance framework definitions in this plan.
- Stories touching report/compliance semantics must run `make prepush-full`.
- Docs and onboarding stories must update enforcement in the same PR via `testinfra/hygiene` and docs validation scripts.

## Current Baseline (Observed)

- Planning inputs validated:
  - `product/dev_guides.md` exists and is readable.
  - `product/architecture_guides.md` exists and is readable.
  - output path `product/PLAN_NEXT.md` resolves inside `/Users/tr/wrkr`.
- The worktree was clean before this plan rewrite.
- Technical launch posture is healthy:
  - `make lint-fast` passed during the audit.
  - `go test ./... -count=1` passed during the audit.
  - fail-closed behavior held for unmanaged evidence output, unmanaged materialized scan roots, degraded campaign inputs, and explicit `verify --path` precedence.
- Current expectation gap is not parser correctness but interpretation:
  - docs already state that low/zero compliance coverage is an evidence-state signal in `docs/commands/evidence.md`, `docs/commands/report.md`, `docs/examples/quickstart.md`, `docs/examples/operator-playbooks.md`, `docs/faq.md`, and `docs/positioning.md`
  - human-readable report/explain output still emits `no findings currently map to bundled compliance controls` from `core/compliance/summary.go`, which can read like missing product support instead of sparse first-run evidence state
- Current funnel gap is top-of-funnel dilution:
  - `README.md` and `docs/examples/quickstart.md` foreground the security/platform path
  - those same first-screen surfaces also mix developer hygiene, compliance handoff, and hosted prerequisites in a way that weakens the primary buyer story and can dead-end users who do not yet have GitHub API/token setup
- Current install trust gap is first-screen discoverability:
  - `README.md` uses the convenience `go install ...@latest` path
  - pinned/reproducible install guidance is canonical but deeper in `docs/install/minimal-dependencies.md`
  - current docs contract tests enforce latest-path visibility for landing README v2, but do not enforce first-screen pinned install discoverability or `wrkr version` verification
- Existing enforcement relevant to this plan already exists:
  - `testinfra/hygiene/wave2_docs_contracts_test.go`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/check_docs_cli_parity.sh`

## Exit Criteria

1. First-run report/evidence human-readable surfaces no longer imply missing framework support when the real state is sparse evidence or zero mapped findings.
2. `wrkr report --json` and `wrkr evidence --json` preserve existing stable keys and exits; any new interpretation field is additive and optional only.
3. README, quickstart, positioning, FAQ, and security-team workflow docs present one explicit primary launch persona:
   - security/platform org posture first
   - developer hygiene secondary
   - `--path` or `--my-setup` called out as fallback when hosted prerequisites are unavailable
4. Hosted prerequisites (`--github-api`, likely token) appear adjacent to the first hosted org posture command instead of buried later in the flow.
5. First-screen install guidance exposes Homebrew, a pinned/reproducible Go path, and `wrkr version` verification without removing the canonical authority of `docs/install/minimal-dependencies.md`.
6. Docs contract enforcement is updated in the same PR so regressions in persona/fallback/install trust are caught automatically.
7. Required lanes pass for each story, including:
   - `make lint-fast`
   - `go test ./testinfra/hygiene -count=1`
   - `make prepush-full` for the runtime semantics story
   - `scripts/check_docs_cli_parity.sh`
   - `scripts/check_docs_storyline.sh`
   - `scripts/check_docs_consistency.sh`
   - `scripts/run_docs_smoke.sh`
   - `scripts/test_uat_local.sh --skip-global-gates` for the install-trust story
8. No schema or version bump is required unless implementation proves an additive optional explanatory field is necessary; any such addition must be explicitly documented and version-reviewed.

## Public API and Contract Map

Stable/public surfaces touched by this plan:

- CLI commands:
  - `wrkr scan`
  - `wrkr report`
  - `wrkr evidence`
  - `wrkr verify`
  - `wrkr version`
- Stable machine-readable surfaces:
  - `scan`: `status`, `target`, `warnings`, `compliance_summary`
  - `report`: `status`, `generated_at`, `top_findings`, `compliance_summary`, `summary`, `md_path`, `pdf_path`
  - `evidence`: `status`, `output_dir`, `frameworks`, `manifest_path`, `chain_path`, `framework_coverage`, `report_artifacts`
  - `version`: `status`, `version`
- Stable docs contract surfaces:
  - README landing v2 section structure
  - `docs/install/minimal-dependencies.md` as canonical pinned install contract
  - `docs/examples/quickstart.md` as onboarding contract
  - `docs/contracts/readme_contract.md` as README variant authority
- Stable human-readable operator surfaces:
  - report markdown/PDF summary sections
  - compliance explanation lines
  - README Start Here / Install sections

Internal surfaces expected to change:

- `core/compliance/summary.go`
- `core/report/build.go`
- `core/report/report_test.go`
- `core/cli/wave3_compliance_test.go`
- `internal/scenarios/wave3_compliance_scenario_test.go`
- `README.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `docs/positioning.md`
- `docs/faq.md`
- `docs/install/minimal-dependencies.md`
- `docs/contracts/readme_contract.md`
- `testinfra/hygiene/wave2_docs_contracts_test.go`
- docs-site or LLM-surface mirrors if first-screen copy/install guidance is duplicated there:
  - `docs-site/src/app/page.tsx`
  - `docs-site/public/llm/quickstart.md`
  - related docs-site start-here mirrors as needed

Shim/deprecation path:

- No CLI shim or flag deprecation is planned.
- Convenience `@latest` install guidance may remain, but only as an explicitly secondary path after README/install contract review.
- No deprecation is planned for `--my-setup` or `--path`; they remain public fallback/secondary paths.

Schema/versioning policy:

- Preferred implementation path: no schema changes and no version bump.
- If a new explanatory field is needed in report/evidence JSON, it must be additive and optional under existing structures.
- No change to proof schemas, lifecycle schemas, or evidence bundle manifest schema is planned.

Machine-readable error expectations:

- `scan --org` / `scan --github-org` without configured GitHub API base continues to fail closed with `dependency_missing` exit `7`.
- `report` keeps current `invalid_input` exit `6` and `runtime_failure` exit `1` behavior.
- `evidence` keeps current `runtime_failure`, `invalid_input`, and `unsafe_operation_blocked` classes and exits.
- This plan does not introduce new machine-readable error codes.

## Docs and OSS Readiness Baseline

README first-screen contract:

- `README.md` stays on landing README v2.
- `## Install` must include:
  - Homebrew
  - pinned/reproducible Go install
  - optional convenience latest path only if clearly secondary
  - `wrkr version` verification
- `## Start Here` must include:
  - explicit launch persona: security/platform-led org posture first
  - nearby hosted prerequisites for org posture
  - developer hygiene as secondary path
  - explicit zero-integration fallback (`--path` and/or `--my-setup`)
- No first-screen copy may imply a hosted-only requirement to experience value.

Integration-first docs flow for this plan:

1. `README.md`
2. `docs/examples/quickstart.md`
3. `docs/examples/security-team.md`
4. `docs/install/minimal-dependencies.md`
5. `docs/commands/scan.md`
6. `docs/commands/report.md`
7. `docs/commands/evidence.md`
8. `docs/faq.md`
9. `docs/positioning.md`

Lifecycle path model the docs must preserve:

- `wrkr scan` creates `.wrkr/last-scan.json` and proof/lifecycle sidecars.
- `wrkr report`, `wrkr evidence`, and `wrkr verify` are saved-state consumers.
- Hosted org posture requires explicit GitHub API configuration.
- `--path` remains the zero-integration repo-local fallback.
- `--my-setup` remains the secondary local hygiene path.

Docs source-of-truth mapping:

- behavior authority:
  - `core/compliance/*`
  - `core/report/*`
  - `core/cli/*`
- install authority:
  - `docs/install/minimal-dependencies.md`
- README contract authority:
  - `docs/contracts/readme_contract.md`
- docs enforcement:
  - `testinfra/hygiene/wave2_docs_contracts_test.go`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/check_docs_cli_parity.sh`
- if docs-site or LLM surfaces are touched, they must mirror the selected first-screen wording and install contract in the same PR

OSS trust baseline:

- Preserve and validate:
  - `CONTRIBUTING.md`
  - `SECURITY.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `.github/ISSUE_TEMPLATE/*`
  - `.github/pull_request_template.md`
- No new community-health file is required in this plan.
- Maintainer/support expectations remain explicit through existing support/security docs; this plan only aligns onboarding and trust discoverability.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Reframe first-run compliance/report output so sparse evidence is not misread as missing framework support | Current human-readable wording can undercut trust even though machine-readable contracts are correct | First-run evidence semantics clarity with stable contracts | Stronger buyer confidence, lower support churn, better audit handoff comprehension | `W1-S01` |
| R2 | Sharpen first-screen funnel around security/platform-led org posture and explicit fallback paths | Top-of-funnel copy currently dilutes the wedge and can dead-end users lacking hosted setup | Funnel focus and onboarding taxonomy alignment | Faster activation, clearer buyer story, lower setup confusion | `W2-S01` |
| R3 | Surface pinned install and version verification at first screen | Security/platform buyers need reproducible install trust without hunting for deeper docs | Install-trust alignment with enforced discoverability | Stronger OSS trust, safer CI onboarding, better release credibility | `W2-S02` |

## Test Matrix Wiring

| Lane | Required commands | Notes |
|---|---|---|
| Fast lane | `make lint-fast`; `go test ./core/compliance ./core/report ./core/cli ./testinfra/hygiene -count=1`; `scripts/check_docs_cli_parity.sh`; `scripts/check_docs_storyline.sh`; `scripts/check_docs_consistency.sh` | Minimum local and PR feedback loop for this plan |
| Core CI lane | `make prepush-full`; `go test ./... -count=1` | Mandatory for `W1-S01`; rerun after wave integration to catch collateral drift |
| Acceptance lane | `go test ./internal/scenarios -count=1 -tags=scenario`; `go test ./internal/acceptance -count=1`; `scripts/run_docs_smoke.sh` | Outside-in validation for report/evidence semantics and docs flow |
| Cross-platform lane | existing `windows-smoke`; install smoke on supported OS matrix via release/install jobs | Required because install discoverability and shell instructions are public OSS surfaces |
| Risk lane | `make test-contracts`; add `make test-hardening` / `make test-chaos` only if implementation expands report/evidence failure-path logic; add `make test-perf` only if artifact generation budgets change materially | Default risk lane here is contract-heavy rather than chaos-heavy |
| Merge/release gating rule | Wave 1 must land before Wave 2. No story closes until its declared lanes are green and docs/test enforcement is updated in the same PR. `W2-S02` also requires `scripts/test_uat_local.sh --skip-global-gates` evidence. | No docs-only or tests-only cleanup PRs after behavior/copy changes |

## Epic W1: First-Run Evidence Semantics

Objective: remove the highest-risk expectation gap from first-run report/evidence output without changing core machine-readable compliance contracts.

### Story W1-S01: Make Sparse-Evidence Compliance Output Explicit and Actionable
Priority: P1
Tasks:
- Add failing tests that capture the intended first-run wording when bundled frameworks are present but `finding_count` / `mapped_finding_count` are zero or sparse.
- Refine `compliance.ExplainRollupSummary` so human-readable output distinguishes:
  - framework support exists
  - current evidence is sparse or gap-heavy
  - next operator action is remediation/rescan, not “enable support”
- Update report headline/audit summary section assembly so the first-screen report facts reinforce evidence-state semantics rather than unsupported-sounding language.
- Keep `compliance_summary` stable. If implementation needs extra explanatory data, add it only as an optional additive field in report/evidence summary payloads.
- Update `docs/commands/report.md`, `docs/commands/evidence.md`, and `docs/examples/operator-playbooks.md` to mirror the exact runtime semantics and operator actions.
- If audit markdown artifact text changes, update report markdown tests/goldens in the same story.
Repo paths:
- `core/compliance/summary.go`
- `core/report/build.go`
- `core/report/report_test.go`
- `core/cli/wave3_compliance_test.go`
- `internal/scenarios/wave3_compliance_scenario_test.go`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `docs/examples/operator-playbooks.md`
Run commands:
- `go test ./core/compliance ./core/report ./core/cli -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `make prepush-full`
Test requirements:
- report/compliance unit tests for sparse-evidence explanation wording
- `--json` stability tests proving existing `compliance_summary` keys remain intact
- scenario/acceptance checks confirming scan/report compliance summaries stay aligned
- markdown/report artifact golden updates if wording changes
- docs parity and storyline checks
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Risk lane (`make test-contracts`)
Acceptance criteria:
- Human-readable report/evidence/compliance explanation no longer says or implies that bundled framework support is absent when sparse evidence is the real condition.
- Existing machine-readable `compliance_summary` and `framework_coverage` keys remain stable.
- Report markdown/PDF and `--explain` output present deterministic next-action guidance for low/zero coverage.
- Updated docs use the same semantics as generated runtime output.
Contract/API impact:
- Existing JSON keys and exit codes remain stable.
- Any new explanatory field must be additive and optional only.
Versioning/migration impact:
- No schema version bump planned.
- If an additive optional field is introduced, document it in command docs and treat migration as none-required for current consumers.
Architecture constraints:
- `core/compliance` remains the authoritative layer for rollup/explanation logic.
- `core/report` remains the authoritative layer for section assembly and template wording.
- `core/cli` stays orchestration-only and must not duplicate compliance interpretation logic.
- Preserve deterministic ordering and byte-stable artifact generation.
ADR required: no
TDD first failing test(s):
- `core/report/report_test.go` sparse-evidence headline/summary expectation test
- `core/cli/wave3_compliance_test.go` contract test for stable JSON with any additive explanation field
- `internal/scenarios/wave3_compliance_scenario_test.go` parity test for scan/report compliance semantics
Cost/perf impact: low
Chaos/failure hypothesis:
- With a valid scan state that contains bundled frameworks but zero mapped findings, report/evidence still emit deterministic, actionable guidance and never imply missing framework support.
Dependencies:
- none
Risks:
- Additive explanation work can accidentally widen schema surface; mitigate by keeping changes human-readable-first and locking JSON tests before implementation.

## Epic W2: Launch Funnel and Install Trust Alignment

Objective: align first-screen launch copy and install trust around the chosen security/platform-led wedge while preserving deterministic fallback paths.

### Story W2-S01: Align README and Quickstart Around One Launch Persona With Explicit Fallbacks
Priority: P2
Tasks:
- Rewrite first-screen copy so `README.md`, `docs/examples/quickstart.md`, `docs/positioning.md`, `docs/faq.md`, and `docs/examples/security-team.md` all tell one consistent story:
  - security/platform org posture first
  - developer hygiene second
  - `--path` or `--my-setup` as explicit fallback when hosted prerequisites are unavailable
- Move hosted prerequisites (`--github-api`, likely token) next to the first org workflow command instead of leaving them as later caveats.
- Keep deterministic `--json` command anchors and avoid adding hidden backend/setup requirements.
- Update `docs/contracts/readme_contract.md` and `testinfra/hygiene/wave2_docs_contracts_test.go` so the chosen primary persona and fallback path are enforced automatically.
- If first-screen wording is duplicated in docs-site or LLM mirrors, update those surfaces in the same PR.
- Include PLG fields in the implementation PR description:
  - `First value outcome`
  - `Time-to-value target`
  - `Activation signal`
  - `Repeat usage signal`
  - `Expansion path`
  - `Friction removed`
Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/examples/personal-hygiene.md`
- `docs/positioning.md`
- `docs/faq.md`
- `docs/contracts/readme_contract.md`
- `testinfra/hygiene/wave2_docs_contracts_test.go`
- `scripts/check_docs_storyline.sh`
- `docs-site/src/app/page.tsx`
- `docs-site/public/llm/quickstart.md`
Run commands:
- `go test ./testinfra/hygiene -count=1`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/check_docs_cli_parity.sh`
- `scripts/run_docs_smoke.sh`
- `make docs-site-build`
- `make docs-site-check`
Test requirements:
- README first-screen contract checks
- docs consistency/storyline checks
- docs source-of-truth mapping checks when docs-site mirrors change
- docs-site build/smoke validation if first-screen mirrors are touched
Matrix wiring:
- Fast lane
- Acceptance lane
- Cross-platform lane (existing docs/install smoke matrix if docs-site/install mirrors are touched)
Acceptance criteria:
- README and quickstart both state the primary launch persona explicitly and consistently.
- Hosted prerequisite guidance appears adjacent to the first hosted org workflow.
- At least one deterministic fallback path is visible before a user can dead-end on hosted setup.
- README contract tests fail if persona or fallback discoverability regresses.
- Any touched docs-site/LLM mirrors stay aligned with the same first-screen story.
Contract/API impact:
- Docs and README contract only; no CLI behavior or schema changes planned.
Versioning/migration impact:
- None.
Architecture constraints:
- Preserve README landing v2 structure unless the contract doc and tests are updated in the same PR.
- Keep integration-before-internals ordering in onboarding docs.
- Do not create conflicting first-screen narratives across README, quickstart, and positioning docs.
ADR required: no
TDD first failing test(s):
- `testinfra/hygiene/wave2_docs_contracts_test.go` persona/fallback contract test
- `scripts/check_docs_storyline.sh` quickstart/flow assertions if tokens change
Cost/perf impact: low
Chaos/failure hypothesis:
- When a user lacks GitHub API/token setup, the first-screen docs still route them to a deterministic fallback instead of a hosted-only dead end.
Dependencies:
- `W1-S01` must land first so docs reflect the finalized compliance/report semantics.
Risks:
- README and quickstart touch the same trust-sensitive surfaces as install guidance; sequence carefully to avoid conflicting copy churn.

### Story W2-S02: Surface Pinned Install and Version Verification at First Screen
Priority: P2
Tasks:
- Update `README.md` install guidance to show:
  - Homebrew path
  - pinned/reproducible Go install
  - convenience latest path only if retained as clearly secondary
  - `wrkr version` verification after install
- Tighten `docs/contracts/readme_contract.md` and `testinfra/hygiene/wave2_docs_contracts_test.go` to require first-screen pinned install discoverability and version verification, not just deep-doc presence.
- Keep `docs/install/minimal-dependencies.md` as the canonical pinned install contract and align any wording or examples needed there.
- Update `docs/trust/release-integrity.md` and any docs-site install mirrors if the first-screen install contract changes.
- Validate the published install path with local release UAT and an explicit `wrkr version --json` smoke command.
- Include PLG fields in the implementation PR description:
  - `First value outcome`
  - `Time-to-value target`
  - `Activation signal`
  - `Repeat usage signal`
  - `Expansion path`
  - `Friction removed`
Repo paths:
- `README.md`
- `docs/install/minimal-dependencies.md`
- `docs/trust/release-integrity.md`
- `docs/contracts/readme_contract.md`
- `testinfra/hygiene/wave2_docs_contracts_test.go`
- `docs-site/src/app/page.tsx`
- `docs-site/public/llm/quickstart.md`
Run commands:
- `go build -o .tmp/wrkr ./cmd/wrkr`
- `./.tmp/wrkr version --json`
- `go test ./testinfra/hygiene -count=1`
- `scripts/check_docs_consistency.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/test_uat_local.sh --skip-global-gates`
- `make docs-site-build`
- `make docs-site-check`
Test requirements:
- version/install discoverability checks
- README/install contract tests
- docs consistency checks
- local UAT validation for published install path
- docs-site build/smoke if first-screen install mirrors are touched
Matrix wiring:
- Fast lane
- Acceptance lane
- Cross-platform lane
Acceptance criteria:
- README install section visibly includes a pinned/reproducible path and `wrkr version` verification.
- If `@latest` remains, it is clearly secondary and contract-consistent with install docs.
- Hygiene tests fail when first-screen pinned install or version verification discoverability regresses.
- Local UAT install smoke passes with the updated install guidance.
Contract/API impact:
- Install/onboarding contract only; no CLI behavior change planned.
Versioning/migration impact:
- None.
Architecture constraints:
- `docs/install/minimal-dependencies.md` remains the canonical install authority.
- Do not introduce conflicting pinned versions across README, install docs, and release-integrity docs.
- Keep install commands deterministic and free of hidden helper dependencies.
ADR required: no
TDD first failing test(s):
- `testinfra/hygiene/wave2_docs_contracts_test.go` install/version discoverability test
- install-doc smoke assertions in docs consistency or UAT validation if needed
Cost/perf impact: low
Chaos/failure hypothesis:
- If latest-tag lookup becomes unavailable or undesirable for a buyer, first-screen docs still provide a deterministic pinned install path and local version verification.
Dependencies:
- `W2-S01` first, because both stories touch README contract surfaces and should not fork the first-screen narrative.
Risks:
- README contract tests currently encode landing-v2 latest-path assumptions; update tests and docs atomically to avoid temporary contract drift.

## Minimum-Now Sequence

1. Wave 1: implement `W1-S01` and freeze the final first-run compliance/report semantics.
2. Wave 2A: implement `W2-S01` after Wave 1 so the first-screen story matches the shipped runtime semantics.
3. Wave 2B: implement `W2-S02` after `W2-S01` because both stories touch `README.md`, README contract tests, and possibly docs-site first-screen mirrors.
4. Run full validation after each wave integration:
   - Wave 1: runtime/report/docs contract lanes
   - Wave 2: docs/onboarding/install/UAT lanes
5. Only start `adhoc-implement` from a fresh branch after confirming the only expected dirty file from this planning turn is `product/PLAN_NEXT.md`.

## Explicit Non-Goals

- No change to detector coverage, risk scoring, or compliance framework definitions.
- No dashboard, hosted control plane, or browser-first onboarding redesign.
- No new network dependency in default scan/report/evidence flows.
- No change to proof record formats, chain semantics, or exit-code taxonomy.
- No cross-repo toolchain or dependency pin remediation in this plan.
- No docs-site visual redesign beyond mirror updates required to keep first-screen messaging/install contract aligned.

## Definition of Done

- All three launch risks are mapped to implemented stories with deterministic acceptance criteria.
- First-run compliance/report wording is no longer ambiguous about sparse evidence versus missing support.
- README, quickstart, positioning, FAQ, and security-team docs are aligned on one primary launch persona and explicit fallback path.
- README install section surfaces pinned install trust and version verification without conflicting with canonical install docs.
- Docs/test enforcement is updated in the same PRs so persona/fallback/install trust regressions are caught automatically.
- Relevant lanes are green for each story, including `make prepush-full` for Wave 1 and local install UAT for `W2-S02`.
- No unexpected dirty files remain beyond the generated planning artifact before handoff to implementation.

# PLAN WRKR_LAUNCH_TRUTH_RESET: Narrow Launch to the Shipped Discovery, Proof, and Regress Wedge

Date: 2026-03-26
Source of truth:
- user-provided audit findings dated 2026-03-26
- `product/dev_guides.md`
- `product/architecture_guides.md`
- `AGENTS.md`
- `README.md`
- `product/wrkr.md`
- `docs/concepts/mental_model.md`
- `docs/positioning.md`
- `docs/commands/action.md`
- `docs/commands/fix.md`
- `docs/commands/report.md`
- `docs/commands/scan.md`
- `docs/commands/evidence.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `docs/state_lifecycle.md`
- `docs/failure_taxonomy_exit_codes.md`
- `docs/trust/security-and-privacy.md`
- `core/cli/action.go`
- `core/cli/fix.go`
- `core/fix/artifacts.go`
- `core/cli/report.go`
- `core/cli/report_pdf.go`
- `core/evidence/stage.go`
- `core/cli/scan_helpers.go`
- `internal/e2e/source/source_e2e_test.go`
- `.github/required-checks.json`
Scope: Wrkr repository only. Planning artifact only. Convert the 2026-03-26 audit recommendations into an execution-ready backlog that moves Wrkr from broad-launch no-go to narrow-launch go without weakening determinism, offline-first defaults, fail-closed policy enforcement, schema stability, exit-code stability, or the authoritative Go-core architecture.

## Global Decisions (Locked)

- This is a planning-only change. No implementation work is in scope for this artifact.
- Minimum-now sequencing is opinionated: ship a narrower, honest OSS launch before attempting to restore broad-launch claims.
- The minimum-now public product is:
  - deterministic discovery
  - posture/risk ranking
  - evidence generation
  - proof verification
  - regress/baseline gating
- The minimum-now public product is not:
  - a direct auto-remediation system
  - a packaged GitHub Action distribution surface
  - a board-ready executive PDF reporting system
- Public copy must not exceed shipped behavior. Docs, README, PRD, command help, examples, and docs-site entry points are treated as contract surfaces.
- `wrkr fix` remains a plan-and-preview surface unless and until an additive explicit apply mode is implemented:
  - current stable behavior is remediation planning
  - current `--open-pr` behavior is deterministic artifact generation under `.wrkr/remediations/<fingerprint>/` plus one PR update/create path
  - no public claim may say that current Wrkr directly edits target repo files or opens one PR per finding
- `wrkr action pr-mode` and `wrkr action pr-comment` remain the only currently shipped action surfaces unless and until a real `action.yml` package is introduced.
- `wrkr report --pdf` remains a stable deterministic artifact surface, but no public claim may describe it as board-ready until pagination, wrapping, and executive acceptance fixtures exist.
- Contract/runtime correctness and architecture-boundary work must precede later docs/onboarding/distribution waves when actual implementation is required.
- All behavior changes must preserve:
  - deterministic default execution
  - offline-first local fallback
  - fail-closed policy and filesystem safety
  - stable JSON and exit-code contracts unless an ADR explicitly approves additive evolution
- Thin orchestration remains in `core/cli/*`; focused packages/helpers should carry parsing, persistence, rendering, fix-apply, and action-wrapper behavior.
- Stories that touch architecture, adapters, failure semantics, or public CLI contracts must run `make prepush-full`.
- Reliability/fault-tolerance stories must run `make test-hardening` and `make test-chaos`.
- Performance-sensitive stories must run `make test-perf`.
- No dashboard-first or managed-service-first scope belongs in this plan.

## Current Baseline (Observed)

- Preconditions validated:
  - `product/dev_guides.md` exists and is readable
  - `product/architecture_guides.md` exists and is readable
  - output path `product/PLAN_NEXT.md` resolves inside `/Users/tr/wrkr`
  - output path parent is writable
- Repository worktree was clean before this plan rewrite.
- OSS trust baseline files are present:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
- Core engineering baseline is strong:
  - `go build -o .tmp/wrkr ./cmd/wrkr`
  - `go test ./... -count=1`
  - `make lint-fast`
  - `make test-docs-consistency`
- The shipped discovery/evidence loop is real and validated:
  - `wrkr scan --path . --state ./.tmp/audit_run/repo-state.json --json`
  - `wrkr evidence --frameworks eu-ai-act,soc2 --state ./.tmp/audit_run/repo-state.json --output ./.tmp/audit_run/evidence --json`
  - `wrkr verify --chain --state ./.tmp/audit_run/repo-state.json --json`
  - `wrkr regress init --baseline ./.tmp/audit_run/repo-state.json --output ./.tmp/audit_run/baseline.json --json`
  - `wrkr regress run --baseline ./.tmp/audit_run/baseline.json --state ./.tmp/audit_run/repo-state.json --json`
- Aha path baseline:
  - curated scenario scan produced `131` findings, `19` tools, `19` agents, and immediately legible top risks
  - repo-root scan produced `6769` findings and an `F` posture score because internal scenario/test fixtures dominate the result
- `wrkr fix` current behavior baseline:
  - `wrkr fix --top 3 --state ./.tmp/audit_scenario/state.json --json` produced remediation records with `patch_preview`
  - `docs/commands/fix.md` and `core/cli/fix.go` describe deterministic remediation artifacts and one PR update/create path
  - `core/fix/artifacts.go` writes `plan.json` plus `.patch` preview files under `.wrkr/remediations/<fingerprint>/`
- Action/distribution baseline:
  - `docs/commands/action.md` documents CLI subcommands `pr-mode` and `pr-comment`
  - repo search found no packaged GitHub Action entrypoint such as `action.yml`
- Executive PDF baseline:
  - generated markdown report length was `86` lines
  - `core/cli/report_pdf.go` currently renders a single-page PDF, steps fixed `0 -16 Td`, and truncates each line to `110` characters
- Filesystem safety baseline is strong and already validated in docs, code, tests, and live probes:
  - unmanaged materialized roots are blocked
  - non-managed evidence output directories are blocked
  - evidence markers reject directory and symlink forms

## Exit Criteria

1. The public minimum-now launch story is consistent across `README.md`, `product/wrkr.md`, command docs, examples, and docs-site entry points:
   - discovery
   - posture/risk
   - evidence
   - verify
   - regress
2. No public source claims that current Wrkr:
   - directly fixes repository files for top findings
   - opens one PR per finding
   - ships `Clyra-AI/wrkr-action@v1`
   - produces a board-ready PDF artifact
   unless the corresponding later wave has completed and its acceptance tests are green.
3. The evaluator-safe first-value path is scenario-first, integration-first, and explicit about repo-root fixture noise.
4. `wrkr fix`, `wrkr action`, and `wrkr report --pdf` help/docs/runtime wording are aligned to actual shipped behavior.
5. CI contains automated drift guards that fail when launch copy regresses into overclaiming before the runtime exists.
6. Minimum-now narrow launch can be approved after Wave 1 and Wave 2 only.
7. Broad-launch claims may be restored only after Wave 3, Wave 4, and Wave 5 complete in order.
8. Every story has deterministic, testable acceptance criteria, explicit lane wiring, and guide-compliant architecture constraints.

## Public API and Contract Map

Stable/public surfaces today:

- `wrkr scan`
- `wrkr evidence`
- `wrkr verify --chain`
- `wrkr regress init`
- `wrkr regress run`
- `wrkr report`
- `wrkr score`
- `wrkr inventory`
- `wrkr mcp-list`
- `wrkr fix`
- `wrkr action pr-mode`
- `wrkr action pr-comment`

Stable/public contract expectations today:

- `wrkr scan`, `wrkr evidence`, `wrkr verify`, `wrkr regress`, and `wrkr report` remain the core OSS value path.
- `wrkr fix` current stable contract is:
  - plan deterministic remediations
  - emit machine-readable plan metadata
  - optionally create or update one PR containing remediation artifacts and patch previews
- `wrkr action` current stable contract is:
  - CLI relevance/filter/comment logic only
  - no packaged GitHub Action surface yet
- `wrkr report --pdf` current stable contract is:
  - deterministic PDF file generation
  - no public quality guarantee beyond deterministic artifact output

Internal surfaces expected to change in later waves:

- `core/cli/fix.go`
- `core/fix/*`
- `core/github/pr/*`
- `core/cli/action.go`
- `core/action/*`
- `core/cli/report_pdf.go`
- `core/cli/report_artifacts.go`
- docs and examples tied to those surfaces
- new packaging files for GitHub Action distribution if Wave 4 lands

Shim/deprecation path:

- Wave 1 and Wave 2 are docs/help/enforcement alignment only; no runtime deprecations are needed.
- If Wave 3 lands, preserve current preview semantics for `wrkr fix` and add explicit apply semantics under a new flag or subcommand. Do not silently change current preview behavior.
- If Wave 4 lands, packaged action behavior must wrap existing CLI logic rather than duplicate it. CLI remains the authoritative engine.
- If Wave 5 lands, keep `--pdf` and `pdf_path` stable while replacing internal rendering mechanics.

Schema/versioning policy:

- Wave 1 and Wave 2 should not change JSON keys, exit codes, or schema versions.
- Wave 3 and Wave 4 may add flags or additive JSON fields, but must not rename or remove existing keys without:
  - ADR approval
  - docs updates
  - compatibility tests
- Wave 5 may change PDF bytes relative to prior goldens, but must preserve repeat-run determinism for a fixed version/input pair and keep CLI JSON/path contracts stable.

Machine-readable error expectations:

- No wave in this plan is allowed to weaken current exit-code stability.
- Any Wave 3 apply-mode or Wave 4 packaged-action work must preserve machine-readable error envelopes for automation consumers.
- Safety failures in future fix/apply/action scheduling work must fail closed, not silently downgrade into warnings.

## Docs and OSS Readiness Baseline

README first-screen contract:

- Must answer, in the first screen:
  - what Wrkr does
  - who it is for
  - the recommended first-value quickstart
  - the hosted-org prerequisites
  - the deterministic local fallback
- Must lead with the shipped wedge:
  - discovery
  - risk ranking
  - evidence
  - verify
  - regress
- Must not lead with:
  - auto-remediation
  - weekly PR cadence
  - packaged GitHub Action
  - executive PDF reporting

Integration-first docs flow:

- Preferred evaluator path:
  - `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
  - `wrkr evidence ... --json`
  - `wrkr verify --chain --json`
  - `wrkr regress ... --json`
- Recommended security/platform production path:
  - `wrkr scan --github-org ... --json`
  - `wrkr evidence ... --json`
  - `wrkr verify --chain --json`
- `wrkr fix`, `wrkr action`, and `wrkr report --pdf` are follow-on surfaces, not first-screen adoption anchors.

Lifecycle path model:

- Managed authoritative state remains under `.wrkr/`
- Scenario/demo docs must distinguish:
  - discovery/proof lifecycle state
  - fix preview artifacts
  - future apply-mode behavior if later waves land
  - CLI action surfaces vs future packaged action surface

Docs source-of-truth mapping:

- Product scope and persona story: `product/wrkr.md`
- Top-level first screen: `README.md`
- Command semantics: `docs/commands/*.md`
- Evaluator and operator flows: `docs/examples/*.md`
- Path model and failure semantics: `docs/state_lifecycle.md`, `docs/failure_taxonomy_exit_codes.md`
- Positioning and mental model: `docs/positioning.md`, `docs/concepts/mental_model.md`

OSS trust baseline:

- Keep existing trust files aligned with any public behavior changes:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
- Issue and PR templates are currently absent and not part of the minimum-now blocker set.
- If Wave 2 expands public maintainer/support expectations, update `CONTRIBUTING.md` and `SECURITY.md` in the same PR.

## Recommendation Traceability

| Recommendation ID | Recommendation | Story mapping |
|---|---|---|
| REC-01 | Keep launch copy centered on discovery, posture, evidence, verify, and regress | W1-S1, W2-S1 |
| REC-02 | Narrow persona promises to “see, rank, prove” until remediation/distribution catches up | W1-S1, W1-S3 |
| REC-03 | Preserve honest prerequisite framing for org posture and local fallback | W1-S1, W2-S1 |
| REC-04 | Put the curated scenario demo path more prominently in public onboarding | W2-S1 |
| REC-05 | Either ship true file-targeted remediation PRs or stop claiming that current Wrkr fixes the issue directly | W1-S2, W3-S1, W3-S2 |
| REC-06 | Either ship a real packaged GitHub Action and scheduled mode or position v1 as CLI-first | W1-S3, W4-S1, W4-S2 |
| REC-07 | Either build proper PDF rendering or stop promising a board-ready PDF | W1-S2, W5-S1, W5-S2 |
| REC-08 | Convert broad-launch no-go into narrow-launch go with explicit wave order | W1-S1, W2-S1, Minimum-Now Sequence |

## Test Matrix Wiring

Fast lane:

- `make prepush`
- `make test-docs-consistency`

Core CI lane:

- `make prepush-full`

Acceptance lane:

- `scripts/run_v1_acceptance.sh --mode=local`
- scoped `go test ./internal/e2e/... -count=1`
- scoped `go test ./internal/integration/... -count=1`

Cross-platform lane:

- `windows-smoke`
- any repo-root CLI smoke already required by `.github/required-checks.json`

Risk lane:

- `make test-risk-lane`
- required for Wave 3, Wave 4 scheduled-mode work, and any story that changes failure semantics or stateful orchestration

Merge/release gating rule:

- `fast-lane` and `windows-smoke` remain required PR checks.
- Stories that touch architecture, adapters, failure semantics, or public CLI behavior must also be wired to `make prepush-full` before merge.
- Stories that add stateful remediation apply flows, scheduled action flows, or deterministic rendering changes must not merge until scoped acceptance and risk lanes are green.
- Broad-launch claims may not be restored until all dependent later-wave stories are complete and their scoped gates are green.

## Epic Wave 1: Contract-Truth Launch Reset

Objective: Close the P0 launch blockers by making every public statement match the shipped discovery/evidence CLI and by preventing copy drift from reintroducing unshipped claims.

### Story W1-S1: Reset First-Screen Positioning and Persona Promises to the Shipped Wedge

Priority: P0
Tasks:
- Rewrite README first-screen copy to lead with discovery, posture, evidence, verify, and regress.
- Rewrite `product/wrkr.md` positioning/persona language so minimum-now v1 is CLI-first and discovery-first.
- Update `docs/positioning.md`, `docs/concepts/mental_model.md`, and related examples to remove broad-launch overclaiming.
- Make the curated scenario flow the explicit evaluator-first quickstart above repo-root scanning.
- Add or extend docs/hygiene enforcement so required first-screen elements and forbidden overclaim phrases are tested.
Repo paths:
- `README.md`
- `product/wrkr.md`
- `docs/positioning.md`
- `docs/concepts/mental_model.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/README.md`
- `testinfra/hygiene`
- `scripts/check_docs_storyline.sh`
Run commands:
- `make test-docs-consistency`
- `scripts/run_docs_smoke.sh --subset`
- `go test ./testinfra/hygiene -count=1`
Test requirements:
- docs consistency checks
- docs storyline/smoke checks
- README first-screen contract checks
- docs source-of-truth mapping checks
Matrix wiring:
- Fast lane: `make test-docs-consistency`
- Core CI lane: `go test ./testinfra/hygiene -count=1`
- Acceptance lane: not required
- Cross-platform lane: `windows-smoke`
- Risk lane: not required
Acceptance criteria:
- README and PRD first screen no longer present Wrkr as an auto-remediation or packaged-action product.
- The recommended first-value path is scenario-first and integration-first.
- Public positioning consistently describes Wrkr as the See/discovery boundary.
- Automated docs/hygiene checks fail if forbidden overclaim phrases reappear.
Contract/API impact:
- Docs-only public contract alignment; no JSON, exit-code, or schema change.
Versioning/migration impact:
- None.
Architecture constraints:
- Preserve the discovery vs control boundary.
- Keep the Go CLI and file-based artifacts as the authoritative product center.
- Maintain integration-first guidance rather than internals-first guidance.
ADR required: no
TDD first failing test(s):
- Add a failing docs/hygiene assertion for required README first-screen elements.
- Add a failing forbidden-phrase assertion for packaged action, direct fix, and board-ready PDF claims.
Cost/perf impact: low
Chaos/failure hypothesis:
- If launch copy drifts back toward broad-launch overclaims, docs/hygiene gates fail before merge.

### Story W1-S2: Align `wrkr fix` and `wrkr report --pdf` Contracts to Runtime Truth

Priority: P0
Tasks:
- Update `docs/commands/fix.md`, `product/wrkr.md`, and operator examples to describe current preview-plan behavior accurately.
- Update `docs/commands/report.md` and product language to stop claiming current PDF output is board-ready.
- Tighten CLI help text in `core/cli/fix.go` and any related help surfaces if wording still implies direct apply semantics.
- Add help/usage and docs parity tests for the clarified `fix` and `report` contracts.
Repo paths:
- `docs/commands/fix.md`
- `docs/commands/report.md`
- `docs/examples/operator-playbooks.md`
- `product/wrkr.md`
- `README.md`
- `core/cli/fix.go`
- `core/cli/report.go`
- `core/cli/root_test.go`
- `core/cli/report_contract_test.go`
Run commands:
- `go test ./core/cli -run 'TestFix|TestReport' -count=1`
- `make test-docs-consistency`
- `make prepush`
Test requirements:
- help/usage tests
- docs CLI parity tests
- machine-readable contract stability tests to confirm no JSON/exit regressions
- docs storyline/smoke checks for user-facing flow wording
Matrix wiring:
- Fast lane: `make prepush`
- Core CI lane: `make test-docs-consistency`
- Acceptance lane: not required
- Cross-platform lane: `windows-smoke`
- Risk lane: not required
Acceptance criteria:
- No public source states that `wrkr fix --top 3` directly edits repo files or opens one PR per finding under current behavior.
- No public source states that the current `--pdf` output is board-ready.
- CLI help and docs say the same thing about `fix` and `report --pdf`.
- Existing JSON keys and exit codes remain unchanged.
Contract/API impact:
- Help text and docs wording only; current CLI runtime envelopes stay stable.
Versioning/migration impact:
- None.
Architecture constraints:
- Preserve explicit side-effect semantics.
- Do not imply `apply` where the current behavior is `plan` or `preview`.
- Keep the reporting contract deterministic and file-based.
ADR required: no
TDD first failing test(s):
- Add a failing CLI help/usage test that checks the `fix` contract sentence.
- Add a failing docs parity/storyline test that forbids board-ready PDF language.
Cost/perf impact: low
Chaos/failure hypothesis:
- If runtime help or docs diverge, help/usage or docs parity tests fail before merge.

### Story W1-S3: Align Action and Distribution Claims to the Actually Shipped CLI Surface

Priority: P0
Tasks:
- Remove or gate product and README claims that imply `Clyra-AI/wrkr-action@v1` currently exists.
- Rewrite `docs/commands/action.md` and related references to position CLI `pr-mode` / `pr-comment` as the current shipped surface.
- Add a guardrail test that prevents packaged-action claims from appearing unless an actual `action.yml` exists in the repo.
- Keep future packaged-action intent documented only as roadmap/follow-on scope, not as current product truth.
Repo paths:
- `product/wrkr.md`
- `README.md`
- `docs/commands/action.md`
- `docs/commands/index.md`
- `core/cli/action.go`
- `core/cli/root_test.go`
- `testinfra/hygiene`
Run commands:
- `go test ./core/cli -run 'TestAction' -count=1`
- `go test ./testinfra/hygiene -count=1`
- `make test-docs-consistency`
Test requirements:
- help/usage tests
- docs consistency checks
- docs/source-of-truth guard that forbids packaged-action claims before packaging exists
Matrix wiring:
- Fast lane: `make test-docs-consistency`
- Core CI lane: `go test ./core/cli -run 'TestAction' -count=1`
- Acceptance lane: not required
- Cross-platform lane: `windows-smoke`
- Risk lane: not required
Acceptance criteria:
- No current public source claims packaged action availability.
- Current docs clearly state that action support today is CLI-based.
- A guardrail test fails if the packaged-action claim returns before the package exists.
Contract/API impact:
- Docs/help alignment only; current CLI JSON and exit contracts remain unchanged.
Versioning/migration impact:
- None.
Architecture constraints:
- Future packaging must wrap the CLI engine rather than copy logic.
- Keep the distribution layer thin and deterministic.
ADR required: no
TDD first failing test(s):
- Add a failing hygiene test that checks for `action.yml` before allowing packaged-action wording.
Cost/perf impact: low
Chaos/failure hypothesis:
- If a future docs change reintroduces packaged-action claims without runtime packaging, hygiene tests fail before merge.

## Epic Wave 2: Aha-First OSS Onboarding

Objective: Convert the current strong curated-scenario experience into the official first-value onboarding path and prevent evaluators from mistaking repo-fixture noise for product failure.

### Story W2-S1: Promote the Evaluator-Safe Scenario Demo Path and Explain Repo-Root Noise

Priority: P1
Tasks:
- Move the curated scenario command path higher than repo-root scan references in onboarding docs.
- Add explicit explanation for why scanning the Wrkr repo root is noisy.
- Keep org prerequisites honest and local fallback explicit.
- Refresh example outputs/screenshots/snippets so they use the scenario path where that helps first value.
Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/README.md`
- `docs/map.md`
- `docs/install/minimal-dependencies.md`
Run commands:
- `make test-docs-consistency`
- `scripts/run_docs_smoke.sh --subset`
- `scripts/test_uat_local.sh --skip-global-gates`
Test requirements:
- docs consistency checks
- docs storyline/smoke checks for user-flow order
- version/install discoverability checks (`wrkr version`, pinned install guidance)
- quickstart smoke for the promoted evaluator path
Matrix wiring:
- Fast lane: `make test-docs-consistency`
- Core CI lane: `scripts/run_docs_smoke.sh --subset`
- Acceptance lane: `scripts/test_uat_local.sh --skip-global-gates`
- Cross-platform lane: `windows-smoke`
- Risk lane: not required
Acceptance criteria:
- First-value evaluator flow uses the curated scenario path.
- Repo-root fixture noise is explicitly explained where needed.
- Hosted org prerequisites and deterministic local fallback remain easy to find.
- Install and `wrkr version --json` verification remain prominent.
Contract/API impact:
- Docs-only onboarding change; runtime contracts unchanged.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep offline-first fallback explicit.
- Do not imply any runtime behavior that the core CLI does not currently provide.
- Preserve integration-before-internals ordering.
ADR required: no
TDD first failing test(s):
- Add a failing docs storyline test for scenario-first onboarding order.
- Add a failing quickstart smoke assertion that the evaluator path remains copy-pasteable.
Cost/perf impact: low
Chaos/failure hypothesis:
- If future edits bury the first-value path behind repo-root scans or hosted prerequisites, docs smoke and UAT checks fail.

### Story W2-S2: Add Automated Launch-Truth Drift Guards to Docs and Hygiene

Priority: P1
Tasks:
- Codify the launch-truth contract in `testinfra/hygiene` and/or docs consistency scripts.
- Enforce required README first-screen sections and forbidden overclaim phrases.
- Add docs source-of-truth mapping checks for `README.md`, `product/wrkr.md`, and command docs.
- Ensure `CHANGELOG.md` update expectations are explicit when public behavior wording changes.
Repo paths:
- `testinfra/hygiene`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `README.md`
- `product/wrkr.md`
- `CHANGELOG.md`
Run commands:
- `go test ./testinfra/hygiene -count=1`
- `make test-docs-consistency`
- `make prepush`
Test requirements:
- docs consistency checks
- README first-screen checks
- integration-before-internals guidance checks
- docs source-of-truth mapping checks
- OSS readiness checks for touched trust files
Matrix wiring:
- Fast lane: `make prepush`
- Core CI lane: `go test ./testinfra/hygiene -count=1`
- Acceptance lane: not required
- Cross-platform lane: `windows-smoke`
- Risk lane: not required
Acceptance criteria:
- CI fails if forbidden claims return before the corresponding runtime/package wave is complete.
- Docs source-of-truth drift is detectable and merge-blocking.
- `CHANGELOG.md` expectations are explicit for public contract wording changes.
Contract/API impact:
- Internal enforcement only; no public runtime contract change.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep enforcement thin and auditable.
- Avoid brittle copy-locking beyond explicit contract phrases and required sections.
- Favor focused hygiene tests over ad hoc shell greps where practical.
ADR required: no
TDD first failing test(s):
- Add failing hygiene tests for forbidden `fix`, `action`, and `board-ready PDF` claims.
- Add failing source-of-truth drift tests for README/product/command-doc alignment.
Cost/perf impact: low
Chaos/failure hypothesis:
- If launch copy regresses during fast-moving follow-on work, hygiene gates catch it before public docs diverge.

## Epic Wave 3: Remediation Engine from Patch Preview to Real Repo Mutation

Objective: Restore future remediation claims only by shipping an explicit, fail-closed apply mode that edits real target files rather than only emitting patch previews.

### Story W3-S1: Introduce Explicit Fix Apply Mode with Fail-Closed Target Resolution

Priority: P1
Tasks:
- Write an ADR for `plan` versus `apply` semantics so the public contract remains explicit and symmetric.
- Keep current preview mode stable and add a new explicit apply surface for supported remediation templates.
- Implement deterministic target resolution for supported fix types and block ambiguous or unsafe targets.
- Ensure apply mode produces real repo file diffs in PRs, not only `.patch` artifacts.
- Update docs/help and add compatibility notes for preview versus apply behavior.
Repo paths:
- `core/cli/fix.go`
- `core/fix/planner.go`
- `core/fix/artifacts.go`
- `core/fix/*`
- `core/github/pr/*`
- `docs/commands/fix.md`
- `docs/examples/operator-playbooks.md`
- `internal/integration/fix`
- `internal/e2e/github_pr`
- `testinfra/contracts`
Run commands:
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `go test ./internal/integration/fix -count=1`
- `go test ./internal/e2e/github_pr -count=1`
Test requirements:
- help/usage tests
- `--json` stability tests
- exit-code contract tests
- machine-readable error envelope tests
- deterministic allow/block fixtures for target resolution
- fail-closed ambiguous-target tests
- reason-code stability checks
- byte-stability repeat-run tests for generated branch/file sets
- crash-safe and atomic-write tests for any local staging state
Matrix wiring:
- Fast lane: `make prepush`
- Core CI lane: `make prepush-full`
- Acceptance lane: `go test ./internal/integration/fix -count=1` and `go test ./internal/e2e/github_pr -count=1`
- Cross-platform lane: `windows-smoke`
- Risk lane: `make test-hardening` and `make test-chaos`
Acceptance criteria:
- Supported fix templates can produce actual repo file edits under an explicit apply surface.
- Current preview behavior remains available and unchanged for existing consumers.
- Ambiguous or unsafe targets fail closed with deterministic machine-readable errors.
- PRs created by apply mode show real changed files rather than only preview artifacts.
Contract/API impact:
- Additive CLI surface and additive JSON fields may be introduced.
- Existing preview-mode keys and exit codes must remain stable.
Versioning/migration impact:
- No schema bump planned.
- Additive migration note required in docs and changelog.
Architecture constraints:
- Thin CLI orchestration with focused apply logic packages.
- Explicit side-effect semantics in API naming (`plan` vs `apply`).
- Cancellation/timeout propagation for PR and network operations.
- Extension points for additional remediation templates without enterprise fork pressure.
ADR required: yes
TDD first failing test(s):
- Add a failing CLI contract test for the new apply surface.
- Add a failing integration test showing a supported remediation produces a real target-file diff.
- Add a failing fail-closed test for ambiguous patch targets.
Cost/perf impact: medium
Chaos/failure hypothesis:
- If network or file-apply steps fail mid-run, the command must not claim a successful applied remediation or leave partially staged state behind.

### Story W3-S2: Add Deterministic Multi-PR Orchestration and Idempotent Remediation Cadence

Priority: P2
Tasks:
- Add an explicit control for splitting top findings across up to `N` PRs.
- Make branch naming, grouping, and PR reuse deterministic across repeated runs.
- Ensure scheduled or repeated executions update existing PRs instead of spamming duplicates.
- Document multi-PR behavior and cap semantics.
Repo paths:
- `core/cli/fix.go`
- `core/github/pr/upsert.go`
- `core/fix/*`
- `docs/commands/fix.md`
- `internal/e2e/github_pr`
- `testinfra/contracts`
Run commands:
- `make prepush-full`
- `make test-hardening`
- `go test ./internal/e2e/github_pr -count=1`
- `make test-contracts`
Test requirements:
- CLI help/usage tests
- deterministic grouping and branch-name tests
- idempotent rerun tests
- machine-readable result envelope tests
- concurrency/contention tests where repeated runs touch the same repo target
Matrix wiring:
- Fast lane: `make prepush`
- Core CI lane: `make prepush-full`
- Acceptance lane: `go test ./internal/e2e/github_pr -count=1`
- Cross-platform lane: `windows-smoke`
- Risk lane: `make test-hardening`
Acceptance criteria:
- A configured top-N run can deterministically create or update up to N PRs.
- Repeated runs with the same inputs do not create duplicate PRs.
- PR grouping order is deterministic and documented.
Contract/API impact:
- Additive controls only; existing preview/apply semantics must remain stable.
Versioning/migration impact:
- None beyond additive docs/changelog updates.
Architecture constraints:
- Keep orchestration deterministic and stateless beyond explicit repo/branch state.
- No hidden background scheduling or out-of-band coordination.
ADR required: no
TDD first failing test(s):
- Add a failing e2e test for deterministic multi-PR grouping.
- Add a failing idempotency test for repeated runs against the same target repo.
Cost/perf impact: medium
Chaos/failure hypothesis:
- Concurrent or repeated scheduled runs must not diverge grouping order or create duplicate remediation PRs.

## Epic Wave 4: Packaged Action and Scheduled Distribution

Objective: Restore future distribution claims only by shipping a real GitHub Action package that wraps the CLI and by adding scheduled governance delivery in a deterministic, fail-closed way.

### Story W4-S1: Package `wrkr-action` as a Real GitHub Action Wrapper

Priority: P1
Tasks:
- Add a real `action.yml` package surface.
- Implement a thin action entrypoint that wraps the existing CLI `action` logic.
- Document action inputs, outputs, and token requirements.
- Add packaging smoke tests and e2e coverage for PR comment mode.
Repo paths:
- `action.yml`
- `scripts/action_entrypoint.sh`
- `docs/commands/action.md`
- `README.md`
- `internal/e2e/action`
- `testinfra/contracts`
Run commands:
- `make prepush-full`
- `go test ./internal/e2e/action -count=1`
- `make test-contracts`
- `make test-docs-consistency`
Test requirements:
- wrapper error-mapping tests
- adapter parity/conformance tests
- action output contract tests
- docs consistency and example checks
- idempotent PR comment update tests
Matrix wiring:
- Fast lane: `make prepush`
- Core CI lane: `make prepush-full`
- Acceptance lane: `go test ./internal/e2e/action -count=1`
- Cross-platform lane: `windows-smoke`
- Risk lane: not required
Acceptance criteria:
- The repo contains a real GitHub Action package.
- The packaged action wraps CLI `pr-mode` / `pr-comment` behavior without duplicating business logic.
- Relevant PR changes produce deterministic, idempotent comment updates.
- Docs can truthfully reference a packaged action surface after merge.
Contract/API impact:
- Additive packaged distribution surface.
- Existing CLI contracts remain authoritative and stable.
Versioning/migration impact:
- None; new distribution surface only.
Architecture constraints:
- Thin orchestration wrapper only.
- Explicit token and error mapping.
- No drift between package behavior and CLI engine behavior.
ADR required: yes
TDD first failing test(s):
- Add a failing e2e test that expects `action.yml` and packaged PR-comment behavior.
Cost/perf impact: low
Chaos/failure hypothesis:
- Missing token or irrelevant change sets must deterministically skip or fail with machine-readable output, never create comment spam.

### Story W4-S2: Add Scheduled Governance Mode with Posture Delta and Controlled Remediation Dispatch

Priority: P2
Tasks:
- Introduce scheduled-mode inputs/outputs for posture delta, summary artifact paths, and repeat-run behavior.
- Make scheduled mode dependent on the CLI scan/report/evidence flow rather than bespoke logic.
- Gate remediation dispatch on Wave 3 completion so scheduled runs do not overclaim direct fixes.
- Add acceptance coverage for summary-only and remediation-enabled scheduled runs.
Repo paths:
- `action.yml`
- `core/cli/action.go`
- `core/action/*`
- `docs/commands/action.md`
- `README.md`
- `internal/e2e/action`
- `.github/workflows/wrkr-action-ci.yml`
Run commands:
- `make prepush-full`
- `make test-hardening`
- `go test ./internal/e2e/action -count=1`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make test-docs-consistency`
Test requirements:
- action output contract tests
- lifecycle/repeat-run tests
- idempotency tests
- machine-readable error envelope tests
- docs consistency and quickstart/storyline checks if usage changes
- hardening coverage for scheduled orchestration failure paths
Matrix wiring:
- Fast lane: `make prepush`
- Core CI lane: `make prepush-full`
- Acceptance lane: `go test ./internal/e2e/action -count=1` and `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane: `windows-smoke`
- Risk lane: `make test-hardening`
Acceptance criteria:
- Scheduled mode emits deterministic posture delta and summary artifact references.
- Summary-only scheduled runs work before remediation dispatch is enabled.
- Remediation dispatch is unavailable or explicitly disabled until Wave 3 apply mode exists.
- Repeated scheduled runs remain idempotent.
Contract/API impact:
- Additive action inputs/outputs only.
Versioning/migration impact:
- None beyond additive docs/changelog updates.
Architecture constraints:
- Keep scheduled mode as thin orchestration over existing CLI flows.
- Propagate cancellation and timeout semantics.
- Avoid hidden background state or service dependencies.
ADR required: yes
TDD first failing test(s):
- Add a failing scheduled-mode acceptance fixture.
- Add a failing idempotent rerun test for scheduled summary output.
Cost/perf impact: medium
Chaos/failure hypothesis:
- Partial scan/evidence/report failures in scheduled mode must surface deterministic failure classes and must not emit false success summaries or remediation claims.

## Epic Wave 5: Executive PDF and Report Delivery Hardening

Objective: Restore future board-ready reporting claims only by replacing the current single-page/truncating PDF renderer with a deterministic, wrapped, paginated renderer and explicit acceptance fixtures.

### Story W5-S1: Replace the Single-Page PDF Renderer with Wrapped, Paginated Deterministic Output

Priority: P2
Tasks:
- Select and document a deterministic rendering approach that supports wrapping and pagination.
- Replace current one-page/truncating behavior in `core/cli/report_pdf.go`.
- Preserve `--pdf` and `pdf_path` public contract stability.
- Add pagination, wrapping, and repeat-run determinism tests.
- Update report docs to describe actual artifact quality guarantees.
Repo paths:
- `core/cli/report_pdf.go`
- `core/cli/report_artifacts.go`
- `docs/commands/report.md`
- `product/wrkr.md`
- `core/cli/report_contract_test.go`
- `testinfra/contracts`
Run commands:
- `make prepush-full`
- `make test-contracts`
- `go test ./core/cli -run 'TestReportPDF|TestReportContract' -count=1`
- `scripts/run_v1_acceptance.sh --mode=local`
Test requirements:
- byte-stability repeat-run tests
- pagination/wrapping fixture or golden tests
- CLI help/usage tests if wording changes
- docs consistency checks
- acceptance coverage for a long multi-section report fixture
Matrix wiring:
- Fast lane: `make prepush`
- Core CI lane: `make prepush-full`
- Acceptance lane: `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane: `windows-smoke`
- Risk lane: not required
Acceptance criteria:
- Long summaries no longer silently fall off-page.
- Critical report content is wrapped or paginated rather than truncated away.
- Fixed-input PDF generation remains deterministic within the version.
- CLI JSON/path contracts remain unchanged.
Contract/API impact:
- Artifact-quality improvement only; flag and JSON contracts stay stable.
Versioning/migration impact:
- No JSON/schema bump.
- One-time PDF golden refresh is acceptable and must be documented in the same PR.
Architecture constraints:
- Deterministic rendering only.
- Any new dependency must be pinned and justified.
- No runtime network/font/download dependency is allowed.
ADR required: yes
TDD first failing test(s):
- Add a failing PDF contract test for a multi-page or long-line fixture that current renderer cannot represent correctly.
Cost/perf impact: medium
Chaos/failure hypothesis:
- Oversized or unusually formatted reports must degrade deterministically or fail explicitly; they must never emit corrupted partial PDFs.

### Story W5-S2: Add Executive Report Acceptance Fixtures and Restore the Board-Ready Claim Only After Passing

Priority: P2
Tasks:
- Add explicit acceptance fixtures for a one-page executive summary and a longer detailed report.
- Define measurable acceptance checks for visibility of key metrics and section coverage.
- Restore product/README claim language only after those fixtures and render checks are green.
- Update changelog/docs to record the claim restoration.
Repo paths:
- `internal/acceptance`
- `product/wrkr.md`
- `README.md`
- `docs/commands/report.md`
- `CHANGELOG.md`
Run commands:
- `scripts/run_v1_acceptance.sh --mode=local`
- `make test-docs-consistency`
- `go test ./internal/acceptance -count=1`
Test requirements:
- acceptance fixtures
- docs consistency checks
- README first-screen checks
- changelog/docs source-of-truth checks for restored claims
Matrix wiring:
- Fast lane: `make test-docs-consistency`
- Core CI lane: `go test ./internal/acceptance -count=1`
- Acceptance lane: `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane: `windows-smoke`
- Risk lane: not required
Acceptance criteria:
- Executive report fixtures prove the board-ready claim with explicit checks.
- Public claim restoration happens only in the same PR that adds the passing acceptance fixtures.
- README/product/report docs remain aligned.
Contract/API impact:
- Docs/positioning only after runtime acceptance proves the capability.
Versioning/migration impact:
- None.
Architecture constraints:
- Claim restoration must be evidence-backed and test-backed, not copy-led.
- Keep the report renderer deterministic and offline-safe.
ADR required: no
TDD first failing test(s):
- Add a failing acceptance check for executive summary visibility before restoring the claim.
Cost/perf impact: low
Chaos/failure hypothesis:
- If the renderer regresses after claim restoration, acceptance fixtures fail before release and the claim is blocked from reappearing.

## Minimum-Now Sequence

Wave 1:
- W1-S1
- W1-S2
- W1-S3

Wave 2:
- W2-S1
- W2-S2

Wave 3:
- W3-S1
- W3-S2

Wave 4:
- W4-S1
- W4-S2

Wave 5:
- W5-S1
- W5-S2

Dependency-driven execution order:

1. Complete Wave 1 first. This removes the release-blocking contract mismatch between shipped behavior and public claims.
2. Complete Wave 2 second. This improves evaluator aha and adds docs/hygiene guardrails so the minimum-now launch remains stable.
3. Stop after Waves 1 and 2 for the minimum-now launch. This is the narrow-launch go point.
4. Execute Wave 3 only when the team wants to restore direct-remediation claims and is ready to add explicit apply semantics.
5. Execute Wave 4 only after Wave 3 if scheduled remediation or packaged-action claims are to be restored.
6. Execute Wave 5 only when the team wants to restore board-ready PDF claims.
7. Do not restore any broad-launch copy until the dependent later wave is complete and its scoped acceptance/tests are green.

## Explicit Non-Goals

- No dashboard-first scope.
- No managed control-plane or hosted service work.
- No runtime enforcement or Gait product work in this repo.
- No weakening of existing determinism, offline-first defaults, or fail-closed semantics.
- No silent mutation of `wrkr fix` semantics without an explicit additive apply-mode contract.
- No packaged-action claim restoration before a real package exists.
- No board-ready PDF claim restoration before renderer and acceptance work land.
- No issue/PR-template or other OSS-polish-only work as a primary blocker unless later waves explicitly expand maintainer workflow scope.

## Definition of Done

- Every audit recommendation maps to at least one story in this plan.
- Wave 1 and Wave 2 together are sufficient to move Wrkr from broad-launch no-go to narrow-launch go.
- After Wave 1 and Wave 2:
  - README, PRD, docs, examples, and help text consistently match shipped behavior
  - evaluator onboarding is scenario-first and explicit about repo-root fixture noise
  - docs/hygiene guardrails block overclaim regression
  - no JSON, exit-code, or schema regressions were introduced
- Later-wave claims are restored only after their corresponding implementation and acceptance stories pass.
- Every implementation story in this plan has:
  - repo-real paths
  - deterministic acceptance criteria
  - explicit lane wiring
  - guide-compliant architecture constraints
  - TDD-first failing tests
  - documented cost/perf impact
  - a chaos/failure hypothesis when risk-bearing

---
name: initial-plan
description: Transform the Wrkr PRD in product/wrkr.md into a world-class, zero-ambiguity execution plan that mirrors the detail level of product/PLAN_v1.md (or gait/product/PLAN_v1.md when needed), while enforcing product/dev_guides.md and product/architecture_guides.md standards for coding, testing, CI, determinism, architecture governance, and contracts. Use when the user asks for an initial build plan from the PRD (not from ideas/recommendations).
disable-model-invocation: true
---

# PRD to Initial Execution Plan (Wrkr)

Execute this workflow when asked to create the initial execution plan from the Wrkr PRD.

## Scope

- Repository root: `.`
- Primary source of truth: `./product/wrkr.md`
- Standards sources of truth:
  - `./product/dev_guides.md`
  - `./product/architecture_guides.md`
- Style reference (structure and depth): `./product/PLAN_v1.md`
- Default output: `./product/PLAN_v1.0.md` (unless user specifies a different target path)
- Planning only. Do not implement code or docs outside the target plan file.

## Preconditions

`wrkr.md` must contain enough implementation detail to drive execution planning. At minimum:
- product scope and goals
- functional requirements
- non-functional requirements
- acceptance criteria
- architecture and tech choices
- CLI surfaces and expected behavior

`product/dev_guides.md` and `product/architecture_guides.md` must define enforceable engineering standards. At minimum:
- toolchain versions
- lint/format requirements
- testing tiers and commands
- CI pipeline expectations
- determinism and contract requirements

If these are missing, stop and output a gap note instead of inventing policy.

## Workflow

1. Read `product/wrkr.md` and extract:
- core product objective and boundaries
- FR/NFR requirements
- acceptance criteria (ACs)
- architecture boundaries and non-goals
- CLI contracts (`--json`, `--explain`, `--quiet`, exit behavior)

2. Read `product/dev_guides.md` and extract locked implementation standards:
- toolchain pins (Go/Python/Node)
- lint and formatting stack
- test tier model (Tier 1-12) and where each tier runs
- CI lane expectations (PR/main/nightly/release)
- coverage gates, determinism, schema and exit code stability
- security scanning and release integrity expectations

3. Read `product/architecture_guides.md` and extract locked architecture execution standards:
- TDD requirements and first-failing-test expectations
- architecture constraints and ADR requirements
- cloud-native execution factors beyond 12-factor expectations
- frugal architecture/cost impact requirements
- chaos/hardening/perf lane triggers and failure-hypothesis expectations

4. Read `./product/PLAN_v1.md` (or `../gait/product/PLAN_v1.md` if local reference is unavailable) to mirror structure depth and story-level specificity.

5. Inspect current repository baseline and convert observed reality into a `Current Baseline (Observed)` section:
- existing directories and key files
- current CI/workflow state
- current command surfaces and gaps versus PRD

6. Build epics by implementation dependency, not by document order:
- Epic 0 foundations/scaffold/contracts
- core runtime epics (source, detection, aggregation, identity, risk, proof, compliance)
- CLI, regressions, and remediation flows
- docs/acceptance/release hardening epics

7. Decompose every epic into execution-ready stories with explicit tasks and test wiring.

8. Add a plan-level `Public API and Contract Map` section that defines:
- stable public surfaces vs internal surfaces
- shim/deprecation path and compatibility window
- schema/versioning policy (what is breaking, when to bump, migration expectations)
- machine-readable error envelope expectations for programmatic consumers
- install/version discoverability (`wrkr version`, minimal dependency install path)

9. Add a plan-level `Docs and OSS Readiness Baseline` section that defines:
- README first-screen contract (what it is, who it is for, how it integrates, first 10 minutes)
- integration-before-internals docs flow using problem -> solution framing
- file/state lifecycle diagram and canonical path model expectations
- single docs source-of-truth policy across repo docs and docs-site
- OSS trust baseline files and maintainer/support expectation clarity

10. Add a plan-level `Test Matrix Wiring` section that maps stories to:
- Fast lane
- Core CI lane
- Acceptance lane
- Cross-platform lane
- Risk lane
- Gating rule

11. Add a dependency-aware `Minimum-Now Sequence` with phased/week execution order and explicit wave order:
- Wave 1: contract/runtime correctness and architecture boundaries
- Wave 2: docs, OSS hygiene, and distribution UX
- Do not schedule Wave 2 stories ahead of Wave 1 dependencies

12. Add `Explicit Non-Goals` and `Definition of Done`.

13. Write the plan to the target file, replacing prior contents.

## Handoff Contract (Planning -> Implementation)

- This skill intentionally leaves the generated plan file modified in the working tree.
- Expected follow-up is an implementation skill on a new branch with that plan as input.
- If additional dirty files exist beyond the generated plan file, stop and scope/clean before implementation.

## Non-Negotiables

- Preserve Wrkr core contracts: deterministic execution, zero data exfiltration by default, fail-closed policy posture, stable schema contracts, stable exit code contracts.
- Keep architecture boundaries testable: source, detection, aggregation, identity, risk, proof, compliance mapping.
- Go core remains authoritative for enforcement and verification logic; Python remains a thin adoption layer.
- Do not introduce hosted-only dependencies into v1 core.
- Do not produce cosmetic/backlog fluff. Every story must be executable by an engineer without clarification meetings.
- No story is complete without same-change tests unless explicitly justified docs-only scope.

## Plan Format Contract

Required top sections:

1. `# PLAN <name>: <theme>`
2. `Date`, `Source of truth`, `Scope`
3. `Global Decisions (Locked)`
4. `Current Baseline (Observed)`
5. `Exit Criteria`
6. `Public API and Contract Map`
7. `Docs and OSS Readiness Baseline`
8. `Test Matrix Wiring`
9. `Epic` sections with objective and story breakdowns
10. `Minimum-Now Sequence` (phased, dependency-aware)
11. `Explicit Non-Goals`
12. `Definition of Done`

Story template (required fields):

- `### Story <ID>: <title>`
- `Priority:`
- `Tasks:`
- `Repo paths:`
- `Run commands:`
- `Test requirements:`
- `Matrix wiring:`
- `Acceptance criteria:`
- `Contract/API impact:` (required for CLI/schema/sdk/library stories)
- `Versioning/migration impact:` (required for schema/contract changes)
- `Architecture constraints:`
- `ADR required: yes|no`
- `TDD first failing test(s):`
- `Cost/perf impact: low|medium|high`
- `Chaos/failure hypothesis:` (required for risk-bearing stories)
- `Semantic invariants:` (required for stories touching identity/lifecycle/manifest/regress)
- Optional when needed:
- `Dependencies:`
- `Risks:`

## Dev Guides Enforcement Contract

For every story, derive required checks from `product/dev_guides.md` by work type. At minimum:

1. Toolchain/runtime changes:
- Lock versions to stated standards (Go 1.26.1, Python 3.13+, Node 22 docs/UI only).
- Include compatibility checks for shared `Clyra-AI/proof` constraints.

2. CLI surface changes (commands/flags/json/exits):
- Add CLI behavior tests and `--json` shape checks.
- Add exit code contract checks.
- Add docs parity checks for command/flag naming.

3. Schema/artifact/proof changes:
- Add schema validation and compatibility tests.
- Add golden fixtures and deterministic artifact checks.
- Add proof chain verify checks where applicable.

4. Detection/risk/policy semantics:
- Add deterministic fixture tests for allow/block/risk ranking behavior.
- Add fail-closed tests for undecidable/ambiguous high-risk paths.
- Add reason-code stability and ranking determinism checks.
- Add regression input-boundary tests (`policy_check`/`policy_violation`/`parse_error` must not become tracked tools).
- Add lifecycle preservation tests (`present=false` identities must not be rewritten to `present=true` by generation flows).
- For stories that clean/reset output paths, add `non-empty + non-managed => fail` tests.
- Add marker trust tests (`marker must be regular file`; reject symlink/directory).

5. Runtime/state/concurrency:
- Add atomic write/checkpoint/lock contention tests.
- Add crash/retry/recovery behavior tests.

6. CI/release/security work:
- Wire required lint/security jobs (golangci-lint, gosec, govulncheck, ruff/mypy/bandit where applicable).
- Add release-integrity checks (SBOM/signing/provenance) when story scope touches release.

7. Docs/examples contract changes:
- Add command-smoke checks for documented flows.
- Update acceptance scripts if operator workflow changed.
- Enforce README first-screen contract (what/who/integration/quickstart).
- Keep integration guidance ahead of internals for changed user flows.
- Keep docs source-of-truth mapping explicit when repo docs/docs-site both change.

8. API/contract lifecycle changes:
- Update public API map classification (stable/internal/shim/deprecated).
- Define schema/version bump rationale and migration expectation for breaking changes.
- Add machine-readable error contract checks for programmatic consumers.
- Verify `wrkr version` and minimal install path discoverability remain accurate.

## Architecture Guides Enforcement Contract

For every story, enforce `product/architecture_guides.md` requirements:

1. TDD requirements:
- Capture first failing test(s) before implementation tasks.
- Require red-green-refactor intent in story acceptance criteria where behavior changes.

2. Architecture governance:
- Specify architecture constraints for layer boundaries touched.
- Mark `ADR required: yes` when changing boundary/data flow/contract/failure class.

3. Frugal architecture:
- Include cost/perf impact classification (`low|medium|high`).
- For perf-sensitive stories, include `make test-perf`.

4. Chaos/reliability operations:
- Risk-bearing stories must include failure hypothesis and lane wiring for:
  - `make test-hardening`
  - `make test-chaos`

5. Contract-first behavior:
- CLI/JSON/exit-code stories must state explicit invariants in acceptance criteria.

6. Boundary discipline and API semantics:
- Keep orchestration layers thin; move parsing/persistence/reporting/policy to focused packages.
- Make side effects explicit in API names and signatures.
- Preserve semantic symmetry (`read` vs `read+validate`, `plan` vs `apply`).
- Propagate `context.Context` cancellation/timeouts through long-running flows.
- Add extension points early for enterprise integrations to reduce fork pressure.

## Testing Tier Mapping (Mandatory)

When assigning `Test requirements:` and `Matrix wiring:` for each story, map to applicable dev-guides tiers explicitly:

1. Tier 1 Unit: pure package logic and parser/scorer unit coverage.
2. Tier 2 Integration: deterministic cross-component behavior with `-count=1`.
3. Tier 3 E2E: CLI invocation, JSON output, and exit code behavior.
4. Tier 4 Acceptance: scenario scripts for operator workflows and golden behavior.
5. Tier 5 Hardening: lock/atomic write/contention/retry/error-envelope resilience.
6. Tier 6 Chaos: controlled fault injection and resilience under failure.
7. Tier 7 Performance: benchmark and latency budget validation.
8. Tier 8 Soak: long-running stability and sustained contention.
9. Tier 9 Contract: schema, JSON shape, byte stability, exit contract compatibility.
10. Tier 10 UAT: install-path validation across source/release/homebrew flows.
11. Tier 11 Scenario: specification-driven outside-in scenario fixtures.
12. Tier 12 Cross-product Integration: compatibility checks with `Clyra-AI/proof`, Axym, and Gait contracts where touched.

High-risk stories must never stop at Tier 1-3 coverage only; include Tier 4/5/9 and add Tier 6/7/8 when risk profile warrants it.

## Test Matrix Wiring Contract

Every generated plan must include this section name exactly: `Test Matrix Wiring`.

The section must define:
- `Fast lane`: pre-push and rapid PR checks.
- `Core CI lane`: mandatory unit and integration checks.
- `Acceptance lane`: version-gated scenario scripts and operator-path checks.
- `Cross-platform lane`: Linux/macOS/Windows expectations for affected stories.
- `Risk lane`: hardening/chaos/performance/contract suites for high-risk stories.
- `Gating rule`: merge/release must block on required lane failure.

The matrix must explicitly map each story ID to one or more lanes.

## CI Pipeline Wiring Contract

In each plan, explicitly state where each required test set executes:

- PR pipeline: fast deterministic checks needed to review safely.
- Main pipeline: core integration/e2e/contract checks on push to main.
- Nightly pipeline: hardening/chaos/performance/soak suites.
- Release pipeline: signing/provenance/security and release acceptance gates.

Each story must identify pipeline placement for its required suites.

## Command Anchors

Include concrete story tasks that reference verifiable command surfaces, including:
- `wrkr scan --json`
- `wrkr regress run --baseline <baseline-path> --json`
- `wrkr verify --chain --json`
- `go test ./...`
- `go test ./... -count=1`

## Quality Gate for Output

Before finalizing, verify:
- every epic traces back to specific FR/NFR/AC statements in `wrkr.md`
- every story has concrete repo paths and executable commands
- acceptance criteria are deterministic and objectively testable
- test requirements match `dev_guides.md` and `architecture_guides.md` requirements
- identity/lifecycle/manifest/regress stories include explicit semantic invariants
- every story includes architecture constraints, TDD first-failing-test requirement, and cost/perf impact
- high-risk stories include hardening/chaos lane wiring
- CLI contract stories include explicit `--json` and exit-code invariants
- API/contract map clearly classifies touched surfaces (stable/internal/shim/deprecated)
- schema/versioning and migration expectations are explicit for contract changes
- machine-readable error behavior is specified for automation/library consumers
- docs baseline covers first-screen README, integration-first flow, and lifecycle path model
- OSS trust baseline files/ownership expectations are planned or explicitly deferred
- sequence enforces Wave 1 before Wave 2 where both exist
- matrix wiring exists for every story
- sequence is dependency-aware and executable end-to-end
- plan respects Wrkr boundaries (See product only; no Axym/Gait feature scope creep)

## Failure Mode

If `wrkr.md`, `dev_guides.md`, or `architecture_guides.md` lacks required planning inputs, write only:

- `No initial plan generated.`
- `Reason:` concise blocker summary.
- `Missing inputs:` exact missing fields/sections needed to proceed.

Do not fabricate plan details when source standards are incomplete.

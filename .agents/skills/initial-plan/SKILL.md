---
name: initial-plan
description: Transform the Wrkr PRD in product/wrkr.md into a world-class, zero-ambiguity execution plan that mirrors the detail level of gait/product/PLAN_v1.md, while enforcing product/dev_guides.md coding, testing, CI, determinism, and contract standards. Use when the user asks for an initial build plan from the PRD (not from ideas/recommendations).
---

# PRD to Initial Execution Plan (Wrkr)

Execute this workflow when asked to create the initial execution plan from the Wrkr PRD.

## Scope

- Repository root: `/Users/davidahmann/Projects/wrkr`
- Primary source of truth: `/Users/davidahmann/Projects/wrkr/product/wrkr.md`
- Standards source of truth: `/Users/davidahmann/Projects/wrkr/product/dev_guides.md`
- Style reference (structure and depth): `/Users/davidahmann/Projects/wrkr/product/PLAN_v1.md`
- Default output: `/Users/davidahmann/Projects/wrkr/product/PLAN_v1.0.md` (unless user specifies a different target path)
- Planning only. Do not implement code or docs outside the target plan file.

## Preconditions

`wrkr.md` must contain enough implementation detail to drive execution planning. At minimum:
- product scope and goals
- functional requirements
- non-functional requirements
- acceptance criteria
- architecture and tech choices
- CLI surfaces and expected behavior

`dev_guides.md` must define enforceable engineering standards. At minimum:
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

3. Read `gait/product/PLAN_v1.md` to mirror structure depth and story-level specificity.

4. Inspect current repository baseline and convert observed reality into a `Current Baseline (Observed)` section:
- existing directories and key files
- current CI/workflow state
- current command surfaces and gaps versus PRD

5. Build epics by implementation dependency, not by document order:
- Epic 0 foundations/scaffold/contracts
- core runtime epics (source, detection, aggregation, identity, risk, proof, compliance)
- CLI, regressions, and remediation flows
- docs/acceptance/release hardening epics

6. Decompose every epic into execution-ready stories with explicit tasks and test wiring.

7. Add a plan-level `Test Matrix Wiring` section that maps stories to:
- Fast lane
- Core CI lane
- Acceptance lane
- Cross-platform lane
- Risk lane
- Gating rule

8. Add a dependency-aware `Minimum-Now Sequence` with phased/week execution order.

9. Add `Explicit Non-Goals` and `Definition of Done`.

10. Write the plan to the target file, replacing prior contents.

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
6. `Test Matrix Wiring`
7. `Epic` sections with objective and story breakdowns
8. `Minimum-Now Sequence` (phased, dependency-aware)
9. `Explicit Non-Goals`
10. `Definition of Done`

Story template (required fields):

- `### Story <ID>: <title>`
- `Priority:`
- `Tasks:`
- `Repo paths:`
- `Run commands:`
- `Test requirements:`
- `Matrix wiring:`
- `Acceptance criteria:`
- Optional when needed:
- `Dependencies:`
- `Risks:`

## Dev Guides Enforcement Contract

For every story, derive required checks from `product/dev_guides.md` by work type. At minimum:

1. Toolchain/runtime changes:
- Lock versions to stated standards (Go 1.25.7, Python 3.13+, Node 22 docs/UI only).
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
- test requirements match `dev_guides.md` tier expectations
- matrix wiring exists for every story
- sequence is dependency-aware and executable end-to-end
- plan respects Wrkr boundaries (See product only; no Axym/Gait feature scope creep)

## Failure Mode

If `wrkr.md` or `dev_guides.md` lacks required planning inputs, write only:

- `No initial plan generated.`
- `Reason:` concise blocker summary.
- `Missing inputs:` exact missing fields/sections needed to proceed.

Do not fabricate plan details when source standards are incomplete.

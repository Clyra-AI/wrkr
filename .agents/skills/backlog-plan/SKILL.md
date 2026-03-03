---
name: backlog-plan
description: Transform strategic recommendations in product/ideas.md into an execution-ready Wrkr backlog plan with epics, stories, tasks, repo paths, commands, acceptance criteria, and explicit test-matrix wiring.
disable-model-invocation: true
---

# Ideas to Backlog Plan (Wrkr)

Execute this workflow when asked to convert strategic feature recommendations into a concrete product backlog plan.

## Scope

- Repository root: `.`
- Input file: `./product/ideas.md`
- Standards sources of truth:
  - `./product/dev_guides.md`
  - `./product/architecture_guides.md`
- Structure references (match level of detail and style):
- `./product/PLAN_v1.md` (preferred local reference, if available)
- `../gait/product/PLAN_v1.md` (fallback reference, if available in your environment)
- Output file: `./product/PLAN_NEXT.md` (unless user specifies a different target)
- Planning only. Do not implement code or docs outside the target plan file.

## Preconditions

- `ideas.md` must contain strategic recommendations with evidence.
- Each recommendation should include:
- recommendation name
- why-now trigger
- strategic capability direction
- moat/benefit rationale
- source links

If these are missing, stop and output a gap note instead of inventing details.

- `product/dev_guides.md` and `product/architecture_guides.md` must exist and be readable.
- Both guides must provide enforceable planning constraints for:
  - testing/CI gates
  - determinism/contracts
  - architecture/TDD/chaos/frugal standards
- If either guide is missing or incomplete, stop with a blocker report.

## Workflow

1. Read `ideas.md` and extract candidate initiatives.
2. Read `product/dev_guides.md` and `product/architecture_guides.md` and lock constraints into planning decisions.
3. Read reference plans to mirror structure and detail level.
4. Cluster ideas into coherent epics (avoid one-idea-per-epic fragmentation).
5. Prioritize using `P0/P1/P2` based on contract risk reduction, moat expansion, adoption leverage, and sequencing dependency.
6. Produce execution-ready epics and stories.
7. For every story, include concrete tasks, repo paths, run commands, acceptance criteria, test requirements, CI matrix wiring, and architecture governance fields.
8. Add `Public API and Contract Map` with stable/internal surfaces, shim/deprecation plan, schema/versioning policy, and machine-readable error expectations.
9. Add `Docs and OSS Readiness Baseline` with README first-screen contract, integration-first docs flow, lifecycle path model, docs source-of-truth, and OSS trust baseline files.
10. Build a plan-level test matrix section mapping stories to CI lanes (fast, integration, acceptance, cross-platform).
11. Ensure each story defines tests based on work type (schema, CLI, gate/policy, determinism, runtime, SDK, docs/examples).
12. Add explicit boundaries and non-goals to prevent scope drift.
13. Add delivery sequencing section (phase/week-based minimum-now path) with explicit wave order:
- Wave 1: contract/runtime correctness and architecture boundaries
- Wave 2: docs, OSS hygiene, distribution UX
14. Add definition of done and release/exit gate criteria.
15. Write full plan to target file, overwriting prior contents.

## Handoff Contract (Planning -> Implementation)

- This skill intentionally leaves the generated plan file modified in the working tree.
- Expected follow-up is `backlog-implement` using that plan file on a new branch.
- If additional dirty files exist beyond the plan output, stop and scope/clean before implementation.

## Non-Negotiables

- Preserve Wrkr core contracts: determinism, offline-first defaults, fail-closed policy posture, schema stability, and exit code stability.
- Respect architecture boundaries: Go core is authoritative for enforcement/verification logic; Python remains thin adoption layer.
- Enforce both planning standards guides in all generated stories:
  - `product/dev_guides.md`
  - `product/architecture_guides.md`
- Avoid dashboard-first or hosted-only dependencies in backlog core.
- Do not include implementation code, pseudo-code, or ticket boilerplate.
- Do not recommend minor polish work as primary backlog items.
- Apply two-wave execution discipline when both classes exist (Wave 1 before Wave 2).
- Use shared cross-repo onboarding taxonomy when stories touch public docs (`README`, install, quickstart, integration, command docs).
- Every story must include test requirements and explicit matrix wiring.
- No story is complete without same-change test updates, except explicitly justified docs-only stories.

## Architecture Guides Enforcement Contract

For architecture/risk/adapter/failure stories, require wiring for:

- `make prepush-full`

For reliability/fault-tolerance stories, require wiring for:

- `make test-hardening`
- `make test-chaos`

For performance-sensitive stories, require wiring for:

- `make test-perf`

For boundary-sensitive stories, require architecture constraints to include:

- thin orchestration with focused packages for parsing/persistence/reporting/policy logic
- explicit side-effect semantics in API names/signatures
- symmetric API semantics (`read` vs `read+validate`, `plan` vs `apply`)
- cancellation/timeout propagation for long-running workflows
- extension points to avoid enterprise forks

## Test Requirements by Work Type (Mandatory)

1. Schema or artifact contract work:
- Add schema validation tests.
- Add or update golden fixtures.
- Add compatibility or migration tests.

2. CLI surface work (flags, args, `--json`, exits):
- Add command tests for help/usage behavior.
- Add `--json` stability tests.
- Add exit code contract tests.
- Add machine-readable error envelope tests for automation/library consumers when applicable.

3. Gate or policy semantics:
- Add deterministic allow/block/require_approval fixture tests.
- Add fail-closed tests for evaluator-missing or undecidable paths.
- Add reason code stability checks.
- Add regression input-boundary tests (`policy_check`/`policy_violation`/`parse_error` must not become tracked tools).
- Add lifecycle preservation tests (`present=false` identities must not be rewritten to `present=true` by generation flows).
- For stories that clean/reset output paths, require `non-empty + non-managed => fail` tests.
- Require marker trust tests (`marker must be regular file`; reject symlink/directory).

4. Determinism, hashing, signing, packaging:
- Add byte-stability tests for repeated runs with identical input.
- Add canonicalization and digest stability tests.
- Add verify/diff determinism tests.

5. Job runtime, state, concurrency, persistence:
- Add pause/resume/cancel/checkpoint lifecycle tests.
- Add crash-safe/atomic write tests.
- Add concurrent execution and contention tests.

6. SDK or adapter boundary work:
- Add wrapper behavior/error-mapping tests.
- Add adapter conformance tests against canonical sidecar/gate path.
- Preserve Go-authoritative decision boundary tests.

7. Docs/examples contract changes:
- Add command-smoke checks for documented flows.
- Add docs-versus-CLI parity checks where possible.
- Update acceptance scripts if docs alter required operator path.
- Ensure README first screen answers what/who/integration/first-value quickly.
- Ensure docs explain integration before internals for touched user flows.
- Keep docs source-of-truth mapping explicit when repo docs/docs-site are both changed.

8. API/contract lifecycle work:
- Add/update public API map classification (stable/internal/shim/deprecated) for touched surfaces.
- Add schema/version bump and migration expectation checks for contract changes.
- Verify install/version discoverability path (`wrkr version`, minimal dependency install guidance).

9. OSS readiness/doc ops work:
- Validate `CONTRIBUTING`, `CHANGELOG`, `CODE_OF_CONDUCT`, issue/PR templates, and security policy links when touched by story scope.
- Document maintainer/support expectations when public OSS behavior changes.

## Test Matrix Wiring Contract (Plan-Level)

Every generated plan must include a section named `Test Matrix Wiring` with:

- `Fast lane`: pre-push or quick CI checks required for each epic.
- `Core CI lane`: required unit/integration UAT checks in default CI.
- `Acceptance lane`: deterministic acceptance scripts required before merge or release.
- `Cross-platform lane`: Linux/macOS/Windows expectations for affected stories.
- `Risk lane`: extra suites for high-risk stories (policy, determinism, security, portability).
- `Gating rule`: merge/release block conditions tied to failed required lanes.

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
9. `Epic` sections with `Objective` and `Story` breakdowns
10. `Minimum-Now Sequence` (phased execution)
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
- Optional when needed:
- `Dependencies:`
- `Risks:`
- `Semantic invariants:` (required for stories touching identity/lifecycle/manifest/regress)

## Quality Gate for Output

Before finalizing, verify:

- Every epic maps back to at least one idea from `ideas.md`.
- Every story is actionable without guesswork.
- Acceptance criteria are testable and deterministic.
- Paths are real and repo-relevant.
- Test requirements match story work type.
- Matrix wiring is present for every story.
- Every story maps to enforceable rules from both guides (`dev_guides.md`, `architecture_guides.md`).
- High-risk stories include hardening/chaos lane wiring.
- CLI contract stories include explicit `--json` and exit-code invariants.
- API/contract map is explicit for touched surfaces and deprecations.
- Schema/versioning and migration expectations are explicit for contract changes.
- Docs baseline includes README first-screen, integration-first flow, and lifecycle path model.
- OSS trust baseline files/maintainer expectations are addressed or explicitly deferred.
- Sequence enforces Wave 1 before Wave 2 where both are present.
- Sequence is dependency-aware.
- Plan stays strategic and execution-relevant (not cosmetic).

## Command Anchors

- Include concrete plan tasks that reference verifiable CLI surfaces, for example:
  - `wrkr scan --json`
  - `wrkr regress run --baseline <baseline-path> --json`
  - `wrkr verify --chain --json`

## Failure Mode

If `ideas.md` lacks strategic quality or evidence, write only:

- `No backlog plan generated.`
- `Reason:` concise blocker summary.
- `Missing inputs:` exact missing fields required to proceed.

Do not fabricate backlog content when source strategy quality is insufficient.

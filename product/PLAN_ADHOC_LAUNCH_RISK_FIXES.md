# PLAN Adhoc: Launch Risk Expectation Alignment

Date: 2026-03-08
Source of truth: Audit findings provided in this run plus `product/dev_guides.md` and `product/architecture_guides.md`
Scope: Fix the top documented launch-risk gaps by aligning public messaging, first-run evidence expectations, OSS scope statements, and stale absolute path references without changing runtime behavior.

## Global Decisions (Locked)

- This plan is docs-and-contract focused. No runtime behavior, schemas, exit codes, or detector logic will change.
- Determinism, offline-first defaults, fail-closed semantics, and existing CLI JSON/exit contracts remain unchanged.
- Wave order is enforced:
  - Wave 1: public contract and expectation corrections
  - Wave 2: internal/public hygiene cleanup for stale absolute references
- README and `docs/` remain the canonical user-facing source of truth. `docs-site/public/llms.txt` and `docs-site/public/llm/*.md` are projection surfaces and must stay aligned when touched.
- `product/wrkr.md` may describe future direction, but unsupported OSS behavior must be labeled explicitly as roadmap/future and not presented as current shipped scope.

## Current Baseline (Observed)

- README promises "Read-only. No integration required." while the same README documents that `--repo` and `--org` require GitHub API configuration.
- First-run evidence coverage can be low on bundled scenarios and is already explained correctly in command docs, but not prominently enough in onboarding surfaces.
- The PRD still presents platform-signal surfaces as part of current scan scope even though the implemented OSS path is centered on repo enumeration/materialization and repo detectors.
- `product/dev_guides.md` and `product/architecture_guides.md` still reference stale absolute filesystem paths.
- Baseline validation before edits is required:
  - `make lint-fast`
  - `make test-fast`

## Exit Criteria

- Public onboarding and positioning surfaces clearly distinguish:
  - local/offline first value
  - hosted repo/org acquisition prerequisites
  - current OSS shipped discovery scope versus future/roadmap platform signals
- Evidence coverage messaging is visible in first-run docs so low initial framework coverage is not misread as product failure.
- Stale absolute filesystem paths are removed from touched product docs.
- All touched docs remain internally consistent across repo docs and docs-site projection files.
- Validation passes:
  - `make lint-fast`
  - `make test-fast`
  - `make test-docs-consistency`
  - `make test-docs-storyline`
  - `scripts/run_v1_acceptance.sh --mode=local`
  - `make codeql`

## Public API and Contract Map

- Stable:
  - CLI commands, flags, JSON envelopes, and exit codes under `cmd/wrkr` and `core/cli`
  - machine-readable docs in `docs/commands/*.md`
  - state/evidence lifecycle semantics in `docs/state_lifecycle.md`
- Internal:
  - planning docs in `product/`
  - docs-site projection content under `docs-site/public/`
- Shim/deprecation path:
  - none; no contract migration is introduced
- Schema/versioning policy:
  - no schema or version changes in this plan
- Machine-readable error expectations:
  - unchanged; docs may clarify them but not modify them

## Docs and OSS Readiness Baseline

- README first screen must state:
  - what Wrkr is
  - who it is for
  - that local path scans are integration-free
  - that repo/org scans require explicit GitHub acquisition setup
- Integration guidance must stay ahead of internals for changed flows.
- Evidence lifecycle and low-coverage interpretation must remain coherent with `docs/commands/evidence.md`.
- `docs/README.md` and `docs/map.md` remain source-of-truth anchors for docs ownership.
- OSS trust baseline files remain intact; only touched if necessary:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`

## Recommendation Traceability

| Recommendation | Why | Story IDs |
|---|---|---|
| Clarify first-run evidence coverage expectations | Prevent false negative first impression on audit-readiness value | S1 |
| Fix README "no integration required" ambiguity | Align public messaging with actual hosted acquisition prerequisites | S1 |
| Scope PRD platform signals as roadmap/future | Avoid claiming unsupported current OSS scan surfaces | S2 |
| Remove stale absolute paths in product docs | Eliminate public/internal hygiene drift and misleading local references | S3 |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - `make test-fast`
- Core CI lane:
  - `make test-docs-consistency`
  - `make test-docs-storyline`
- Acceptance lane:
  - `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane:
  - covered via `scripts/run_v1_acceptance.sh --mode=local` cross-platform build lane
- Risk lane:
  - `make codeql`
- Merge/release gating rule:
  - All above lanes must pass after implementation. No story is complete if its mapped lanes are red.

## Epic W1: Public Contract and Expectation Corrections

Objective: Align README, core docs, and docs-site projection surfaces with the actual shipped OSS product, especially around acquisition prerequisites and evidence coverage interpretation.

### Story S1: Align onboarding messaging for acquisition prerequisites and evidence expectations

Priority: P0
Tasks:
- Update README first-screen copy to distinguish local path scans from hosted repo/org scans.
- Add explicit first-run evidence coverage expectation language to README and quickstart-level docs.
- Update affected FAQ/positioning/operator guidance if needed so the same distinction is not contradicted elsewhere.
- Sync any touched docs-site LLM projection files for the changed onboarding language.
Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/faq.md`
- `docs/positioning.md`
- `docs/examples/operator-playbooks.md`
- `docs-site/public/llms.txt`
- `docs-site/public/llm/*.md`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
Test requirements:
- Docs/examples changes:
  - docs consistency checks
  - storyline/smoke checks
  - README first-screen what/who/integration/quickstart checks
- API/contract lifecycle and OSS-readiness changes:
  - version/install discoverability checks via `./.tmp/wrkr version --json`
Matrix wiring:
- Fast lane: baseline `make lint-fast`, `make test-fast`
- Core lane: `make test-docs-consistency`, `make test-docs-storyline`
- Acceptance lane: deferred to epic validation via `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane: deferred to epic validation via acceptance bundle
- Risk lane: deferred to plan validation via `make codeql`
Acceptance criteria:
- README no longer implies repo/org scans are integration-free.
- README and quickstart explicitly say local `--path` is the zero-integration first-value flow.
- Evidence coverage messaging states that low first-run coverage reflects current evidence state, not lack of framework support.
- No touched repo docs or docs-site projections contradict the new messaging.
Contract/API impact:
- None; docs-only clarification of existing behavior
Versioning/migration impact:
- None
Architecture constraints:
- Do not change runtime behavior or CLI contracts.
- Keep integration-first guidance ahead of internals.
ADR required: no
TDD first failing test(s):
- Docs parity/storyline checks as red/green validation for touched content
Cost/perf impact: low
Chaos/failure hypothesis:
- Not applicable; no runtime behavior changes

### Story S2: Relabel non-shipped platform signals in PRD as future roadmap scope

Priority: P1
Tasks:
- Update `product/wrkr.md` to distinguish current OSS shipped discovery scope from future/secondary platform signals.
- Ensure the PRD wording does not imply current support for IdP grants, GitHub App install discovery, or browser extension inventory in OSS.
- Keep positioning aligned with current implementation boundaries.
Repo paths:
- `product/wrkr.md`
Run commands:
- `make test-docs-consistency`
Test requirements:
- Docs/examples changes:
  - docs consistency checks for touched source-of-truth files
- API/contract lifecycle:
  - none; no machine contract changes
Matrix wiring:
- Fast lane: baseline `make lint-fast`, `make test-fast`
- Core lane: `make test-docs-consistency`
- Acceptance lane: deferred to epic validation via `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane: deferred to epic validation via acceptance bundle
- Risk lane: deferred to plan validation via `make codeql`
Acceptance criteria:
- `product/wrkr.md` clearly labels platform signals as future/additive rather than current OSS shipped scope.
- The PRD still preserves strategic direction without overstating current implementation.
Contract/API impact:
- None; planning-doc scope clarification only
Versioning/migration impact:
- None
Architecture constraints:
- Preserve the current source/detection boundary descriptions and do not imply runtime or hosted-control features.
ADR required: no
TDD first failing test(s):
- Docs consistency validation for touched file set
Cost/perf impact: low
Chaos/failure hypothesis:
- Not applicable; no runtime behavior changes

## Epic W2: Hygiene and Standards Path Cleanup

Objective: Remove stale absolute-path references from product guidance so public/internal guidance is portable and not tied to a maintainer workstation.

### Story S3: Replace stale absolute path references in product standards docs

Priority: P2
Tasks:
- Replace stale absolute path references in `product/dev_guides.md`.
- Replace stale absolute path references in `product/architecture_guides.md`.
- Keep guidance semantically identical while making references repo-relative and portable.
Repo paths:
- `product/dev_guides.md`
- `product/architecture_guides.md`
Run commands:
- `make test-docs-consistency`
Test requirements:
- Docs/examples changes:
  - docs consistency checks
- OSS readiness:
  - ensure touched policy docs remain coherent and portable
Matrix wiring:
- Fast lane: baseline `make lint-fast`, `make test-fast`
- Core lane: `make test-docs-consistency`
- Acceptance lane: deferred to plan validation via `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane: deferred to plan validation via acceptance bundle
- Risk lane: deferred to plan validation via `make codeql`
Acceptance criteria:
- No stale maintainer-specific absolute paths remain in the touched files.
- References are repo-relative or generic and still point readers to the correct canonical docs.
Contract/API impact:
- None
Versioning/migration impact:
- None
Architecture constraints:
- Preserve normative meaning; only path portability may change.
ADR required: no
TDD first failing test(s):
- Docs consistency validation for touched files
Cost/perf impact: low
Chaos/failure hypothesis:
- Not applicable; no runtime behavior changes

## Minimum-Now Sequence

1. Create this plan and validate it satisfies the implementation contract.
2. Branch from updated `origin/main` using the plan-handoff workflow.
3. Run baseline:
  - `make lint-fast`
  - `make test-fast`
4. Execute Wave 1:
  - S1
  - S2
5. Validate Wave 1:
  - `make test-docs-consistency`
  - `make test-docs-storyline`
  - `scripts/run_v1_acceptance.sh --mode=local`
6. Execute Wave 2:
  - S3
7. Run plan-level validation:
  - `make test-docs-consistency`
  - `make test-docs-storyline`
  - `scripts/run_v1_acceptance.sh --mode=local`
  - `make codeql`
8. Revalidate Exit Criteria and Definition of Done.

## Explicit Non-Goals

- No detector, source-acquisition, risk, proof, or evidence algorithm changes
- No new platform-signal adapters or enterprise-only discovery features
- No docs-site visual/layout work beyond projection sync needed for wording alignment
- No release tagging, commit, or push

## Definition of Done

- All in-scope stories S1-S3 are implemented.
- Wave 1 stories are completed and validated before Wave 2 is closed.
- Required validation commands pass with evidence captured.
- Public messaging no longer overclaims current OSS scope or obscures hosted acquisition prerequisites.
- First-run evidence expectations are explicit in onboarding surfaces.
- Stale absolute-path references are removed from touched product guides.

# PLAN WRKR_README_REFRAME: Locked README Rewrite, Contract Realignment, and Docs-Site Parity

Date: 2026-03-11  
Source of truth: user-provided main README rewrite dated 2026-03-11, `product/dev_guides.md`, `product/architecture_guides.md`, `AGENTS.md`, and the observed repo/docs/runtime baseline from this planning run  
Scope: Wrkr repository only. Planning artifact only. Two-wave plan. Wave 1 is contract/runtime correctness required to make the locked README commands truthful. Wave 2 is README/docs/OSS/distribution alignment around that locked README body.

## Global Decisions (Locked)

- The user-provided README markdown in Appendix A is a locked artifact. Implementation must copy it verbatim into `README.md` and must not paraphrase, reorder, or inject extra prose inside that locked body.
- Because the locked README diverges from the current Wrkr README contract, implementation must introduce an explicit new Wrkr README contract or documented variant. Do not silently weaken tests/scripts without documenting the new contract.
- Preserve Wrkr's deterministic, offline-first, fail-closed posture. No LLM calls, no dashboard-first scope, no default scan-data exfiltration, and no background services are allowed.
- Preserve architecture boundaries:
  - Source
  - Detection
  - Aggregation
  - Identity
  - Risk
  - Proof emission
  - Compliance mapping/evidence output
- Keep Go core authoritative for runtime behavior. Docs-site remains a projection/onboarding surface only and must not duplicate Go scan/risk/proof logic.
- Any runtime changes required by the locked README must be additive only. No public schema major bump and no exit-code changes are allowed.
- `wrkr-regress-baseline.json` remains the canonical artifact emitted by `wrkr regress init`. Any support for raw scan-state baselines in `wrkr regress run` is an additive compatibility path only.
- Pinned/reproducible install guidance remains mandatory in a canonical doc surface even though the locked README uses `go install github.com/Clyra-AI/wrkr/cmd/wrkr@latest`.
- Docs are executable contract. Any README/command/workflow change must ship with repo docs, docs-site projections, LLM projection files, and enforcement updates in the same implementation sequence.
- OSS trust/support discoverability cannot disappear. If the locked README omits current governance/support content, that discoverability must move to canonical docs/docs-site surfaces rather than being dropped.
- Required PR gates observed in-repo today are `fast-lane`, `scan-contract`, `wave-sequence`, and `windows-smoke`. Story-level lanes below add to, not replace, those gates.
- First-value outcome for this plan:
  - Developer: `wrkr scan --my-setup --json` -> `wrkr mcp-list --state ./.wrkr/last-scan.json --json` -> `wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json`
  - Security/platform: `wrkr scan --github-org ... --json` -> `wrkr evidence ... --json` -> `wrkr verify --chain ... --json`
- Time-to-value target after implementation:
  - Developer local posture value in under 10 minutes from install.
  - Security-team org posture handoff in one saved-state flow without README/docs drift.

## Current Baseline (Observed)

- `git status --short` was clean before this plan update.
- `README.md` currently follows the old shared section model:
  - `## Install`
  - `## First 10 Minutes (Offline, No Setup)`
  - `## Integration (One PR)`
  - `## Command Surface`
  - `## Trust and Project Relationship`
  - `## Governance and Support`
- `docs/contracts/readme_contract.md`, `scripts/check_docs_consistency.sh`, and `testinfra/hygiene/wave2_docs_contracts_test.go` currently enforce that old README section model, pinned Go install wording in `README.md`, docs-map linkage, and community health links in `README.md`.
- `docs/map.md` currently requires README first-screen changes to update docs-site LLM projection files in the same change.
- `docs-site/src/app/page.tsx` and `docs-site/public/llms.txt` still foreground `/scan`, `/docs/start-here`, `wrkr init`, and the current homepage messaging rather than the locked README narrative.
- `docs/commands/regress.md` and `core/cli/regress.go` currently treat `wrkr-regress-baseline.json` as the only accepted `regress run` baseline input. `runRegressRun` loads only `regress.Baseline`.
- `docs/commands/inventory.md` and the current README use `.wrkr/inventory-baseline.json` only for `inventory --diff`.
- The locked README's CI example uses:
  - `wrkr regress run --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json`
  - That example is not currently truthful against the CLI implementation and command docs.
- `core/evidence/evidence.go` and existing tests confirm `eu-ai-act`, `soc2`, and `pci-dss` are supported framework IDs.
- OSS trust baseline files already exist in-repo:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - issue templates under `.github/ISSUE_TEMPLATE/`
  - `.github/pull_request_template.md`
- `.github/required-checks.json` currently requires four merge-blocking checks:
  - `fast-lane`
  - `scan-contract`
  - `wave-sequence`
  - `windows-smoke`

## Exit Criteria

1. `README.md` matches Appendix A exactly.
2. Every command shown in Appendix A is truthful against current CLI behavior or an additive compatibility path implemented in the same rollout.
3. `wrkr regress run --baseline <scan-state-path> --state <current-state> --json` works deterministically when `<scan-state-path>` is a saved scan snapshot copied to `.wrkr/inventory-baseline.json`, without breaking current `wrkr-regress-baseline.json` behavior.
4. Existing regress exit codes and drift JSON contract remain stable.
5. Wrkr README contract enforcement no longer depends on the old section model, and the new contract is documented rather than implied.
6. Pinned/reproducible install guidance remains canonical and validated in install/release docs even though the locked README uses `@latest`.
7. `docs/examples/*`, `docs/commands/*`, `docs/positioning.md`, `docs/map.md`, docs-site landing content, and LLM projection files align with the new README narrative and workflow examples.
8. OSS trust/support discoverability remains explicit through canonical docs/docs-site/community-health surfaces even if absent from the main README.
9. Required PR checks and story-level lanes below pass before merge.

## Public API and Contract Map

Stable/public surfaces touched in this plan:

- `README.md` landing copy, install flow, developer workflow, security-team workflow, positioning, and learn-more links.
- `wrkr regress run --baseline <path> [--state <path>] --json`
- `docs/examples/quickstart.md`
- `docs/examples/personal-hygiene.md`
- `docs/examples/security-team.md`
- `docs/commands/scan.md`
- `docs/commands/mcp-list.md`
- `docs/commands/inventory.md`
- `docs/commands/evidence.md`
- `docs/commands/regress.md`
- `docs/commands/index.md`
- `docs/positioning.md`
- Public docs-site landing and AI/LLM projection surfaces under `docs-site/src/app/page.tsx` and `docs-site/public/*`

Internal surfaces expected to change:

- `core/cli/regress.go`
- `core/regress/*`
- `core/cli/root.go`
- `internal/e2e/regress/*`
- `testinfra/contracts/*`
- `testinfra/hygiene/*`
- `scripts/check_docs_consistency.sh`
- `docs/contracts/readme_contract.md`
- `docs/roadmap/cross-repo-readme-alignment.md`
- `docs/map.md`
- `docs/README.md`
- `docs/install/minimal-dependencies.md`
- `docs/trust/release-integrity.md`
- `docs-site/public/llms.txt`
- `docs-site/public/llm/*.md`
- `docs-site/src/lib/*`

Shim/deprecation path:

- `wrkr-regress-baseline.json` remains the canonical artifact emitted by `wrkr regress init`.
- Raw scan-state baseline support in `wrkr regress run` is additive only and must not deprecate `regress init`.
- The old README section model is deprecated for Wrkr landing content only after the new contract is documented and enforced.
- Browser bootstrap at `/scan` remains available but becomes subordinate to CLI-first onboarding; it is not removed.
- Pinned install remains canonical in install/release docs even though the locked README uses `@latest`.

Schema/versioning policy:

- No scan/evidence schema major bump is planned.
- Any `regress run` JSON additions must be additive, deterministic, and documented in `docs/commands/regress.md`.
- Exit-code behavior remains unchanged.
- If `docs/contracts/readme_contract.md` changes materially, the migration note must live in that doc and the cross-repo tracker must be updated in the same PR.

Machine-readable error expectations:

- `wrkr regress run --baseline` missing path remains `invalid_input` with exit `6`.
- Drift remains exit `5`.
- If a provided baseline path is neither a valid regress baseline artifact nor a valid scan snapshot, Wrkr must fail closed with a stable machine-readable error envelope.
- Existing supported regress workflows must retain stable `--json` payload shape and exit behavior.

## Docs and OSS Readiness Baseline

README first-screen contract:

- `README.md` becomes a locked landing surface focused on:
  - product one-liner
  - install
  - developer workflow
  - security-team workflow
  - why/value
  - detection scope
  - scope boundaries
  - Gait relationship
  - workflows
  - command surface
  - output/contracts
  - security/privacy
  - learn-more links
- Because the locked body omits the current trust/governance footer, `README.md` is no longer the only OSS trust discoverability surface.

Integration-first docs flow:

1. Main README points to `docs/commands/` and `docs/examples/`.
2. `docs/examples/personal-hygiene.md` remains the canonical developer local-machine workflow.
3. `docs/examples/security-team.md` remains the canonical security-team org/evidence workflow.
4. `docs/commands/*.md` remain the canonical command contracts.
5. `docs/install/minimal-dependencies.md` remains the canonical pinned/reproducible install guide.
6. `docs/state_lifecycle.md` remains the canonical artifact path/lifecycle reference.
7. Docs-site and LLM projections mirror the new README framing without inventing runtime behavior.

Lifecycle path model:

- `docs/state_lifecycle.md` remains canonical for:
  - `.wrkr/last-scan.json`
  - `.wrkr/inventory-baseline.json`
  - `.wrkr/wrkr-regress-baseline.json`
  - `.wrkr/wrkr-manifest.yaml`
  - `.wrkr/proof-chain.json`
  - evidence output directories
- Even if the locked README no longer links `docs/state_lifecycle.md`, quickstart and command docs still must.

Docs source-of-truth for this plan:

- Landing copy: `README.md`
- Install and release integrity: `docs/install/minimal-dependencies.md`, `docs/trust/release-integrity.md`
- Command contracts: `docs/commands/*.md`
- Workflow docs: `docs/examples/*.md`
- Positioning and docs governance: `docs/positioning.md`, `docs/map.md`, `docs/README.md`, `docs/contracts/readme_contract.md`
- Public projections: `docs-site/src/app/page.tsx`, `docs-site/public/llms.txt`, `docs-site/public/llm/*.md`

OSS trust baseline:

- `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, issue templates, and PR template remain mandatory.
- Maintainer/support expectations must stay discoverable from canonical docs/docs-site surfaces because the locked README omits the current footer.
- `docs/governance/content-visibility.md` remains authoritative for directory notice and review policy.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Replace `README.md` with the exact user-provided markdown | The user explicitly locked the landing copy | Tighten market-facing positioning and workflow framing | Clearer front-door message with lower copy ambiguity | W2-S02 |
| R2 | Make every command example in the locked README truthful | The locked README is public contract, not aspirational copy | Contract-first delivery | Prevents immediate trust loss and support burden | W1-S01, W2-S02 |
| R3 | Replace the old hard-coded README enforcement model with an explicit new Wrkr contract | Current tests/scripts would fail the locked README | Docs governance realignment | Keeps future README changes auditable rather than ad hoc | W2-S01 |
| R4 | Preserve reproducible install and OSS trust discoverability outside the locked README body | The locked README drops current pinned-install/governance footer content | Split landing copy from deeper install/trust contract docs | Keeps release integrity and OSS trust intact without changing the locked README | W2-S04 |
| R5 | Align docs-site and LLM projections with the new README | Current docs-site/LLM surfaces still project the old story | Distribution parity | Prevents repo/docs-site/assistant drift | W2-S03 |
| R6 | Keep developer and security-team examples consistent across README and canonical docs | README links must land on truthful workflows | Workflow coherence | Lower onboarding friction and faster first value | W2-S02, W2-S03, W2-S04 |

## Test Matrix Wiring

Fast lane:

- `make lint-fast`
- `make test-fast`
- targeted `go test` for changed `core/cli`, `core/regress`, `testinfra/hygiene`, and `testinfra/contracts` packages

Core CI lane:

- `make prepush`
- `make test-contracts`
- `make test-docs-consistency`
- `make test-docs-storyline`

Acceptance lane:

- `go test ./internal/scenarios -run '^TestScenarioContracts$' -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./internal/e2e/regress -count=1`
- `scripts/run_v1_acceptance.sh --mode=local` for public CLI contract stories
- `scripts/run_docs_smoke.sh`
- `make docs-site-install`
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`

Cross-platform lane:

- `windows-smoke`
- existing `core-matrix` behavior on Ubuntu/macOS/Windows when Go code changes

Risk lane:

- `make prepush-full`
- `make test-hardening`
- `make test-chaos`

Merge/release gating rule:

- Required PR checks remain `fast-lane`, `scan-contract`, `wave-sequence`, and `windows-smoke`.
- Any story touching public CLI/runtime behavior must also show green `make prepush-full` plus targeted contract/e2e evidence before merge.
- Any story touching README/docs/docs-site must also show green docs consistency/storyline/docs-site checks in the same PR.
- No release is allowed with unresolved drift between the locked README, canonical repo docs, and public docs-site/LLM projection surfaces.

## Epic W1-E1: Make Locked README CLI Examples Truthful

Objective: add only the runtime compatibility needed so the locked README's CI distribution example and workflow claims are accurate, while preserving current regress artifact behavior and deterministic exits.

### Story W1-S01: Accept scan-state baselines in `wrkr regress run` as an additive compatibility path
Priority: P0
Tasks:
- Add failing contract and e2e tests proving `wrkr regress run --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json` works when the baseline file is a raw scan snapshot.
- Extend baseline loading to detect and normalize either a persisted regress baseline artifact or a raw scan snapshot copied from `.wrkr/last-scan.json`.
- Preserve current `wrkr regress init` output path and existing `wrkr-regress-baseline.json` behavior.
- Keep JSON drift result shape and exit codes stable; if adding a baseline-type field, make it additive and deterministic.
- Update `wrkr help`, `docs/commands/regress.md`, and any relevant compatibility docs to explain the two accepted baseline inputs and the preferred/canonical path.
Repo paths:
- `core/cli/regress.go`
- `core/regress/*`
- `core/cli/root.go`
- `docs/commands/regress.md`
- `internal/e2e/regress/*`
- `testinfra/contracts/*`
Run commands:
- `go test ./core/regress ./core/cli -count=1`
- `go test ./internal/e2e/regress -count=1`
- `go test ./testinfra/contracts -run 'TestRegressDriftExitCodeContract|TestScanContract_NoJSONOrExitRegressionAcrossWaves' -count=1`
- `make test-contracts`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- CLI help/usage tests
- `--json` stability tests for both baseline input forms
- exit-code contract tests (`0`, `5`, `6`)
- compatibility tests proving current regress baseline artifacts remain valid
- additive raw scan-state baseline tests
- determinism repeat-run tests for the same baseline/state pairs
- machine-readable error envelope tests for invalid or ambiguous baseline files
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Cross-platform lane
- Risk lane
Acceptance criteria:
- `wrkr regress run` accepts a raw scan snapshot baseline without requiring an intermediate `regress init`.
- `wrkr regress run` continues to accept `wrkr-regress-baseline.json` without output or exit regression.
- Invalid baseline files still fail closed with deterministic machine-readable errors.
- `wrkr inventory --diff` behavior is unchanged.
- Docs and help text correctly distinguish `inventory-baseline.json` versus `wrkr-regress-baseline.json`.
Contract/API impact: additive public CLI contract expansion for `wrkr regress run --baseline`; no breaking change to existing flags, JSON keys, or exits.
Versioning/migration impact: no schema version bump; if a new JSON field is added to disclose normalized baseline input type, it must be additive only and documented.
Architecture constraints:
- Keep CLI orchestration thin; baseline format detection belongs in focused regress/state parsing helpers, not in report or docs layers.
- Preserve symmetric semantics: `inventory --diff` remains raw scan-state drift review, `regress run` remains policy/approval drift gate with additive convenience input handling.
- Preserve deterministic ordering and cancellation propagation for file loads.
- Do not add network calls or permissive fallback behavior.
ADR required: yes
TDD first failing test(s):
- Contract test: `regress run` accepts a raw scan snapshot baseline copied to `.wrkr/inventory-baseline.json`.
- Regression test: existing `wrkr-regress-baseline.json` still yields identical drift output as before.
- Error test: invalid baseline file fails closed with stable JSON error fields.
Cost/perf impact: low
Chaos/failure hypothesis: if the baseline path points to an unexpected but parseable JSON file, Wrkr must deterministically reject it rather than silently producing a no-drift result or an empty comparison.
Dependencies: none
Risks:
- Ambiguous baseline auto-detection could weaken fail-closed behavior if the format discriminator is too loose.
- Help/docs drift could leave users with two baseline concepts but only one clearly explained.

## Epic W2-E1: Replace the Front Door Without Losing Contract or Trust

Objective: roll out the exact user-supplied README copy and align all docs/distribution surfaces, while preserving reproducible install guidance, source-of-truth clarity, and OSS trust discoverability.

### Story W2-S01: Introduce a documented Wrkr README contract that matches the locked README body
Priority: P0
Tasks:
- Add failing docs-hygiene tests and/or consistency checks that express the new allowed Wrkr README structure and remove hard-coded dependence on the old section model.
- Revise `docs/contracts/readme_contract.md` to describe the new Wrkr landing contract and whether the old shared section model becomes deprecated or remains as a separate variant.
- Update `docs/roadmap/cross-repo-readme-alignment.md` to reflect the new contract stance for Proof/Gait and any required follow-up dates.
- Update `scripts/check_docs_consistency.sh` and `testinfra/hygiene/wave2_docs_contracts_test.go` to enforce the new contract intentionally rather than by omission.
- Record docs source-of-truth consequences in `docs/map.md` and `docs/README.md`.
Repo paths:
- `docs/contracts/readme_contract.md`
- `docs/roadmap/cross-repo-readme-alignment.md`
- `scripts/check_docs_consistency.sh`
- `testinfra/hygiene/wave2_docs_contracts_test.go`
- `docs/map.md`
- `docs/README.md`
- optional ADR path under `docs/decisions/`
Run commands:
- `go test ./testinfra/hygiene -run 'TestReadmeContractSectionsPresent|TestDocsSourceOfTruthSectionsPresent' -count=1`
- `make test-docs-consistency`
- `make test-docs-storyline`
- `make prepush`
Test requirements:
- docs consistency checks for the new README contract rules
- README first-screen checks
- docs source-of-truth mapping checks
- OSS readiness checks ensuring support/discoverability is still enforced somewhere canonical
- contract/hygiene tests for contract doc and cross-repo roadmap updates
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
Acceptance criteria:
- Wrkr README enforcement matches the intended new landing model and no longer depends on the old section names.
- Contract docs explain where governance/support and pinned install requirements moved if they no longer live in `README.md`.
- Cross-repo alignment tracker is explicit about Proof/Gait follow-ups instead of leaving silent divergence.
- Docs consistency/hygiene tests fail if the new Wrkr landing contract drifts.
Contract/API impact: public docs contract change for repo landing content; no CLI/runtime behavior change.
Versioning/migration impact: docs-contract-only migration note required in `docs/contracts/readme_contract.md`.
Architecture constraints:
- Keep docs governance explicit and auditable; do not weaken enforcement by deleting tests without replacement.
- Preserve `docs/map.md` as the source-of-truth router for docs edits and validation.
- Do not move product/runtime semantics into docs-site-only pages.
ADR required: yes
TDD first failing test(s):
- Hygiene test expecting the new Wrkr README contract structure.
- Consistency check failing until contract doc and tracker are updated.
Cost/perf impact: low
Chaos/failure hypothesis: if the README contract changes without matching test/script updates, docs consistency and hygiene checks must fail before merge.
Dependencies: W1-S01
Risks:
- Over-generalizing the new Wrkr README contract could create unnecessary cross-repo churn for Proof/Gait.
- Under-specifying the new contract could make future README edits unreviewable.

### Story W2-S02: Replace `README.md` with the exact locked markdown and align canonical repo docs to it
Priority: P0
Tasks:
- Copy the Appendix A markdown verbatim into `README.md`; do not paraphrase, reorder, or inject extra prose inside the locked body.
- Update workflow docs and command docs so the README links resolve and the referenced flows are consistent:
  - `docs/examples/quickstart.md`
  - `docs/examples/personal-hygiene.md`
  - `docs/examples/security-team.md`
  - `docs/commands/scan.md`
  - `docs/commands/mcp-list.md`
  - `docs/commands/inventory.md`
  - `docs/commands/evidence.md`
  - `docs/commands/regress.md`
  - `docs/commands/index.md`
  - `docs/positioning.md`
- Align any linked examples to the locked README narrative, including developer-first flow, security-team flow, Gait relationship, and explicit scope boundaries.
- Keep `docs/state_lifecycle.md` and pinned install guidance authoritative where the locked README is intentionally lighter.
- Add or update README-first-screen validation so future edits cannot drift from the locked body without an intentional contract change.
Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/examples/personal-hygiene.md`
- `docs/examples/security-team.md`
- `docs/commands/scan.md`
- `docs/commands/mcp-list.md`
- `docs/commands/inventory.md`
- `docs/commands/evidence.md`
- `docs/commands/regress.md`
- `docs/commands/index.md`
- `docs/positioning.md`
- `docs/state_lifecycle.md`
- `testinfra/hygiene/*`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `scripts/run_docs_smoke.sh`
- `go test ./testinfra/hygiene -count=1`
- `make prepush`
Test requirements:
- README first-screen checks, including exact-copy enforcement or locked-fragment enforcement
- docs consistency checks
- storyline/smoke checks for developer and security-team flows
- integration-before-internals guidance checks for touched flows
- version/install discoverability checks ensuring deeper pin/repro guidance remains reachable
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
Acceptance criteria:
- `README.md` matches Appendix A exactly.
- All README links resolve to existing docs.
- The developer flow (`scan --my-setup` -> `mcp-list` -> `inventory --diff`) and security-team flow (`scan --github-org` -> `evidence`) are consistent across README and `docs/examples`.
- The README's `regress run` example is truthful because W1-S01 shipped first.
- The README no longer overstates browser bootstrap or the old section-model promises.
Contract/API impact: user-facing docs contract only, except for reliance on the additive `regress run` baseline compatibility from W1-S01.
Versioning/migration impact: none beyond docs-contract migration already captured in W2-S01.
Architecture constraints:
- Preserve integration-before-internals ordering in docs.
- Keep runtime truth anchored in Go CLI behavior and command docs, not marketing copy alone.
- Do not widen product scope beyond current deterministic/file-based boundaries.
ADR required: no
TDD first failing test(s):
- README contract/hygiene check comparing `README.md` against the locked expected body or required verbatim sections.
- Docs storyline smoke failing until linked examples and command docs align.
Cost/perf impact: low
Chaos/failure hypothesis: if the locked README is applied without updating linked docs, docs consistency and storyline smoke should fail before merge.
Dependencies: W1-S01, W2-S01
Risks:
- Exact-copy enforcement can create noisy diffs if not paired with a clear contract update path.
- Linked docs may accidentally preserve older terminology and cause partial drift.

### Story W2-S03: Align docs-site landing and LLM projection surfaces with the new README narrative
Priority: P1
Tasks:
- Update `docs-site/src/app/page.tsx` hero, quickstart, FAQ, and supporting callouts to match the locked README's positioning and command flow.
- Update `docs-site/public/llms.txt` and the relevant `docs-site/public/llm/*.md` projections so assistant/crawler context reflects the new README, supported flows, and baseline semantics.
- Keep `/scan` available but subordinate to CLI-first onboarding; remove dashboard-first emphasis from home and LLM projection copy.
- Ensure docs-site navigation and links continue to surface canonical docs paths after the README rewrite.
Repo paths:
- `docs-site/src/app/page.tsx`
- `docs-site/public/llms.txt`
- `docs-site/public/llm/product.md`
- `docs-site/public/llm/quickstart.md`
- `docs-site/public/llm/contracts.md`
- `docs-site/public/llm/faq.md`
- `docs-site/src/lib/navigation.ts`
- `docs-site/src/lib/scan-bootstrap.ts`
- `docs-site/src/lib/scan-bootstrap.test.ts`
Run commands:
- `make test-docs-consistency`
- `make docs-site-install`
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`
- `make test-docs-storyline`
Test requirements:
- docs-site smoke checks
- LLM projection consistency checks
- README first-screen to docs-site projection checks
- docs source-of-truth mapping checks when repo markdown and docs-site are both changed
Matrix wiring:
- Core CI lane
- Acceptance lane
Acceptance criteria:
- Docs-site landing copy no longer conflicts with the new README framing.
- LLM projection files reflect the new developer/security-team flows and supported command examples.
- `/scan` remains available but is not positioned as the primary first-value path.
- Docs-site build/smoke passes with the updated content.
Contract/API impact: public docs-site and LLM projection content only; no CLI/runtime behavior change.
Versioning/migration impact: none.
Architecture constraints:
- Docs-site remains a projection and onboarding surface only; no duplication of Go scan/risk/proof logic.
- Preserve canonical docs routing and `/docs/start-here` install references where they remain authoritative.
ADR required: no
TDD first failing test(s):
- Docs-site smoke or projection tests failing on old hero/quickstart/LLM content.
Cost/perf impact: low
Chaos/failure hypothesis: if README and docs-site diverge, docs-site projection and smoke checks must fail before merge.
Dependencies: W2-S01, W2-S02
Risks:
- LLM projection files can drift separately from repo markdown if not updated in the same PR.
- Overcorrecting away from `/scan` could accidentally hide an existing supported surface rather than simply de-emphasizing it.

### Story W2-S04: Preserve reproducible install and OSS trust discoverability outside the locked README body
Priority: P1
Tasks:
- Move or reinforce pinned/repro install guidance in `docs/install/minimal-dependencies.md` and `docs/trust/release-integrity.md` so it remains canonical even though the locked README uses `go install ...@latest`.
- Update `docs/README.md`, `docs/map.md`, and/or docs-site navigation to make `CONTRIBUTING`, `SECURITY`, `CODE_OF_CONDUCT`, `CHANGELOG`, and support expectations easily discoverable without relying on `README.md`.
- Update docs consistency/hygiene checks so they enforce the new locations for install reproducibility and OSS trust links.
- Validate that published install-path parity/UAT guidance still points at the reproducible pinned path.
Repo paths:
- `docs/install/minimal-dependencies.md`
- `docs/trust/release-integrity.md`
- `docs/README.md`
- `docs/map.md`
- `CONTRIBUTING.md`
- `CHANGELOG.md`
- `SECURITY.md`
- `CODE_OF_CONDUCT.md`
- `scripts/check_docs_consistency.sh`
- `testinfra/hygiene/wave2_docs_contracts_test.go`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `scripts/test_uat_local.sh --skip-global-gates`
- `go test ./testinfra/hygiene -run 'TestInstallDocsSmokeGoOnlyPath|TestCommunityHealthFilesAndLinks|TestDocsSourceOfTruthSectionsPresent' -count=1`
Test requirements:
- version/install discoverability checks
- README first-screen vs install-doc split checks
- OSS readiness checks for community health file discoverability
- docs source-of-truth mapping checks
- install-path UAT smoke where published parity is affected
Matrix wiring:
- Core CI lane
- Acceptance lane
Acceptance criteria:
- Pinned/reproducible install guidance remains canonical and validated even though the main README uses `@latest`.
- Community health and support links remain discoverable from canonical docs/docs-site surfaces.
- Docs consistency tests enforce the new trust/install locations intentionally.
- Release-integrity docs and UAT commands remain accurate.
Contract/API impact: docs/distribution contract only.
Versioning/migration impact: none.
Architecture constraints:
- Keep install/release-integrity guidance as audited documentation, not ad hoc README commentary.
- Preserve docs source-of-truth separation between landing copy and reproducible install/release contract docs.
ADR required: no
TDD first failing test(s):
- Hygiene test expecting reproducible install guidance in install docs rather than only README.
- Hygiene test expecting OSS trust discoverability through the revised canonical docs surface.
Cost/perf impact: low
Chaos/failure hypothesis: if the README drops trust/install details without replacement, docs consistency and UAT smoke must fail before merge.
Dependencies: W2-S01, W2-S02
Risks:
- Moving trust/install discoverability out of README could reduce discoverability if docs navigation is not updated at the same time.
- UAT/docs parity could drift if pinned install guidance and release-integrity docs are updated separately.

## Minimum-Now Sequence

1. Implement W1-S01 so the locked README's `regress run` example is true before landing docs.
2. Implement W2-S01 to redefine and enforce the Wrkr README contract intentionally.
3. Implement W2-S02 to apply the exact README and align canonical repo docs/examples/command references.
4. Implement W2-S04 to restore pinned-install and OSS trust discoverability around the new README.
5. Implement W2-S03 after canonical repo markdown is final so docs-site and LLM projections mirror the shipped README.

Parallelization after dependency checkpoints:

- W2-S04 can run in parallel with late-stage W2-S03 once W2-S02 is stable.
- No Wave 2 story should start before W1-S01 and W2-S01 because both define the runtime and contract truth the README depends on.

## Explicit Non-Goals

- No implementation work in this planning artifact.
- No Axym or Gait feature work beyond documentation of current relationship boundaries.
- No dashboard-first, browser-first, or control-plane expansion.
- No detection/risk/proof/compliance feature additions beyond what is required to make the locked README examples truthful.
- No exit-code taxonomy changes.
- No toolchain, dependency, or release-version pin changes.
- No removal of `/scan`, `regress init`, or current docs-site capabilities; only positioning and compatibility alignment.

## Definition of Done

- Every story above is implemented in dependency order with required lanes green.
- `README.md` equals Appendix A verbatim.
- `wrkr regress run` supports both canonical regress baselines and raw scan-state baselines without breaking determinism, `--json`, or exit codes.
- Docs contract, canonical repo docs, docs-site landing, and LLM projections all tell the same story.
- Pinned install guidance and OSS trust/support discoverability remain canonical and validated.
- `docs/map.md` and docs consistency/hygiene checks clearly define where future landing/install/trust edits belong.
- No unresolved drift remains between repo markdown and public docs-site projection surfaces.
- The working tree contains only intentional plan/implementation changes when the follow-up implementation starts.

## Appendix A: Locked README Markdown

````markdown
# Wrkr

Know what AI tools, agents, and MCP servers are configured on your machine and in your org before they become unreviewed access.

Wrkr gives developers a fast, read-only inventory of their local AI setup and gives security teams an evidence-ready view of org-wide AI tooling posture. It discovers supported AI dev tools, MCP servers, and agent frameworks, maps what they can touch, shows what changed, and emits proof artifacts for audits and CI.

Developer-first. Security-ready. Deterministic by default.

Docs: [clyra-ai.github.io/wrkr](https://clyra-ai.github.io/wrkr/) | Command reference: [`docs/commands/`](docs/commands/) | Examples: [`docs/examples/`](docs/examples/)

## Install

### Homebrew

```bash
brew install Clyra-AI/tap/wrkr
```

### Go install


```bash
go install github.com/Clyra-AI/wrkr/cmd/wrkr@latest

```

## Start Here

### Developers

Start with your own machine.

```bash
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json

cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

In one flow, Wrkr answers:

- What AI tools, agents, and MCP servers are configured in my local setup?
- Which API-key environments are present without exposing secret values?
- Which MCP servers are requesting access, over what transport, and with what trust status?
- What changed since my last known-good snapshot?

Abbreviated `scan --my-setup` example:

```json
{
  "status": "ok",
  "target": {
    "mode": "my_setup"
  },
  "top_findings": [
    {
      "risk_score": 9.3,
      "finding": {
        "severity": "high",
        "finding_type": "mcp_server",
        "tool_type": "mcp",
        "location": ".claude/settings.json"
      }
    },
    {
      "risk_score": 7.4,
      "finding": {
        "severity": "high",
        "finding_type": "secret_presence",
        "tool_type": "secret",
        "location": "process:env"
      }
    },
    {
      "risk_score": 6.8,
      "finding": {
        "severity": "medium",
        "finding_type": "tool_config",
        "tool_type": "agent_project",
        "location": "Projects/payments-bot/AGENTS.md"
      }
    }
  ],
  "warnings": [
    "MCP visibility may be incomplete because these declaration files failed to parse: .codex/config.yaml"
  ]
}
```

Abbreviated `mcp-list` example:

```json
{
  "status": "ok",
  "rows": [
    {
      "server_name": "postgres-prod",
      "transport": "stdio",
      "requested_permissions": ["db.write"],
      "privilege_surface": ["write"],
      "gateway_coverage": "unprotected",
      "trust_status": "unreviewed",
      "risk_note": "Gateway posture is unprotected; review least-privilege controls."
    },
    {
      "server_name": "slack",
      "transport": "http",
      "requested_permissions": ["network.access"],
      "privilege_surface": ["read"],
      "gateway_coverage": "protected",
      "trust_status": "trusted",
      "risk_note": "Static MCP declaration discovered; verify package pinning and trust."
    }
  ]
}
```

Wrkr is not a vulnerability scanner. It inventories what is configured and what it can touch. Use dedicated tools such as Snyk for package and server vulnerability assessment.

### Security Teams

Then widen from personal hygiene to org posture.

```bash
wrkr scan --github-org acme --github-api https://api.github.com --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
```

Hosted scans usually need GitHub authentication for private repos and to avoid public API rate limits.

Abbreviated org-scan example:

```json
{
  "status": "ok",
  "target": {
    "mode": "org",
    "value": "acme"
  },
  "top_findings": [
    {
      "risk_score": 9.7,
      "finding": {
        "rule_id": "WRKR-A004",
        "severity": "critical",
        "tool_type": "agent",
        "location": "services/ops/agent.py"
      }
    }
  ],
  "inventory": {
    "tools": 47,
    "agents": 12
  },
  "agent_privilege_map": [
    {
      "agent_id": "wrkr:langchain:services/ops/agent.py:planner:42-88:acme",
      "framework": "langchain",
      "bound_tools": ["postgres-prod", "slack"],
      "bound_data_sources": ["prod-db"],
      "bound_auth_surfaces": ["OPENAI_API_KEY"],
      "deployment_status": "deployed",
      "production_write": true
    }
  ],
  "compliance_summary": {
    "frameworks": [
      {
        "framework": "soc2",
        "mapped_finding_count": 12
      },
      {
        "framework": "eu-ai-act",
        "mapped_finding_count": 8
      },
      {
        "framework": "pci-dss",
        "mapped_finding_count": 5
      }
    ]
  }
}
```

Your developers are already using AI coding tools, agents, and MCP servers. That is not the problem. The problem is being unable to inventory them, map what they can touch, and prove they are governed.

Wrkr scans your GitHub org, shows supported AI tools and agents with privilege mapping and policy gaps, and emits evidence bundles your team can hand to auditors. Your developers keep moving. You get the posture and the proof.

## Why Wrkr

AI tool usage is already happening across developer machines, repositories, MCP configs, and CI pipelines.

Developers need fast answers:

- What is configured on my machine?
- What can it touch?
- What changed since last scan?

Security teams need organization-wide answers:

- Which AI tools and agents exist across repos?
- Which ones have production write, credential access, or broad execution privileges?
- Which findings map to policy and compliance frameworks?
- Can we hand an auditor a deterministic evidence bundle instead of a spreadsheet?

Wrkr answers both without requiring runtime interception or moving scan data out of your environment.

## What You Get

- Local AI setup inventory for supported user-home config surfaces.
- MCP server catalog with transport, requested permissions, trust overlay, and posture notes.
- Org-wide inventory of AI tools, agent frameworks, CI execution patterns, and MCP declarations.
- Deterministic, instance-scoped agent identity and privilege mapping.
- Native structured parsing for supported agent frameworks including LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex, MCP-client patterns, and conservative custom-agent scaffolds.
- Relationship resolution from agents to tools, data sources, auth surfaces, and deployment artifacts.
- Ranked findings, attack-path context, and posture scoring.
- `inventory --diff` for drift review against a known-good snapshot.
- Policy findings with stable rule IDs and remediation text.
- Compliance mappings for EU AI Act, SOC 2, PCI-DSS, and related frameworks.
- Signed evidence bundles for audit and CI workflows.
- Native JSON, SARIF, and proof-friendly output contracts.

## What Wrkr Detects

Wrkr is deterministic and file-based by default.

It detects supported signals from:

- Local-machine setup rooted at the current user home directory.
- Repository config and source surfaces.
- GitHub repo and org acquisition targets.
- MCP declarations and gateway posture.
- AI tool configs for Claude, Cursor, Codex, Copilot, skills, and CI agent execution patterns.
- Agent definitions and bindings from supported framework-native sources.
- Deployment artifacts linking agents to Docker, Kubernetes, serverless, and CI/CD paths.
- Prompt-channel and attack-path risk signals from static artifacts.

## What Wrkr Does Not Do

- It does not probe MCP endpoints live by default.
- It does not replace package or vulnerability scanners.
- It does not enforce runtime tool behavior or block agents.
- It does not monitor live runtime traffic.
- It does not use LLMs in scan, risk, or proof paths.

Wrkr is the inventory and posture layer. Gait is the control layer when runtime enforcement is needed.

## Works With Gait

Wrkr discovers what is configured. Gait enforces what is allowed to execute.

Use Wrkr when you want to answer:

- What tools and agents exist?
- What can they touch?
- What changed?
- Where are the policy and compliance gaps?

Use Gait when you want to answer:

- Should this action be allowed right now?
- Should this tool be blocked, gated, or require approval?

The two products complement each other. Wrkr gives you the inventory and evidence. Gait gives you runtime control.

## Typical Workflows

### Personal AI setup hygiene

```bash
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

### Repo or org posture review

```bash
wrkr scan --github-org acme --github-api https://api.github.com --json
wrkr report --top 5 --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
```

### CI distribution

```bash
wrkr scan --path . --sarif --json
wrkr regress run --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

## Command Surface

- `wrkr scan` scans local setup, repos, or GitHub orgs.
- `wrkr mcp-list` projects MCP posture from saved state.
- `wrkr inventory --diff` shows deterministic drift from baseline.
- `wrkr report` renders ranked summaries from saved state.
- `wrkr evidence` builds signed, compliance-ready evidence bundles.
- `wrkr verify` verifies proof-chain integrity.
- `wrkr regress` gates on drift and regressions.
- `wrkr version` reports CLI version in human or JSON form.

## Output And Contracts

Wrkr treats machine-readable output and exit codes as product contracts.

- `--json` emits stable machine-readable output.
- `--sarif` emits SARIF `2.1.0` for security tooling and GitHub code scanning workflows.
- Partial-result mode preserves findings when a detector or source path fails non-fatally.
- `--timeout` and signal cancellation are enforced end-to-end.
- Exit codes remain deterministic across success, runtime failure, verification failure, policy/schema violation, approval-required, regress drift, invalid input, dependency missing, and unsafe-operation-blocked paths.

## Security And Privacy

- Read-only by default.
- No raw secret values are emitted in findings.
- Local setup scans keep data in your environment.
- Evidence is file-based, portable, and verifiable.
- Same input, same output, barring explicit timestamps and version fields.

## Learn More

- Quickstart: [`docs/examples/quickstart.md`](docs/examples/quickstart.md)
- Personal hygiene workflow: [`docs/examples/personal-hygiene.md`](docs/examples/personal-hygiene.md)
- Security-team workflow: [`docs/examples/security-team.md`](docs/examples/security-team.md)
- Scan command: [`docs/commands/scan.md`](docs/commands/scan.md)
- MCP list: [`docs/commands/mcp-list.md`](docs/commands/mcp-list.md)
- Inventory drift: [`docs/commands/inventory.md`](docs/commands/inventory.md)
- Evidence bundles: [`docs/commands/evidence.md`](docs/commands/evidence.md)
- Positioning: [`docs/positioning.md`](docs/positioning.md)
````

# PLAN WRKR_ARTIFACT_BOUNDARY_HARDENING: Release-Safe Artifact Consumers and Atomic Evidence Commit

Date: 2026-03-18
Source of truth:
- user-provided full-repo review findings dated 2026-03-18
- `product/dev_guides.md`
- `product/architecture_guides.md`
- `core/cli/verify.go`
- `core/cli/campaign.go`
- `core/evidence/evidence.go`
- `core/verify/verify.go`
- `docs/commands/verify.md`
- `docs/commands/campaign.md`
- `docs/commands/evidence.md`
- `docs/commands/scan.md`
- `docs/trust/proof-chain-verification.md`
- `docs/state_lifecycle.md`
- `schemas/v1/report/campaign-summary.schema.json`
- `core/cli/root_test.go`
- `core/cli/campaign_test.go`
- `core/verify/verify_test.go`
- `core/evidence/evidence_test.go`
- `internal/e2e/campaign/campaign_e2e_test.go`
- `testinfra/contracts/story7_contracts_test.go`
Scope: Wrkr repository only. Planning artifact only. Remediate the three review-proven P1 artifact-boundary defects without weakening determinism, offline-first defaults, fail-closed behavior, schema stability, or exit-code stability.

## Global Decisions (Locked)

- Treat this as contract/runtime correctness work first. Docs ship in the same story as the behavior they describe.
- Preserve Wrkr CLI flags, JSON output keys, schema versioning posture, proof-record formats, and exit codes `0..8`.
- `wrkr verify --chain --path <chain>` must treat the explicit chain path as the authority for verifier-key lookup unless the caller explicitly passed `--state`.
- `wrkr campaign aggregate` will fail closed on degraded or partial scan artifacts in this plan. Do not introduce a permissive degraded-success mode in this wave.
- `wrkr evidence` must build in a same-parent managed stage directory and only publish to the requested `--output` path after manifest generation, signing, and verification succeed.
- No partial managed evidence bundle may remain visible at the final output path after any failure.
- Preserve existing managed-path trust rules:
  - evidence marker `.wrkr-evidence-managed`
  - non-empty unmanaged output directories fail closed
  - marker must remain a regular file
- Keep `core/cli` thin. Authoritative logic belongs in focused packages for verify, campaign validation, evidence staging, and persistence.
- Stories that touch CLI contract behavior, filesystem side effects, or failure semantics must run `make prepush-full`.
- Reliability and failure-path stories must run `make test-hardening` and `make test-chaos`.
- Evidence staging changes are performance-sensitive and must also run `make test-perf`.
- No dashboard/docs-site scope, no `Clyra-AI/proof` API change, no new network paths, and no dashboard-first or polish-first work in this plan.

## Current Baseline (Observed)

- Planning inputs validated:
  - `product/dev_guides.md` exists and is readable
  - `product/architecture_guides.md` exists and is readable
  - output path `product/PLAN_NEXT.md` resolves inside `/Users/tr/wrkr`
- The review established three release-blocking artifact-boundary defects:
  - `verify`: ambient `WRKR_STATE_PATH` can silently downgrade authenticated verification even when `--path` is explicit.
  - `campaign aggregate`: syntactically valid but degraded scan artifacts can still produce a clean success envelope.
  - `evidence`: failed builds can clear or replace a managed output directory with partial new contents.
- Existing coverage is substantial but has specific gaps:
  - `core/cli/root_test.go` already checks `chain_and_attestation` and `chain_only` outcomes, but not explicit `--path` precedence against ambient `WRKR_STATE_PATH`.
  - `core/cli/campaign_test.go` covers happy-path aggregation and basic invalid input, but not `partial_result`, `source_degraded`, or `source_errors` rejection.
  - `core/evidence/evidence_test.go` covers marker trust and unmanaged directory blocking, but not preservation of a prior good bundle during late-stage failure.
- Current command docs already describe partial scan semantics upstream:
  - `docs/commands/scan.md` documents `partial_result`, `source_errors`, and `source_degraded`.
- Current downstream contract gap:
  - `docs/commands/campaign.md` does not define how degraded scan artifacts should be handled.
  - `schemas/v1/report/campaign-summary.schema.json` has no degraded-input metadata fields.
- Current evidence docs promise fail-closed output ownership safety, but they do not yet promise staged or atomic publish semantics.
- Review validation already established a healthy starting point:
  - `go test ./...` passed during the review.
  - `wrkr scan --path scenarios/wrkr/scan-mixed-org/repos --json`, `wrkr verify --chain --json`, and `wrkr regress init/run --json` reproduced baseline behavior.
  - Synthetic repros confirmed the verify downgrade, campaign false-green path, and evidence partial-output leak.

## Exit Criteria

1. `wrkr verify --chain --path <chain> --json` produces the same verifier-key lookup and authenticity result regardless of ambient `WRKR_STATE_PATH` when `--state` is not passed.
2. `wrkr campaign aggregate --input-glob ... --json` rejects degraded or partial scan artifacts deterministically with a stable `invalid_input` envelope and exit `6`.
3. `wrkr evidence --frameworks ... --output <dir> --json` stages all bundle work outside the final target path and only publishes to the target after full bundle success.
4. Failed evidence builds leave either:
   - no bundle at the target path, or
   - the prior valid managed bundle intact
5. `docs/commands/verify.md`, `docs/commands/campaign.md`, `docs/commands/evidence.md`, and any touched trust/lifecycle docs match the implemented behavior in the same PR.
6. No schema or version bump is required unless implementation proves it unavoidable; if that happens, the change must be additive, documented, and explicitly version-reviewed.
7. Required tests and lanes for each story pass, including:
   - `make lint-fast`
   - `make test-contracts`
   - `make prepush-full`
   - `make test-hardening`
   - `make test-chaos`
   - `make test-perf` for the evidence story

## Public API and Contract Map

Stable/public surfaces touched by this plan:

- CLI commands:
  - `wrkr verify --chain`
  - `wrkr campaign aggregate`
  - `wrkr evidence`
- Stable verify JSON keys:
  - `status`
  - `chain.path`
  - `chain.intact`
  - `chain.count`
  - `chain.head_hash`
  - `chain.reason`
  - `chain.verification_mode`
  - `chain.authenticity_status`
- Stable campaign JSON success shape:
  - `status`
  - `campaign`
- Stable evidence JSON success shape:
  - `status`
  - `output_dir`
  - `frameworks`
  - `manifest_path`
  - `chain_path`
  - `framework_coverage`
  - `report_artifacts`
- Stable exit-code and error-envelope expectations:
  - `verify`: `verification_failure` exit `2`, `invalid_input` exit `6`
  - `campaign`: `invalid_input` exit `6`, `runtime_failure` exit `1`
  - `evidence`: `invalid_input` exit `6`, `runtime_failure` exit `1`, `unsafe_operation_blocked` exit `8`
- Stable managed-output ownership contracts:
  - `.wrkr-evidence-managed`
  - non-empty unmanaged output dir fails closed
  - marker must be a regular file

Internal surfaces expected to change:

- `core/cli/verify.go`
- `core/cli/campaign.go`
- `core/evidence/evidence.go`
- likely new evidence staging helper:
  - `core/evidence/stage.go`
  - or a narrowly scoped reusable helper under `internal/`
- tests:
  - `core/cli/root_test.go`
  - `core/cli/campaign_test.go`
  - `core/verify/verify_test.go`
  - `core/evidence/evidence_test.go`
  - `internal/e2e/campaign/campaign_e2e_test.go`
  - `testinfra/contracts/story7_contracts_test.go`
- docs:
  - `docs/commands/verify.md`
  - `docs/commands/campaign.md`
  - `docs/commands/evidence.md`
  - `docs/commands/scan.md`
  - `docs/trust/proof-chain-verification.md`
  - `docs/state_lifecycle.md`

Shim/deprecation path:

- No CLI shim or deprecation path is planned for `verify` or `evidence`.
- Degraded scan artifact acceptance in `campaign aggregate` is treated as unsafe undocumented behavior, not a supported contract.
- Any future desire for an additive degraded-success path requires a separate plan and explicit schema review.

Schema/versioning policy:

- Preferred implementation path: no schema changes and no version bump.
- If campaign degraded-input metadata must become visible, it must be additive optional data under `schema_version: v1`.
- No evidence bundle schema version change is planned.

Machine-readable error expectations:

- `verify` keeps its current success and failure envelope fields; only precedence resolution changes.
- `campaign aggregate` on degraded inputs should emit a stable `invalid_input` envelope naming the offending artifact and degraded markers.
- `evidence` keeps existing error classes; failed builds must not leave a consumable partial target bundle.

## Docs and OSS Readiness Baseline

README first-screen contract:

- Keep `README.md` focused on product value and the core `scan -> evidence -> verify` flow.
- Do not add maintainer-only implementation detail to the README unless a public trust claim would otherwise be inaccurate.

Integration-first docs flow for this plan:

1. `docs/commands/scan.md`
2. `docs/commands/campaign.md`
3. `docs/commands/verify.md`
4. `docs/trust/proof-chain-verification.md`
5. `docs/commands/evidence.md`
6. `docs/state_lifecycle.md`

Lifecycle path model the docs must preserve:

- `scan` creates authoritative state and proof-chain inputs.
- `verify` authenticates from state or explicit chain path.
- `campaign aggregate` consumes complete `scan --json` artifacts only.
- `evidence` consumes saved state and publishes managed bundle outputs atomically.

Docs source-of-truth mapping:

- behavior authority: `core/cli/*`, `core/evidence/*`, `core/verify/*`
- command docs: `docs/commands/*`
- trust semantics: `docs/trust/proof-chain-verification.md`
- lifecycle semantics: `docs/state_lifecycle.md`

OSS readiness baseline:

- Existing trust files remain the baseline:
  - `README.md`
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `.github/ISSUE_TEMPLATE/*`
  - `.github/pull_request_template.md`
- No new OSS governance file is required by this plan.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Respect explicit `--path` over ambient `WRKR_STATE_PATH` in `verify` | Prevent silent downgrade from authenticated verification to structural-only success | Tighten command-boundary precedence and proof trustworthiness | Stronger release and promotion integrity with no contract sprawl | `W1-S01` |
| R2 | Reject degraded or partial scan artifacts in `campaign aggregate` | Eliminate false-green org rollups from incomplete upstream acquisition | Fail closed at the artifact-consumer boundary | Safer automation and more trustworthy campaign summaries | `W1-S02` |
| R3 | Stage and atomically publish evidence bundles | Prevent failed reruns from destroying or replacing the last known-good bundle with partial new contents | Crash-safe managed output semantics | Stronger evidence portability, operator trust, and audit confidence | `W2-S01` |

## Test Matrix Wiring

| Lane | Required commands | Notes |
|---|---|---|
| Fast lane | `make lint-fast`; `make test-contracts`; targeted `go test ./core/cli ./core/verify ./core/evidence -count=1` | Minimum local and PR feedback loop |
| Core CI lane | `make prepush-full`; `go test ./... -count=1` | Mandatory for all stories in this plan because failure semantics and filesystem side effects are touched |
| Acceptance lane | `go test ./internal/e2e/verify -count=1`; `go test ./internal/e2e/campaign -count=1`; targeted contract suites | Outside-in confirmation for command behavior |
| Cross-platform lane | existing `windows-smoke`; existing core matrix lanes | Required because env-var precedence, globbing, and filesystem publish behavior must stay portable |
| Risk lane | `make test-hardening`; `make test-chaos`; `make test-perf` for evidence staging | Mandatory for all stories here; `make test-perf` is required only for `W2-S01` |
| Merge/release gating rule | No story closes until fast, core, acceptance, and relevant risk lanes are green; docs parity checks must pass in the same PR as behavior changes | No docs-only or tests-only follow-up PRs |

## Epic W1: Artifact Consumer Fail-Closed Corrections

Objective: remove the two false-confidence paths in artifact consumers before any broader distribution or docs work.

### Story W1-S01: Respect Explicit Verify Chain Path Over Ambient State Env
Priority: P0
Tasks:
- Add a failing CLI contract test that proves explicit `--path` ignores ambient `WRKR_STATE_PATH` when `--state` is not passed.
- Refactor verifier-key lookup into an explicit precedence helper:
  - explicit `--state`
  - explicit `--path`
  - resolved default state path
- Keep `core/verify` as the authoritative verifier and preserve current success/failure JSON keys.
- Update verify command and trust docs to state that explicit path lookup is authoritative unless `--state` is also provided.
- Re-run deterministic verify contract and e2e checks.
Repo paths:
- `core/cli/verify.go`
- `core/cli/root_test.go`
- `core/verify/verify_test.go`
- `docs/commands/verify.md`
- `docs/trust/proof-chain-verification.md`
Run commands:
- `go test ./core/cli ./core/verify -count=1`
- `go test ./internal/e2e/verify -count=1`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- CLI `--json` stability tests with and without ambient `WRKR_STATE_PATH`
- exit-code contract checks for success, missing `--chain`, and invalid verifier-key material
- machine-readable envelope tests for `verification_failure` and `invalid_input`
- deterministic repeat-run test confirming path precedence does not alter stable output unexpectedly
- docs parity and docs consistency checks for verify/trust docs
Matrix wiring:
- Fast lane: `go test ./core/cli ./core/verify -count=1`, `make lint-fast`, `make test-contracts`
- Core CI lane: `make prepush-full`
- Acceptance lane: `go test ./internal/e2e/verify -count=1`
- Cross-platform lane: `windows-smoke`
- Risk lane: `make test-hardening`, `make test-chaos`
Acceptance criteria:
- Explicit `--path` verification yields the same `verification_mode` and `authenticity_status` regardless of ambient `WRKR_STATE_PATH` when `--state` is omitted.
- Explicit `--state` continues to take precedence.
- Success and failure JSON envelopes remain backward-compatible.
- Updated docs describe the implemented precedence exactly.
Contract/API impact:
- Clarifies existing `verify` lookup precedence without adding flags, keys, or exit codes.
Versioning/migration impact:
- No schema change, no version bump, no migration path required.
Architecture constraints:
- Keep CLI as thin orchestration only.
- Keep proof verification and authenticity logic authoritative in `core/verify`.
- Do not let ambient env override more-specific explicit CLI input.
- Preserve offline deterministic behavior.
ADR required: no
TDD first failing test(s):
- `core/cli/root_test.go`: `TestVerifyExplicitChainPathIgnoresAmbientWRKRStatePath`
- `core/cli/root_test.go`: `TestVerifyExplicitStateStillOverridesAmbientWRKRStatePath`
Cost/perf impact: low
Chaos/failure hypothesis:
- Fault: ambient `WRKR_STATE_PATH` points to missing or unrelated signing material while the user passes an explicit chain path.
- Expected: verification still loads the key material associated with the explicit chain path and preserves authenticated results or existing stable failure envelopes.

### Story W1-S02: Fail Closed On Degraded Campaign Scan Artifacts
Priority: P0
Tasks:
- Add failing CLI and e2e tests for campaign inputs where `partial_result`, `source_degraded`, or `source_errors` are present.
- Extend artifact validation in `campaign aggregate` so `status=ok` is necessary but not sufficient.
- Reject degraded or partial scan artifacts with stable `invalid_input` output that names the offending artifact and reason markers.
- Keep successful campaign output and `schemas/v1/report/campaign-summary.schema.json` unchanged for complete artifacts.
- Update campaign docs and cross-link scan docs so upstream completeness requirements are explicit.
Repo paths:
- `core/cli/campaign.go`
- `core/cli/campaign_test.go`
- `internal/e2e/campaign/campaign_e2e_test.go`
- `docs/commands/campaign.md`
- `docs/commands/scan.md`
Run commands:
- `go test ./core/cli -count=1`
- `go test ./internal/e2e/campaign -count=1`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
Test requirements:
- deterministic fail-closed fixtures for `partial_result`, `source_degraded`, and `source_errors`
- CLI `invalid_input` envelope tests with stable exit `6`
- happy-path regression tests proving complete artifacts still aggregate unchanged
- contract check that campaign summary schema and required success fields stay stable
- docs consistency and CLI parity checks
Matrix wiring:
- Fast lane: `go test ./core/cli -count=1`, `make lint-fast`, `make test-contracts`
- Core CI lane: `make prepush-full`
- Acceptance lane: `go test ./internal/e2e/campaign -count=1`
- Cross-platform lane: `windows-smoke`
- Risk lane: `make test-hardening`, `make test-chaos`
Acceptance criteria:
- `campaign aggregate` exits `6` with a stable `invalid_input` envelope when any matched artifact is degraded or partial.
- Complete scan artifacts continue to aggregate with the same success payload shape and schema version.
- Docs explicitly say campaign aggregation consumes complete `scan --json` artifacts only.
Contract/API impact:
- Narrows campaign input acceptance to complete artifacts while keeping success output stable.
Versioning/migration impact:
- No schema bump planned and no migration path required for complete-artifact consumers.
Architecture constraints:
- Validate at the CLI/artifact boundary, not in downstream rendering or docs alone.
- Do not introduce a permissive degraded-success mode in this wave.
- Preserve deterministic input ordering and stable error classes.
ADR required: no
TDD first failing test(s):
- `core/cli/campaign_test.go`: `TestCampaignAggregateRejectsPartialResultArtifact`
- `core/cli/campaign_test.go`: `TestCampaignAggregateRejectsDegradedArtifact`
- `internal/e2e/campaign/campaign_e2e_test.go`: degraded scan fixture rejected with exit `6`
Cost/perf impact: low
Chaos/failure hypothesis:
- Fault: matched scan artifact is syntactically valid JSON but semantically incomplete because source acquisition partially failed.
- Expected: `campaign aggregate` rejects the artifact deterministically rather than producing a false-green summary.

## Epic W2: Atomic Evidence Bundle Commit

Objective: make evidence output crash-safe and operator-trustworthy by publishing only complete verified bundles.

### Story W2-S01: Stage And Atomically Publish Evidence Bundles
Priority: P0
Tasks:
- Add failing tests that prove:
  - invalid late-stage builds do not leave partial target bundles
  - a prior valid managed bundle survives a failed rerun intact
- Introduce same-parent managed staging flow for `wrkr evidence`:
  - validate target ownership and marker trust without clearing the target in place
  - create a stage dir beside the target
  - write all bundle files to the stage dir
  - build manifest, sign bundle, and verify bundle in the stage dir
  - swap stage into the final target only after full success
  - clean stage and backup dirs deterministically on success and best-effort on failure
- Keep side-effect semantics explicit in helper names and signatures.
- Preserve existing error classes and managed-marker trust rules.
- Update evidence and lifecycle docs so managed bundle publication semantics are explicit and auditable.
Repo paths:
- `core/evidence/evidence.go`
- `core/evidence/stage.go`
- `core/evidence/evidence_test.go`
- `core/cli/root_test.go`
- `testinfra/contracts/story7_contracts_test.go`
- `docs/commands/evidence.md`
- `docs/state_lifecycle.md`
- `internal/atomicwrite/atomicwrite.go` only if a reusable swap helper is intentionally extracted there
Run commands:
- `go test ./core/evidence ./core/cli -count=1`
- `go test ./testinfra/contracts -count=1`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_consistency.sh`
- `make prepush-full`
- `make test-hardening`
- `make test-chaos`
- `make test-perf`
Test requirements:
- keep existing non-empty unmanaged dir and marker trust tests green
- add crash-safe publish tests for invalid framework and injected late failure paths
- add preservation tests showing an earlier valid managed bundle remains intact after failed rerun
- add any required contention tests if new staging helpers coordinate shared paths
- run byte-stability repeat-run tests for successful bundles
- verify digest and bundle verification determinism after staged publish
- run docs parity and lifecycle consistency checks
Matrix wiring:
- Fast lane: `go test ./core/evidence ./core/cli -count=1`, `make lint-fast`, `make test-contracts`
- Core CI lane: `make prepush-full`
- Acceptance lane: `go test ./testinfra/contracts -count=1`
- Cross-platform lane: `windows-smoke`
- Risk lane: `make test-hardening`, `make test-chaos`, `make test-perf`
Acceptance criteria:
- Failed evidence builds never expose partial new bundle contents at the final target path.
- If the target already contains a valid managed bundle, a later failed build leaves that prior bundle intact.
- Successful builds still emit the documented files and JSON success envelope unchanged.
- Managed marker rules, output ownership safety, and error-class mapping remain intact.
- Docs describe staged publish semantics accurately.
Contract/API impact:
- Strengthens managed output publication semantics while leaving CLI success/failure envelope fields unchanged.
Versioning/migration impact:
- No schema or CLI version bump planned.
Architecture constraints:
- Keep evidence staging and publish logic inside the evidence/compliance boundary.
- Use same-parent staging to minimize cross-filesystem rename surprises.
- Make destructive steps explicit in helper APIs.
- Preserve fail-closed ownership checks and bundle verification before publish.
- Ensure cancellation and failure cleanup never mutates unrelated user paths.
ADR required: yes
TDD first failing test(s):
- `core/evidence/evidence_test.go`: `TestBuildDoesNotLeavePartialBundleOnInvalidFramework`
- `core/evidence/evidence_test.go`: `TestBuildPreservesPreviousManagedBundleWhenLateFailureOccurs`
- `testinfra/contracts/story7_contracts_test.go`: staged publish exposes complete bundle only on success
Cost/perf impact: medium
Chaos/failure hypothesis:
- Fault: bundle generation fails after several files are written, or after stage verification but before final swap.
- Expected: the stage dir is cleaned or quarantined, the final target remains absent or continues to point to the prior good bundle, and no partial managed target bundle is exposed.

## Minimum-Now Sequence

Wave 1:
- `W1-S01` Respect explicit verify chain path precedence
- `W1-S02` Reject degraded campaign scan artifacts
- Exit wave only when verify and campaign docs/tests/contracts are all green in the same branch.

Wave 2:
- `W2-S01` Stage and atomically publish evidence bundles
- Exit wave only when failure-injection tests prove prior bundle preservation or empty-target safety and docs reflect the new publish semantics.

Dependency order rationale:

- `W1-S01` and `W1-S02` are the smallest, highest-signal contract corrections and remove immediate false-confidence paths for proof verification and org rollups.
- `W2-S01` is more invasive because it changes managed output publication semantics and requires staged filesystem behavior, hardening coverage, and likely an ADR.
- Docs and contract updates remain coupled to each story rather than deferred to a later documentation-only wave.

## Explicit Non-Goals

- No new CLI commands or flags.
- No new exit codes.
- No change to `scan` acquisition behavior beyond clarifying its existing degraded artifact fields where needed.
- No permissive degraded-success campaign mode in this plan.
- No changes to `Clyra-AI/proof` APIs, proof-record types, or chain schema.
- No dashboard, docs-site UI, or packaging work.
- No unrelated release workflow or CI modernization work.

## Definition of Done

- Every review recommendation maps to a completed story with passing tests and updated docs.
- TDD evidence exists for each story through newly added or updated failing-first tests.
- CLI `--json` behavior and exit-code contracts remain stable for successful paths and documented failure classes.
- Campaign aggregation is fail-closed for degraded upstream artifacts.
- Evidence output publication is staged and failure-safe at the final target path.
- Docs parity and consistency checks pass in the same PR as code changes.
- Required fast, core, acceptance, cross-platform, and risk lanes are green for each story.
- Worktree after implementation is scoped to the planned files and any deliberate additive helper/ADR files only.

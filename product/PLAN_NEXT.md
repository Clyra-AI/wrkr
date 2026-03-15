# PLAN WRKR_P1_BOUNDARY_REMEDIATION: Identity Scope and Repo-Root File Safety

Date: 2026-03-15
Source of truth: user-provided review findings from 2026-03-15, `product/dev_guides.md`, `product/architecture_guides.md`, `product/wrkr.md`, `docs/specs/wrkr-manifest.md`, and `docs/state_lifecycle.md`
Scope: Wrkr repository only. Planning artifact only. Fix the two verified release-blocking findings around identity-state scoping and detector file-boundary enforcement. No implementation work is performed in this plan.

## Global Decisions (Locked)

- Preserve Wrkr's deterministic, offline-first, fail-closed behavior in default scan, risk, regress, proof, and evidence paths.
- Keep the current exit-code contract unchanged: `0,1,2,3,4,5,6,7,8`.
- Keep public JSON envelopes additive only. No field removals, no field retyping, and no schema major bump are allowed in this plan.
- Treat lifecycle/inventory/manifest identities as real tool identities only. Posture-only and bookkeeping findings are not approvable identities.
- Treat `secret_presence`, `source_discovery`, and similar non-tool surfaces as findings/risk signals only. They must not become manifest identities, inventory agents, or regress baseline tools.
- Legacy state, manifest, and regress baseline artifacts that already contain non-tool identities must remain readable. Migration handling must prevent false drift or approval workflows without breaking file compatibility.
- Repo-root boundary enforcement belongs in the shared detection/parsing layer. Do not duplicate symlink trust logic independently in each detector.
- Detector file reads must never ingest content outside the selected repo root. Unsafe path resolution must fail closed at the file boundary with deterministic machine-readable signaling.
- Architecture/risk/adapter/failure semantics work in this plan must run `make prepush-full`.
- Boundary-sensitive and reliability-sensitive stories in this plan must also run `make test-hardening` and `make test-chaos`.
- If shared parsing helpers materially increase detector hot-path work, run `make test-perf` and update performance notes in the PR.
- Any PR implementing Stories `W1-S01`, `W1-S02`, or `W2-S01` requires an ADR because these stories change contract semantics and failure handling.

## Current Baseline (Observed)

- `git status --short --branch` was clean before generating this plan.
- `product/dev_guides.md` and `product/architecture_guides.md` were present and readable.
- `go build ./cmd/wrkr` completed successfully.
- `go test ./... -count=1` completed successfully, including contract, scenario, and acceptance packages already wired in the repo.
- Direct CLI verification showed the first finding is real:
  - `wrkr scan --my-setup --json` emitted `secret` and `source_repo` entries as full manifest identities and inventory agents.
  - A baseline created without `OPENAI_API_KEY` and rescanned with `OPENAI_API_KEY` caused `wrkr regress run --json` to return drift with `new_unapproved_tool` for `wrkr:secret-...`.
- Direct CLI verification showed the second finding is real:
  - A repo-owned symlinked `.codex/config.toml` pointing outside the selected repo root was parsed as valid Codex config during `wrkr scan --path --json`.
  - A repo-owned symlinked `.env` pointing outside the selected repo root leaked external `credential_keys=OPENAI_API_KEY` into scan output.
- Existing CI and release workflow coverage is already strong:
  - `.github/workflows/main.yml`
  - `.github/workflows/release.yml`
  - `make prepush-full`
  - `make test-contracts`
  - `make test-scenarios`
  - `make test-hardening`
  - `make test-chaos`
  - `make test-perf`
- `sdk/python` is not present in this repository, so no SDK wrapper work is in scope for this plan.
- OSS trust baseline files already exist:
  - `README.md`
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `.github/ISSUE_TEMPLATE/*`
  - `.github/pull_request_template.md`

## Exit Criteria

1. `wrkr scan`, `wrkr manifest generate`, `wrkr identity`, `wrkr lifecycle`, `wrkr evidence`, and `wrkr regress` treat only real tool identities as lifecycle-bearing state.
2. `secret_presence`, `source_discovery`, and equivalent posture/bookkeeping findings remain in findings/risk surfaces but do not materialize into `snapshot.identities`, manifest identities, inventory agents, or `agent_privilege_map`.
3. Legacy manifests, snapshots, and regress baselines containing non-tool identities remain readable and do not produce false `new_unapproved_tool`, `removed`, or approval-history drift.
4. Detector file reads reject repo-owned symlinks that resolve outside `scope.Root` and never ingest outside-root config, env, workflow, or MCP content.
5. Unsafe path handling remains deterministic, sorted, and machine-readable without changing the stable exit-code contract.
6. `wrkr scan --json` on mixed safe/unsafe repo trees continues to return valid results for unaffected repos and surfaces explicit unsafe-path diagnostics for the offending files.
7. README, command docs, lifecycle/spec docs, and quickstart examples match the implemented runtime semantics in the same rollout.
8. All required fast, core CI, acceptance, cross-platform, and risk lanes for each story are green.

## Public API and Contract Map

Stable/public surfaces touched by this plan:

- `wrkr scan --json`
- `wrkr manifest generate --json`
- `wrkr regress init --baseline <scan-state-path> --json`
- `wrkr regress run --baseline <baseline-path> --state <state-path> --json`
- `wrkr identity list --json`
- `wrkr identity show <agent_id> --json`
- `wrkr lifecycle --json`
- JSON artifacts saved beside scan state:
  - `.wrkr/last-scan.json`
  - `.wrkr/wrkr-manifest.yaml`
  - `.wrkr/wrkr-regress-baseline.json`
  - `.wrkr/proof-chain.json`
- User-facing docs/specs:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/manifest.md`
  - `docs/commands/regress.md`
  - `docs/state_lifecycle.md`
  - `docs/specs/wrkr-manifest.md`
  - `docs/examples/quickstart.md`
  - `docs/trust/security-and-privacy.md`
  - `docs/contracts/readme_contract.md`

Internal surfaces expected to change:

- `core/model/identity_bearing.go`
- `core/aggregate/inventory/*`
- `core/cli/scan_helpers.go`
- `core/regress/*`
- `core/manifestgen/*`
- `core/detect/parse.go`
- `core/detect/codex/*`
- `core/detect/claude/*`
- `core/detect/secrets/*`
- `core/detect/mcp/*`
- targeted CLI, E2E, acceptance, scenario, contract, and hardening test files

Shim and deprecation path:

- Existing artifact fields remain in place.
- Legacy manifest/snapshot/baseline entries for non-tool identities remain readable.
- New runtime behavior must exclude those legacy non-tool identities from fresh lifecycle synthesis and regress comparisons rather than rewriting the file format.
- `agent_id` remains the stable identity field for real tool identities; this plan only tightens which findings are allowed to become identities.

Schema and versioning policy:

- No schema major bump is planned.
- If an additional machine-readable unsafe-path classification is added, it must be additive under the current `v1` line.
- Any contract-facing field/value additions require matching docs and contract tests in the same PR.
- Count or content changes caused by removing non-tool identities are treated as a bug fix to semantic correctness, not as a schema migration.

Machine-readable error expectations:

- Exit codes stay unchanged.
- Whole-command exit behavior stays unchanged unless a pre-existing command already treats the affected path as fatal.
- File-level repo-root escapes must not silently read external data.
- Unsafe file handling must surface through deterministic parse or detector diagnostics with stable ordering in `--json` output.
- Partial-failure behavior must remain explicit and sorted.

## Docs and OSS Readiness Baseline

README first-screen contract:

- README must describe Wrkr as discovering AI tool posture and generating deterministic proof artifacts.
- README must not imply that environment-key presence or source bookkeeping becomes an approvable identity.
- README must state that local path scans are bounded to the selected repo root and do not intentionally read files outside that boundary.

Integration-first docs flow for this plan:

1. `README.md`
2. `docs/commands/scan.md`
3. `docs/state_lifecycle.md`
4. `docs/specs/wrkr-manifest.md`
5. `docs/commands/manifest.md`
6. `docs/commands/regress.md`
7. `docs/examples/quickstart.md`
8. `docs/trust/security-and-privacy.md`
9. `docs/contracts/readme_contract.md`

Lifecycle path model that docs must preserve:

- `.wrkr/last-scan.json` is the authoritative scan snapshot.
- `.wrkr/wrkr-manifest.yaml` is the lifecycle/approval manifest for real tool identities.
- `.wrkr/wrkr-regress-baseline.json` is the canonical regress baseline artifact.
- `.wrkr/proof-chain.json` remains the proof-chain path.
- Findings can include risk-only/posture-only signals that never become identities.

Docs source-of-truth mapping for this plan:

- CLI/runtime behavior: `docs/commands/*.md`
- lifecycle and artifact placement: `docs/state_lifecycle.md`
- manifest contract scope: `docs/specs/wrkr-manifest.md`
- public landing copy: `README.md`
- security/boundary guarantees: `docs/trust/security-and-privacy.md`
- README first-screen enforcement: `docs/contracts/readme_contract.md`

OSS readiness baseline:

- Existing trust files are sufficient for this plan.
- No new maintainer policy or support-policy artifact is required.
- User-visible behavior changes must still update the affected docs in the same PR.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Restrict lifecycle/inventory state to real tool identities | Transient env-key presence and source bookkeeping should not become approvable identities or regress blockers | Contract-first identity engine with explicit tool-bearing boundaries | More trustworthy approvals, lower false drift, stronger enterprise credibility | `W1-S01`, `W1-S02`, `W3-S01` |
| R2 | Fail closed on symlinked files that escape the selected repo root | Untrusted repos must not coerce Wrkr into reading data outside the requested scan boundary | Boundary-enforced file access in the detection layer | Safer local scans, less false discovery, stronger privacy posture | `W2-S01`, `W2-S02`, `W3-S01` |

## Test Matrix Wiring

Fast lane:

- `make lint-fast`
- targeted `go test` package runs with `-count=1`

Core CI lane:

- `make prepush`
- `go test ./internal/integration -count=1` when integration helpers or cross-package behavior changes

Acceptance lane:

- `make test-scenarios`
- targeted E2E/acceptance runs with `-count=1`
- explicit CLI contract commands with `--json`

Cross-platform lane:

- `go test ./core/cli -count=1`
- `go test ./core/detect/... -count=1`
- `go test ./core/regress -count=1`
- symlink tests must skip cleanly on platforms/environments that do not support the fixture

Risk lane:

- `make prepush-full`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make test-perf` when detector helper hot-path cost changes materially

Merge/release gating rule:

- Wave 1 and Wave 2 are release-blocking runtime fixes. They cannot merge without green fast, core CI, acceptance, cross-platform, and required risk-lane checks.
- Wave 3 is release-blocking for any release that publishes the corrected semantics externally.
- No implementation PR may land docs-only wording for these fixes before the corresponding runtime wave is green.

## Wave 1 - Epic W1: Identity-State Contract Correction

Objective: tighten the identity, inventory, manifest, and regress pipeline so only real tool identities participate in lifecycle and approval state.

### Story W1-S01: Replace broad exclusion logic with authoritative real-tool allowlists

Priority: P0
Tasks:
- Replace the current negative-filter approach in `core/model/identity_bearing.go` with explicit allowlists for lifecycle-bearing and inventory-bearing findings.
- Encode `secret_presence`, `source_discovery`, `policy_check`, `policy_violation`, `parse_error`, and other posture/bookkeeping finding classes as non-bearing by default.
- Keep the allowlist authoritative in one place and have downstream identity/inventory callers consume that shared policy instead of re-encoding it.
- Add legacy compatibility filtering so older snapshots/manifests/baselines that already contain non-tool identities remain readable but are excluded from fresh identity synthesis and drift comparison.
- Verify `observedTools`, `SnapshotTools`, `manifestgen.GenerateUnderReview`, and inventory builders all use the same authoritative semantics.
Repo paths:
- `core/model/identity_bearing.go`
- `core/cli/scan_helpers.go`
- `core/regress/regress.go`
- `core/manifestgen/generate.go`
- `core/aggregate/inventory/inventory.go`
- `core/model/identity_bearing_test.go`
- `core/cli/scan_observed_tools_test.go`
- `core/regress/regress_test.go`
- `core/manifestgen/generate_test.go`
Run commands:
- `go test ./core/model ./core/aggregate/inventory ./core/cli ./core/regress ./core/manifestgen -count=1`
- `make test-contracts`
- `make prepush-full`
- `go run ./cmd/wrkr scan --my-setup --state ./.tmp/p1-identity-state.json --json`
- `go run ./cmd/wrkr regress init --baseline ./.tmp/p1-identity-state.json --output ./.tmp/p1-identity-baseline.json --json`
- `go run ./cmd/wrkr regress run --baseline ./.tmp/p1-identity-baseline.json --state ./.tmp/p1-identity-state.json --json`
Test requirements:
- unit allowlist tests for lifecycle-bearing and inventory-bearing helpers
- regress compatibility tests for legacy baselines containing non-tool identities
- manifest generation tests proving non-tool findings do not emit identity records
- CLI `--json` stability tests for scan/regress/manifest when only non-tool findings change
- contract tests if any machine-readable additive metadata is introduced
Matrix wiring:
- Fast lane: `make lint-fast`; targeted `go test` packages above
- Core CI lane: `make prepush`
- Acceptance lane: `make test-scenarios`; targeted `go test ./internal/e2e/regress ./internal/e2e/manifest -count=1`
- Cross-platform lane: `go test ./core/cli ./core/regress -count=1`
- Risk lane: `make prepush-full`; `make test-contracts`; `make test-hardening`
Acceptance criteria:
- `secret_presence` and `source_discovery` findings no longer create manifest identities, inventory agents, or `agent_privilege_map` rows.
- A transient `OPENAI_API_KEY` change alone no longer yields `new_unapproved_tool` drift.
- Legacy state and baseline files containing non-tool identities remain readable and do not fail closed as invalid input.
- Output ordering stays deterministic.
Contract/API impact:
- Tightens the semantic contract for which findings become lifecycle/inventory state.
- JSON field names stay stable; only the set of materialized identities changes.
Versioning/migration impact:
- No schema major bump.
- Legacy artifact compatibility must be preserved by runtime filtering rather than file-format rewrite.
Architecture constraints:
- Keep identity-bearing classification authoritative in the Go core model layer.
- Do not duplicate allowlists across CLI, regress, manifest, or inventory code.
- Use explicit helper names that make side effects and semantics clear.
- Preserve deterministic ordering and offline defaults.
- If inventory and lifecycle semantics intentionally differ, encode separate explicit helpers and tests rather than hidden branching.
ADR required: yes
TDD first failing test(s):
- `TestIsIdentityBearingFinding_UsesExplicitAllowlist`
- `TestIsInventoryBearingFinding_UsesExplicitAllowlist`
- `TestObservedToolsExcludesSecretPresenceAndSourceDiscovery`
- `TestCompareIgnoresLegacyNonToolBaselineEntries`
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: a `--my-setup` or `--path` scan with stable real tool findings yields no regress drift.
- Fault: non-tool findings toggle on/off and legacy artifacts still contain non-tool identities.
- Expected: no false `new_unapproved_tool` drift, no manifest pollution, deterministic sorted outputs, and exit `0` unless a real tool change exists.

### Story W1-S02: Propagate corrected identity semantics through downstream CLI and artifact flows

Priority: P0
Tasks:
- Audit downstream consumers of `snapshot.Identities`, inventory agents, and regress baselines so report/evidence/identity/lifecycle flows do not reintroduce non-tool identities.
- Add outside-in fixtures proving `wrkr identity list`, `wrkr lifecycle`, `wrkr manifest generate`, and `wrkr regress run` stay aligned after the allowlist change.
- Update acceptance/scenario coverage so transient env-key presence and source bookkeeping remain finding-only across saved-state workflows.
- Regenerate and review any deterministic goldens affected by the corrected semantic scope.
Repo paths:
- `core/cli/root_test.go`
- `core/cli/identity.go`
- `core/cli/lifecycle.go`
- `core/report/build.go`
- `core/evidence/evidence.go`
- `core/export/appendix/export.go`
- `internal/e2e/regress/*`
- `internal/e2e/manifest/*`
- `internal/acceptance/*`
- `internal/scenarios/*`
Run commands:
- `go test ./core/cli ./core/report ./core/evidence ./core/export/appendix -count=1`
- `go test ./internal/e2e/regress ./internal/e2e/manifest -count=1`
- `go test ./internal/acceptance -count=1`
- `make test-scenarios`
- `make prepush-full`
Test requirements:
- CLI contract tests for `scan`, `manifest generate`, `identity`, `lifecycle`, and `regress` `--json` outputs
- E2E tests for saved-state and baseline compatibility flows
- acceptance/scenario fixtures covering transient env-key toggles and source bookkeeping
- golden updates where deterministic counts or rows change because of corrected semantics
Matrix wiring:
- Fast lane: targeted `go test ./core/cli ./core/report ./core/evidence -count=1`
- Core CI lane: `make prepush`
- Acceptance lane: `go test ./internal/e2e/regress ./internal/e2e/manifest -count=1`; `go test ./internal/acceptance -count=1`; `make test-scenarios`
- Cross-platform lane: `go test ./core/cli -count=1`
- Risk lane: `make prepush-full`; `make test-contracts`; `make test-hardening`
Acceptance criteria:
- `wrkr identity list` and `wrkr lifecycle --json` no longer expose non-tool identities for the reviewed fixtures.
- `wrkr manifest generate --json` emits only real tool identities from corrected scan state.
- Evidence/report/export flows remain valid and deterministic after identity filtering.
- Scenario and acceptance coverage encode the corrected semantics externally, not only in unit tests.
Contract/API impact:
- No public field removals.
- Downstream identity-related counts and rows may change to reflect corrected semantics.
Versioning/migration impact:
- No schema version bump.
- Count changes are documented as semantic bug fixes.
Architecture constraints:
- Keep downstream consumers thin; the classification decision must remain upstream and authoritative.
- Avoid ad hoc filtering in each presentation/export layer unless it is explicitly contract-scoped and tested.
- Preserve deterministic artifact ordering.
ADR required: yes
TDD first failing test(s):
- `TestIdentityListOmitsNonToolFindingsFromScanState`
- `TestManifestGenerateOmitsLegacyNonToolIdentities`
- `TestE2ERegressRunIgnoresTransientSecretPresenceForToolDrift`
- `TestAcceptanceMySetupSecretPresenceRemainsFindingOnly`
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: downstream commands render saved scan state consistently.
- Fault: corrected upstream identity filtering removes rows that old downstream assumptions expected.
- Expected: downstream commands stay deterministic, artifact generation does not crash, and only true tool identities remain addressable.

## Wave 2 - Epic W2: Repo-Root Boundary Enforcement for Detector File Access

Objective: ensure detectors never read files outside the selected repo root, even when the repo contains symlinks pointing elsewhere.

### Story W2-S01: Introduce shared boundary-safe file helpers for detector reads

Priority: P0
Tasks:
- Add shared helper(s) in `core/detect/parse.go` for boundary-safe existence checks and file reads.
- Resolve candidate paths with `Lstat` and `EvalSymlinks`, then reject any file whose final target escapes `scope.Root`.
- Keep within-root symlinks deterministic and explicitly supported or explicitly rejected by the shared helper; do not leave mixed detector behavior.
- Adopt the helper across structured parsing and direct read paths used by Codex, Claude, MCP, and secrets detectors.
- Add a stable machine-readable unsafe-path classification for rejected outside-root file reads.
Repo paths:
- `core/detect/parse.go`
- `core/detect/parse_test.go`
- `core/detect/codex/detector.go`
- `core/detect/codex/detector_test.go`
- `core/detect/claude/detector.go`
- `core/detect/claude/detector_test.go`
- `core/detect/mcp/detector.go`
- `core/detect/mcp/detector_test.go`
- `core/detect/secrets/detector.go`
- `core/detect/secrets/detector_test.go`
Run commands:
- `go test ./core/detect ./core/detect/codex ./core/detect/claude ./core/detect/mcp ./core/detect/secrets -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make test-perf`
- `make prepush-full`
Test requirements:
- unit tests for boundary-safe helper behavior:
  - outside-root symlink escape rejected
  - in-root symlink behavior explicit and deterministic
  - dangling symlink behavior deterministic
  - symlink loop behavior deterministic
- detector tests proving external `.codex/config.toml`, `.env`, `.mcp.json`, and Claude settings are not read
- contract tests for any additive unsafe-path error classification
- perf check if helper cost is measurable on detector hot paths
Matrix wiring:
- Fast lane: targeted `go test` packages above
- Core CI lane: `make prepush`
- Acceptance lane: targeted E2E/CLI scan checks from Wave 2 Story 2
- Cross-platform lane: `go test ./core/detect/... -count=1`
- Risk lane: `make prepush-full`; `make test-contracts`; `make test-hardening`; `make test-chaos`; `make test-perf`
Acceptance criteria:
- Root-escaping symlinked config/env/workflow files are not read.
- Scan output never includes external `credential_keys`, approval policy, MCP, or Claude settings from outside the selected repo root.
- Unsafe-path handling is deterministic and machine-readable.
- Output ordering remains stable.
Contract/API impact:
- Adds a stable unsafe-path classification for file-level boundary violations.
- Does not change the global exit-code contract.
Versioning/migration impact:
- Additive only.
- No schema major bump.
Architecture constraints:
- Boundary enforcement must live in shared detector helpers, not bespoke detector code.
- Helper names must make semantics explicit, such as `read within root` versus plain `read`.
- Preserve bounded deterministic ordering and avoid unbounded retry or traversal behavior.
- Keep extension points centralized so future detectors do not fork the trust model.
ADR required: yes
TDD first failing test(s):
- `TestReadFileWithinRootRejectsSymlinkEscape`
- `TestReadFileWithinRootHandlesDanglingSymlinkDeterministically`
- `TestCodexDetectorRejectsExternalSymlinkedConfig`
- `TestSecretsDetectorRejectsExternalSymlinkedEnv`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Steady state: detector reads repo-owned config files only.
- Fault: repo contains escape symlink, dangling symlink, or symlink loop.
- Expected: no outside-root read occurs, the offending file is surfaced deterministically, unaffected files still scan, and the process does not hang.

### Story W2-S02: Add end-to-end hardening coverage for unsafe repo-root file surfaces

Priority: P1
Tasks:
- Add CLI/E2E tests that reproduce the reviewed path-scan escape cases with symlinked `.codex/config.toml` and `.env`.
- Add mixed-repo fixtures so one unsafe repo does not suppress valid findings from sibling repos.
- Extend hardening/chaos coverage to repeated scans and edge cases involving dangling links and loops.
- Assert deterministic JSON ordering for the resulting findings, parse errors, and detector errors.
Repo paths:
- `core/cli/root_test.go`
- `core/cli/scan_partial_errors_test.go`
- `internal/e2e/source/source_e2e_test.go`
- `internal/scenarios/*`
- `scripts/test_hardening_core.sh`
- `scripts/test_chaos_*.sh`
Run commands:
- `go test ./core/cli -count=1`
- `go test ./internal/e2e/source -count=1`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- CLI `--json` stability tests for mixed safe/unsafe repo scans
- E2E path-scan fixtures for symlink escape cases
- hardening tests for repeated-run determinism
- chaos tests for symlink loop and dangling-link failure modes
- scenario fixture coverage if user-visible semantics are documented as outside-in behavior
Matrix wiring:
- Fast lane: targeted `go test ./core/cli -count=1`
- Core CI lane: `make prepush`
- Acceptance lane: `go test ./internal/e2e/source -count=1`; `make test-scenarios`
- Cross-platform lane: `go test ./core/cli -count=1`
- Risk lane: `make prepush-full`; `make test-hardening`; `make test-chaos`
Acceptance criteria:
- `wrkr scan --path --json` no longer ingests outside-root config or env content.
- Mixed repo scans continue to return valid findings for safe repos.
- Dangling links and loops fail deterministically without hangs or non-deterministic ordering.
- The reviewed reproductions are encoded as permanent tests.
Contract/API impact:
- Reinforces the `scan --json` contract with explicit unsafe-path behavior and stable ordering.
Versioning/migration impact:
- None beyond the additive unsafe-path classification introduced in `W2-S01`.
Architecture constraints:
- Keep CLI behavior thin over detector-layer enforcement.
- Do not introduce command-specific symlink handling that diverges from shared helper semantics.
- Preserve explicit partial-failure behavior and deterministic ordering.
ADR required: no
TDD first failing test(s):
- `TestScanPathRejectsExternalSymlinkedCodexConfig`
- `TestScanPathRejectsExternalSymlinkedEnv`
- `TestE2EScanPathMixedReposPreservesSafeFindingsWhenOneRepoIsUnsafe`
- `TestChaosUnsafeSymlinkLoopDoesNotHang`
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: a mixed path scan returns deterministic findings for all repos.
- Fault: one repo contains escape/dangling/looping symlinks.
- Expected: only the offending files surface deterministic diagnostics, safe repos still produce findings, and no hang or exit-code drift occurs.

## Wave 3 - Epic W3: Docs and Contract Alignment

Objective: align README, command docs, lifecycle docs, and manifest spec wording with the corrected runtime semantics.

### Story W3-S01: Update docs to match real-tool identity scope and repo-root safety guarantees

Priority: P1
Tasks:
- Update README first-screen wording so env-key presence and source bookkeeping are described as findings/risk signals, not approvable identities.
- Update `docs/commands/scan.md` to document repo-root-safe file reads and root-escaping symlink rejection behavior.
- Update `docs/state_lifecycle.md` and `docs/specs/wrkr-manifest.md` so the manifest identity profile is clearly scoped to real tool identities only.
- Update `docs/commands/manifest.md`, `docs/commands/regress.md`, `docs/examples/quickstart.md`, and `docs/trust/security-and-privacy.md` to match the corrected semantics.
- Update `docs/contracts/readme_contract.md` if the README first-screen contract needs new enforcement text.
Repo paths:
- `README.md`
- `docs/commands/scan.md`
- `docs/commands/manifest.md`
- `docs/commands/regress.md`
- `docs/state_lifecycle.md`
- `docs/specs/wrkr-manifest.md`
- `docs/examples/quickstart.md`
- `docs/trust/security-and-privacy.md`
- `docs/contracts/readme_contract.md`
Run commands:
- `make test-docs-consistency`
- `scripts/run_docs_smoke.sh`
- `go test ./testinfra/contracts ./testinfra/hygiene -count=1`
Test requirements:
- docs consistency checks
- README first-screen checks
- docs smoke checks for touched command/user flows
- source-of-truth mapping checks if contract wording changes
Matrix wiring:
- Fast lane: `make test-docs-consistency`
- Core CI lane: `go test ./testinfra/contracts ./testinfra/hygiene -count=1`
- Acceptance lane: `scripts/run_docs_smoke.sh`
- Cross-platform lane: none required beyond existing workflow coverage
- Risk lane: none
Acceptance criteria:
- Docs do not imply that `secret_presence` or `source_discovery` become manifest identities or approval targets.
- Docs explicitly state that root-escaping symlinked files are rejected and not read during repo scans.
- README, command docs, lifecycle docs, and manifest spec all tell the same story.
- Docs checks are green in the same PR as the runtime changes.
Contract/API impact:
- Docs and examples only; no runtime field changes.
Versioning/migration impact:
- None.
Architecture constraints:
- Docs must mirror runtime truth in the same PR.
- Keep integration-first flow intact and avoid introducing new unsupported claims.
ADR required: no
TDD first failing test(s):
- README/docs contract checks for updated first-screen wording
- docs consistency/parity checks for `scan`, `manifest`, and `regress`
Cost/perf impact: low

## Minimum-Now Sequence

Wave 1:

1. Implement `W1-S01` first to establish the authoritative identity-bearing allowlist and legacy compatibility path.
2. Implement `W1-S02` next to propagate the corrected semantics through CLI, saved-state, and outside-in acceptance surfaces.

Wave 2:

3. Implement `W2-S01` after Wave 1 is green so file-boundary enforcement lands in one shared helper layer.
4. Implement `W2-S02` immediately after `W2-S01` so the verified repros become permanent CLI/E2E/hardening coverage before docs are updated.

Wave 3:

5. Implement `W3-S01` only after Waves 1 and 2 are green, so docs reflect final runtime behavior rather than interim wording.

Implementation handoff note:

- This plan is intended for `adhoc-implement` on a fresh branch.
- The worktree was clean before generating this plan; implementation should start only if the working tree still contains no unrelated changes beyond this plan file.

## Explicit Non-Goals

- No detector coverage expansion to new tools, providers, or runtime modes.
- No change to the stable exit-code contract.
- No schema major version bump.
- No new networked or enrich-mode behavior.
- No change to proof-chain signing or verify semantics beyond what falls out of corrected identity content.
- No fix for unrelated review observations outside these two verified P1 findings.
- No dashboard/UI/docs-site redesign work beyond contract-alignment docs updates required by these fixes.

## Definition of Done

- Every user-provided recommendation maps to one or more stories in this plan.
- Each story has concrete repo paths, commands, tests, acceptance criteria, and matrix wiring.
- Contract-impacting stories preserve additive compatibility and document migration expectations.
- Boundary-sensitive stories include authoritative shared-helper design, fail-closed semantics, and hardening/chaos coverage.
- CLI-facing stories include explicit `--json` and exit-code invariants.
- Docs updates are included for every user-visible semantic change.
- Required ADR expectations are called out for architecture-impacting stories.
- The execution order is dependency-driven: runtime semantics first, docs last.

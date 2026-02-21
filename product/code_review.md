# PLAN Code Review Remediation: Fail-Closed Source and Lifecycle/Regress Contract Hardening

Date: 2026-02-21
Source of truth: User-provided findings (P1/P1/P2) from full-repo code review; repository contracts in `product/wrkr.md`, `product/dev_guides.md`, and `product/Clyra_AI.md`
Scope: Planning-only backlog for remediation of three confirmed findings in source acquisition, regress identity boundaries, and lifecycle approval-state semantics

## Global Decisions (Locked)
- Org/repo scan modes must be fail-closed when real GitHub acquisition cannot be performed.
- Synthetic source targets (for example `org/default`) are not valid scan artifacts for compliance proof flows.
- Identity-bearing finding boundaries must be defined once and reused by lifecycle and regress logic.
- Policy/meta findings are not approval-tracked tools and must not drive `new_unapproved_tool` regress drift.
- Non-approved lifecycle states (`under_review`, `deprecated`, `revoked`) must never persist `approval_status=valid`.
- CLI/exit-code contracts remain stable unless explicitly versioned; this plan preserves existing exit-code meanings.

## Current Baseline (Observed)
- Repro 1 (fail-open source acquisition): `./.tmp/wrkr scan --org acme --json` returned `status=ok`, `exit=0`, and synthesized `source_manifest.repos[0].repo=acme/default` with no GitHub API configured.
- Repro 2 (regress boundary leak): baseline built from scan state contained `policy-*` and `source-repo-*` tool IDs; removing one policy tool from baseline yielded `wrkr regress run ...` `exit=5` with reason `new_unapproved_tool` for `wrkr:policy-...`.
- Repro 3 (approval-state contradiction): after `identity approve` then `identity revoke` (no reason), `identity show --json` reported `status=revoked` with `approval_status=valid`.
- Runtime baseline sanity: `go test ./... -count=1` passed during review run; scan/regress/verify command anchors were executable with `--json`.

## Exit Criteria
- `--org` and `--repo` scans without real GitHub acquisition no longer emit synthetic repos and no longer succeed falsely.
- Regress baseline/tool comparison excludes policy/meta finding classes by shared rule with lifecycle identity boundaries.
- Manual non-approved transitions cannot leave `approval_status=valid`.
- Updated tests prove deterministic behavior, fail-closed behavior, and stable reason-code semantics.
- CLI/docs remain aligned for changed behavior and error outcomes.

## Normalized Recommendations
- `REC-1`
- Recommendation: fail closed for org/repo scans when GitHub acquisition is not configured or cannot execute.
- Why: current behavior can fabricate repos and generate false compliance evidence.
- Strategic direction: enforce source-of-truth acquisition preconditions at connector and CLI boundary.
- Expected moat/benefit: stronger audit trust and lower false-positive/false-green operational risk.
- `REC-2`
- Recommendation: apply one shared identity-bearing finding boundary across lifecycle and regress paths.
- Why: policy/meta findings currently leak into regress tool state and trigger false drift.
- Strategic direction: centralize finding-class eligibility and reuse it in both pipelines.
- Expected moat/benefit: higher signal quality in regression enforcement and lower noise in approvals workflows.
- `REC-3`
- Recommendation: normalize approval state on non-approved manual transitions and finalize reason policy.
- Why: `revoked` identities can retain `approval_status=valid`, creating contradictory lifecycle semantics.
- Strategic direction: tighten lifecycle transition invariants and CLI contract behavior.
- Expected moat/benefit: predictable governance semantics and safer downstream policy decisions.

## Recommendation Traceability
- `REC-1` Fail-open org/repo scans fabricate source repos when GitHub API is unset -> `EPIC-CR1 / Story CR1-S1`, `EPIC-CR1 / Story CR1-S2`
- `REC-2` Regress path treats policy findings as tools, causing false drift -> `EPIC-CR2 / Story CR2-S1`, `EPIC-CR2 / Story CR2-S2`
- `REC-3` Revoke/deprecate can leave `approval_status=valid` when no reason is supplied -> `EPIC-CR3 / Story CR3-S1`, `EPIC-CR3 / Story CR3-S2`

## Test Matrix Wiring
- Fast lane: unit tests for touched packages (`core/source/github`, `core/regress`, `core/lifecycle`, `core/cli`) plus lint/static checks.
- Core CI lane: `go test ./... -count=1` plus scenario/E2E suites impacted by source, regress, identity, and lifecycle behavior.
- Acceptance lane: `internal/acceptance` and scenario specs validating command contracts and drift semantics.
- Cross-platform lane: smoke coverage on Linux/macOS/Windows for CLI flag handling and path behavior.
- Risk lane: command anchors with JSON outputs:
- `wrkr scan --json`
- `wrkr regress init --baseline <state-path> --json`
- `wrkr regress run --baseline <baseline-path> --json`
- `wrkr verify --chain --json`
- Merge/release gating rule: no merge until all required lanes pass and new/updated contract tests pass with deterministic outputs.

## EPIC-CR1: Fail-Closed GitHub Source Acquisition
Objective: Eliminate fabricated source manifests and enforce acquisition preconditions for `--repo` and `--org` scan modes.

### Story CR1-S1: Enforce hard preconditions for org/repo acquisition
Priority: P0
Tasks:
- Replace fail-open path in GitHub connector when `BaseURL` is empty for org/repo modes.
- Decide and codify strict behavior:
- Option A: require explicit `--github-api`/`WRKR_GITHUB_API_BASE` and token policy.
- Option B: default to `https://api.github.com` and execute real acquisition, surfacing failures.
- Ensure acquisition failures are surfaced as deterministic error codes/messages in CLI scan path.
Repo paths:
- `core/source/github/connector.go`
- `core/cli/scan.go`
- `core/source/org/acquire.go`
Run commands:
- `go test ./core/source/github ./core/source/org ./core/cli -count=1`
- `./.tmp/wrkr scan --org acme --json`
- `./.tmp/wrkr scan --repo acme/backend --json`
Test requirements:
- Gate/fail-closed fixtures for unset API base and unreachable API.
- Deterministic error payload and exit-code assertions for org/repo modes.
- Reason-code stability checks for affected CLI errors.
Matrix wiring:
- Fast lane: yes
- Core CI lane: yes
- Acceptance lane: yes (CLI contract/E2E)
- Cross-platform lane: yes
- Risk lane: yes (`scan --json`)
Acceptance criteria:
- No synthetic repos are emitted for org/repo modes.
- Org/repo scan without viable acquisition path does not return false success.
- Error semantics are deterministic and documented.
Dependencies:
- None
Risks:
- Potential behavior shift for users who previously relied on offline synthetic fallback.

### Story CR1-S2: Align docs and command contracts for new acquisition semantics
Priority: P1
Tasks:
- Update command docs for `scan` to reflect hard requirements and fail-closed behavior.
- Update examples to avoid synthetic/offline org fallback assumptions.
- Add CLI contract tests for help text/error contracts where required.
Repo paths:
- `docs/commands/scan.md`
- `docs/commands/index.md`
- `docs/examples/quickstart.md`
- `internal/e2e/cli_contract/cli_contract_e2e_test.go`
Run commands:
- `go test ./internal/e2e/cli_contract -count=1`
- `./.tmp/wrkr scan --help`
Test requirements:
- CLI behavior tests for updated usage text and JSON error shape.
- Docs consistency checks for scan mode preconditions.
Matrix wiring:
- Fast lane: yes
- Core CI lane: yes
- Acceptance lane: yes
- Cross-platform lane: yes
- Risk lane: no
Acceptance criteria:
- Docs/examples match actual CLI behavior.
- Contract tests enforce updated expectations.
Dependencies:
- `CR1-S1`

## EPIC-CR2: Regress and Lifecycle Identity Boundary Unification
Objective: Prevent policy/meta findings from entering approval/lifecycle regression tool state and creating false drift.

### Story CR2-S1: Introduce shared identity-bearing finding classifier
Priority: P0
Tasks:
- Create shared predicate/helper that defines identity-bearing finding classes.
- Apply helper in lifecycle observed-tool construction and regress snapshot-tool extraction.
- Preserve deterministic sorting and canonical identity derivation.
Repo paths:
- `core/cli/scan.go`
- `core/regress/regress.go`
- `core/model` (new shared helper file)
Run commands:
- `go test ./core/regress ./core/cli ./core/model -count=1`
- `./.tmp/wrkr scan --path scenarios/wrkr/scan-mixed-org/repos --state .tmp/cr2-state.json --json`
- `./.tmp/wrkr regress init --baseline .tmp/cr2-state.json --output .tmp/cr2-baseline.json --json`
Test requirements:
- Unit tests proving policy/meta findings are excluded from identity-bearing tool state.
- Determinism tests showing stable tool ordering and IDs run-to-run.
- Boundary tests for allowed classes (tool configs, skills, mcp, ci-agent, etc.).
Matrix wiring:
- Fast lane: yes
- Core CI lane: yes
- Acceptance lane: yes
- Cross-platform lane: yes
- Risk lane: yes (`scan`, `regress init`)
Acceptance criteria:
- Lifecycle and regress consume the same identity-bearing class definition.
- Policy findings no longer appear as approval-tracked tools.
Dependencies:
- None

### Story CR2-S2: Lock regress drift semantics against policy-induced false positives
Priority: P1
Tasks:
- Add regress tests reproducing and preventing `new_unapproved_tool` from policy/meta baseline deltas.
- Add E2E fixture where policy findings change but tool findings remain stable; assert no drift for policy-only changes.
- Validate existing revoked/permission-expansion behaviors still hold for true tools.
Repo paths:
- `core/regress/regress_test.go`
- `internal/e2e/regress/regress_e2e_test.go`
- `internal/scenarios` (policy/regress scenario fixture updates)
Run commands:
- `go test ./core/regress ./internal/e2e/regress ./internal/scenarios -count=1`
- `./.tmp/wrkr regress run --baseline .tmp/cr2-baseline.json --state .tmp/cr2-state.json --json`
Test requirements:
- Repro fixture for removed policy tool in baseline resulting in no drift.
- Existing drift reasons remain deterministic for real tool deltas.
- Byte-stable baseline outputs unaffected except intended class filtering.
Matrix wiring:
- Fast lane: yes
- Core CI lane: yes
- Acceptance lane: yes
- Cross-platform lane: yes
- Risk lane: yes (`regress run --json`)
Acceptance criteria:
- Policy/rule-pack changes do not trigger `new_unapproved_tool`.
- Real tool lifecycle regressions still trigger expected reason codes.
Dependencies:
- `CR2-S1`

## EPIC-CR3: Lifecycle Approval-State Consistency on Manual Transitions
Objective: Ensure manual transitions to non-approved states cannot retain `approval_status=valid` and cannot mislead downstream approval logic.

### Story CR3-S1: Normalize approval state for non-approved lifecycle states
Priority: P1
Tasks:
- Update manual transition logic so `review`, `deprecate`, and `revoke` always move approval state away from `valid`.
- Optionally clear/retain approval metadata consistently (document chosen rule).
- Verify regress `isApproved` behavior remains coherent with updated lifecycle state semantics.
Repo paths:
- `core/lifecycle/lifecycle.go`
- `core/cli/identity.go`
- `core/regress/regress.go`
- `core/lifecycle/lifecycle_test.go`
Run commands:
- `go test ./core/lifecycle ./core/cli ./core/regress -count=1`
- `./.tmp/wrkr identity approve <agent_id> --approver @qa --scope test --expires 90d --state <state> --json`
- `./.tmp/wrkr identity revoke <agent_id> --state <state> --json`
- `./.tmp/wrkr identity show <agent_id> --state <state> --json`
Test requirements:
- Lifecycle tests for approve->revoke/deprecate/review state transitions.
- JSON contract tests asserting non-approved states never report `approval_status=valid`.
- Reason-code and transition record stability tests.
Matrix wiring:
- Fast lane: yes
- Core CI lane: yes
- Acceptance lane: yes
- Cross-platform lane: yes
- Risk lane: yes (`identity` + `regress run --json`)
Acceptance criteria:
- `revoked/deprecated/under_review` identities cannot carry `approval_status=valid`.
- No contradictory state appears in `identity show` history.
Dependencies:
- None

### Story CR3-S2: Decide and enforce `--reason` policy for non-approved transitions
Priority: P2
Tasks:
- Choose contract policy:
- Path 1: require `--reason` for `review/deprecate/revoke`.
- Path 2: keep optional but enforce deterministic default reason in transition diff.
- Implement selected behavior and update docs/help accordingly.
- Add CLI contract tests for argument validation/output semantics.
Repo paths:
- `core/cli/identity.go`
- `docs/commands/identity.md`
- `core/cli/root_test.go`
- `internal/e2e/cli_contract/cli_contract_e2e_test.go`
Run commands:
- `go test ./core/cli ./internal/e2e/cli_contract -count=1`
- `./.tmp/wrkr identity revoke --help`
Test requirements:
- CLI argument contract tests.
- JSON output stability tests for transition payload.
- Docs consistency checks for changed semantics.
Matrix wiring:
- Fast lane: yes
- Core CI lane: yes
- Acceptance lane: yes
- Cross-platform lane: yes
- Risk lane: no
Acceptance criteria:
- Reason policy is explicit, deterministic, and test-enforced.
- Docs and CLI behavior are aligned.
Dependencies:
- `CR3-S1`

## Minimum-Now Sequence
1. `CR1-S1` fail-closed source acquisition behavior.
2. `CR2-S1` shared identity-bearing boundary helper.
3. `CR2-S2` regress false-drift guardrails.
4. `CR3-S1` lifecycle approval-state normalization.
5. `CR1-S2` and `CR3-S2` docs/CLI contract finalization.

## Explicit Non-Goals
- No new dashboard/UI scope.
- No expansion of detector catalog beyond boundary/contract fixes required for these findings.
- No schema version bump unless a hard compatibility break is unavoidable.
- No Python/SDK feature additions.

## Definition of Done
- All three findings are covered by merged stories with passing tests in declared matrix lanes.
- `scan`, `regress`, `identity`, and `verify` command contracts remain deterministic and documented.
- Fail-closed behavior is verified for undecidable/unconfigured acquisition paths.
- Regress drift reasons are free of policy/meta false positives.
- Lifecycle state and approval status semantics are internally consistent and evidence-verifiable.

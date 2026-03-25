# PLAN WRKR_GTM_ACTION_PATH_AND_OPERABILITY: Large-Org Operability, Govern-First Action Paths, and Honest Static Delivery Truth

Date: 2026-03-25
Source of truth:
- user-provided Updated GTM-Critical Work List dated 2026-03-25
- `product/dev_guides.md`
- `product/architecture_guides.md`
- `AGENTS.md`
- `README.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/commands/mcp-list.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/faq.md`
- `docs/positioning.md`
- `docs/trust/detection-coverage-matrix.md`
- `core/cli/scan.go`
- `core/cli/scan_helpers.go`
- `core/source/github/connector.go`
- `core/source/org/acquire.go`
- `core/report/build.go`
- `core/report/activation.go`
- `core/report/types.go`
- `core/aggregate/attackpath/graph.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/detect/ciagent/detector.go`
- `core/detect/mcp/detector.go`
- `core/detect/mcpgateway/detector.go`
- `core/detect/workstation/detector.go`
- `core/owners/owners.go`
- `core/policy/eval/eval.go`
- `core/policy/loader.go`
- `core/compliance/rulemap.go`
Scope: Wrkr repository only. Planning artifact only. Close the current GTM-critical Wrkr-side gaps around large-org scan operability, first-scan value presentation, delivery-path truth, ownership/governance quality, MCP/local wedge depth, non-human execution identity, and static-message honesty without weakening determinism, offline-first defaults, fail-closed behavior, schema stability, or exit-code stability.

## Global Decisions (Locked)

- `github.com/Clyra-AI/proof v0.4.6` remains the correct pinned dependency for this plan; no proof-version remediation wave is required.
- Contract/runtime work lands before docs-only/onboarding polish. Later docs waves may clarify earlier runtime changes, but not replace them.
- `wrkr scan` stdout remains reserved for the final machine-readable JSON payload when `--json` is set.
- Long-running `--json` scans may emit additive progress, retry, cooldown, resume, and completion lines to stderr only.
- Additive scan output ergonomics are allowed:
  - new `--json-path <path>`
  - explicit resume UX for interrupted org scans via `--resume`
- `--json-path` must not weaken current `--json` stdout behavior:
  - `--json` alone keeps current stdout contract
  - `--json-path` writes the final JSON artifact to disk
  - `--json --json-path` writes byte-identical final JSON to both stdout and file
- Org-scan checkpoint state lives under `.wrkr/` with atomic writes, deterministic ordering, and existing managed-path safety semantics.
- `core/cli/scan.go` stays thin. Source acquisition, progress/cooldown state, checkpoint logic, and JSON sink helpers belong in focused packages/helpers.
- New report and scan surfaces are additive only:
  - extend `activation` beyond `my_setup`
  - add `action_paths`
  - add `action_path_to_control_first`
  - add additive ownership and non-human identity fields
- Existing `attack_paths`, `top_attack_paths`, `top_findings`, `inventory`, `agent_privilege_map`, `compliance_summary`, and exit codes `0..8` remain stable.
- Workflow and MCP capability extraction must remain structured-parse-first. Regex-only logic is not acceptable for YAML/JSON/TOML-backed config semantics.
- Production impact language stays target-backed:
  - `write_capable` is always safe to claim
  - `production_write` is safe to claim only when production targets are configured and valid
- Ownership compatibility is preserved:
  - current owner string remains
  - `owner_source`, `ownership_status`, and `operational_owner` are additive
- Approval-gap modeling remains static-only. Wrkr may claim missing or ambiguous approval structure, but never claim observed reviewer behavior or shipped runtime behavior.
- Runtime provenance, live MCP behavior, and proposed-vs-shipped claims stay out of Wrkr-only docs, report templates, and public wording.
- Stories that change architecture boundaries, risk logic, adapters, or failure semantics must run `make prepush-full`.
- Reliability and concurrency stories must also run `make test-hardening` and `make test-chaos`.
- Performance-sensitive org-acquisition stories must also run `make test-perf`.

## Current Baseline (Observed)

- Planning inputs validated:
  - `product/dev_guides.md` exists and is readable
  - `product/architecture_guides.md` exists and is readable
  - output path `product/PLAN_NEXT.md` resolves inside `/Users/tr/wrkr`
- The worktree was clean before this plan rewrite.
- Current toolchain/dependency baseline already matches org policy:
  - Go `1.26.1`
  - `github.com/Clyra-AI/proof v0.4.6`
  - `gopkg.in/yaml.v3 v3.0.1`
- `wrkr scan` already supports:
  - `--github-org`
  - `--state`
  - `--report-md`
  - `--sarif`
  - `--timeout`
  - `--json`
  - `--quiet`
  - production-target policy loading
  - approved-tools policy loading
- GitHub acquisition already has deterministic retry/backoff/cooldown behavior in `core/source/github/connector.go`, and docs already mention retry/degradation semantics.
- Large-org hosted operability is still incomplete:
  - no `--json-path`
  - no visible progress lines in `--json` mode
  - sequential org acquisition in `core/source/org/acquire.go`
  - no interruption/resume path
- First-value activation exists only for `my_setup`:
  - `core/report/activation.go` hard-gates on `target.mode=my_setup`
  - `scan` and `report` already expose additive `activation` for local-machine scans
  - org/path scans do not yet project a govern-first activation view
- Attack-path modeling exists but is still coarse:
  - `core/aggregate/attackpath/graph.go` builds repo-local entry/pivot/target edges
  - there is no first-class `action_path_to_control_first`
  - there is no normalized per-path `recommended_action`
  - there is no delivery-chain semantic object spanning PR -> merge -> deploy
- Delivery-path capability truth is still shallow:
  - `core/detect/ciagent/detector.go` uses heuristic string detection for headless, secret access, and approval gates
  - first-class workflow permissions like `repo.write`, `merge.execute`, `deploy.write`, `db.write`, and `iac.write` are not yet derived
- Ownership still collapses explicit and inferred states:
  - `core/owners/owners.go` returns a single owner string with deterministic fallback
  - no `owner_source`
  - no `ownership_status`
  - no path-level `operational_owner`
- MCP and local-machine wedge coverage exists but is generic:
  - `core/detect/mcp/detector.go` emits coarse `mcp.access`
  - `core/detect/mcpgateway/detector.go` adds coverage posture
  - `core/report/mcp_list.go` renders list rows
  - `core/detect/workstation/detector.go` finds local tool/config/secrets, but not sanctioned-vs-unsanctioned governance gaps
- Non-human execution identity is not yet first-class:
  - no dedicated GitHub App, bot, or service-account inventory
  - no identity-to-action-path correlation
- Correctness rails exist but need explicit GTM hardening:
  - `core/policy/loader.go` already normalizes `WRKR-A###`
  - `core/compliance/rulemap.go` already maps bundled framework controls
  - `core/detect/detect.go` already classifies `permission_denied`, but end-to-end surfacing is not yet fully guaranteed across detectors
- Docs already state some static boundaries, but not strongly enough for the GTM wedge:
  - hosted token guidance is present but not fine-grained PAT specific
  - large-org runbook is not yet explicit
  - docs/templates still need a repository-wide audit against runtime-provenance and live-MCP overclaiming

## Exit Criteria

1. Large-org operators can follow one documented fine-grained PAT recipe and complete the recommended org-scan path without guessing token scopes or whether the scan is hung.
2. `wrkr scan --json` preserves stdout JSON-only behavior while surfacing deterministic progress, retry, cooldown, resume, and completion lines to stderr.
3. `--json-path` works for scan output without breaking current `--json` stdout behavior, and `--json --json-path` emits byte-identical final JSON to both sinks.
4. Interrupted org scans can resume from deterministic checkpoint state under `.wrkr/` and produce the same final sorted result as a clean run.
5. Org/path scans emit additive activation items that project immediate review candidates without mutating existing ranked findings.
6. Wrkr emits first-class, ranked `action_paths` plus one `action_path_to_control_first` object with a stable `recommended_action` enum of `inventory|approval|proof|control`.
7. Workflow capability extraction and PR -> merge -> deploy correlation are strong enough to back software-delivery GTM claims while remaining static-only and target-backed.
8. Ownership surfaces distinguish explicit vs inferred ownership and emit `operational_owner` on privilege/action-path views.
9. MCP action-surface and local-governance-gap signals become materially stronger while remaining deterministic and offline-first.
10. Non-human execution identities can be inventoried and tied to prioritized action paths.
11. `WRKR-A###` compliance mapping remains correct end-to-end.
12. Permission/stat/read failures are surfaced explicitly in scan JSON instead of being silently dropped.
13. Docs, examples, and report templates remain inside Wrkr’s posture-only/static-only boundary.
14. GTM scenario packs cover all listed wedge scenarios and are wired into deterministic contracts and scenario lanes.
15. No story weakens:
  - deterministic ordering
  - offline-first defaults
  - proof-chain portability
  - exit codes `0..8`
  - existing public JSON keys or meanings

## Public API and Contract Map

Stable/public surfaces touched by this plan:

- CLI commands:
  - `wrkr scan`
  - `wrkr report`
  - `wrkr mcp-list`
- Stable scan flags:
  - existing: `--json`, `--state`, `--timeout`, `--report-md`, `--report-md-path`, `--sarif`, `--sarif-path`, `--github-org`, `--github-api`, `--github-token`
  - new additive: `--json-path`, `--resume`
- Stable machine-readable scan surfaces:
  - existing: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `attack_paths`, `top_attack_paths`, `inventory`, `privilege_budget`, `agent_privilege_map`, `repo_exposure_summaries`, `profile`, `posture_score`, `compliance_summary`, `warnings`, `detector_errors`
  - new additive: `activation` for `org` and `path`, `action_paths`, `action_path_to_control_first`
- Stable machine-readable inventory and privilege surfaces:
  - existing `inventory.tools[*].locations[*].owner`
  - new additive `owner_source`, `ownership_status`, `operational_owner`
  - new additive `inventory.non_human_identities[*]`
  - new additive `agent_privilege_map[*].operational_owner`
- Stable machine-readable MCP/report surfaces:
  - richer `mcp-list` row permission/privilege signals are additive
  - report summary may surface additive activation/action-path objects, but existing summary sections remain intact
- Stable docs contract surfaces:
  - `README.md` first-screen install/start-here contract
  - `docs/commands/scan.md`
  - `docs/examples/quickstart.md`
  - `docs/examples/security-team.md`
  - `docs/faq.md`
  - `docs/positioning.md`
  - `docs/trust/detection-coverage-matrix.md`

Internal surfaces expected to change:

- `core/cli/scan.go`
- `core/cli/scan_helpers.go`
- `core/source/github/connector.go`
- `core/source/org/acquire.go`
- new helper packages under `core/source/org/` for checkpoint/progress state
- `core/report/activation.go`
- `core/report/build.go`
- `core/report/types.go`
- `core/report/mcp_list.go`
- `core/aggregate/attackpath/graph.go`
- new helper packages under `core/aggregate/` for delivery-chain and identity correlation
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/detect/ciagent/detector.go`
- `core/detect/compiledaction/detector.go`
- new capability helpers under `core/detect/`
- `core/detect/mcp/detector.go`
- `core/detect/mcpgateway/detector.go`
- `core/detect/workstation/detector.go`
- `core/owners/owners.go`
- `core/policy/eval/eval.go`
- `core/policy/rules/builtin.yaml`
- `core/policy/loader.go`
- `core/compliance/rulemap.go`
- `core/report/templates/`
- `internal/scenarios/`
- `scenarios/wrkr/`
- `testinfra/contracts/`
- `testinfra/hygiene/`

Shim/deprecation path:

- No existing flag or key deprecation is planned.
- Existing `attack_paths` / `top_attack_paths` remain intact while new `action_paths` / `action_path_to_control_first` land additively.
- Existing owner string fields remain and are not replaced.
- No proof-record, lifecycle-state, or exit-code deprecation is planned.

Schema/versioning policy:

- Preferred implementation path is additive-only with no schema version bump.
- New top-level scan/report fields are optional and omitted when not applicable.
- Checkpoint files under `.wrkr/` are internal implementation artifacts, versioned independently, and are not public OSS compatibility commitments.
- If any public schema bump becomes unavoidable during implementation, stop and create an ADR plus explicit migration note before merge.

Machine-readable error expectations:

- `--json-path` path validation/write errors must remain machine-readable and use existing error classes:
  - `invalid_input` for invalid flag/value combinations
  - `runtime_failure` for write failures
  - `unsafe_operation_blocked` if managed-path safety is violated
- `--resume` with missing/mismatched checkpoint metadata must fail deterministically with machine-readable error detail.
- Stderr progress lines are additive operator UX only and are not a machine-readable API.
- Permission/stat/read failures must appear in `detector_errors`, `parse_error`, or `warnings` as applicable and remain sorted/deterministic.
- `production_write` must never become true unless production targets are configured and valid.

## Docs and OSS Readiness Baseline

README first-screen contract:

- `README.md` remains security/platform-led first.
- `## Install` must keep:
  - Homebrew
  - pinned/reproducible Go path
  - `wrkr version --json` verification
- `## Start Here` must keep:
  - hosted org posture as the recommended first path
  - deterministic local fallback paths (`--path`, `--my-setup`)
  - explicit hosted prerequisites
  - link to the large-org runbook
- PAT guidance must point to fine-grained PAT setup for the GitHub endpoints Wrkr actually calls.

Integration-first docs flow for this plan:

1. `README.md`
2. `docs/examples/quickstart.md`
3. `docs/commands/scan.md`
4. `docs/examples/security-team.md`
5. `docs/faq.md`
6. `docs/commands/report.md`
7. `docs/commands/mcp-list.md`
8. `docs/positioning.md`
9. `docs/trust/detection-coverage-matrix.md`

Lifecycle path model the docs must preserve:

- `wrkr scan` remains the authoritative state producer.
- `.wrkr/last-scan.json` remains the canonical saved-state handoff for `report`, `mcp-list`, `evidence`, `verify`, and follow-on flows.
- `--json-path` is an additive export convenience, not a replacement for `.wrkr/last-scan.json`.
- `.wrkr/` checkpoint state is resumability metadata for hosted org scans, not a proof artifact.
- `report`, `mcp-list`, and docs must continue to distinguish:
  - discovered static posture
  - governance gaps
  - configured production-target backing
  - proof/evidence artifacts

Docs source-of-truth mapping:

- CLI behavior authority:
  - `core/cli/*`
- hosted acquisition and PAT endpoint authority:
  - `core/source/github/connector.go`
- activation/action-path authority:
  - `core/report/*`
  - `core/aggregate/*`
  - `core/risk/*`
- ownership and governance authority:
  - `core/owners/*`
  - `core/policy/*`
- MCP posture authority:
  - `core/detect/mcp/*`
  - `core/detect/mcpgateway/*`
  - `core/report/mcp_list.go`
- docs enforcement:
  - `scripts/check_docs_cli_parity.sh`
  - `scripts/check_docs_storyline.sh`
  - `scripts/check_docs_consistency.sh`
  - `scripts/run_docs_smoke.sh`
  - `testinfra/hygiene/*`

OSS trust baseline:

- Preserve and validate existing baseline files:
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `.github/ISSUE_TEMPLATE/*`
  - `.github/pull_request_template.md`
- This plan does not require new community-health files.
- Any user-visible behavior change must update docs and tests in the same PR.

## Recommendation Traceability

| Rec ID | Recommendation | Story mapping |
|---|---|---|
| R1 | Fine-grained GitHub PAT docs | `W1-S03` |
| R2 | Stderr progress in `--json` mode | `W1-S01` |
| R3 | `--json-path` | `W1-S01` |
| R4 | Large-org recommended runbook | `W1-S03` |
| R5 | Bounded concurrency and resume/checkpoint | `W1-S02` |
| R6 | Org/path activation surface | `W2-S01` |
| R7 | `action_path_to_control_first` object | `W2-S02` |
| R8 | `recommended_action` per path | `W2-S02` |
| R9 | Workflow capability extraction | `W3-S01` |
| R10 | PR -> merge -> deploy chain semantics | `W3-S02` |
| R11 | Production-write claims stay target-backed | `W3-S02` |
| R12 | `owner_source` and `ownership_status` | `W4-S01` |
| R13 | Path-level `operational_owner` | `W4-S01` |
| R14 | Sharper static approval-gap modeling | `W4-S02` |
| R15 | Richer MCP action-surface modeling | `W5-S01` |
| R16 | Local/CLI governance-gap comparison | `W5-S02` |
| R17 | First-class non-human identity inventory | `W6-S01` |
| R18 | Non-human identity correlated to action path | `W6-S02` |
| R19 | Keep `WRKR-A###` mapping correct end-to-end | `W7-S01` |
| R20 | Surface stat/permission failures | `W7-S02` |
| R21 | Keep runtime provenance out of Wrkr-only claims | `W7-S03` |
| R22 | Keep live MCP/runtime tool-action claims out | `W7-S03` |
| R23 | GTM scenario packs and contract wiring | `W8-S01` |

## Test Matrix Wiring

Lane definitions:

- Fast lane:
  - `make lint-fast`
  - focused `go test` for touched packages with `-count=1`
  - docs checks when docs are touched
- Core CI lane:
  - `make prepush`
  - `make prepush-full` for architecture/risk/adapter/failure changes
- Acceptance lane:
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - targeted internal/e2e or acceptance commands for story-specific user flows
- Cross-platform lane:
  - existing `windows-smoke`
  - story-specific CLI/contract coverage on Linux/macOS/Windows when public behavior changes
- Risk lane:
  - `make test-contracts`
  - `make test-hardening`
  - `make test-chaos`
  - `make test-perf`
  - story-specific parity/contract/hardening commands as required
- Merge/release gating rule:
  - stories may merge only after all declared `Yes` lanes are green
  - Wave 1 must complete before Wave 2
  - docs must update in the same PR as any user-visible behavior change
  - scenario/contract updates must ship in the same PR as any new public JSON surface

Story-to-lane map:

| Story | Fast | Core CI | Acceptance | Cross-platform | Risk |
|---|---|---|---|---|---|
| W1-S01 | Yes | Yes | Yes | Yes | Yes |
| W1-S02 | Yes | Yes | Yes | Yes | Yes |
| W1-S03 | Yes | No | Yes | No | No |
| W2-S01 | Yes | Yes | Yes | Yes | Yes |
| W2-S02 | Yes | Yes | Yes | Yes | Yes |
| W3-S01 | Yes | Yes | Yes | Yes | Yes |
| W3-S02 | Yes | Yes | Yes | Yes | Yes |
| W4-S01 | Yes | Yes | Yes | Yes | Yes |
| W4-S02 | Yes | Yes | Yes | Yes | Yes |
| W5-S01 | Yes | Yes | Yes | Yes | Yes |
| W5-S02 | Yes | Yes | Yes | Yes | Yes |
| W6-S01 | Yes | Yes | Yes | Yes | Yes |
| W6-S02 | Yes | Yes | Yes | Yes | Yes |
| W7-S01 | Yes | Yes | Yes | Yes | Yes |
| W7-S02 | Yes | Yes | Yes | Yes | Yes |
| W7-S03 | Yes | No | Yes | No | No |
| W8-S01 | No | Yes | Yes | No | Yes |

## Epic W1: Large-Org Scan Operability

Objective: make hosted org scans feel reliable and controllable for 300-repo operators without weakening deterministic output contracts.

### Story W1-S01: Add Deterministic JSON Output Ergonomics for Long Org Scans
Priority: P1
Tasks:
- Add failing CLI and contract tests for `--json-path`, stdout/stderr separation, and final-payload byte identity.
- Add stderr-only progress lines for `--json` mode covering:
  - repo count discovery
  - current repo index
  - retry/backoff
  - cooldown waits
  - completion summary
- Keep stdout reserved for the final JSON payload and suppress progress lines under `--quiet`.
- Add deterministic JSON sink handling so the final payload can be written to stdout, file, or both without duplication drift.
- Update command docs and README examples to document `--json-path`.
Repo paths:
- `core/cli/scan.go`
- `core/cli/scan_helpers.go`
- `core/source/github/connector.go`
- `core/cli/jsonmode.go`
- `core/cli/`
- `internal/e2e/cli_contract/`
- `testinfra/contracts/`
- `README.md`
- `docs/commands/scan.md`
Run commands:
- `go test ./core/cli ./core/source/github -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- CLI help/usage tests for `--json-path`
- `--json` stability tests
- stdout/file byte-identity tests for `--json --json-path`
- retry/backoff stderr visibility tests with `429` and `5xx` fixture servers
- machine-readable error-envelope tests for invalid or unwritable `--json-path`
- docs CLI parity updates
Matrix wiring:
- Fast lane: focused `go test` for `core/cli` and `core/source/github`
- Core CI lane: `make prepush-full`
- Acceptance lane: targeted CLI contract/e2e coverage for stdout/stderr separation
- Cross-platform lane: CLI contract coverage on Linux/macOS/Windows
- Risk lane: `make test-contracts`, `make test-hardening`, `make test-chaos`
Acceptance criteria:
- `wrkr scan ... --json` keeps stdout JSON-only and emits progress to stderr only.
- `wrkr scan ... --json-path out.json` writes the final JSON payload to `out.json`.
- `wrkr scan ... --json --json-path out.json` writes byte-identical final JSON to stdout and file.
- Retry/cooldown events are visible and deterministic in stderr for hosted org scans.
- No existing `--json` consumer breaks.
Contract/API impact:
- Adds public `--json-path` to `wrkr scan`.
- Adds stderr progress as operator UX only; stdout JSON contract is unchanged.
Versioning/migration impact:
- No schema version bump.
- No migration required for existing state or proof artifacts.
Architecture constraints:
- Keep sink orchestration in CLI helpers and connector callbacks, not in report/risk packages.
- Preserve cancellation and timeout propagation across progress callbacks.
- Do not introduce buffered progress that can reorder lines relative to repo processing.
- Keep progress non-authoritative; only final JSON is contractual.
ADR required: no
TDD first failing test(s):
- `core/cli/scan_json_path_test.go`
- `core/cli/scan_progress_test.go`
- `internal/e2e/cli_contract/cli_contract_e2e_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- Under `429`, `5xx`, and cooldown conditions, Wrkr still emits one valid final JSON payload and never interleaves progress lines into stdout.

### Story W1-S02: Add Bounded Concurrency and Explicit Resume for Org Acquisition
Priority: P1
Tasks:
- Add failing tests for deterministic worker concurrency, checkpoint persistence, interruption, and resume.
- Introduce bounded worker concurrency for org materialization while preserving stable final ordering.
- Add checkpoint metadata under `.wrkr/` with atomic writes and deterministic repo-completion records.
- Add explicit `--resume` UX for interrupted org scans so fresh and resumed runs are distinguishable.
- Ensure resumed runs reuse completed repo materialization safely and continue from pending work only.
- Update large-org docs to document resume behavior and checkpoint location/semantics.
Repo paths:
- `core/cli/scan.go`
- `core/cli/scan_helpers.go`
- `core/source/org/acquire.go`
- `core/source/github/connector.go`
- `core/source/org/`
- `testinfra/contracts/`
- `internal/scenarios/`
- `docs/commands/scan.md`
- `docs/examples/security-team.md`
Run commands:
- `go test ./core/source/org ./core/source/github ./core/cli -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make test-perf`
- `make prepush-full`
Test requirements:
- contention/concurrency tests
- crash-safe checkpoint atomic-write tests
- interruption/resume scenario tests
- deterministic final-ordering tests against synthetic large-org fixtures
- performance budget checks for bounded concurrency
- CLI contract tests for `--resume` help, success, and mismatch failures
Matrix wiring:
- Fast lane: focused `go test` for source/CLI packages
- Core CI lane: `make prepush-full`
- Acceptance lane: scenario test for interruption/resume on representative org fixture
- Cross-platform lane: checkpoint/resume contract tests on Linux/macOS/Windows
- Risk lane: `make test-contracts`, `make test-hardening`, `make test-chaos`, `make test-perf`
Acceptance criteria:
- Org acquisition is bounded-concurrent, not unbounded.
- Final repo ordering and final JSON ordering remain deterministic.
- An interrupted run can be resumed explicitly with `--resume`.
- Resume mismatches fail deterministically instead of silently mixing checkpoints.
- Resumed output matches the final result of a clean uninterrupted run.
Contract/API impact:
- Adds public `--resume` to `wrkr scan`.
- Adds internal checkpoint metadata under `.wrkr/`; checkpoint file format is internal, not public API.
Versioning/migration impact:
- No public schema bump.
- Internal checkpoint metadata includes its own version marker and safe invalidation rules.
Architecture constraints:
- Keep checkpoint IO isolated from detection/risk/report packages.
- Maintain explicit side-effect semantics in resume helpers.
- Preserve cancellation and timeout propagation across worker pool operations.
- Fail closed on checkpoint corruption, ownership violations, or fingerprint mismatch.
ADR required: yes
TDD first failing test(s):
- `core/source/org/acquire_resume_test.go`
- `core/cli/scan_resume_test.go`
- `internal/scenarios/org_resume_scenario_test.go`
Cost/perf impact: medium
Chaos/failure hypothesis:
- If the process is interrupted mid-run or mid-checkpoint write, Wrkr either resumes safely from the last durable checkpoint or fails closed without corrupting final ordering or silently skipping repos.
Dependencies:
- `W1-S01`

### Story W1-S03: Document Fine-Grained PAT Setup and the Large-Org Runbook
Priority: P1
Tasks:
- Map documented token requirements to the exact GitHub endpoints Wrkr calls:
  - org repo listing
  - repo metadata
  - git trees
  - blobs
- Add a fine-grained PAT recipe that matches those endpoints and avoids overscoped guidance.
- Add the recommended large-org command path including:
  - `--state`
  - `--report-md`
  - `--sarif`
  - `--timeout`
  - `--json-path`
  - `--resume`
  - retry/cooldown expectations
  - partial-result interpretation
- Update FAQ and quickstart so hosted prerequisites, PAT scope, and fallback paths stay aligned.
- Validate docs against the hosted connector behavior in code.
Repo paths:
- `README.md`
- `docs/commands/scan.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/faq.md`
- `core/source/github/connector.go`
- `testinfra/hygiene/`
Run commands:
- `make test-docs-consistency`
- `scripts/run_docs_smoke.sh`
- `go test ./testinfra/hygiene -count=1`
Test requirements:
- docs consistency checks
- README first-screen checks
- docs storyline/smoke checks
- source-of-truth mapping checks for connector behavior vs docs
- manual validation note for private test-org fine-grained PAT dry run
Matrix wiring:
- Fast lane: docs checks and hygiene tests
- Core CI lane: not required beyond story-local checks
- Acceptance lane: docs smoke and storyline validation
- Cross-platform lane: no
- Risk lane: no
Acceptance criteria:
- PAT docs name the least-privilege fine-grained access needed for the hosted scan path.
- README, scan docs, quickstart, security-team example, and FAQ tell the same story.
- The large-org runbook gives one opinionated command path and explains retries, cooldowns, partial results, and resume.
Contract/API impact:
- Docs-only for PAT/runbook guidance, except for documenting `--json-path` and `--resume`.
Versioning/migration impact:
- No schema, version, or exit-code change.
Architecture constraints:
- Docs must reflect real connector behavior and fail-closed semantics.
- Fallback paths must remain explicit and honest.
ADR required: no
TDD first failing test(s):
- `testinfra/hygiene/wave2_docs_contracts_test.go`
- docs smoke/storyline checks
Cost/perf impact: low
Chaos/failure hypothesis:
- When operators hit rate limits or private-repo auth failures, the documented path must still let them recover without guessing scopes or whether partial results are trustworthy.
Dependencies:
- `W1-S01`
- `W1-S02`

## Epic W2: Govern-First First-Scan Value

Objective: make the first meaningful action explicit for org/path scans without mutating the raw risk ranking or overstating runtime truth.

### Story W2-S01: Extend Activation Beyond `my_setup` to Org and Path Scans
Priority: P1
Tasks:
- Add failing tests for org/path activation payloads in scan and report outputs.
- Generalize activation projection to support `org` and `path` modes.
- Add compact activation item classes for:
  - unknown-to-security write-capable paths
  - production-target-backed paths
  - approval-gap paths
  - govern-first candidate paths
- Keep `top_findings` and `ranked_findings` unchanged; activation remains additive.
- Add share-profile sanitization for any new activation fields.
- Update scan/report docs to document activation outside `my_setup`.
Repo paths:
- `core/report/activation.go`
- `core/report/build.go`
- `core/report/types.go`
- `core/cli/scan.go`
- `core/report/activation_test.go`
- `core/cli/report_contract_test.go`
- `internal/scenarios/`
- `docs/commands/scan.md`
- `docs/commands/report.md`
Run commands:
- `go test ./core/report ./core/cli -count=1`
- `go test ./internal/scenarios -run '^TestOrgActivation' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- additive JSON contract tests for activation on `org` and `path`
- scenario tests with deterministic activation ordering
- report contract tests for additive activation summary
- share-profile sanitization tests
- docs CLI parity updates
Matrix wiring:
- Fast lane: `go test ./core/report ./core/cli -count=1`
- Core CI lane: `make prepush-full`
- Acceptance lane: scenario and report contract tests
- Cross-platform lane: CLI/report contract coverage on supported OS runners
- Risk lane: `make test-contracts`
Acceptance criteria:
- `activation` is emitted for eligible `org` and `path` scans.
- Existing `my_setup` activation behavior remains unchanged.
- Activation is additive and does not reorder or delete ranked findings.
- Public/share-profile outputs sanitize activation data consistently.
Contract/API impact:
- Broadens existing `activation` surface to additional target modes without changing prior keys.
Versioning/migration impact:
- No version bump; additive optional output only.
Architecture constraints:
- Activation stays in `core/report` as a projection layer, not a second risk engine.
- Inputs must come from already-computed deterministic scan/risk state.
- No network or runtime observation allowed.
ADR required: yes
TDD first failing test(s):
- `core/report/activation_test.go`
- `core/cli/report_contract_test.go`
- `internal/scenarios/org_activation_scenario_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- If source coverage is partial or no eligible items exist, Wrkr emits a deterministic empty/reasoned activation result instead of overstating first-action confidence.

### Story W2-S02: Add Ranked `action_paths` and `action_path_to_control_first`
Priority: P1
Tasks:
- Define a normalized action-path object that combines:
  - identity
  - write capability
  - production targeting
  - ownership
  - approval gap
  - credential access
  - deployment status
  - attack-path score
- Add a stable `recommended_action` enum of `inventory|approval|proof|control`.
- Add `action_paths` plus one `action_path_to_control_first` to scan/report outputs.
- Preserve existing `attack_paths` / `top_attack_paths` and use them as supporting rather than replacement surfaces.
- Add deterministic summary counts such as total paths, write-capable paths, production-target-backed paths, and govern-first count.
- Add scenario fixtures that prove stable ranking and recommendation outcomes.
Repo paths:
- `core/aggregate/attackpath/graph.go`
- `core/risk/risk.go`
- `core/report/types.go`
- `core/report/build.go`
- `core/cli/scan.go`
- `core/cli/report_contract_test.go`
- `internal/scenarios/`
- `docs/commands/scan.md`
- `docs/commands/report.md`
Run commands:
- `go test ./core/aggregate/... ./core/risk ./core/report ./core/cli -count=1`
- `go test ./internal/scenarios -run '^TestActionPathToControlFirst' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- new schema/contract tests for additive action-path objects
- deterministic ranking and recommendation tests
- golden/scenario output updates
- report contract tests for govern-first projection
- compatibility assertions that legacy attack-path surfaces remain intact
Matrix wiring:
- Fast lane: focused aggregate/risk/report/CLI tests
- Core CI lane: `make prepush-full`
- Acceptance lane: action-path scenario coverage
- Cross-platform lane: CLI/report contract coverage
- Risk lane: `make test-contracts`
Acceptance criteria:
- Scan/report outputs include `action_paths` and exactly one `action_path_to_control_first` when eligible data exists.
- `recommended_action` values remain inside the locked enum.
- Representative scenario output can summarize `12 action paths`, `5 write-capable`, `3 production-target-backed`, `1 govern first`.
- Existing attack-path outputs remain available and deterministic.
Contract/API impact:
- Adds new public additive scan/report objects: `action_paths`, `action_path_to_control_first`, and `recommended_action`.
Versioning/migration impact:
- No version bump planned; additive contract only.
Architecture constraints:
- Raw graph correlation remains separate from ranking logic.
- Risk scoring owns ordering and recommendation derivation.
- Report assembly consumes pre-ranked data rather than recomputing its own semantics.
- Any missing ownership/deployment/identity input must degrade confidence, not fabricate certainty.
ADR required: yes
TDD first failing test(s):
- `core/risk/risk_test.go`
- `core/cli/report_contract_test.go`
- `internal/scenarios/action_path_to_control_first_scenario_test.go`
Cost/perf impact: medium
Chaos/failure hypothesis:
- If ownership, deployment, or production-target inputs are incomplete, Wrkr degrades to lower-confidence recommendations instead of escalating unsupported `control` or `production_write` claims.
Dependencies:
- `W2-S01`

## Epic W3: Software-Delivery Path Truth

Objective: strengthen static delivery-path claims so Wrkr can safely show how AI-assisted write access can move from PR to deploy without runtime overreach.

### Story W3-S01: Add Structured Workflow Capability Extraction
Priority: P1
Tasks:
- Add failing tests and fixtures for PR automation, deploy workflows, Terraform/Helm/Kubernetes, and migration flows.
- Introduce a focused workflow-capability helper under `core/detect/` that parses GitHub Actions YAML with typed structures.
- Extend compiled-action and CI detectors to emit first-class permissions such as:
  - `repo.write`
  - `pull_request.write`
  - `merge.execute`
  - `deploy.write`
  - `db.write`
  - `iac.write`
- Correlate known deploy/migration/action patterns without regex-only YAML semantics.
- Emit stable evidence keys explaining why each capability was derived.
Repo paths:
- `core/detect/ciagent/detector.go`
- `core/detect/compiledaction/detector.go`
- `core/detect/`
- `fixtures/`
- `internal/scenarios/`
- `docs/trust/detection-coverage-matrix.md`
- `docs/commands/scan.md`
Run commands:
- `go test ./core/detect/... -count=1`
- `go test ./internal/scenarios -run '^TestWorkflowCapabilities' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- parser/schema tests for workflow documents
- capability fixture tests for PR, deploy, IaC, and migration cases
- deterministic evidence/reason-code checks
- scenario acceptance for capability extraction
- docs coverage-matrix updates
Matrix wiring:
- Fast lane: `go test ./core/detect/... -count=1`
- Core CI lane: `make prepush-full`
- Acceptance lane: workflow-capability scenarios
- Cross-platform lane: deterministic contract checks on supported OS runners
- Risk lane: `make test-contracts`
Acceptance criteria:
- Workflow-related findings and downstream surfaces emit first-class permissions backed by static evidence.
- Malformed or ambiguous workflow files do not overclaim permissions.
- Known deployment and migration fixtures produce deterministic capability outputs.
Contract/API impact:
- Adds richer additive permission/evidence data to existing scan surfaces.
Versioning/migration impact:
- No version bump.
- Existing `ci_autonomy` and compiled-action findings remain compatible.
Architecture constraints:
- Use structured YAML parsing for Actions workflows.
- Keep provider/action heuristics isolated behind detector helpers.
- No runtime GitHub calls or live workflow evaluation.
- Preserve deterministic evidence ordering and reason-code stability.
ADR required: yes
TDD first failing test(s):
- `core/detect/ciagent/detector_test.go`
- `core/detect/compiledaction/detector_test.go`
- `internal/scenarios/workflow_capabilities_scenario_test.go`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Partial or malformed workflow configs must surface parse errors and conservative capability omission, never false-positive deploy or merge claims.

### Story W3-S02: Correlate PR -> Merge -> Deploy Chains and Keep Production Claims Honest
Priority: P1
Tasks:
- Build a delivery-chain correlator over workflow capability extraction and production-target inputs.
- Correlate AI write paths through PR creation, merge capability, workflow trigger, deployment artifact, and production-target match.
- Surface delivery-chain semantics inside action-path outputs and rank them deterministically.
- Harden public/report wording so missing or invalid production targets never imply production impact.
- Add tests for configured, invalid, and missing production-target cases.
Repo paths:
- `core/aggregate/attackpath/graph.go`
- `core/aggregate/`
- `core/risk/risk.go`
- `core/report/build.go`
- `core/cli/scan.go`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `internal/scenarios/`
- `testinfra/contracts/`
Run commands:
- `go test ./core/aggregate/... ./core/risk ./core/report ./core/cli -count=1`
- `go test ./internal/scenarios -run '^TestDeliveryChainCorrelation' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- end-to-end delivery-chain fixture tests
- configured/invalid/missing production-target contract tests
- report wording/golden tests
- action-path ranking regression tests
- scenario acceptance for PR -> merge -> deploy
Matrix wiring:
- Fast lane: aggregate/risk/report/CLI tests
- Core CI lane: `make prepush-full`
- Acceptance lane: delivery-chain scenarios
- Cross-platform lane: CLI/report contract checks
- Risk lane: `make test-contracts`
Acceptance criteria:
- A fixture with PR write + auto-merge + deploy produces a ranked delivery-chain-aware action path.
- Missing or invalid production targets never produce `production_write=true`.
- Public/report wording falls back to `write_capable` plus production-target status when target backing is absent.
Contract/API impact:
- Adds additive delivery-chain metadata to action-path outputs while preserving existing `production_write` semantics.
Versioning/migration impact:
- No version bump; additive fields only.
Architecture constraints:
- Delivery correlation belongs in aggregation, not in docs/report-only logic.
- Risk scoring may amplify path score from chain semantics, but only from static evidence.
- Fail closed or degrade explicitly on missing production-target backing.
ADR required: yes
TDD first failing test(s):
- `core/risk/risk_test.go`
- `core/cli/root_test.go`
- `internal/scenarios/delivery_chain_correlation_scenario_test.go`
Cost/perf impact: medium
Chaos/failure hypothesis:
- Ambiguous merge/deploy edges or invalid production-target policy must degrade to explicit non-production claims instead of silently inflating blast radius.
Dependencies:
- `W3-S01`
- `W2-S02`

## Epic W4: Ownership and Governance Reality

Objective: distinguish real ownership and review structure from deterministic fallback so Wrkr can tell operators which path needs governance first and who should own the next move.

### Story W4-S01: Add Ownership Provenance and `operational_owner`
Priority: P1
Tasks:
- Refactor owner resolution to return:
  - current owner string
  - `owner_source`
  - `ownership_status`
- Preserve fallback owner compatibility for existing downstream consumers.
- Add `operational_owner` to privilege-map and action-path surfaces using repo ownership, deployment context, and deterministic platform fallback rules.
- Add fixtures with and without `CODEOWNERS`.
- Thread additive ownership metadata through inventory, privilege-budget, action-path, and report surfaces.
Repo paths:
- `core/owners/owners.go`
- `core/aggregate/inventory/inventory.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/report/types.go`
- `core/report/build.go`
- `internal/scenarios/`
- `testinfra/contracts/`
Run commands:
- `go test ./core/owners ./core/aggregate/... ./core/report -count=1`
- `go test ./internal/scenarios -run '^TestOwnershipQuality' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- explicit-vs-fallback ownership unit tests
- additive contract tests for ownership fields
- scenario acceptance for explicit, inferred, and unresolved operational owners
- golden updates for privilege/action-path rows
Matrix wiring:
- Fast lane: focused owner/aggregate/report tests
- Core CI lane: `make prepush-full`
- Acceptance lane: ownership-quality scenarios
- Cross-platform lane: CLI contract coverage
- Risk lane: `make test-contracts`
Acceptance criteria:
- Existing owner string stays present.
- New additive fields distinguish explicit and inferred ownership everywhere downstream.
- At least one scenario shows a named team as `operational_owner` and another shows deterministic inferred/unresolved status.
Contract/API impact:
- Adds additive fields to inventory, privilege-map, action-path, and report outputs.
Versioning/migration impact:
- No version bump; legacy owner field remains.
Architecture constraints:
- `core/owners` stays authoritative for owner provenance.
- Aggregation owns `operational_owner` derivation from multiple inputs.
- Missing ownership evidence must be surfaced explicitly, not normalized away.
ADR required: yes
TDD first failing test(s):
- `core/owners/owners_test.go`
- `core/aggregate/inventory/inventory_test.go`
- `internal/scenarios/ownership_quality_scenario_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- Missing or conflicting ownership sources must result in deterministic inferred/unknown status, never silent fallback that looks explicit.

### Story W4-S02: Strengthen Static Approval-Gap Modeling
Priority: P1
Tasks:
- Add failing policy and scenario tests for:
  - missing approval source
  - ambiguous deployment gate
  - auto-deploy without human gate
  - missing proof requirement
- Extend static source extraction so approval/gate/proof evidence is captured consistently.
- Update builtin policy rules/evaluation logic with stable reason codes and no runtime-reviewer assumptions.
- Surface sharper approval-gap facts into report/action-path outputs.
Repo paths:
- `core/policy/eval/eval.go`
- `core/policy/rules/builtin.yaml`
- `core/detect/agentframework/source.go`
- `core/detect/ciagent/detector.go`
- `internal/scenarios/`
- `scenarios/wrkr/agent-policy-outcomes/`
- `testinfra/contracts/`
Run commands:
- `go test ./core/policy/... ./core/detect/agentframework ./core/detect/ciagent -count=1`
- `go test ./internal/scenarios -run '^TestApprovalGapModeling' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- deterministic allow/block/require-approval fixtures
- fail-closed ambiguous-gate tests
- stable reason-code checks
- scenario coverage for ambiguous and missing gate structures
- contract tests for approval-gap reporting
Matrix wiring:
- Fast lane: focused policy/detector tests
- Core CI lane: `make prepush-full`
- Acceptance lane: approval-gap scenarios
- Cross-platform lane: policy contract coverage
- Risk lane: `make test-contracts`
Acceptance criteria:
- Missing or ambiguous approval structure produces explicit static findings.
- Auto-deploy without human gate remains a deterministic high-risk outcome.
- Wrkr never implies observed reviewer behavior; it only claims static structure or its absence.
Contract/API impact:
- Sharpens additive policy/detail surfaces while preserving stable rule IDs and exit behavior.
Versioning/migration impact:
- No schema bump.
- Existing bundled rule IDs remain canonical; richer details are additive.
Architecture constraints:
- Evaluation remains static-only.
- Rule IDs and reason codes must stay stable.
- Ambiguous high-risk approval structure must fail closed in policy semantics.
ADR required: yes
TDD first failing test(s):
- `core/policy/eval/eval_test.go`
- `core/policy/policy_test.go`
- `internal/scenarios/approval_gap_modeling_scenario_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- If approval metadata is incomplete, Wrkr must classify the gap explicitly rather than treating the path as safe-by-default.
Dependencies:
- `W3-S01`

## Epic W5: Partial Wedge Expansion

Objective: deepen the MCP and local-machine partial wedge so Wrkr can tell operators where governance is weaker even before full org delivery-path correlation is complete.

### Story W5-S01: Add Richer MCP Action-Surface Modeling
Priority: P1
Tasks:
- Add failing MCP fixtures for distinct read/write/admin-style declaration surfaces.
- Extend MCP parsing so config and gateway signals imply stronger action-surface semantics than generic `mcp.access`.
- Correlate gateway posture with MCP privilege signals and render them clearly in `mcp-list`.
- Update MCP risk notes so stronger write/admin surfaces are explained without live probing claims.
Repo paths:
- `core/detect/mcp/detector.go`
- `core/detect/mcpgateway/detector.go`
- `core/report/mcp_list.go`
- `fixtures/`
- `internal/scenarios/`
- `docs/commands/mcp-list.md`
- `docs/trust/detection-coverage-matrix.md`
Run commands:
- `go test ./core/detect/mcp ./core/detect/mcpgateway ./core/report -count=1`
- `go test ./internal/scenarios -run '^TestMCPActionSurface' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- MCP parser/fixture tests
- gateway correlation tests
- `mcp-list` contract tests for additive permission fields
- docs matrix updates
- scenario acceptance for dangerous MCP action surface
Matrix wiring:
- Fast lane: focused MCP/report tests
- Core CI lane: `make prepush-full`
- Acceptance lane: MCP action-surface scenarios
- Cross-platform lane: CLI/report contract coverage
- Risk lane: `make test-contracts`
Acceptance criteria:
- MCP rows distinguish materially different action surfaces.
- Gateway posture influences rendered risk notes and privilege interpretation.
- Wrkr still makes static/config-based claims only.
Contract/API impact:
- Enriches additive MCP permission and privilege-surface data; existing row keys remain.
Versioning/migration impact:
- No version bump.
Architecture constraints:
- Static config parsing only.
- Keep declaration parsing separate from gateway posture parsing and report rendering.
- No live endpoint behavior, session observation, or runtime claim.
ADR required: yes
TDD first failing test(s):
- `core/detect/mcp/detector_test.go`
- `core/report/mcp_list_test.go`
- `internal/scenarios/mcp_action_surface_scenario_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- Ambiguous MCP declarations must degrade to unknown privilege surface with explicit warning rather than escalating to write/admin claims.

### Story W5-S02: Add Deterministic Local Governance-Gap Comparison
Priority: P1
Tasks:
- Add failing local-machine fixtures for sanctioned and unsanctioned tool/config usage.
- Compare workstation discoveries against approved-tools or sanctioned config baselines.
- Emit deterministic findings for local governance gaps without promoting secret-presence signals into lifecycle identities.
- Thread local governance-gap counts into inventory/report surfaces where helpful.
- Update personal-hygiene and scan docs if any new local-governance fields are surfaced.
Repo paths:
- `core/detect/workstation/detector.go`
- `core/policy/approvedtools/`
- `core/aggregate/inventory/inventory.go`
- `docs/examples/personal-hygiene.md`
- `docs/commands/scan.md`
- `internal/scenarios/`
- `testinfra/contracts/`
Run commands:
- `go test ./core/detect/workstation ./core/policy/approvedtools ./core/aggregate/inventory -count=1`
- `go test ./internal/scenarios -run '^TestLocalGovernanceGap' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- sanctioned-vs-unsanctioned fixture tests
- additive contract tests for local-governance-gap findings
- scenario acceptance for local governance gap
- docs consistency checks if local output wording changes
Matrix wiring:
- Fast lane: focused workstation/policy/aggregate tests
- Core CI lane: `make prepush-full`
- Acceptance lane: local governance-gap scenarios
- Cross-platform lane: CLI contract coverage on supported OS runners
- Risk lane: `make test-contracts`
Acceptance criteria:
- Local-machine fixtures can distinguish sanctioned vs unsanctioned tool/config usage deterministically.
- Missing approved-tools baseline yields explicit unavailable-reference behavior, not false unsanctioned claims.
- Secret values remain redacted and do not become identities.
Contract/API impact:
- Adds additive local governance-gap findings and optional inventory/report rollups.
Versioning/migration impact:
- No version bump.
Architecture constraints:
- Keep workstation discovery separate from policy comparison.
- Stay fully local/offline.
- Preserve current secret-handling constraints.
ADR required: no
TDD first failing test(s):
- `core/detect/workstation/detector_test.go`
- `core/policy/approvedtools/approvedtools_test.go`
- `internal/scenarios/local_governance_gap_scenario_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- If the sanctioned baseline is absent or invalid, Wrkr must emit an explicit reference-basis gap rather than silently labeling local usage compliant or noncompliant.

## Epic W6: Non-Human Execution Identity

Objective: inventory and rank the durable non-human identities that sit behind AI-enabled delivery paths so operators can see not just what can write, but which identity likely does the writing.

### Story W6-S01: Add First-Class Non-Human Identity Inventory
Priority: P2
Tasks:
- Add failing fixtures for GitHub Apps, bot users, and service-account style env/config references.
- Create focused detectors for non-human identity signals in workflows, action configs, and related repo artifacts.
- Add an additive inventory collection for non-human identities with deterministic type/source metadata.
- Keep identity detection static-only and repo-local to the selected scan inputs.
Repo paths:
- `core/detect/`
- `core/aggregate/inventory/inventory.go`
- `internal/scenarios/`
- `scenarios/wrkr/`
- `testinfra/contracts/`
- `docs/trust/detection-coverage-matrix.md`
Run commands:
- `go test ./core/detect/... ./core/aggregate/inventory -count=1`
- `go test ./internal/scenarios -run '^TestNonHumanIdentityInventory' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- detector fixture tests for GitHub App, bot, and service-account cases
- additive inventory contract tests
- docs matrix updates
- scenario acceptance for non-human identity inventory
Matrix wiring:
- Fast lane: focused detect/inventory tests
- Core CI lane: `make prepush-full`
- Acceptance lane: non-human identity scenarios
- Cross-platform lane: CLI contract coverage
- Risk lane: `make test-contracts`
Acceptance criteria:
- Wrkr inventories non-human identities tied to AI-enabled paths when the evidence is static and in-repo.
- Identity rows distinguish type and source deterministically.
- Ambiguous identity evidence does not overclaim GitHub App or service-account status.
Contract/API impact:
- Adds additive `inventory.non_human_identities[*]` public surface.
Versioning/migration impact:
- No version bump; optional collection only.
Architecture constraints:
- Detection remains static-only and offline-first.
- Identity inventory must not require remote GitHub resolution.
- Deterministic sorting and stable type enums are required.
ADR required: yes
TDD first failing test(s):
- `core/detect/nonhumanidentity_test.go`
- `core/aggregate/inventory/inventory_test.go`
- `internal/scenarios/nonhuman_identity_inventory_scenario_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- Ambiguous actor strings or env refs must result in unknown/low-confidence identity classification rather than false-positive GitHub App or service-account inventory.

### Story W6-S02: Correlate Non-Human Identity to Prioritized Action Paths
Priority: P2
Tasks:
- Add failing scenario tests where a bot or app is the durable execution identity behind a top-ranked path.
- Correlate workflow/action capability rows to detected non-human identities.
- Surface execution identity and rationale in prioritized action paths and govern-first output.
- Keep correlation deterministic when multiple candidate identities exist.
Repo paths:
- `core/aggregate/attackpath/graph.go`
- `core/aggregate/`
- `core/report/types.go`
- `core/report/build.go`
- `internal/scenarios/`
- `testinfra/contracts/`
Run commands:
- `go test ./core/aggregate/... ./core/report -count=1`
- `go test ./internal/scenarios -run '^TestIdentityToActionPath' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- identity-to-path correlation tests
- action-path contract tests for additive execution identity fields
- scenario acceptance for bot/app-backed paths
- regression checks for ambiguous identity resolution
Matrix wiring:
- Fast lane: aggregate/report tests
- Core CI lane: `make prepush-full`
- Acceptance lane: identity correlation scenarios
- Cross-platform lane: CLI/report contract coverage
- Risk lane: `make test-contracts`
Acceptance criteria:
- Govern-first paths can name a durable non-human execution identity when evidence supports it.
- Multiple possible identities resolve deterministically or remain explicitly ambiguous.
- Existing action-path ranking stays stable except where new identity evidence materially changes rank/explanation.
Contract/API impact:
- Adds additive execution-identity fields to action-path/report outputs.
Versioning/migration impact:
- No version bump.
Architecture constraints:
- Correlation belongs in aggregation, not in detector packages.
- Missing identity evidence must remain empty/unknown rather than fabricated.
- Ranking changes must be explainable from deterministic evidence.
ADR required: yes
TDD first failing test(s):
- `core/risk/risk_test.go`
- `core/cli/report_contract_test.go`
- `internal/scenarios/identity_to_action_path_scenario_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- If multiple identity candidates fit the same path, Wrkr must emit a deterministic ambiguous/unknown result rather than randomly selecting one.
Dependencies:
- `W6-S01`
- `W2-S02`
- `W3-S02`

## Epic W7: Correctness and Honest Boundaries

Objective: preserve the GTM wedge by keeping policy/compliance mappings correct, making filesystem failures visible, and preventing message drift beyond Wrkr’s static boundary.

### Story W7-S01: Keep `WRKR-A###` Mapping Correct End-to-End
Priority: P1
Tasks:
- Add failing end-to-end tests that prove agent findings, policy outcomes, and bundled compliance summaries stay aligned on canonical `WRKR-A###`.
- Harden alias normalization and compliance mapping expectations so custom policy packs cannot silently skew bundled framework mapping.
- Add scenario coverage that exercises policy evaluation through to compliance output.
Repo paths:
- `core/policy/loader.go`
- `core/compliance/rulemap.go`
- `core/policy/ruleid.go`
- `core/policy/`
- `internal/scenarios/`
- `testinfra/contracts/`
Run commands:
- `go test ./core/policy/... ./core/compliance -count=1`
- `go test ./internal/scenarios -run '^TestPolicyComplianceMapping' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- alias normalization tests
- policy/compliance end-to-end contract tests
- scenario acceptance for mapped compliance output
- regression coverage for duplicate or legacy rule IDs
Matrix wiring:
- Fast lane: focused policy/compliance tests
- Core CI lane: `make prepush-full`
- Acceptance lane: policy/compliance scenario coverage
- Cross-platform lane: CLI contract coverage
- Risk lane: `make test-contracts`
Acceptance criteria:
- Canonical `WRKR-A###` IDs remain the only bundled compliance-mapping authority.
- Agent-policy scenario scans produce correct compliance rollups.
- Alias/legacy IDs do not silently remap bundled framework controls.
Contract/API impact:
- No new public surface; correctness hardening only.
Versioning/migration impact:
- No schema, version, or exit-code change.
Architecture constraints:
- Loader normalization remains the single canonical rule-ID entry point.
- Compliance rule maps must consume canonical IDs only.
ADR required: no
TDD first failing test(s):
- `core/policy/policy_test.go`
- `core/policy/loader_test.go`
- `internal/scenarios/policy_compliance_mapping_scenario_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- Custom or aliased rule packs must fail deterministically or normalize safely rather than causing silent compliance drift.

### Story W7-S02: Surface Stat and Permission Failures Instead of Hiding Them
Priority: P1
Tasks:
- Add failing permission-denied and stat-failure fixtures covering parse helpers and representative detectors.
- Audit detectors for swallowed filesystem errors and route them into deterministic `parse_error`, `detector_errors`, or warning surfaces.
- Ensure explain/human-readable output also calls out incomplete posture due to permission failures.
- Update scan docs to document the surfaced failure behavior.
Repo paths:
- `core/detect/parse.go`
- `core/detect/detect.go`
- `core/detect/`
- `core/cli/scan_partial_errors_test.go`
- `docs/commands/scan.md`
- `internal/scenarios/`
- `testinfra/contracts/`
Run commands:
- `go test ./core/detect/... ./core/cli -count=1`
- `go test ./internal/scenarios -run '^TestPermissionFailureSurfacing' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- permission-denied filesystem fixtures
- parse/detector error contract tests in JSON
- explain-output visibility tests
- scenario acceptance for partial results with surfaced errors
- docs updates for failure semantics
Matrix wiring:
- Fast lane: detect/CLI tests
- Core CI lane: `make prepush-full`
- Acceptance lane: permission-failure scenarios
- Cross-platform lane: CLI contract coverage on supported OS runners
- Risk lane: `make test-contracts`
Acceptance criteria:
- Permission-denied and stat failures are visible in final JSON for affected scans.
- Non-fatal failures keep partial results explicit and deterministic.
- Wrkr no longer silently suppresses these filesystem failures.
Contract/API impact:
- Strengthens additive error surfaces; no exit-code change unless an existing fatal boundary is crossed.
Versioning/migration impact:
- No schema version bump.
- Existing error envelopes remain the compatibility shape.
Architecture constraints:
- Keep fatal vs non-fatal distinction explicit and deterministic.
- Sort surfaced errors for stable output.
- Do not downgrade root-level fail-closed boundaries.
ADR required: yes
TDD first failing test(s):
- `core/detect/parse_test.go`
- `core/cli/scan_partial_errors_test.go`
- `internal/scenarios/permission_failure_surfacing_scenario_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- When one repo/path becomes unreadable mid-scan, Wrkr must preserve deterministic partial output and explicit error surfaces rather than hanging, silently skipping, or crashing without context.

### Story W7-S03: Lock Wrkr Messaging to the Static/Posture Boundary
Priority: P1
Tasks:
- Audit README, positioning docs, command docs, trust matrix, examples, and report templates for runtime overclaiming.
- Remove or rewrite any Wrkr-only wording that implies:
  - runtime provenance
  - live MCP behavior
  - actual tool actions observed in flight
  - proposed-vs-shipped behavior
- Align report templates and public-facing examples with the same posture-only/static-only language.
- Add docs/tests so future wording drift is caught in CI.
Repo paths:
- `README.md`
- `docs/positioning.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/commands/mcp-list.md`
- `docs/trust/detection-coverage-matrix.md`
- `core/report/templates/`
- `testinfra/hygiene/`
Run commands:
- `make test-docs-consistency`
- `scripts/run_docs_smoke.sh`
- `go test ./testinfra/hygiene -count=1`
Test requirements:
- docs consistency checks
- storyline/smoke checks
- trust-boundary wording checks in hygiene tests
- report-template review/golden checks where text output changes
Matrix wiring:
- Fast lane: docs and hygiene checks
- Core CI lane: not required beyond story-local checks
- Acceptance lane: docs smoke/storyline coverage
- Cross-platform lane: no
- Risk lane: no
Acceptance criteria:
- Wrkr-only docs/templates stay inside the static/posture boundary.
- No docs/template path implies live MCP behavior or runtime observation.
- Public wording distinguishes configured posture from runtime truth consistently.
Contract/API impact:
- Docs/template wording only; no schema or exit-code change.
Versioning/migration impact:
- No versioning impact.
Architecture constraints:
- Wording must mirror actual machine evidence surfaces.
- Template phrasing must not outrun static evidence available in scan state.
ADR required: no
TDD first failing test(s):
- `testinfra/hygiene/detection_scope_docs_test.go`
- docs consistency/storyline checks
Cost/perf impact: low
Chaos/failure hypothesis:
- N/A for runtime behavior; the failure mode here is message drift, which must be caught by docs/template checks before merge.

## Epic W8: GTM Scenario Packs and Contract Proof

Objective: make the GTM wedge continuously provable through deterministic scenario fixtures and contract tests.

### Story W8-S01: Add GTM Scenario Packs and Wire Them Into Contracts
Priority: P1
Tasks:
- Add scenario packs covering:
  - unknown-to-security + write-capable
  - production-target-backed path
  - fallback vs explicit ownership
  - MCP dangerous action surface
  - local governance gap
  - bot/app-backed execution path
  - PR -> merge -> deploy chain
- Update scenario coverage maps and contract assertions for new additive public surfaces.
- Ensure scenario fixtures are byte-stable and suitable for repeated CI execution.
- Add contract coverage for any new scan/report JSON keys introduced by prior waves.
Repo paths:
- `scenarios/wrkr/`
- `internal/scenarios/`
- `internal/scenarios/coverage_map.json`
- `testinfra/contracts/`
- `scripts/validate_scenarios.sh`
Run commands:
- `go test ./core/detect/... ./core/aggregate/... ./core/report ./core/proofmap ./core/policy/... -count=1`
- `go test ./testinfra/contracts/... -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `make test-contracts`
Test requirements:
- scenario/spec tests for all listed GTM packs
- contract tests for additive JSON fields
- golden updates for deterministic outputs
- coverage-map updates tying scenarios back to the new behavior set
Matrix wiring:
- Fast lane: no
- Core CI lane: scenario and contract suites as part of merge validation
- Acceptance lane: full scenario pack execution
- Cross-platform lane: no
- Risk lane: `make test-contracts` plus scenario validation
Acceptance criteria:
- All seven GTM scenario packs exist and pass.
- Scenario outputs are deterministic and stable across repeated runs.
- Any public contract added in Waves 1-7 is represented in scenario or contract coverage.
Contract/API impact:
- Test/fixture coverage only, except for locking any additive public fields introduced earlier.
Versioning/migration impact:
- No version change.
Architecture constraints:
- Scenarios remain spec artifacts, not best-effort examples.
- No live network dependency in scenario execution.
ADR required: no
TDD first failing test(s):
- `internal/scenarios/*`
- `testinfra/contracts/*`
Cost/perf impact: medium
Chaos/failure hypothesis:
- If a later change weakens ordering, hides partial failures, or overclaims delivery/runtime truth, the scenario pack must fail deterministically and block merge.
Dependencies:
- `W1-S01`
- `W1-S02`
- `W2-S02`
- `W3-S02`
- `W4-S01`
- `W5-S01`
- `W6-S02`
- `W7-S02`

## Minimum-Now Sequence

Wave 1:
- `W1-S01` Add deterministic JSON output ergonomics
- `W1-S02` Add bounded concurrency and explicit resume
- `W7-S01` Keep `WRKR-A###` mapping correct end-to-end
- `W7-S02` Surface stat/permission failures instead of hiding them
- `W1-S03` Document fine-grained PAT setup and the large-org runbook

Wave 2:
- `W2-S01` Extend activation beyond `my_setup`
- `W2-S02` Add ranked `action_paths` and `action_path_to_control_first`

Wave 3:
- `W3-S01` Add structured workflow capability extraction
- `W3-S02` Correlate PR -> merge -> deploy chains and keep production claims honest
- `W4-S01` Add ownership provenance and `operational_owner`
- `W4-S02` Strengthen static approval-gap modeling

Wave 4:
- `W5-S01` Add richer MCP action-surface modeling
- `W5-S02` Add deterministic local governance-gap comparison

Wave 5:
- `W6-S01` Add first-class non-human identity inventory
- `W6-S02` Correlate non-human identity to prioritized action paths

Wave 6:
- `W7-S03` Lock Wrkr messaging to the static/posture boundary
- `W8-S01` Add GTM scenario packs and wire them into contracts

Why this order:

- Wave 1 removes adoption blockers and preserves correctness rails before adding new meaning-rich surfaces.
- Wave 2 makes first value explicit only after large-org scans are operable enough to use.
- Wave 3 strengthens delivery-path truth before later wedge-expansion and message-hardening work.
- Wave 4 and Wave 5 deepen governance precision after the core action-path model exists.
- Wave 5 and Wave 6 are staged because identity correlation depends on action-path and delivery-chain semantics already being stable.
- Final docs-boundary lock and full scenario pack consolidation happen last so they can freeze the full end-state, not an intermediate one.

## Explicit Non-Goals

- No proof dependency upgrade or cross-repo proof-contract work.
- No dashboard, hosted control plane, or runtime enforcement product work.
- No live GitHub, MCP, or deployment runtime observation beyond the already-selected static scan inputs.
- No package/server vulnerability scanning wedge in Wrkr.
- No broad browser-extension, IdP-grant, or generic GitHub App inventory product expansion beyond AI-linked delivery-path identity needs.
- No breaking schema rename/removal for existing `scan`, `report`, `inventory`, `mcp-list`, or proof-chain surfaces.
- No nondeterministic telemetry or scan-data exfiltration.

## Definition of Done

- Every recommendation `R1..R23` maps to at least one completed story.
- All touched public JSON surfaces are additive-only unless an ADR explicitly approves a versioned change.
- All user-visible behavior changes update docs and tests in the same PR.
- Required lanes for each story are green.
- Risk-bearing stories include:
  - TDD-first tests
  - deterministic contract coverage
  - documented failure-mode expectations
- Concurrency, retry, cooldown, and resume behavior have chaos/hardening coverage.
- New action-path, ownership, MCP, and identity semantics have scenario coverage.
- Docs and templates remain inside Wrkr’s static/posture boundary.
- Proof, exit-code, determinism, and fail-closed guarantees remain intact.

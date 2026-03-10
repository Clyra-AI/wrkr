# PLAN WRKR_LAUNCH_BLOCKERS_WAVE1: Self-Serve Activation and Contract Hardening

Date: 2026-03-10  
Source of truth: user-provided launch audit findings dated 2026-03-10, `product/dev_guides.md`, `product/architecture_guides.md`, `AGENTS.md`, and the observed repository/runtime baseline from this audit run  
Scope: Wrkr repository only. Planning artifact only. One wave only. Scope is limited to launch-blocking contract/runtime correctness plus the minimum doc and OSS-readiness updates required to ship those fixes safely.

## Global Decisions (Locked)

- This plan is intentionally one wave only. It covers the March 10, 2026 no-go blockers and the minimum contract-doc parity required to release them. Broader OSS/distribution polish is deferred.
- Preserve Wrkr's deterministic, offline-first, fail-closed behavior. No LLM calls, no new background services, no dashboard-first work, and no default scan-data exfiltration are allowed.
- Preserve architecture boundaries:
  - Source
  - Detection
  - Aggregation
  - Identity
  - Risk
  - Proof emission
  - Compliance mapping/evidence output
- Keep Go core authoritative for parser behavior, auth resolution, reporting semantics, and fail-closed enforcement. Python remains out of scope except for existing thin scripts and docs tooling.
- Do not globally relax strict parsing for Wrkr-owned contracts such as policy files, manifests, schemas, or proof/evidence artifacts. Any additive-tolerant parsing introduced in this wave must be isolated to vendor-owned config adapters.
- Preserve current exit-code contracts:
  - `0` success
  - `1` runtime failure
  - `2` verification failure
  - `3` policy/schema violation
  - `4` approval required
  - `5` regression drift
  - `6` invalid input
  - `7` dependency missing
  - `8` unsafe operation blocked
- Preserve current hosted acquisition dependency contract:
  - `scan --repo` and `scan --org` still require explicit `--github-api` or `WRKR_GITHUB_API_BASE`
  - missing GitHub API base remains `dependency_missing` with exit `7`
- If ambient GitHub token fallback is added, it must be additive only and must not weaken explicit flag/config precedence.
- Docs are executable contract in this wave. Any user-visible CLI/auth/warning behavior change must update command docs, first-screen docs, and storyline docs in the same PR.
- Every story in this wave must include tests and matrix wiring. Stories touching parser boundaries, auth/external adapters, or warning/failure semantics must wire `make prepush-full`. Reliability-sensitive stories must also wire `make test-hardening` and `make test-chaos`.
- Time-to-first-value is a first-class requirement for this wave:
  - Developer first-value target: `wrkr scan --my-setup --json` then `wrkr mcp-list --state ... --json` should yield usable posture or an explicit incompleteness warning in two commands.
  - Hosted first-value target: `wrkr scan --repo/--org` should be self-serve when `--github-api` and an ambient or explicit token are configured.

## Current Baseline (Observed)

- Fact: `go test ./... -count=1` passed on 2026-03-10 across unit, integration, e2e, acceptance, `testinfra/contracts`, and `testinfra/hygiene`.
- Fact: bundled repo-path activation works:
  - `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.tmp/audit/scenario-state.json --production-targets ./docs/examples/production-targets.v1.yaml --json` returned `status=ok`, `total_findings=132`, `inventory.summary.total_tools=25`.
  - `wrkr evidence --frameworks eu-ai-act,soc2 --state ./.tmp/audit/scenario-state.json --output ./.tmp/audit/evidence --json` returned `status=ok`.
  - `wrkr verify --chain --state ./.tmp/audit/scenario-state.json --json` returned `chain.intact=true` and `authenticity_status=verified`.
  - `wrkr regress run --baseline ./.tmp/audit/scenario-baseline.json --state ./.tmp/audit/scenario-state.json --json` returned `drift_detected=false`.
- Fact: local-machine first-value is currently broken for live vendor configs:
  - On 2026-03-10, `wrkr scan --my-setup --state ./.tmp/audit/my-setup.json --json` emitted parse errors for:
    - Claude unknown field `feedbackSurveyState`
    - Codex unknown keys `model`, `model_context_window`, `model_reasoning_effort`
  - On 2026-03-10, `wrkr mcp-list --state ./.tmp/audit/my-setup.json --json` returned `status=ok`, `row_count=0`, `warnings=null`.
- Fact: hosted self-serve onboarding is currently brittle without explicit auth:
  - On 2026-03-10, `wrkr scan --repo Clyra-AI/wrkr --github-api https://api.github.com --state ./.tmp/audit/public-repo-state.json --json` failed with GitHub `403 API rate limit exceeded`.
- Fact: fail-closed filesystem ownership controls are working in live probes:
  - evidence output path misuse returned `unsafe_operation_blocked` with exit `8`
  - materialized source root misuse returned `unsafe_operation_blocked` with exit `8`
- Fact: `wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json` wrote `/Users/tr/.wrkr/config.json` and returned `scan.token_configured=false`.

## Exit Criteria

1. `wrkr scan --my-setup --json` no longer emits parse errors solely because supported Claude/Codex configs contain additive vendor fields that Wrkr does not consume.
2. Malformed vendor configs still emit deterministic `parse_error` findings; this wave must not weaken syntax-error detection.
3. `wrkr mcp-list --state ... --json` returns deterministic warning context when known MCP-bearing files failed to parse and zero MCP rows would otherwise look like a clean result.
4. Hosted `scan --repo` and `scan --org` resolve GitHub tokens deterministically using one documented precedence order, and that order is consistent across code and docs.
5. GitHub unauthenticated/rate-limited hosted scan failures remain fail-closed but become actionable, with stable machine-readable error envelopes and explicit auth guidance.
6. Front-door docs describe Wrkr as repo/config/CI posture plus evidence tooling, not as a broader live SaaS/browser/IdP inventory platform.
7. Docs, CLI help/usage, examples, and failure-taxonomy references all align in the same PR for any user-visible change.
8. All story-level lane requirements pass before merge, with required branch gates still satisfied by `fast-lane` and `windows-smoke`.

## Public API and Contract Map

Stable/public surfaces touched in this wave:

- `wrkr scan --my-setup --json`
- `wrkr scan --repo <owner/repo> --github-api <url> [--github-token <token>] --json`
- `wrkr scan --org <org> --github-api <url> [--github-token <token>] --json`
- `wrkr mcp-list --state <path> --json`
- `wrkr init --non-interactive --json` documentation and expectation notes only
- User-visible docs and contract references:
  - `README.md`
  - `docs/examples/quickstart.md`
  - `docs/examples/personal-hygiene.md`
  - `docs/examples/security-team.md`
  - `docs/commands/scan.md`
  - `docs/commands/mcp-list.md`
  - `docs/positioning.md`
  - `docs/faq.md`
  - `docs/state_lifecycle.md`

Internal surfaces expected to change:

- `core/detect/parse.go`
- `core/detect/claude/*`
- `core/detect/codex/*`
- `core/cli/scan.go`
- `core/source/github/*`
- `core/report/mcp_list.go`
- `core/cli/mcp_list.go`
- detector, CLI, e2e, scenario, contract, and docs-smoke tests under `core/`, `internal/`, and `testinfra/`

Shim/deprecation path:

- `--github-token` remains the explicit override. Ambient token fallback, if added, is additive only and must not deprecate the flag.
- Unknown additive vendor fields in supported Claude/Codex configs stop being treated as parse errors; truly malformed JSON/TOML/YAML remains a `parse_error`.
- `mcp-list` reuses additive warning surfaces; no removal or rename of existing success keys is allowed.
- If `scan --json` adds a new warning field, it must be additive only and must preserve existing top-level keys.

Schema/versioning policy:

- No schema major bump is planned in this wave.
- JSON contract changes must be additive only.
- Exit-code behavior must remain stable.
- If a new warning collection is added to `scan --json`, it must be:
  - deterministic in ordering
  - documented in `docs/commands/scan.md`
  - covered by CLI contract tests

Machine-readable error expectations:

- `scan --repo/--org` without `--github-api` or `WRKR_GITHUB_API_BASE` remains `dependency_missing` with exit `7`.
- Hosted GitHub rate-limit or auth failures remain `runtime_failure` with exit `1`, but the message must explicitly direct the operator to the canonical auth path.
- Malformed supported vendor config files remain non-fatal findings, not command-fatal errors.
- Additive vendor fields in supported Claude/Codex config variants must not produce `parse_error` findings.
- `mcp-list --json` must distinguish between:
  - genuinely no MCP declarations found
  - zero rows because known MCP-bearing config parsing failed upstream

## Docs and OSS Readiness Baseline

README first-screen contract:

- README must lead with Wrkr's actual OSS value: deterministic repo/config/CI posture and evidence output.
- README must keep the local-machine and hosted scan flows copy-pasteable.
- Hosted examples must include the canonical auth contract, not just the GitHub API base.

Integration-first docs flow:

1. Install
2. `wrkr scan --my-setup --json`
3. `wrkr mcp-list --state ./.wrkr/last-scan.json --json`
4. Hosted `wrkr scan --repo/--org` with explicit API base and token contract
5. `wrkr inventory --diff`
6. `wrkr evidence`
7. `wrkr verify`
8. `wrkr regress`

Lifecycle path model:

- `docs/state_lifecycle.md` remains the canonical path model for:
  - `.wrkr/last-scan.json`
  - `.wrkr/wrkr-regress-baseline.json`
  - `.wrkr/wrkr-manifest.yaml`
  - `.wrkr/proof-chain.json`
  - evidence output directories

Docs source-of-truth for this wave:

- CLI contract docs under `docs/commands/`
- first-screen README and example guides
- `docs/positioning.md`
- `docs/faq.md`
- `docs/state_lifecycle.md`

OSS trust baseline:

- No new OSS trust-file epic is in scope for this one-wave plan.
- If user-visible behavior changes materially, update `CHANGELOG.md` in the implementation PR.
- Maintainer/support expectations remain explicit through existing OSS trust files; do not widen product promises beyond shipped behavior in this wave.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Fix parser compatibility for current Claude/Codex configs | Restore the marketed local-machine first-value path | Vendor-adapter hardening without weakening Wrkr contracts | Higher self-serve activation and lower false-negative posture gaps | W1-S01 |
| R2 | Make missing MCP posture visible when parse errors suppress extraction | Prevent silent zero-row false confidence | Explicit failure visibility | Safer operator triage and more truthful `mcp-list` output | W1-S02 |
| R3 | Support a single canonical GitHub token contract in hosted scan | Remove self-serve onboarding ambiguity | Hosted acquisition hardening | Faster org/repo activation and less rate-limit friction | W1-S03 |
| R4 | Keep hosted scan fail-closed but actionable on rate limit/auth errors | Preserve determinism while improving operator recovery | External-adapter resilience | Lower launch friction without changing safety stance | W1-S03 |
| R5 | Tighten launch messaging to repo/config/CI posture and evidence | Avoid over-claiming product scope | Expectation management | Better OSS trust and less launch confusion | W1-S04 |
| R6 | Keep docs aligned with actual fixed behavior in the same PR | Docs are executable contract | Contract-first delivery | Lower support burden and safer automation adoption | W1-S02, W1-S03, W1-S04 |
| R7 | Preserve fail-closed filesystem, proof, and exit-code contracts while fixing onboarding | Do not regress the parts that are already strong | Launch blocker remediation without scope creep | Maintains trust while fixing the highest-value adoption edges | W1-S01, W1-S02, W1-S03 |

## Test Matrix Wiring

Fast lane:

- `make lint-fast`
- `make test-fast`
- targeted package tests for changed detector, CLI, report, and source packages

Core CI lane:

- `make prepush`
- `make test-contracts`
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`

Acceptance lane:

- `go test ./internal/scenarios -run '^TestScenarioContracts$' -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `scripts/run_v1_acceptance.sh --mode=local`
- targeted e2e suites for scan and CLI contracts

Cross-platform lane:

- `windows-smoke`
- targeted CLI contract coverage for scan and hosted-source behavior on Linux/macOS/Windows CI lanes where applicable

Risk lane:

- `make prepush-full`
- `make test-risk-lane`
- `make test-hardening`
- `make test-chaos`

Merge/release gating rule:

- Required merge-blocking checks remain `fast-lane` and `windows-smoke`.
- For stories that wire Risk lane commands, those lanes must be green in PR validation before merge even if not branch-protection named checks.
- No release is allowed with unresolved parser-compatibility regressions, hosted auth contract drift, or docs/CLI parity failures.

## Epic W1-E1: Restore Self-Serve Activation Without Weakening Contracts

Objective: fix the two March 10, 2026 launch blockers, local-machine first-value failure and hosted auth/rate-limit onboarding friction, while preserving Wrkr's deterministic, fail-closed architecture and keeping docs aligned with shipped behavior.

### Story W1-S01: Add additive-tolerant vendor parsing for supported Claude and Codex configs
Priority: P0
Tasks:
- Capture the audited live-config incompatibilities as deterministic fixtures for Claude and Codex.
- Introduce detector-scoped or vendor-adapter parse behavior that ignores unknown vendor-owned fields while still failing on malformed syntax.
- Recover known-field extraction for supported Claude/Codex capabilities from current config variants, including the known MCP-bearing locations already in scope.
- Preserve strict parsing for Wrkr-owned contracts such as policy, manifest, baseline, proof, evidence, and profile schemas.
- Add/update scenario and CLI contract coverage so repeated scans produce byte-stable findings for the same vendor fixture set.
Repo paths:
- `core/detect/parse.go`
- `core/detect/claude/*`
- `core/detect/codex/*`
- `core/source/localsetup/*`
- `core/cli/*`
- `internal/scenarios/*`
- `scenarios/wrkr/**`
Run commands:
- `go test ./core/detect/claude ./core/detect/codex ./core/cli -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Parser/schema unit tests for supported additive vendor fields
- Fixture/golden updates for current Claude/Codex config variants
- Compatibility tests proving malformed syntax still returns `parse_error`
- CLI `--json` stability tests for `scan --my-setup`
- Determinism repeat-run tests for findings ordering and counts
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Risk lane
Acceptance criteria:
- A supported Claude config containing `feedbackSurveyState` but otherwise valid syntax does not produce a `parse_error` finding.
- A supported Codex config containing `model`, `model_context_window`, and `model_reasoning_effort` but otherwise valid syntax does not produce a `parse_error` finding.
- The same files still produce deterministic tool/MCP-related findings from the known fields Wrkr consumes.
- A malformed Claude/Codex config still produces a deterministic `parse_error` finding and does not crash or silently skip.
Contract/API impact:
- `wrkr scan --json` may emit a different mix of findings for the same supported vendor config because false parse errors are removed and real posture findings are restored.
- No flag, exit-code, or top-level JSON-envelope changes are allowed in this story.
Versioning/migration impact:
- No schema version bump expected.
- Compatibility change is additive and behavioral only.
Architecture constraints:
- Keep thin orchestration in CLI; parsing authority remains in focused detector/adapter packages.
- Do not collapse vendor config handling into shared loose parsing for Wrkr-owned contracts.
- Keep side-effect semantics explicit in helper names and signatures.
- Preserve cancellation and timeout propagation in scan flows.
- Favor extension points that let Wrkr absorb upstream additive vendor fields without enterprise forks.
ADR required: yes
TDD first failing test(s):
- `TestClaudeDetectorIgnoresAdditiveVendorFields`
- `TestCodexDetectorIgnoresAdditiveVendorFields`
- `TestClaudeDetectorStillFailsMalformedJSON`
- `TestCodexDetectorStillFailsMalformedTOML`
Cost/perf impact: low
Chaos/failure hypothesis:
- If a vendor adds new non-breaking fields to a supported config file, Wrkr should still emit deterministic posture from known fields. If the file is syntactically malformed, Wrkr should emit a deterministic `parse_error` without panicking, hanging, or inventing posture.

### Story W1-S02: Surface parse-suppressed MCP posture explicitly in `scan` and `mcp-list`
Priority: P0
Tasks:
- Define the deterministic set of parse-error locations that can suppress MCP visibility for existing supported inputs.
- Reuse or extend existing warning surfaces so operators can distinguish "no MCP servers found" from "state incomplete because known MCP-bearing configs failed to parse."
- Update `mcp-list` output building to inspect saved-state parse errors and emit sorted, stable warnings when MCP posture may be incomplete.
- If `scan --json` needs a new warning surface, make it additive only and keep ordering deterministic.
- Update `--explain` and relevant docs/examples to describe the new warning semantics without changing success/exit behavior.
Repo paths:
- `core/report/mcp_list.go`
- `core/cli/mcp_list.go`
- `core/cli/scan.go`
- `docs/commands/mcp-list.md`
- `docs/commands/scan.md`
- `docs/examples/personal-hygiene.md`
- `docs/examples/quickstart.md`
Run commands:
- `go test ./core/report ./core/cli -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `scripts/check_docs_cli_parity.sh`
- `scripts/run_docs_smoke.sh`
- `make prepush-full`
Test requirements:
- CLI help/usage tests when docs/examples change
- `--json` stability tests for additive warning fields
- Machine-readable warning-envelope tests for `mcp-list`
- Deterministic allow/block/incomplete fixtures for parse-suppressed MCP visibility
- Scenario or e2e coverage for the audited local-machine failure shape
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Risk lane
Acceptance criteria:
- When zero MCP rows are returned and the saved state contains parse errors for known MCP-bearing files, `wrkr mcp-list --json` emits non-empty deterministic warnings.
- When no MCP declarations exist and no relevant parse suppression occurred, `wrkr mcp-list --json` remains a clean zero-row result without false warnings.
- Any new `scan --json` warning field is additive, documented, and stable across repeated runs.
Contract/API impact:
- Touches machine-readable warning semantics for `mcp-list` and possibly `scan`.
- Existing success keys must remain intact; additive fields only.
Versioning/migration impact:
- No schema bump expected.
Architecture constraints:
- Keep reporting and warning derivation in reporting/CLI layers, not inside unrelated risk or evidence packages.
- Make side-effect semantics explicit: warnings explain incompleteness, they do not mutate findings.
- Preserve symmetry between saved-state read behavior and reporting behavior.
ADR required: no
TDD first failing test(s):
- `TestBuildMCPListWarnsOnSuppressedMCPConfigs`
- `TestMCPListDoesNotWarnOnCleanZeroRows`
- `TestScanJSONEmitsDeterministicMCPVisibilityWarning`
Cost/perf impact: low
Chaos/failure hypothesis:
- If known MCP-bearing files fail to parse upstream, users must receive a deterministic incompleteness warning instead of a silent zero-row false negative.

### Story W1-S03: Unify hosted GitHub token resolution and rate-limit guidance for `scan`
Priority: P1
Tasks:
- Decide and implement the canonical hosted-scan token precedence:
  - `--github-token`
  - config token
  - `WRKR_GITHUB_TOKEN`
  - `GITHUB_TOKEN`
- Preserve explicit `--github-api` or `WRKR_GITHUB_API_BASE` as the only hosted network source selector.
- Add actionable error translation for GitHub unauthenticated or insufficiently authenticated rate-limit failures while preserving fail-closed exit semantics.
- Update hosted scan docs, examples, and `init` expectation notes so config-persisted auth and ambient env auth are clearly distinguished.
- Add tests for precedence, no-token paths, env-token success paths, and 403 rate-limit messaging.
Repo paths:
- `core/cli/scan.go`
- `core/source/github/*`
- `core/cli/init.go`
- `core/cli/*`
- `README.md`
- `docs/commands/scan.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/faq.md`
- `product/plan-run.md`
Run commands:
- `go test ./core/source/github ./core/cli -count=1`
- `go test ./internal/integration/source -count=1`
- `go test ./internal/e2e/source -count=1`
- `scripts/check_docs_cli_parity.sh`
- `make prepush-full`
Test requirements:
- CLI behavior tests for flag/config/env precedence
- `--json` stability and error-envelope tests
- Exit-code contract tests proving missing GitHub API base stays exit `7`
- Adapter error-mapping tests for 403 rate-limit/auth failures
- Docs consistency and storyline checks for hosted examples
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
- Cross-platform lane
- Risk lane
Acceptance criteria:
- Hosted scan uses `WRKR_GITHUB_TOKEN` or `GITHUB_TOKEN` when `--github-token` is not passed and config token is absent.
- `--github-token` still overrides config and ambient env values.
- A GitHub rate-limit/auth failure remains fail-closed but returns actionable remediation text pointing to the canonical hosted auth path.
- `scan --repo/--org` without `--github-api` or `WRKR_GITHUB_API_BASE` still fails with `dependency_missing` and exit `7`.
Contract/API impact:
- Touches hosted scan auth-source resolution and runtime failure messaging.
- No new exit code, no removal of existing flags, and no hidden network defaults are allowed.
Versioning/migration impact:
- No schema or command version bump expected.
Architecture constraints:
- Keep auth resolution in the CLI/source boundary, not scattered across detectors or unrelated packages.
- Preserve bounded retry/backoff and explicit dependency-loss semantics.
- No credential persistence by default when ambient env fallback is used.
- Make API names and error mapping explicit about read/materialize behavior.
ADR required: yes
TDD first failing test(s):
- `TestScanUsesEnvGitHubTokenWhenFlagAndConfigAreUnset`
- `TestScanGitHubTokenPrecedenceFlagOverConfigOverEnv`
- `TestScanHostedRateLimitMessageIsActionable`
- `TestScanMissingGitHubAPIBaseStillFailsClosed`
Cost/perf impact: low
Chaos/failure hypothesis:
- If hosted acquisition is attempted without sufficient auth and GitHub returns a 403 rate-limit/auth response, Wrkr must fail deterministically with actionable guidance and without partial synthetic repository results.

### Story W1-S04: Align front-door docs and launch messaging with shipped OSS scope and fixed onboarding contract
Priority: P1
Tasks:
- Rewrite the README first screen and first-10-minutes flow so it matches actual shipped OSS behavior after Stories W1-S01 through W1-S03.
- Update example guides so local-machine flow documents MCP incompleteness warnings and hosted flow documents the canonical auth contract.
- Tighten positioning and FAQ copy to say Wrkr is repo/config/CI posture and evidence tooling, not live browser extension, IdP, or GitHub App inventory in OSS default mode.
- Keep docs ordered integration-first, not internals-first.
- Update `CHANGELOG.md` if any externally visible auth or warning behavior changes ship in the same PR.
Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/examples/personal-hygiene.md`
- `docs/examples/security-team.md`
- `docs/commands/scan.md`
- `docs/commands/mcp-list.md`
- `docs/positioning.md`
- `docs/faq.md`
- `docs/state_lifecycle.md`
- `CHANGELOG.md`
Run commands:
- `scripts/check_docs_cli_parity.sh`
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
- `make prepush`
Test requirements:
- Docs consistency checks
- Storyline and smoke checks for updated user flows
- README first-screen checks
- Integration-before-internals guidance checks for touched flows
- Version/install discoverability checks for hosted/local examples
Matrix wiring:
- Fast lane
- Core CI lane
- Acceptance lane
Acceptance criteria:
- README and example guides no longer over-claim default OSS coverage beyond repo/config/CI posture and evidence.
- Hosted examples explicitly show the canonical auth contract.
- Local-machine docs explain that parse-suppressed MCP posture now appears as explicit warning context rather than silent zero-row results.
- Docs smoke and parity gates pass without manual exceptions.
Contract/API impact:
- Docs-only for public messaging and command guidance, except for reflecting Stories W1-S02 and W1-S03.
Versioning/migration impact:
- None expected.
Architecture constraints:
- Docs must describe shipped behavior only.
- Preserve docs source-of-truth alignment across README, command docs, and example guides.
ADR required: no
TDD first failing test(s):
- `scripts/check_docs_storyline.sh`
- `scripts/check_docs_consistency.sh`
- `scripts/run_docs_smoke.sh`
Cost/perf impact: low
Chaos/failure hypothesis:
- If docs diverge from shipped auth or warning behavior, users will misconfigure hosted scans or misread zero-row MCP posture. This story closes that operational failure mode with executable docs checks.

## Minimum-Now Sequence

1. W1-S01
   - Remove false parse errors from supported additive vendor fields before touching warning UX or docs.
2. W1-S02
   - Add explicit incompleteness signaling so remaining parse-failure cases cannot silently suppress MCP posture.
3. W1-S03
   - Unify hosted auth behavior and actionable rate-limit guidance once local-machine activation is restored.
4. W1-S04
   - Land first-screen and example doc updates only after runtime behavior is settled.

Implementation order inside the wave:

- Branch 1 or PR slice 1: W1-S01 plus the minimum command-doc notes required by the behavior change
- Branch 1 or PR slice 2: W1-S02 plus `mcp-list` and personal-hygiene docs
- Branch 1 or PR slice 3: W1-S03 plus hosted-scan docs and `init` expectation notes
- Branch 1 or PR slice 4: W1-S04 final README/positioning/FAQ alignment and changelog

## Explicit Non-Goals

- No new detection surfaces for browser extension inventory, IdP grants, GitHub App installs, or other platform-signal roadmap items.
- No dashboard, docs-site redesign, or UI shell work.
- No changes to proof, evidence, verify, regress, lifecycle, or exit-code contracts outside the launch blockers covered here.
- No new network defaults, live MCP probing, or runtime telemetry collection.
- No automatic persistence of ambient GitHub env tokens into config files by default.
- No cross-repo toolchain or scanner-remediation wave.

## Definition of Done

- Every recommendation in this plan maps to at least one completed story with green acceptance criteria.
- Local-machine first-value path is restored for the audited Claude/Codex compatibility failures from 2026-03-10.
- `mcp-list` can no longer silently present parse-suppressed zero-row posture as a clean result.
- Hosted scan auth precedence is implemented, documented, and covered by contract tests.
- README, command docs, quickstarts, FAQ, and positioning all reflect shipped behavior and pass executable docs gates.
- Determinism, fail-closed behavior, and architecture boundaries are preserved and explicitly revalidated through the required lane matrix.
- Implementation PR(s) include:
  - TDD evidence
  - exact commands run
  - ADRs for Stories W1-S01 and W1-S03
  - no unrelated feature work

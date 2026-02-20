# PLAN v1: Wrkr (Deterministic Discovery-to-Proof Build Plan)

Date: 2026-02-20
Source of truth: `product/wrkr.md`, `product/dev_guides.md`, and `AGENTS.md`
Scope: Wrkr v1 OSS CLI only (See product). No Axym/Gait feature implementation beyond `Clyra-AI/proof` interoperability contracts.

This plan is execution-first: every story includes concrete paths, commands, tests, lane wiring, and deterministic acceptance criteria.

---

## Positioning Update (AI-DSPM)

Wrkr is an open-source AI Development Security Posture Management (AI-DSPM) scanner: Trivy for AI tool configurations. It scans repos for AI tool posture including misconfigurations, overprivileged agents, unpinned dependencies, unapproved MCP connections, and shadow AI tooling.

Competitive layer map:

| Layer | What It Governs | Who's Building Here | Crowded? |
|---|---|---|---|
| LLM / Model layer | Prompt injection, hallucination, output safety | Guardrails AI, NeMo, WitnessAI, HiddenLayer | Very |
| Agent runtime layer | Identity, sandboxing, kill switches, scope enforcement | ConductorOne, Orchid, Strata, MintMCP | Getting crowded |
| Network / traffic layer | Data loss, shadow AI traffic, API monitoring | Aurascape, Oximy, Zscaler/Netskope AI features | Crowded with incumbents |
| Configuration / posture layer | What's declared, approved, pinned, manifested, drifted | **Wrkr** | Empty |

Wrkr coexists with runtime controls: it produces the inventory and manifest describing what should be true. Runtime tools enforce against that declaration. Wrkr does not replace runtime guardrails; it feeds them.

---

## Global Decisions (Locked)

- Core runtime is Go only (`cmd/wrkr`, `core/`, `internal/`), pinned to Go `1.25.7`.
- Python (`3.13+`) is allowed only for scripts/test tooling; Node (`22+`) is docs/UI only.
- Scan/risk/proof paths are deterministic and non-generative: no LLM calls in runtime pipelines.
- Zero scan-data egress by default: inventory/risk/proof artifacts remain local unless user explicitly opens PRs.
- Default scan mode is offline-deterministic after source acquisition; `--enrich` is explicitly non-deterministic and opt-in.
- Artifacts may include explicit timestamp/version fields; determinism checks must either fix clock input or exclude those explicit time/version fields from byte-stability assertions.
- Architecture boundaries are mandatory and testable: source, detection, aggregation, identity, risk, proof emission, compliance mapping.
- Structured parsing is required for JSON/YAML/TOML configs; regex-only detection is not acceptable for structured inputs.
- Secret handling is presence-only detection. Secret values are never extracted or persisted.
- Proof records use `Clyra-AI/proof` primitives and shared record types: `scan_finding`, `risk_assessment`, `approval`, `lifecycle_transition`.
- Configuration policy rules and posture profiles are data-driven YAML contracts loaded from `Clyra-AI/proof/policies/wrkr/` and are deterministic in offline mode.
- Exit code contract is locked as API surface: `0,1,2,3,4,5,6,7,8` per `product/dev_guides.md`.
- All user-facing commands support `--json`; major commands support `--explain`; CI paths support `--quiet`.
- JSON digests/signatures use RFC 8785 canonicalization and deterministic byte output.
- YAML behavior shared with the Clyra ecosystem uses `gopkg.in/yaml.v3` compatibility.
- `Clyra-AI/proof` stays within one minor release of latest org policy and never below minimum supported baseline.
- Fail-closed is default for ambiguous high-risk policy/risk conditions.

---

## Current Baseline (Observed)

Repository snapshot (2026-02-20):

- Runtime scaffold exists: `go.mod`, `cmd/wrkr`, `core/`, `internal/`, `schemas/`, CI workflows, release config, and developer tooling files are present.
- Implemented baseline CLI: `init` and `scan` command paths with `--json`, `--quiet`, `--explain` handling in current scaffold.
- Implemented baseline engines: source acquisition (`repo`/`org`/`path`), local state snapshot, deterministic diffing by tuple key, and e2e/integration coverage for current scope.
- Missing v1 command surface: `report`, `evidence`, `verify`, `regress`, `identity`, `fix`, `manifest`, plus dedicated `export`/lifecycle-read views.
- Missing v1 product depth: detector coverage, policy/profile/score posture engine completeness, proof emission, compliance mapping, remediation loops, and full AC1-AC20 acceptance closure.
- Gap to PRD remains substantial: current implementation is early foundation with partial FR1/FR8 path only.

---

## Exit Criteria

Wrkr v1 is done when all criteria below are automated and passing:

1. AC1: 10-minute org scan flow (`install -> init -> scan --org`) produces inventory + top findings.
2. AC2: `wrkr report --pdf` generates a board-ready one-page risk summary.
3. AC3: `wrkr evidence --frameworks eu-ai-act,soc2` outputs signed/verifiable bundle.
4. AC4: `wrkr fix --top 3` opens deterministic remediation PRs with passing CI.
5. AC5: detector fixture coverage is 100% for supported tool surfaces.
6. AC6: `wrkr scan --diff` reports only real deltas, no unchanged false positives.
7. AC7: zero-egress offline path works post-source acquisition; `--enrich` requires network and errors clearly when unavailable.
8. AC8: `wrkr verify --chain` and `proof verify --chain` both validate emitted chains.
9. AC9: mixed-source proof chains (wrkr+axym+gait records) verify end-to-end.
10. AC10: posture regressions fail with exit `5` and precise drift reasons.
11. AC11: deterministic identity lifecycle with approvals, expiry, revoke, and chain history works.
12. AC12: autonomous/headless CI detections are classified and ranked correctly.
13. AC13: aggregate repo exposure summaries are emitted and ranked with individual findings.
14. AC14: MCP supply-chain trust scoring and remediation are deterministic offline and enriched when requested.
15. AC15: skill detection/risk scoring/remediation signals are complete and ranked.
16. AC16: PR-mode action comments only on relevant file changes with risk deltas.
17. AC17: `wrkr manifest generate` creates under-review baseline and preserves trust deficit until explicit approval.
18. AC18: policy check emits deterministic pass/fail rule outcomes and policy-violation proof records.
19. AC19: profile compliance reports deterministic percentage, failing rules, and trend deltas.
20. AC20: posture score command/report emits deterministic score, grade, weighted breakdown, and trend proof records.

NFR gates:

- Determinism: same input -> same outputs (excluding explicit timestamp/version fields and opt-in enriched signals).
- Data sovereignty: no scan data exfil by default.
- Performance: 100 repos <= 10 minutes, 500 repos <= 30 minutes, diff <= 2 minutes for 100 repos.
- Security/release integrity: signing, SBOM, vulnerability scan, provenance, and contract stability gates pass.

---

## Recommendation Traceability

| Recommendation | Planned Coverage |
|---|---|
| AI-DSPM positioning reframe and coexistence language | Positioning Update section; Story 8.1 docs parity updates |
| FR11 Configuration Policy Engine with built-in YAML rules and custom policy loading | Story 2.5, Story 4.1, Story 5.2, Story 6.1 |
| FR12 Posture Profiles (baseline/standard/strict) | Story 3.4, Story 4.3, Story 5.2 |
| FR13 AI Posture Score and standalone `wrkr score` | Story 3.5, Story 4.1, Story 5.4, Story 6.3 |
| Elevate `wrkr-manifest.yaml` as open specification | Story 8.3 |
| AC18/AC19/AC20 acceptance closure | Story 7.1, Story 8.2 |
| Skill scanning refinement (transitive ceiling, policy conflicts, sprawl concentration) | Story 2.3, Story 2.5, Story 3.1, Story 3.3, Story 4.1, Story 6.1, Story 7.1, Story 8.2 |

---

## Test Matrix Wiring

Lane definitions (required for every story):

- Fast lane: Tier 1 + minimal lint + focused Tier 9 checks, pre-push and PR-safe runtime.
- Core CI lane: Tier 1-3 deterministic package/integration/CLI checks.
- Acceptance lane: Tier 4 + Tier 11 scenario checks for operator workflows and spec conformance.
- Cross-platform lane: impacted tests run on Linux/macOS/Windows (PR or main depending cost).
- Risk lane: Tier 5/6/7/8/9/12 for high-risk, fail-closed, resilience, performance, and interop.

Pipeline placement (global):

- PR pipeline: Fast lane mandatory, selected Core CI checks, Windows smoke.
- Main pipeline: full Core CI + Acceptance + Contract checks (`Tier 9`) and selected hardening suites.
- Nightly pipeline: Risk lane heavy suites (`Tier 5/6/7/8/12`) and long-running validations.
- Release pipeline: Acceptance + Risk + UAT (`Tier 10`) + signing/provenance/security gates.

Scenario coverage contract (dev-guides alignment):

- Tier 11 scenario tests are required for every FR and AC path touched by a story.
- Scenario fixtures in `scenarios/` are treated as spec artifacts and are merge-blocking on failure.
- Every new FR introduced by this plan (FR11, FR12, FR13) must have at least one dedicated Tier 11 scenario fixture.
- Scenario tooling commands are explicit acceptance anchors: `scripts/validate_scenarios.sh` and `go test ./internal/scenarios -count=1 -tags=scenario`.

Story-to-lane map:

| Story | Fast | Core CI | Acceptance | Cross-platform | Risk |
|---|---|---|---|---|---|
| 0.1 | Yes | Yes | No | Yes | No |
| 0.2 | Yes | Yes | No | Yes | No |
| 0.3 | Yes | Yes | Yes | Yes | Yes |
| 1.1 | Yes | Yes | Yes | Yes | No |
| 1.2 | Yes | Yes | Yes | Yes | Yes |
| 1.3 | Yes | Yes | Yes | Yes | No |
| 2.1 | Yes | Yes | Yes | Yes | No |
| 2.2 | Yes | Yes | Yes | Yes | Yes |
| 2.3 | Yes | Yes | Yes | Yes | Yes |
| 2.4 | Yes | Yes | Yes | Yes | Yes |
| 2.5 | Yes | Yes | Yes | Yes | Yes |
| 3.1 | Yes | Yes | Yes | Yes | Yes |
| 3.2 | Yes | Yes | Yes | Yes | Yes |
| 3.3 | Yes | Yes | Yes | Yes | Yes |
| 3.4 | Yes | Yes | Yes | Yes | Yes |
| 3.5 | Yes | Yes | Yes | Yes | Yes |
| 4.1 | Yes | Yes | Yes | Yes | Yes |
| 4.2 | Yes | Yes | Yes | Yes | Yes |
| 4.3 | Yes | Yes | Yes | Yes | Yes |
| 5.1 | Yes | Yes | Yes | Yes | No |
| 5.2 | Yes | Yes | Yes | Yes | Yes |
| 5.3 | Yes | Yes | Yes | Yes | Yes |
| 5.4 | Yes | Yes | Yes | Yes | Yes |
| 6.1 | Yes | Yes | Yes | Yes | Yes |
| 6.2 | Yes | Yes | Yes | Yes | Yes |
| 6.3 | Yes | Yes | Yes | Yes | Yes |
| 7.1 | Yes | Yes | Yes | Yes | Yes |
| 7.2 | No | Yes | Yes | Yes | Yes |
| 8.1 | Yes | Yes | Yes | Yes | No |
| 8.2 | No | Yes | Yes | Yes | Yes |
| 8.3 | Yes | Yes | Yes | Yes | No |

Gating rule:

- A story cannot be marked complete unless every lane marked `Yes` above is green in its assigned pipeline(s).
- Merge to `main` blocks on any required lane failure.
- Release tags block on any required Release-pipeline lane failure.

---

## Epic 0: Foundations, Scaffold, and Contract Rails

Objective: create a buildable, pinned, deterministic Wrkr repo with enforceable quality/security/release gates.
Traceability: FR8, NFR2-NFR5, dev-guide toolchain/CI/exit/contract standards.

### Story 0.1: Bootstrap runtime scaffold and tracked plan artifacts
Priority: P0
Tasks:
- Create canonical layout: `cmd/wrkr/`, `core/`, `internal/`, `schemas/v1/`, `scripts/`, `testinfra/`, `scenarios/`, `.github/workflows/`.
- Initialize module and binary entrypoint (`go mod init`, root command stub).
- Ensure `product/PLAN_v1.md` and other required planning docs are tracked per repo hygiene standards.
- Add base docs: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`.
Repo paths:
- `go.mod`
- `cmd/wrkr/main.go`
- `core/`
- `internal/`
- `schemas/v1/`
- `product/PLAN_v1.md`
- `.gitignore`
Run commands:
- `go mod tidy`
- `go build ./cmd/wrkr`
- `go test ./...`
Test requirements:
- Tier 1: module/bootstrap tests for entrypoint and package load.
- Tier 9: repository hygiene checks for required/prohibited tracked paths.
Matrix wiring:
- Lanes: Fast, Core CI, Cross-platform.
- Pipeline placement: PR (`go build`, Tier 1 smoke), Main (same on linux/macos/windows).
Acceptance criteria:
- `go build ./cmd/wrkr` succeeds on all three OS runners.
- Required tracked plan docs pass hygiene check.

### Story 0.2: Pin toolchains, dependencies, and local developer commands
Priority: P0
Tasks:
- Pin Go `1.25.7`, Python `3.13`, Node `22` in local/CI config.
- Add `Makefile` targets: `fmt`, `lint`, `test`, `test-integration`, `test-e2e`, `build`, `hooks`, `prepush`, `prepush-full`.
- Configure `.pre-commit-config.yaml` with required Go/Python/security hooks.
- Pin baseline dependencies (including `Clyra-AI/proof` policy-compliant range).
Repo paths:
- `.tool-versions`
- `Makefile`
- `.pre-commit-config.yaml`
- `go.mod`
- `go.sum`
Run commands:
- `make fmt`
- `make lint`
- `make test`
- `go test ./...`
Test requirements:
- Tier 1: Make target smoke and script unit checks.
- Tier 9: pinned version and no-floating-tool checks.
Matrix wiring:
- Lanes: Fast, Core CI, Cross-platform.
- Pipeline placement: PR (fast lint/test), Main (full lint/test on linux/macos/windows).
Acceptance criteria:
- `make fmt && make lint && make test` succeeds on clean checkout.
- Pinned tool/version checks fail when versions drift.

### Story 0.3: Wire CI pipelines, security scans, and release integrity
Priority: P0
Tasks:
- Add PR/Main/Nightly/Release workflows with pinned action/tool versions.
- Add workflow-level `concurrency` groups with `cancel-in-progress: true` for PR/Main/Nightly/Release.
- Wire required scanners: `golangci-lint`, `gosec`, `govulncheck`, `ruff`, `mypy`, `bandit`, CodeQL.
- Add path-based change detection for expensive lanes/scanners while keeping baseline fast lint/test/contract checks always-on.
- If CodeQL is merge-blocking, ensure it emits PR statuses on `pull_request`; otherwise do not include it in required PR checks.
- Add release integrity flow: GoReleaser, checksums, Syft SBOM, Grype scan, cosign signing, provenance.
- Enforce branch protection required checks contract:
  - non-empty, unique, sorted required-check list.
  - every required check maps to a status emitted by `pull_request` workflows.
  - required checks cannot reference main-only, nightly-only, or release-only statuses.
- Add workflow contract tests for trigger correctness, required-check mapping, concurrency blocks, and path-filter fragments.
Repo paths:
- `.github/workflows/pr.yml`
- `.github/workflows/main.yml`
- `.github/workflows/nightly.yml`
- `.github/workflows/release.yml`
- `.goreleaser.yaml`
- `scripts/check_repo_hygiene.sh`
- `scripts/check_branch_protection_contract.sh`
- `testinfra/contracts/story0_contracts_test.go`
Run commands:
- `go test ./... -count=1`
- `govulncheck -mode=binary ./cmd/wrkr`
- `sha256sum -c dist/checksums.txt`
- `bash scripts/check_branch_protection_contract.sh`
- `go test ./testinfra/contracts -count=1`
Test requirements:
- Tier 2/3: CI workflow smoke and deterministic run.
- Tier 5: release artifact integrity checks.
- Tier 9: contract and schema checks in main pipeline, including workflow/branch-protection contract assertions.
- Tier 10: release install-path checks before tags.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (fast + workflow contract subset), Main (core+full contracts), Nightly (hardening/perf subsets), Release (full integrity gate).
Acceptance criteria:
- Workflow matrix runs successfully on PR and main.
- Required checks contract fails when a required status does not run on `pull_request`.
- PR/Main/Nightly/Release workflows all enforce `concurrency` with cancellation of stale runs.
- Release workflow emits signed artifacts with verifiable checksums/SBOM/provenance.

---

## Epic 1: Source Layer and Target Acquisition

Objective: implement deterministic acquisition for repo/org/path targets and incremental diff state.
Traceability: FR1 target modes, FR7 CI integration inputs, FR8 CLI contracts, AC1/AC6/AC7.

### Story 1.1: Implement init config and target resolver contracts
Priority: P0
Tasks:
- Implement `wrkr init` interactive/non-interactive configuration.
- Persist split auth profiles (`scan` read-only, `fix` read-write) and default scan target.
- Enforce mutually exclusive target flags: `--repo`, `--org`, `--path`.
- Implement clear invalid-input error envelopes (exit `6`) for invalid target combinations.
Repo paths:
- `cmd/wrkr/init.go`
- `core/config/`
- `schemas/v1/config/`
- `internal/e2e/init/`
Run commands:
- `wrkr init --json`
- `wrkr scan --repo acme/backend --json`
- `wrkr scan --org acme --json`
Test requirements:
- Tier 1: config parsing/serialization and validation.
- Tier 3: CLI target-flag behavior and exit-code checks.
- Tier 9: stable JSON shape and exit envelope compatibility.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR (unit + CLI arg checks), Main (full e2e target matrix).
Acceptance criteria:
- Exactly one target source accepted per scan invocation.
- Misconfigured target selection exits `6` with stable JSON error schema.

### Story 1.2: Build GitHub/org/path source connectors
Priority: P0
Tasks:
- Implement GitHub repo and org source acquisition using token-scope-safe APIs.
- Implement local path scanning mode (`--path`) for air-gapped/pre-cloned workflows.
- Add graceful partial-failure handling: one repo failure does not terminate full org scan.
- Ensure no non-GitHub network dependency in default scan path after acquisition.
Repo paths:
- `core/source/github/`
- `core/source/local/`
- `core/source/org/`
- `internal/integration/source/`
Run commands:
- `wrkr scan --repo acme/backend --json`
- `wrkr scan --org acme --json`
- `wrkr scan --path ./local-repos --json`
- `go test ./... -count=1`
Test requirements:
- Tier 1: source adapter unit tests.
- Tier 2: deterministic integration tests with simulated GitHub responses.
- Tier 3: CLI source-mode e2e tests.
- Tier 4: air-gapped acceptance script.
- Tier 5: retry/error-classification tests.
- Tier 9: stable source metadata schema.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit/integration subset), Main (full source matrix), Nightly (hardening/retry stress).
Acceptance criteria:
- `--repo`, `--org`, and `--path` all produce stable source manifests.
- Org scan continues and reports per-repo failures without data loss.

### Story 1.3: Implement incremental state and diff engine
Priority: P0
Tasks:
- Persist last scan state to `.wrkr/last-scan.json` (local deterministic cache).
- Implement tuple-keyed diff (`tool_type`, `location`, `org`) and changed-permission detection.
- Add `wrkr scan --diff` output contract for added/removed/changed findings only.
- Support CI baseline load from artifact/cache when local file absent.
Repo paths:
- `core/state/`
- `core/diff/`
- `cmd/wrkr/scan.go`
- `internal/e2e/diff/`
Run commands:
- `wrkr scan --org acme --json`
- `wrkr scan --org acme --diff --json`
- `go test ./... -count=1`
Test requirements:
- Tier 1: diff algorithm correctness.
- Tier 2: deterministic state read/write integration.
- Tier 3: CLI diff output behavior.
- Tier 11: scenario fixture for unchanged repos producing zero diff noise.
- Tier 9: diff JSON contract stability.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR (unit+contract), Main (integration+scenario).
Acceptance criteria:
- `--diff` reports only true additions/removals/permission changes.
- Re-running without changes produces byte-stable diff output.

---

## Epic 2: Detection Engine and Sensor Surface Coverage

Objective: implement deterministic structured detectors across required AI surfaces and execution contexts.
Traceability: FR1, FR3, FR7, FR11, AC5/AC12/AC14/AC15/AC16/AC18, NFR3 deterministic output.

### Story 2.1: Define detector interfaces and canonical finding model
Priority: P0
Tasks:
- Implement detector interfaces and registration for repo/org scopes.
- Define typed finding model with explainable risk context fields.
- Extend finding model for policy outcomes: `finding_type`, `rule_id`, `check_result`, `severity`, `remediation`.
- Add strict parser contracts for JSON/YAML/TOML; no regex-only structured parsing.
- Build detector fixture harness for deterministic replay.
Repo paths:
- `core/detect/`
- `core/model/finding.go`
- `internal/testutil/detectors/`
- `schemas/v1/findings/`
Run commands:
- `go test ./core/detect/...`
- `go test ./... -count=1`
Test requirements:
- Tier 1: interface and parser unit tests.
- Tier 2: detector registry and fixture integration.
- Tier 9: finding schema and enum stability checks.
- Tier 11: scenario fixture that validates typed parse-error reporting and canonical finding shape.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR (unit), Main (integration + schema guards).
Acceptance criteria:
- All detectors emit canonical finding shape with deterministic field ordering.
- Structured config parsing failures return typed parse errors, not silent drops.

### Story 2.2: Implement Claude/Cursor/Codex/Copilot config detectors
Priority: P0
Tasks:
- Implement detectors for required paths and config formats:
  - Claude: `.claude/`, `CLAUDE.md`, `.mcp.json`, hooks/commands.
  - Cursor: `.cursor/rules/*.mdc`, `.cursorrules`, `.cursor/mcp.json`.
  - Codex: `.codex/config.toml`, `.codex/config.yaml`, `AGENTS.md`, `AGENTS.override.md`.
  - Copilot: `.github/copilot-*`, `.vscode/mcp.json`, org controls.
- Extract permissions, automation hints, and config metadata deterministically.
- Add coverage fixtures for deprecated and current file surfaces.
Repo paths:
- `core/detect/claude/`
- `core/detect/cursor/`
- `core/detect/codex/`
- `core/detect/copilot/`
- `scenarios/wrkr/scan-mixed-org/`
Run commands:
- `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
- `go test ./core/detect/... -count=1`
Test requirements:
- Tier 1: parser unit tests per detector.
- Tier 2: cross-detector integration on mixed fixtures.
- Tier 4: detector acceptance scripts.
- Tier 11: outside-in scenario expectations for full tool coverage.
- Tier 9: stable finding field/value contracts.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+integration subset), Main (acceptance+scenario), Nightly (expanded fixture matrix).
Acceptance criteria:
- Fixture repos containing known tool configs are detected at 100% recall.
- Unchanged fixtures produce byte-stable tool inventories.

### Story 2.3: Implement MCP, Skills, dependency, secret-presence, and compiled-action detectors
Priority: P0
Tasks:
- Detect MCP declarations across required files and extract transport, endpoint, credential references, annotations.
- Implement offline supply-chain trust scoring (pinning, lockfile, transport).
- Add optional `--enrich` branch for advisory/registry lookups, explicitly tagged non-deterministic.
- Detect skills in `.claude/skills/` and `.agents/skills/`; extract `allowed-tools`, invocation policy, MCP dependencies.
- Compute per-repo transitive skill privilege union (`skill_privilege_ceiling`) from all skill `allowed-tools`.
- Compute `skill_privilege_concentration` metrics (`exec_ratio`, `write_ratio`, `exec_write_ratio`) so concentration is modeled separately from union presence.
- Emit per-skill contribution signals when a skill adds high-privilege capability to the ceiling (for example `proc.exec`).
- Detect skill-policy conflicts by cross-referencing skill `allowed-tools` with `.gait/` and `gait.yaml` block/approval rules.
- Compute deterministic skill sprawl metrics per repo (`total`, `exec`, `write`, `read`, `none`).
- Detect AI dependencies and API-key presence without value extraction.
- Detect compiled-action artifacts and plans:
  - `.claude/scripts/`
  - `workflows/` and `agent-plans/` multi-step JSON/YAML definitions
  - `*.agent-script.json` and `*.ptc.json`
  - CI steps invoking agent scripts (for example `run: gait eval --script ...`)
- Extract deterministic compiled-action metadata: `tool_sequence`, `step_count`, referenced risk classes, approval-source signal.
Repo paths:
- `core/detect/mcp/`
- `core/detect/skills/`
- `core/detect/gaitpolicy/`
- `core/detect/dependency/`
- `core/detect/secrets/`
- `core/detect/compiledaction/`
- `core/supplychain/`
Run commands:
- `wrkr scan --json`
- `wrkr scan --enrich --json`
- `go test ./core/detect/... -count=1`
Test requirements:
- Tier 1: scoring and parser units.
- Tier 1: skill ceiling/sprawl/conflict classifier units.
- Tier 2: mixed-surface integration tests.
- Tier 4: acceptance fixture scripts for MCP/skills findings.
- Tier 4: compiled-action fixtures for true positive/true negative coverage.
- Tier 5: fail-closed behavior when enrichment is requested but unavailable.
- Tier 9: secret redaction and schema stability checks.
- Tier 9: compiled-action finding schema/golden stability.
- Tier 11: scenario fixtures for AC14 and refined AC15 (ceiling union + conflict + sprawl assertions).
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (offline deterministic path), Main (full detector matrix), Nightly (enrichment simulation + resilience).
Acceptance criteria:
- Offline mode emits deterministic MCP trust scores for identical inputs.
- Secret values are never present in outputs, logs, or proof records.
- Repos with no compiled-action artifacts emit zero compiled-action findings (no false positives).
- Skill transitive privilege ceiling, concentration ratios, and skill sprawl metrics are deterministic and included in detector outputs.
- Skill-policy conflicts are emitted with stable detail fields (skill, grant, conflicting policy rule).

### Story 2.4: Implement CI/headless autonomy detector and PR change-surface classifier
Priority: P0
Tasks:
- Detect headless/CI invocations in `.github/workflows/*`, Jenkinsfiles, and equivalent pipeline config.
- Classify autonomy levels: `interactive`, `copilot`, `headless_gated`, `headless_auto`.
- Extract approval-gate and secret-access signals (`environment` reviewers, `secrets.*`, deployment keys).
- Build PR-mode path classifier for Wrkr Action comments on relevant AI config changes only.
Repo paths:
- `core/detect/ciagent/`
- `core/risk/autonomy/`
- `core/action/changes/`
- `internal/e2e/action/`
Run commands:
- `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
- `go test ./core/detect/ciagent/... -count=1`
- `go test ./internal/e2e/action -count=1`
Test requirements:
- Tier 1: autonomy classifier units.
- Tier 2: workflow parser integration.
- Tier 3: PR-mode CLI/e2e behavior.
- Tier 4: acceptance tests for autonomous-risk ranking.
- Tier 5: fail-closed handling for ambiguous high-risk CI configs.
- Tier 9: stable autonomy enum and reason-code contracts.
- Tier 11: AC12/AC16 scenario fixtures.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+targeted integration), Main (full acceptance/scenario), Nightly (fault injection on malformed workflows).
Acceptance criteria:
- Autonomous CI invocations with secrets and no gate are consistently top-ranked critical findings.
- Docs-only PR fixture does not trigger PR-mode comment behavior.

### Story 2.5: Implement configuration policy engine and YAML-backed built-in rules
Priority: P0
Tasks:
- Implement deterministic policy evaluator that runs after detection and before final risk aggregation.
- Load built-in rules from `Clyra-AI/proof/policies/wrkr/*.yaml` with strict schema validation.
- Support custom org policies via `wrkr scan --policy <path>` and repository default `wrkr-policy.yaml`.
- Emit named pass/fail rule checks and policy-violation findings using WRKR rule IDs.
- Ship v1 built-in rule pack WRKR-001 through WRKR-015 with fixed semantics and remediation text.
- Add skill-governance policy rules:

  | ID | Title | Severity |
  |---|---|---|
  | WRKR-013 | Skill privilege ceiling must not include `proc.exec` + credentials | high |
  | WRKR-014 | Skill allowed-tools must not conflict with Gait policy | high |
  | WRKR-015 | Skill sprawl: no repo should have >50% exec-granting skills | medium |

- For WRKR-013, `credentials` is evaluated from deterministic credential-presence signals only (for example `.env` key presence, CI `secrets.*` references, and manifest credential scopes).
- Enforce rule-versioning contract: semantic changes require new rule IDs.
Repo paths:
- `core/policy/`
- `core/policy/rules/`
- `core/policy/eval/`
- `schemas/v1/policy/`
- `scenarios/wrkr/policy-check/`
- `internal/scenarios/`
Run commands:
- `wrkr scan --json`
- `wrkr scan --policy ./fixtures/wrkr-policy.yaml --json`
- `go test ./core/policy/... -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
Test requirements:
- Tier 1: rule parser, expression evaluator, and deterministic rule-selection units.
- Tier 2: detector-to-policy integration tests using mixed fixtures.
- Tier 3: CLI `--policy` behavior and error envelope tests.
- Tier 4: acceptance script for policy check workflow.
- Tier 5: fail-closed behavior for malformed/ambiguous policy definitions.
- Tier 9: policy schema, rule ID, and reason-code stability checks.
- Tier 11: AC18 scenario fixture with WRKR-001 fail, WRKR-002 fail, WRKR-004 pass, and custom-rule extension.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+schema+CLI subset), Main (integration+acceptance+scenario), Nightly (fault-injection on invalid policy packs).
Acceptance criteria:
- `wrkr scan` emits deterministic policy pass/fail results for identical input and rule set.
- `--policy` custom rules are evaluated with the same engine and appear in findings with stable rule IDs.
- Policy violations are represented as first-class findings consumable by risk scoring.
- WRKR-013/014/015 are evaluated and surfaced with deterministic IDs, severities, and remediation hints.
- AC18 remains policy-engine focused; skill-specific WRKR-013/014/015 behavior is validated through refined AC15 scenarios.

---

## Epic 3: Aggregation, Identity Lifecycle, and Risk Scoring

Objective: convert detector outputs into actionable org posture with deterministic IDs, lifecycle state, and ranked risks.
Traceability: FR2, FR3, FR10, FR11, FR12, FR13, AC11/AC13/AC15/AC19/AC20 plus NFR3 deterministic behavior.

### Story 3.1: Build inventory aggregation, dedupe, ownership, and repo exposure summaries
Priority: P0
Tasks:
- Implement inventory builder producing YAML/JSON outputs with stable ordering.
- Deduplicate shared tools across repos while retaining location context.
- Derive ownership via CODEOWNERS + deterministic fallback heuristic.
- Emit `RepoExposureSummary` (permission union, data union, highest autonomy, combined score).
- Emit `skill_privilege_ceiling` in `RepoExposureSummary` as the union of skill-granted capabilities.
- Emit `skill_privilege_concentration` in `RepoExposureSummary` as `{ exec_ratio, write_ratio, exec_write_ratio }`.
- Emit `skill_sprawl` in `RepoExposureSummary` as `{ total, exec, write, read, none }`.
- Implement point-in-time inventory export contract for cross-product context exchange (`export_version`, `exported_at`, `org`, `tools[]`).
- Include context fields required for Gait/Axym enrichment: `data_class`, `endpoint_class`, `autonomy_level`, `risk_score`, `approval_status`, and canonical lifecycle state.
Repo paths:
- `core/aggregate/inventory/`
- `core/aggregate/exposure/`
- `core/owners/`
- `core/export/inventory/`
- `schemas/v1/inventory/`
- `schemas/v1/export/`
Run commands:
- `wrkr scan --json`
- `wrkr scan --json > wrkr-inventory.json`
- `wrkr export --format inventory --json`
- `go test ./core/aggregate/... -count=1`
Test requirements:
- Tier 1: aggregation and owner-derivation units.
- Tier 1: skill ceiling and skill sprawl aggregation units.
- Tier 2: cross-repo dedupe integration.
- Tier 3: CLI inventory output tests.
- Tier 3: export command behavior tests (output path, empty inventory behavior, deterministic ordering).
- Tier 4: acceptance script for aggregate exposure outputs.
- Tier 9: inventory schema and byte-stable golden checks.
- Tier 9: inventory export schema + golden checks (timestamp-aware determinism assertions).
- Tier 11: AC13 and refined AC15 scenarios.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+schema), Main (integration+acceptance), Nightly (large fixture scaling).
Acceptance criteria:
- Inventory includes all required tool fields and deterministic ordering.
- Repo exposure summaries are present and reproducible across runs.
- Empty scans produce valid exports with `tools: []` and no runtime error.
- Repo exposure summaries include deterministic `skill_privilege_ceiling`, `skill_privilege_concentration`, and `skill_sprawl` fields.

### Story 3.2: Implement deterministic identity lifecycle and manifest state indexing
Priority: P0
Tasks:
- Implement deterministic identity assignment: `wrkr:<tool_id>:<org>`.
- Implement lifecycle states and transitions with command support: review, approve, deprecate, revoke.
- Keep canonical lifecycle enum contract unchanged: `discovered`, `under_review`, `approved`, `active`, `deprecated`, `revoked`.
- Derive current lifecycle state from scan history + approval history:
  - first seen -> `discovered`
  - present with valid approval -> `active`
  - present with missing/expired approval -> `under_review`
- Derive deterministic scan-delta signals without introducing new lifecycle enum values:
  - `removed` (previously present, now absent)
  - `reappeared` (previously removed, now present)
  - `modified` (contract fields changed: `data_class`, `endpoint_class`, `autonomy_level`)
- Emit structured lifecycle transition payloads with `previous_state`, `new_state`, `trigger`, and `diff` metadata.
- Persist current state in `wrkr-manifest.yaml`; persist history in proof chain.
- Implement approval expiry default (90 days) and automatic `under_review` demotion when expired.
Repo paths:
- `core/identity/`
- `core/lifecycle/`
- `cmd/wrkr/identity.go`
- `core/manifest/`
- `schemas/v1/identity/`
Run commands:
- `wrkr identity list --json`
- `wrkr lifecycle --org <org> --json`
- `wrkr identity show <id> --json`
- `wrkr identity approve <id> --approver @maria --scope read-only --expires 90d --json`
- `go test ./core/identity/... -count=1`
Test requirements:
- Tier 1: state-machine and ID derivation units.
- Tier 1: lifecycle derivation unit tests for discovered/active/under_review outcomes.
- Tier 2: manifest+chain integration tests.
- Tier 2: scan-history transition tests for removed/reappeared/modified trigger generation.
- Tier 3: CLI lifecycle command tests.
- Tier 4: approval/revoke acceptance flow tests.
- Tier 4: lifecycle drift acceptance scenarios for disappearance/reappearance/config change.
- Tier 5: concurrency/atomic-write tests for lifecycle persistence.
- Tier 9: lifecycle event schema and exit-code stability.
- Tier 11: AC11 scenario.
- Tier 12: identity interop checks with Gait/Axym record references.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+contract), Main (integration+acceptance), Nightly (contention/stale-lock tests), Release (interop spot-check).
Acceptance criteria:
- Same tool in same org yields the same `agent_id` on every scan.
- Revoked tools reappearing in regress flow are deterministically flagged as drift.
- Lifecycle-delta triggers (`removed`, `reappeared`, `modified`) are deterministic and explainable.

### Story 3.3: Implement risk scoring, ranking, endpoint/data class derivation, and explainability
Priority: P0
Tasks:
- Implement blast radius, privilege level, and trust deficit axis calculators.
- Apply autonomy multipliers and execution-context amplification for CI/headless usage.
- Derive `endpoint_class` and `data_class` tags using deterministic rules.
- Include MCP supply-chain and Gait coverage modifiers in trust deficit.
- Add compiled-action composite-risk amplification when multi-step plans chain high-risk tools.
- Add policy violation severity contribution so critical WRKR policy failures consistently affect top-N rank.
- Add transitive skill privilege amplification using `skill_privilege_ceiling` for presence and `skill_privilege_concentration` for concentration.
- Add high-severity scoring for `skill_policy_conflict` findings (`finding_type: skill_policy_conflict`).
- Add skill-sprawl amplification when `exec+write` skills exceed 50% of repo skill count.
- Correlate WRKR-014 and `skill_policy_conflict` to one canonical finding key to avoid duplicate counting.
- Implement top-N ranked findings with deterministic tie-breakers and `--explain` rationale.
Repo paths:
- `core/risk/`
- `core/risk/classify/`
- `cmd/wrkr/report.go`
- `schemas/v1/risk/`
Run commands:
- `wrkr scan --json`
- `wrkr report --top 5 --json`
- `wrkr report --top 5 --explain`
- `go test ./core/risk/... -count=1`
Test requirements:
- Tier 1: scoring formula and class-derivation units.
- Tier 1: compiled-action composite scoring units.
- Tier 1: policy-violation contribution units.
- Tier 1: skill ceiling/sprawl/conflict scoring units.
- Tier 1: conflict dedupe/correlation units for WRKR-014 and `skill_policy_conflict`.
- Tier 2: risk aggregation integration tests.
- Tier 3: CLI ranking output tests.
- Tier 4: acceptance test for top finding ordering.
- Tier 5: fail-closed tests for undecidable high-risk conditions.
- Tier 7: benchmark checks on scoring throughput.
- Tier 9: stable reason-codes and ranking determinism contracts.
- Tier 11: AC12/AC13/AC14/refined AC15 scenarios.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+contract), Main (integration+acceptance), Nightly (perf + resilience scoring suites).
Acceptance criteria:
- Identical input fixtures yield identical ranked output and risk scores.
- High-autonomy CI finding outranks equivalent interactive finding by policy-defined multiplier.
- Equivalent high-risk tools embedded in compiled actions rank above the same tools found in isolation.
- Skills that introduce `proc.exec` into repo ceiling are flagged and influence aggregate rank deterministically.
- Skill-policy mismatches are counted once in aggregate scoring even when both policy and conflict views are emitted.

### Story 3.4: Implement posture profiles (`baseline`, `standard`, `strict`)
Priority: P0
Tasks:
- Implement profile model and evaluator that maps profiles to required rule sets and thresholds.
- Load built-in profiles from `Clyra-AI/proof/policies/wrkr/profiles/*.yaml`.
- Support `wrkr scan --profile [baseline|standard|strict]` with deterministic compliance percentage output.
- Support custom profile extension/override from `wrkr-policy.yaml`.
- Include WRKR-013/014/015 mapping in built-in profile definitions with explicit thresholds per profile.
- Emit per-profile failing-rule lists and compliance deltas against previous scan state.
Repo paths:
- `core/policy/profile/`
- `core/policy/profileeval/`
- `schemas/v1/profile/`
- `scenarios/wrkr/profile-compliance/`
- `internal/scenarios/`
Run commands:
- `wrkr scan --profile baseline --json`
- `wrkr scan --profile standard --json`
- `wrkr scan --profile strict --json`
- `go test ./core/policy/profile/... -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
Test requirements:
- Tier 1: profile parser and threshold-evaluator units.
- Tier 2: policy-engine to profile integration tests.
- Tier 3: CLI `--profile` output and error-contract tests.
- Tier 4: acceptance workflow for profile compliance reporting.
- Tier 5: fail-closed handling for invalid profile references.
- Tier 9: profile schema/enums and output-shape contracts.
- Tier 11: AC19 scenario fixture validating compliance percentage, failing rules, and delta output.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+contract subset), Main (integration+acceptance+scenario), Nightly (edge-case profile matrices).
Acceptance criteria:
- Profile evaluation is deterministic for fixed rules and inputs.
- `wrkr scan --profile standard` reports compliance percentage and explicit failing rule IDs.
- Profile results are consumable by risk report and evidence bundle generation.

### Story 3.5: Implement AI posture score computation and trend model
Priority: P0
Tasks:
- Implement deterministic 0-100 posture score model with fixed default weights:
  - policy pass rate 40%
  - approval coverage 20%
  - severity distribution 20%
  - profile compliance 10%
  - drift rate 10%
- Implement grade mapping `A/B/C/D/F` and trend delta logic against prior scan.
- Add configurable score weights in `wrkr-policy.yaml` with validation constraints.
- Persist score breakdown for reporting, CI output, and proof emission.
Repo paths:
- `core/score/`
- `core/score/model/`
- `schemas/v1/score/`
- `scenarios/wrkr/posture-score/`
- `internal/scenarios/`
Run commands:
- `wrkr scan --json`
- `wrkr scan --diff --json`
- `wrkr score --json`
- `go test ./core/score/... -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
Test requirements:
- Tier 1: weighting, normalization, and grading units.
- Tier 2: score input aggregation integration tests.
- Tier 3: score command/report output tests.
- Tier 4: acceptance workflow validating score and delta output.
- Tier 5: fail-closed behavior for invalid custom weight configs.
- Tier 7: benchmark coverage for score computation overhead.
- Tier 9: score schema, grade-band, and determinism contracts.
- Tier 11: AC20 scenario fixture validating deterministic score, grade, and delta behavior.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+contract), Main (integration+acceptance+scenario), Nightly (perf/regression score suites).
Acceptance criteria:
- Same scan results and weights always produce identical score outputs.
- `wrkr score` returns score, grade, weighted breakdown, and trend delta.
- Score output is compatible with downstream proof emission and CI policy gates.

---

## Epic 4: Proof Emission, Chain Verification, and Compliance Mapping

Objective: emit signed proof artifacts and compliance bundles that are verifiable, portable, and cross-product compatible.
Traceability: FR4, FR5, FR11, FR12, FR13, AC3/AC8/AC9/AC15/AC18/AC19/AC20, NFR4 signing and chain integrity.

### Story 4.1: Emit signed proof records for findings, risk, approval, and lifecycle events
Priority: P0
Tasks:
- Integrate `Clyra-AI/proof` for `proof.NewRecord`, `proof.Sign`, `proof.AppendToChain`.
- Map finding and risk entities into `scan_finding` and `risk_assessment` records.
- Map policy violations to `scan_finding` with `finding_type: policy_violation`, `rule_id`, and profile context metadata.
- Map skill/policy mismatches to `scan_finding` with `finding_type: skill_policy_conflict` and conflict metadata fields.
- Correlate WRKR-014 policy output to the canonical `skill_policy_conflict` finding via shared metadata key, without emitting duplicate conflict records.
- Map posture score outputs to `risk_assessment` records with weighted breakdown and grade.
- Map identity transitions into `approval` and `lifecycle_transition` records.
- Encode lifecycle transition payload fields: `previous_state`, `new_state`, `trigger`, `diff`.
- For scan-delta lifecycle triggers that do not change canonical lifecycle state, require explicit same-state transitions with populated `trigger`/`diff`.
- Persist append-only chain metadata with deterministic ordering.
Repo paths:
- `core/proofemit/`
- `core/proofmap/`
- `core/identity/` (event hooks)
- `schemas/v1/proof-outputs/`
Run commands:
- `wrkr scan --json`
- `wrkr identity approve <id> --approver @maria --scope read-only --json`
- `go test ./core/proofemit/... -count=1`
Test requirements:
- Tier 1: mapper and emitter units.
- Tier 2: chain append integration tests.
- Tier 3: CLI proof output behavior.
- Tier 4: acceptance script verifying emitted evidence set.
- Tier 5: tamper/stale-chain recovery tests.
- Tier 9: record-type and field contract tests.
- Tier 11: refined AC15 plus AC18 and AC20 scenario fixtures for conflict/policy/score record emission.
- Tier 9: canonical finding-key contract checks preventing duplicate WRKR-014 + conflict emission.
- Tier 12: mixed-source chain append compatibility checks.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+contract), Main (integration+acceptance), Nightly (tamper/recovery stress), Release (interop verification).
Acceptance criteria:
- All required record types are emitted with valid signatures.
- Chain append remains deterministic and tamper-evident.
- Policy violations and posture score records are chain-verifiable and stable across repeated runs.
- Skill-policy conflict findings are emitted as proof records with stable field contracts.
- WRKR-014 linkage preserves policy visibility without duplicating conflict findings in proof output.

### Story 4.2: Implement chain verification command and proof interop contract checks
Priority: P0
Tasks:
- Implement `wrkr verify --chain` command path and JSON output envelope.
- Verify full chain integrity and detect breakpoints deterministically.
- Add compatibility tests that validate Wrkr records with standalone `proof verify`.
- Guarantee verification exit-code behavior (`0` success, `2` verification failure, `6` invalid input).
Repo paths:
- `cmd/wrkr/verify.go`
- `core/verify/`
- `internal/e2e/verify/`
Run commands:
- `wrkr verify --chain --json`
- `proof verify --chain --json`
- `go test ./internal/e2e/verify -count=1`
Test requirements:
- Tier 1: verifier units.
- Tier 3: CLI verification e2e tests.
- Tier 4: acceptance tamper-detection script.
- Tier 9: exit-code and JSON contract checks.
- Tier 12: cross-product mixed-chain verification.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+exit contract), Main (e2e+acceptance), Nightly (mixed-chain fuzzed integrity checks), Release (final chain gate).
Acceptance criteria:
- `wrkr verify --chain --json` matches expected contract and interoperates with `proof verify`.
- Tampered chain deterministically exits `2` with stable reason fields.

### Story 4.3: Implement compliance evidence bundle generation
Priority: P1
Tasks:
- Load framework definitions from `Clyra-AI/proof/frameworks/*.yaml`.
- Generate evidence bundle structure with inventory, risk report, mappings, gaps, proof records, and signatures.
- Include cross-product inventory context snapshot (`inventory.json`) in the evidence directory for Axym/Gait ingestion.
- Include profile compliance report and posture score breakdown in evidence outputs.
- Support framework selection flags and deterministic artifact naming.
- Add bundle verification integration test path.
Repo paths:
- `core/compliance/`
- `core/evidence/`
- `cmd/wrkr/evidence.go`
- `schemas/v1/evidence/`
Run commands:
- `wrkr evidence --frameworks eu-ai-act,soc2 --json`
- `proof verify --bundle ./wrkr-evidence --json`
- `go test ./core/compliance/... -count=1`
Test requirements:
- Tier 1: mapping logic units.
- Tier 2: framework loading/integration tests.
- Tier 3: CLI evidence command tests.
- Tier 4: auditor-package acceptance script.
- Tier 5: fail-closed tests for missing/invalid framework files.
- Tier 9: bundle schema/field compatibility.
- Tier 11: AC3 and AC19 scenario fixtures.
- Tier 12: ingestion compatibility with Axym expectations where applicable.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+schema), Main (integration+acceptance), Nightly (resilience tests with malformed frameworks), Release (bundle verify gate).
Acceptance criteria:
- Evidence bundle is portable, signed, and independently verifiable.
- Selected framework outputs match deterministic expected mappings.
- Evidence includes profile compliance percentage/failing rules and posture score metadata.

---

## Epic 5: CLI Surface Contracts and Posture Regression

Objective: deliver complete CLI contract behavior and regression gates for ongoing posture control.
Traceability: FR8, FR9, FR11, FR12, FR13, AC1/AC2/AC6/AC10/AC15/AC17/AC18/AC19/AC20, exit-code contract section in dev guides.

### Story 5.1: Build CLI root contract (`--json`, `--quiet`, `--explain`, exit envelope)
Priority: P0
Tasks:
- Implement root command with shared option parsing and consistent output envelope.
- Centralize exit-code mapping to locked contract.
- Provide JSON schema for command success/error envelopes.
- Add strict parser for `--quiet` vs human output interaction rules.
- Ensure `--json` parse/flag errors emit machine-readable JSON error output only (no mixed human usage text).
- Add explicit contract coverage for invalid-flag ordering variants (`--json --bad-flag` and `--bad-flag --json`).
Repo paths:
- `cmd/wrkr/root.go`
- `core/cli/`
- `schemas/v1/cli/`
- `internal/e2e/cli_contract/`
Run commands:
- `wrkr --help`
- `wrkr scan --json`
- `wrkr scan --quiet --json`
- `go test ./internal/e2e/cli_contract -count=1`
Test requirements:
- Tier 1: shared CLI helper units.
- Tier 3: command envelope and flag behavior tests.
- Tier 9: exit-code and JSON-shape contract tests, including pure-JSON parse-error output under `--json`.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR (contract tests), Main (full command matrix).
Acceptance criteria:
- All commands produce stable machine-readable output under `--json`.
- Invalid flag input with `--json` remains parseable JSON-only output regardless of flag order.
- Exit-code contract remains unchanged across command families.

### Story 5.2: Implement scan/report/export/evidence/manifest/identity/lifecycle command flows
Priority: P0
Tasks:
- Implement command handlers for `scan`, `report`, `export`, `evidence`, `manifest generate`, identity lifecycle commands, and lifecycle-read views.
- Add `scan` posture flags: `--policy <path>` and `--profile [baseline|standard|strict]`.
- Implement report rendering for terminal and PDF (`wrkr report --pdf`).
- Ensure command docs and runtime flags remain synchronized.
- Add bounded, deterministic `--explain` output for major commands.
- Enforce evidence output-directory safety: cleanup/reset only for Wrkr-managed directories.
- Validate evidence ownership marker type before cleanup (`regular file` only; reject symlink/directory).
- Fail closed on unsafe evidence output path conditions with machine-readable error envelopes and exit `8`.
Repo paths:
- `cmd/wrkr/scan.go`
- `cmd/wrkr/report.go`
- `cmd/wrkr/export.go`
- `cmd/wrkr/evidence.go`
- `cmd/wrkr/manifest.go`
- `cmd/wrkr/identity.go`
- `cmd/wrkr/lifecycle.go`
- `docs/commands/`
Run commands:
- `wrkr scan --json`
- `wrkr scan --policy ./fixtures/wrkr-policy.yaml --json`
- `wrkr scan --profile standard --json`
- `wrkr report --pdf --json`
- `wrkr export --format inventory --json`
- `wrkr evidence --frameworks eu-ai-act,soc2 --output <managed-output-dir> --json`
- `wrkr evidence --frameworks eu-ai-act,soc2 --output <non-managed-output-dir> --json`
- `wrkr manifest generate --json`
- `wrkr identity list --json`
- `wrkr lifecycle --org <org> --json`
Test requirements:
- Tier 1: command handler units.
- Tier 2: command-to-core integration tests.
- Tier 3: CLI e2e for primary user workflows.
- Tier 3: export/lifecycle command e2e with deterministic output checks.
- Tier 3: evidence command e2e for managed/non-managed output-directory paths.
- Tier 4: acceptance scripts for AC1/AC2/AC15/AC17/AC18/AC19 command paths.
- Tier 5: fail-closed safety tests for unsafe evidence output cleanup attempts.
- Tier 9: docs-to-CLI consistency and schema contracts.
- Tier 9: stable JSON error envelope and exit `8` contract checks for unsafe output-path rejection.
- Tier 11: workflow scenarios for operator usage.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+contract), Main (e2e+acceptance), Nightly (extended workflow matrix).
Acceptance criteria:
- Core persona workflow completes end-to-end via CLI only.
- PDF and JSON report outputs are reproducible for fixed fixtures.
- `wrkr export --format inventory` writes deterministic inventory snapshots with explicit timestamp semantics.
- `wrkr scan --policy` and `wrkr scan --profile` outputs remain stable and schema-valid under `--json`.
- `wrkr evidence` refuses cleanup on non-managed output dirs and rejects marker symlink/directory types, with stable JSON error envelope and exit `8`.

### Story 5.3: Implement regress baseline and drift command suite
Priority: P0
Tasks:
- Implement `wrkr regress init --baseline [scan-path]` and portable baseline artifact format.
- Implement `wrkr regress run --baseline <baseline-path> --json` with deterministic drift detection.
- Enforce drift semantics: new unapproved tool, revoked tool reappearance, unapproved permission expansion -> exit `5`.
- Integrate regression checks with identity lifecycle state and manifest approvals.
Repo paths:
- `cmd/wrkr/regress.go`
- `core/regress/`
- `schemas/v1/regress/`
- `internal/e2e/regress/`
Run commands:
- `wrkr regress init --baseline ./fixtures/known-good-scan.json --json`
- `wrkr regress run --baseline <baseline-path> --json`
- `go test ./core/regress/... -count=1`
Test requirements:
- Tier 1: comparator units.
- Tier 2: baseline I/O and comparator integration.
- Tier 3: CLI regress e2e tests.
- Tier 4: acceptance drift workflows.
- Tier 5: atomic write/recovery under interrupted baseline updates.
- Tier 9: regression result schema + exit-code contract tests.
- Tier 11: AC10 posture regression scenario.
- Tier 12: cross-product regression semantics parity checks.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+contract), Main (integration+acceptance), Nightly (resilience + contention), Release (regression gate).
Acceptance criteria:
- Drift conditions deterministically produce exit `5` and machine-readable reasons.
- Same baseline + same scan input yields identical pass/fail result.

### Story 5.4: Implement standalone `wrkr score` command and CLI contracts
Priority: P0
Tasks:
- Implement `wrkr score` command for score-only evaluation from latest scan state.
- Support `wrkr score --json`, `wrkr score --explain`, and CI-safe `--quiet`.
- Provide deterministic score breakdown/grade/trend envelopes and stable error modes.
- Ensure score command docs, examples, and schema files are versioned with CLI behavior.
Repo paths:
- `cmd/wrkr/score.go`
- `core/cli/score/`
- `schemas/v1/score/`
- `internal/e2e/score/`
- `docs/commands/score.md`
Run commands:
- `wrkr score --json`
- `wrkr score --explain`
- `go test ./internal/e2e/score -count=1`
Test requirements:
- Tier 1: score command handler units.
- Tier 2: score command integration with core score engine.
- Tier 3: CLI e2e for output and exit-code behavior.
- Tier 4: acceptance script for score command operator flow.
- Tier 9: schema/exit-code/output contract checks.
- Tier 11: AC20 scenario for deterministic score command output.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+contract), Main (integration+acceptance), Nightly (extended score command matrix).
Acceptance criteria:
- `wrkr score` emits deterministic score, grade, breakdown, and trend fields.
- CLI contracts for `--json` and error envelopes are stable and parseable.

---

## Epic 6: Remediation PR Loop and CI Action Integration

Objective: turn discovery into recurring actionable remediation with deterministic PR generation and CI integration.
Traceability: FR6, FR7, FR11, FR13, AC4/AC15/AC16/AC18/AC20, goals around recurring weekly cadence.

### Story 6.1: Implement remediation planner and deterministic patch generation
Priority: P1
Tasks:
- Build remediation planner for top-N ranked findings.
- Implement patch generators for: pinning versions, MCP pin+lockfile guidance, manifest generation updates, autonomy downgrade suggestions, CI gate additions, skill hardening.
- Add policy-rule remediation templates keyed by WRKR IDs with deterministic fix instructions.
- Add remediation templates for `skill_policy_conflict` findings and high skill-sprawl repos.
- Generate deterministic patch previews and commit messages with risk rationale.
- Ensure auto-fix skips unsupported cases with explicit reason codes.
Repo paths:
- `core/fix/`
- `core/fix/templates/`
- `cmd/wrkr/fix.go`
- `internal/integration/fix/`
Run commands:
- `wrkr fix --top 3 --json`
- `go test ./core/fix/... -count=1`
Test requirements:
- Tier 1: remediation rule units.
- Tier 2: patch generation integration tests.
- Tier 3: CLI fix command behavior tests.
- Tier 4: acceptance scripts for AC4/AC15/AC18 fix loops.
- Tier 5: fail-closed tests for ambiguous patch targets.
- Tier 9: deterministic patch/diff output checks.
- Tier 11: remediation scenario fixtures including policy-violation and skill-policy-conflict findings.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+contract), Main (integration+acceptance), Nightly (fuzzing patch edge cases).
Acceptance criteria:
- `wrkr fix --top 3` produces three deterministic, reviewable remediations for eligible findings.
- Unsupported findings return explicit non-fixable reason codes without partial edits.

### Story 6.2: Implement GitHub PR integration with split auth profiles
Priority: P1
Tasks:
- Implement PR creation/update flow under write-capable `fix` profile only.
- Enforce explicit error path when only scan profile token is configured.
- Support configurable bot identity (default `wrkr-bot`) for branch/PR metadata.
- Add branch naming and idempotency rules for scheduled remediation runs.
Repo paths:
- `core/github/pr/`
- `core/auth/`
- `cmd/wrkr/fix.go`
- `internal/e2e/github_pr/`
Run commands:
- `wrkr fix --top 3 --json`
- `go test ./internal/e2e/github_pr -count=1`
Test requirements:
- Tier 1: auth/profile validation units.
- Tier 2: PR API integration tests with simulated responses.
- Tier 3: CLI PR open/update behavior tests.
- Tier 4: acceptance script for write-token required flow.
- Tier 5: retry/idempotency tests for transient API failures.
- Tier 9: stable PR payload and error contract tests.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit+integration subset), Main (full e2e), Nightly (retries/idempotency stress).
Acceptance criteria:
- Write operations fail closed with clear guidance when only scan token exists.
- Re-running remediation does not open duplicate PRs for unchanged findings.

### Story 6.3: Ship `wrkr-action` for scheduled and PR modes
Priority: P1
Tasks:
- Publish GitHub Action entrypoint `Clyra-AI/wrkr-action@v1`.
- Implement scheduled mode: full scan, profile compliance delta, posture score trend, optional auto-open remediation PRs.
- Implement PR mode: changed-file filter, risk delta comment, approval/manifest guidance.
- Add optional threshold-based merge blocking for high-risk changes.
Repo paths:
- `action/`
- `.github/workflows/wrkr-action-ci.yml`
- `core/action/`
- `internal/e2e/action/`
Run commands:
- `go test ./internal/e2e/action -count=1`
- `wrkr scan --json`
- `wrkr report --json`
- `wrkr score --json`
Test requirements:
- Tier 2: action runtime integration tests.
- Tier 3: action CLI invocation e2e.
- Tier 4: scheduled and PR acceptance scripts.
- Tier 5: fail-closed behavior for missing required secrets/config.
- Tier 9: action output and comment payload contract checks.
- Tier 11: AC16 and AC20 scenarios.
- Tier 12: proof-chain compatibility check for records emitted in action mode.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (unit/integration), Main (full e2e+acceptance), Nightly (failure-mode stress), Release (action package validation).
Acceptance criteria:
- PR-mode comments trigger only for AI-config-affecting changes.
- Scheduled runs produce deterministic posture deltas for fixed fixture inputs.
- Scheduled mode includes posture score delta text and profile compliance deltas with deterministic values.

---

## Epic 7: Determinism, Hardening, and Cross-Product Assurance

Objective: enforce byte-stable contracts and resilience under failure/scale across the governance loop.
Traceability: NFR3/NFR4, dev-guide Tier 5-12 requirements, AC7/AC8/AC9/AC10/AC15/AC18/AC19/AC20.

### Story 7.1: Implement determinism and contract test suites
Priority: P0
Tasks:
- Add golden-file and byte-stability tests for inventories, risk reports, regress outputs, and proof chains.
- Add explicit schema compatibility checks for `schemas/v1/*` and JSON field/enum stability.
- Add exit code contract tests across command families.
- Add policy/profile/score determinism contract tests and frozen-weight reproducibility checks.
- Add contract tests for `skill_policy_conflict` finding schema and `RepoExposureSummary.skill_privilege_ceiling` / `skill_sprawl` stability.
- Add contract tests for `RepoExposureSummary.skill_privilege_concentration` and one-finding conflict dedupe semantics.
- Add workflow/branch-protection contract tests for:
  - trigger correctness by workflow type (PR/Main/Nightly/Release),
  - required-check mapping to `pull_request` statuses,
  - required-check ordering/uniqueness constraints,
  - concurrency block presence,
  - path-filter contract fragments for expensive lanes.
- Add contract tests for evidence output-directory safety:
  - reject non-managed non-empty directories,
  - reject marker symlink/directory types,
  - exclude ownership marker file from evidence manifest entries.
- Add deterministic command-smoke harness for key anchors.
- Add scenario-coverage gate ensuring every FR and AC touched by changed stories maps to Tier 11 fixtures.
Repo paths:
- `internal/contracts/`
- `internal/scenarios/`
- `schemas/v1/`
- `scripts/validate_contracts.sh`
- `testinfra/contracts/`
Run commands:
- `go test ./...`
- `go test ./... -count=1`
- `go test ./testinfra/contracts -count=1`
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `wrkr scan --json`
- `wrkr verify --chain --json`
- `wrkr regress run --baseline <baseline-path> --json`
Test requirements:
- Tier 2: deterministic cross-component integration.
- Tier 3: e2e command behavior with cache disabled.
- Tier 4: acceptance command smoke scripts.
- Tier 9: full contract suite (byte stability, exit codes, schema compatibility, workflow/branch-protection contracts).
- Tier 9: evidence output-directory safety contracts including exit `8` behavior and marker trust checks.
- Tier 11: scenario fixtures for spec-driven behavior including refined AC15 and AC18/AC19/AC20.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: PR (subset contracts including workflow/required-check contracts), Main (full Tier 9 + scenarios), Nightly (expanded fixture volume), Release (contract freeze gate).
Acceptance criteria:
- Contract suite detects any schema/exit/output drift before merge.
- Contract suite detects workflow trigger/required-check contract drift before merge.
- Contract suite detects evidence output-directory ownership/marker trust regressions before merge.
- Key command anchors remain deterministic across Linux/macOS/Windows.
- Scenario coverage gate fails when FR/AC changes are not mapped to Tier 11 fixtures.

### Story 7.2: Add hardening, chaos, performance, soak, and Tier 12 interop suites
Priority: P1
Tasks:
- Add Tier 5 tests for atomic writes, lock contention, stale lock recovery, retry classes.
- Add Tier 6 fault-injection scripts for parser/source/proof boundary failures.
- Add Tier 6 fault-injection cases for evidence output marker spoofing and unsafe shared output-path cleanup attempts.
- Add Tier 7 benchmark and command latency budget checks (including policy/profile/score execution paths and 100/500 repo scan targets).
- Add Tier 8 soak tests for sustained contention and long-running scan stability.
- Add Tier 12 cross-product suite validating mixed proof chains and agent-ID consistency.
Repo paths:
- `scripts/test_hardening_*.sh`
- `scripts/test_chaos_*.sh`
- `perf/bench_baseline.json`
- `perf/runtime_slo_budgets.json`
- `scenarios/cross-product/`
- `internal/integration/interop/`
Run commands:
- `go test ./internal/integration -count=1`
- `go test -bench . -benchmem -count=5 ./core/...`
- `scripts/test_hardening_all.sh`
- `scripts/test_chaos_all.sh`
Test requirements:
- Tier 5: full resilience checks.
- Tier 6: controlled chaos/fault injection.
- Tier 6: evidence output-path safety fault-injection checks (marker-type spoofing, shared-path misconfiguration).
- Tier 7: performance regression detection.
- Tier 8: soak stability checks.
- Tier 12: cross-product governance loop checks.
Matrix wiring:
- Lanes: Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: Main (targeted hardening smoke), Nightly (full Tier 5-8 + 12), Release (required subset of Tier 5/7/12).
Acceptance criteria:
- High-risk paths meet fail-closed and recovery expectations under injected faults.
- Evidence output-path safety remains fail-closed under marker spoofing and misconfiguration fault cases.
- Performance budgets pass for mandated NFR scan targets.
- Policy/profile/score paths remain within documented latency and resource budgets.

---

## Epic 8: Documentation, Acceptance Harness, and Release Readiness

Objective: keep docs aligned with shipped behavior and block release until all launch-critical criteria are automated.
Traceability: AC1-AC20 completeness, dev-guide docs standards, release integrity requirements.

### Story 8.1: Implement docs parity, examples, and operator smoke checks
Priority: P1
Tasks:
- Publish command docs for all shipped CLI surfaces with exact flags and exit codes.
- Add quickstart and operator playbooks for scan, fix, evidence, verify, regress, and identity lifecycle.
- Add AI-DSPM positioning language and coexistence guidance consistent with product framing.
- Add offline-safe examples and expected outputs.
- Document evidence output-directory ownership safety rules and unsafe-path failure behavior (including exit `8`).
- Add docs-to-CLI consistency checks in CI.
Repo paths:
- `README.md`
- `docs/commands/`
- `docs/examples/`
- `scripts/check_docs_cli_parity.sh`
- `product/wrkr.md` (only if external contract text changes)
Run commands:
- `wrkr scan --json`
- `wrkr scan --profile standard --json`
- `wrkr evidence --frameworks eu-ai-act,soc2 --json`
- `wrkr evidence --frameworks eu-ai-act,soc2 --output <managed-output-dir> --json`
- `wrkr score --json`
- `wrkr verify --chain --json`
- `wrkr regress run --baseline <baseline-path> --json`
Test requirements:
- Tier 3: CLI command smoke from docs examples.
- Tier 4: acceptance scripts for documented operator workflows.
- Tier 9: docs parity checks for flags/exits/command names.
- Tier 11: docs-linked scenario references validated for FR11/FR12/FR13 workflows.
- Tier 10: install-path UAT smoke against docs instructions.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR (parity lint + smoke subset), Main (full docs smoke), Release (UAT docs validation).
Acceptance criteria:
- All documented commands execute successfully with expected outputs in CI.
- No doc references stale flag names, exit codes, or unsupported workflows.
- Docs clearly describe evidence output ownership safety behavior and unsafe-path failure semantics.

### Story 8.2: Build v1 acceptance gate and release go/no-go checklist
Priority: P0
Tasks:
- Implement acceptance runner that automates AC1-AC20 against deterministic fixtures.
- Include refined AC15 fixture assertions for skill ceiling union, conflict emission, and sprawl metrics.
- Include refined AC15 fixture assertions for skill concentration ratios and non-duplicated conflict scoring.
- Add acceptance fixtures for evidence output-path safety (non-managed dir rejection, marker-type trust checks).
- Add release gate requiring green acceptance summary before tag publication.
- Generate release scorecard artifact with lane status, AC status, and known exceptions.
- Enforce no-go policy if required acceptance or contract checks fail.
Repo paths:
- `scripts/run_v1_acceptance.sh`
- `internal/acceptance/`
- `.github/workflows/release.yml`
- `product/PLAN_v1.md` (status updates only)
Run commands:
- `scripts/run_v1_acceptance.sh`
- `go test ./... -count=1`
- `wrkr scan --json`
- `wrkr verify --chain --json`
- `wrkr regress run --baseline <baseline-path> --json`
Test requirements:
- Tier 4: full acceptance suite (AC1-AC20).
- Tier 4: acceptance fixtures for evidence output ownership safety and fail-closed behavior.
- Tier 5/6/7/8: high-risk release gate subsets.
- Tier 9: contract freeze checks.
- Tier 10: full install-path UAT.
- Tier 11: scenario conformance pass.
- Tier 12: cross-product chain/identity compatibility.
Matrix wiring:
- Lanes: Core CI, Acceptance, Cross-platform, Risk.
- Pipeline placement: Main (pre-release acceptance dry-run), Nightly (full stress cadence), Release (blocking gate).
Acceptance criteria:
- Release pipeline blocks when any required AC or lane check fails.
- Release scorecard reports all mandatory criteria as pass before publication.
- Release gate blocks if evidence output-path safety acceptance fixtures fail.

### Story 8.3: Elevate `wrkr-manifest.yaml` as an open specification
Priority: P1
Tasks:
- Define the manifest spec contract scope and independent versioning model.
- Document canonical fields: approved tools, blocked tools, review-pending tools, policy constraints, permission scopes, approver metadata.
- Publish interoperability guidance for non-Wrkr producers/consumers of `wrkr-manifest.yaml`.
- Add contribution model for new tool types, policy fields, and permission scopes.
- Add adoption metric tracking guidance for public-manifest count.
Repo paths:
- `docs/specs/wrkr-manifest.md`
- `product/wrkr.md`
- `docs/commands/manifest.md`
- `schemas/v1/manifest/`
Run commands:
- `wrkr manifest generate --json`
- `go test ./internal/e2e/manifest -count=1`
- `scripts/check_docs_cli_parity.sh`
Test requirements:
- Tier 1: manifest schema validation units.
- Tier 3: manifest command e2e against updated schema.
- Tier 4: acceptance script for manifest generation + approval workflow documentation alignment.
- Tier 9: manifest schema/version compatibility checks.
- Tier 10: install-path docs smoke for manifest workflows.
Matrix wiring:
- Lanes: Fast, Core CI, Acceptance, Cross-platform.
- Pipeline placement: PR (schema/docs parity), Main (e2e+acceptance), Release (schema+docs freeze gate).
Acceptance criteria:
- Manifest spec is independently versioned and docs match CLI-generated artifacts.
- External tools can consume/produce spec-valid manifest files without Wrkr runtime dependency.

---

## Minimum-Now Sequence

Dependency-aware phased execution (assume 2-week sprints):

1. Phase 0 (Week 1): Stories `0.1-0.3`.
- Output: buildable repo, pinned toolchains, CI/security/release rails in place.

2. Phase 1 (Weeks 2-3): Stories `1.1-1.3` and `2.1`.
- Output: deterministic source acquisition + scan target contract + detector framework.

3. Phase 2 (Weeks 4-6): Stories `2.2-2.5`, `3.1`.
- Output: full sensor-surface detection (including compiled actions) + policy engine + autonomy/CI signals + aggregate inventory and export model.

4. Phase 3 (Weeks 7-8): Stories `3.2-3.5`, `4.1-4.2`, `5.1`.
- Output: lifecycle derivation + ranked risk (including policy/profile/score inputs) + signed proof emission + verify command + locked CLI envelope.

5. Phase 4 (Weeks 9-10): Stories `4.3`, `5.2-5.4`, `6.1`.
- Output: evidence bundles (with cross-product inventory snapshot, profile compliance, and posture score), full command surface (including export/lifecycle/score views), posture regression gates, deterministic remediation generation.

6. Phase 5 (Weeks 11-12): Stories `6.2-6.3`, `7.1`, `8.1`.
- Output: PR automation loop, GitHub Action modes with score/profile deltas, contract/scenario confidence, docs parity.

7. Phase 6 (Weeks 13-14): Stories `7.2`, `8.2-8.3`.
- Output: hardening/chaos/perf/soak + cross-product integration + AC1-AC20 release gate + manifest open-spec publication.

Execution rule:

- No phase starts until predecessor phase contract tests are green.
- High-risk stories must include Tier 4/5/9 minimum before they are considered complete.

---

## Explicit Non-Goals

- No runtime enforcement of tool actions (Gait responsibility).
- No deep compliance interpretation engine beyond Wrkr evidence mapping scope (Axym responsibility).
- No SaaS-only dependencies in v1 core scan/risk/proof paths.
- No non-GitHub source platforms in v1.
- No replacement of shared `Clyra-AI/proof` contracts with Wrkr-local schema variants.
- No regex-only parsing for structured config formats.
- No extraction/storage of secret values.
- No LLM-driven scoring or inference in deterministic scan/risk/proof paths.

---

## Definition of Done

A story is done only when all items below are true:

- Code changes are in-scope for Wrkr and preserve architecture boundaries.
- Toolchain/dependency versions are pinned and policy-compliant.
- Same-change tests are included and mapped to required tiers.
- Required matrix lanes for the story are green in assigned pipelines.
- `--json` outputs, exit codes, and schema contracts are covered by Tier 9 checks.
- Deterministic behavior is validated (`go test ./... -count=1` where required).
- Tier 11 scenario coverage is present for every FR/AC touched by the story and passes in CI.
- No scan-data exfiltration path is introduced by default.
- Security/release checks pass for scope that touches build/release surfaces.
- User-facing command/flag/exit/schema changes include doc updates in the same change.
- For proof-touching work, chain integrity and `proof` interop checks pass.

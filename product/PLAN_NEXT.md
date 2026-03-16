# PLAN WRKR_OSS_LAUNCH_ALIGNMENT: Release Integrity, Launch Positioning, and Optional Developer-First Activation

Date: 2026-03-15
Source of truth: user-provided launch audit findings from 2026-03-15, `product/dev_guides.md`, `product/architecture_guides.md`, `product/wrkr.md`, `README.md`, `docs/examples/quickstart.md`, `docs/commands/scan.md`, `docs/trust/release-integrity.md`, and current docs-site landing/bootstrap surfaces.
Scope: Wrkr repository only. Planning artifact only. Convert the verified launch-readiness recommendations into an execution-ready backlog plan that clears the current public OSS launch blockers without expanding Wrkr into hosted/dashboard scope.

## Global Decisions (Locked)

- Preserve Wrkr's deterministic, offline-first, fail-closed behavior in default scan, risk, regress, proof, verify, and evidence paths.
- Keep the stable CLI exit-code contract unchanged: `0,1,2,3,4,5,6,7,8`.
- Keep public JSON envelopes backward-compatible. No field removals, retyping, or schema-major bumps are allowed in this plan.
- Recommended minimum-now launch persona is `security/platform`. Developer local-hygiene remains supported, but it is not the primary public promise unless the optional Wave 2 runtime work also lands.
- Release-integrity claims must be atomic across normative docs, workflow implementation, local enforcement scripts, hygiene tests, and release validation. No docs-only or workflow-only pin change may ship.
- Browser `/scan` remains a thin read-only bootstrap/projection surface only. It must not imply hosted scan execution, persistent dashboard state, or a required server-side control plane.
- If Wave 2 is implemented, it must use additive contract shape for developer-first activation output. Existing `findings`, `ranked_findings`, `top_findings`, and `summary` fields remain available and machine-readable.
- Architecture, risk, adapter, report-selection, or failure-semantics changes in this plan must run `make prepush-full`.
- Release-integrity, filesystem-boundary, or fault-path changes in this plan must run `make test-hardening` and `make test-chaos`.
- Performance-sensitive changes in this plan must run `make test-perf`.
- Any implementation PR for `W1-S01`, `W1-S02`, or `W2-S01` requires an ADR because those stories change release-contract enforcement or contract-facing CLI/report behavior.

## Current Baseline (Observed)

- `git status --short --branch` was clean before generating this plan.
- `product/dev_guides.md` and `product/architecture_guides.md` were present, readable, and enforceable for testing, determinism, CI, TDD, chaos, frugal architecture, and boundary governance.
- Output path validation passed:
  - requested path: `product/PLAN_NEXT.md`
  - resolved path stayed inside `/Users/tr/wrkr`
- Core technical validation already completed successfully:
  - `go build -o .tmp/wrkr ./cmd/wrkr`
  - `go test ./... -count=1`
  - `make test-docs-consistency test-docs-storyline`
  - `make docs-site-install docs-site-lint docs-site-build docs-site-check`
  - `make docs-site-audit-prod`
- Deterministic scenario validation showed the product core is healthy:
  - `./.tmp/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json` returned `131` findings, `19` tools, `19` agents, and deterministic risk/compliance output.
  - `./.tmp/wrkr evidence --frameworks eu-ai-act,soc2 --json` succeeded and produced deterministic report artifacts.
  - `./.tmp/wrkr verify --chain --json` returned authenticated integrity (`verification_mode=chain_and_attestation`, `authenticity_status=verified`).
- Verified fail-closed safety behavior is already strong:
  - unsafe evidence output dirs returned exit `8` / `unsafe_operation_blocked`
  - unmanaged materialized roots returned exit `8` / `unsafe_operation_blocked`
  - root-escaping symlinked `.env` and `.codex/config.toml` produced `parse_error.kind=unsafe_path` with no secret leakage
- Verified launch blockers from the audit remain real:
  - `wrkr scan --my-setup --json` in the current environment found real tools but the first visible ranked output was dominated by policy IDs (`WRKR-005/006/007/001/002`) instead of concrete activation items.
  - `wrkr mcp-list --state <my-setup-state> --json` returned `0` rows in the same local run, so the current public developer-first story does not reliably produce the promised first-run "aha".
  - `.github/workflows/release.yml` installs `cosign v2.4.3` while `product/dev_guides.md` pins `v2.5.3`.
  - release SBOM/vulnerability tooling is not enforced with the same exact-version rigor described in `product/dev_guides.md`.
  - `scripts/check_toolchain_pins.sh` hard-fails only `gosec`, `golangci-lint`, and `.tool-versions` lines today.
- Current public packaging still dilutes the strongest wedge:
  - homepage gives similar prominence to `Start Here`, `Security Team Flow`, and `Browser Bootstrap`
  - `/scan` currently markets "Trigger a read-only Wrkr org scan in about 60 seconds", which risks creating hosted-product expectations
  - `docs/contracts/readme_contract.md` currently allows the landing README to remain developer-machine-first, which conflicts with the recommended minimum-now launch posture
- Existing OSS trust baseline files already exist and do not need new artifacts for this plan:
  - `README.md`
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `CODE_OF_CONDUCT.md`
  - `SECURITY.md`
  - `.github/ISSUE_TEMPLATE/*`
  - `.github/pull_request_template.md`

## Exit Criteria

1. Release workflow tool versions for signing, SBOM, and artifact vulnerability scanning are aligned with `product/dev_guides.md`, or the normative claim is narrowed in the same atomic change.
2. Local enforcement and hygiene tests fail fast when release-critical tool pins drift from the documented contract.
3. `README`, quickstart/docs-site landing, and scan command docs make the minimum-now launch persona explicit and no longer imply a broader developer-first promise than the shipped first-run experience supports.
4. Hosted/org-scan prerequisites (`--github-api`, token expectations, rate-limit/privacy constraints) are visible on primary onboarding surfaces.
5. `/scan` is clearly secondary and read-only, with no copy that implies hosted scanning, persistent state, or browser-authoritative runtime behavior.
6. If Wave 2 is implemented, `my_setup` flows expose an additive first-value activation surface that promotes concrete tool/MCP/secret signals over abstract policy-only items when those concrete findings exist.
7. All required fast, core CI, acceptance, cross-platform, docs, release-smoke, and risk lanes for the selected waves are green.
8. The full validation set used in the audit is rerun before launch sign-off:
  - `go test ./... -count=1`
  - `make test-docs-consistency test-docs-storyline`
  - `make docs-site-install docs-site-lint docs-site-build docs-site-check`
  - `make docs-site-audit-prod`
  - targeted `wrkr scan`, `wrkr report`, `wrkr evidence`, `wrkr verify`, and fail-closed path probes

## Public API and Contract Map

Stable/public surfaces touched by this plan:

- `wrkr scan --my-setup --json`
- `wrkr report --json`
- `wrkr mcp-list --json`
- `wrkr verify --chain --json`
- `wrkr version`
- install and release-parity contract surfaces:
  - `README.md`
  - `docs/install/minimal-dependencies.md`
  - `docs/trust/release-integrity.md`
- onboarding and positioning surfaces:
  - `docs/examples/quickstart.md`
  - `docs/examples/security-team.md`
  - `docs/commands/scan.md`
  - `docs/positioning.md`
  - `docs/contracts/readme_contract.md`
  - docs-site `/`
  - docs-site `/docs/start-here`
  - docs-site `/scan`

Internal surfaces expected to change:

- `.github/workflows/release.yml`
- `scripts/check_toolchain_pins.sh`
- `testinfra/hygiene/toolchain_pins_test.go`
- release/install validation helpers:
  - `scripts/test_uat_local.sh`
  - possibly `.github/workflows/main.yml` or `.github/workflows/pr.yml` if enforcement wiring changes
- if Wave 2 is executed:
  - `core/cli/scan.go`
  - `core/cli/report.go`
  - `core/report/build.go`
  - `core/report/types.go`
  - `core/cli/root_test.go`
  - `core/cli/report_contract_test.go`
  - `internal/e2e/cli_contract/cli_contract_e2e_test.go`
  - `internal/scenarios/`
- docs-site launch surfaces:
  - `docs-site/src/app/page.tsx`
  - `docs-site/src/app/scan/page.tsx`
  - `docs-site/src/components/scan/ScanBootstrapShell.tsx`
  - `docs-site/src/lib/navigation.ts`
  - `docs-site/src/lib/docs.ts`

Shim and deprecation path:

- Wave 1 does not require a user-facing shim; it tightens release/process enforcement only.
- Wave 2, if implemented, must be additive:
  - retain existing `findings`, `ranked_findings`, `top_findings`, and report summary structures
  - add a new `my_setup`-specific activation surface rather than repurposing raw risk arrays by default
  - allow docs to migrate from existing quickstart examples to the new activation surface without breaking automation consumers
- Wave 3 updates docs and positioning only; it must not introduce hidden runtime requirements or hosted dependencies.

Schema and versioning policy:

- No schema-major bump is planned.
- Wave 1 and Wave 3 should not change CLI JSON schemas.
- Wave 2 may add new JSON fields or new nested summary sections only.
- Any additive CLI/report field introduced in Wave 2 requires:
  - docs update in the same PR
  - fixture/golden updates
  - compatibility tests proving older consumers can ignore the field

Machine-readable error expectations:

- Existing CLI error envelope format and exit-code mapping remain unchanged.
- Release pin enforcement failures surface via CI/hygiene tooling, not new CLI exit codes.
- If Wave 2 adds activation output, absence must be deterministic:
  - empty/omitted for non-`my_setup` targets
  - explicit empty result or deterministic reason for `my_setup` when no qualifying concrete findings exist
- Fail-closed behavior for filesystem ownership markers, unsafe symlinks, and missing hosted dependencies remains unchanged.

## Docs and OSS Readiness Baseline

README first-screen contract for this plan:

- Minimum-now launch posture must lead with security/platform posture-and-proof value.
- Developer local-hygiene may remain visible, but it must be framed as secondary unless Wave 2 also lands.
- Primary public surfaces must explicitly state:
  - Wrkr is CLI-first and file-based
  - org scans require explicit GitHub API configuration
  - private repos and rate-limit avoidance usually require a token
  - `/scan` is not a hosted replacement for the CLI
- If the README contract changes materially, `docs/contracts/readme_contract.md` must be updated in the same PR.

Integration-first docs flow for this plan:

1. `README.md`
2. `docs/examples/security-team.md`
3. `docs/commands/scan.md`
4. `docs/examples/quickstart.md`
5. `docs/install/minimal-dependencies.md`
6. `docs/trust/release-integrity.md`
7. `docs/positioning.md`
8. `docs/contracts/readme_contract.md`
9. `docs-site/src/app/page.tsx`
10. `docs-site/src/app/scan/page.tsx`
11. `docs-site/src/components/scan/ScanBootstrapShell.tsx`

Lifecycle path model that docs must preserve:

- `.wrkr/last-scan.json` remains the authoritative saved scan state.
- `.wrkr/proof-chain.json` remains the proof-chain path verified by `wrkr verify --chain`.
- `wrkr-evidence/` remains a user-selected output root subject to fail-closed ownership checks.
- Browser/docs-site surfaces never replace the Go CLI as the authoritative scan/risk/proof runtime.
- Hosted org acquisition remains an explicit source mode, not an automatic browser-managed flow.

Docs source-of-truth mapping for this plan:

- CLI/runtime behavior: `docs/commands/*.md`
- onboarding examples: `docs/examples/*.md`
- install contract: `docs/install/minimal-dependencies.md`
- release-integrity contract: `docs/trust/release-integrity.md`
- product boundary framing: `docs/positioning.md`
- README contract rules: `docs/contracts/readme_contract.md`
- docs-site landing/secondary UX: `docs-site/src/app/*`, `docs-site/src/components/*`, `docs-site/src/lib/*`

OSS trust baseline:

- Existing trust/support files are sufficient for this plan.
- No new governance file is required.
- Public-behavior changes must keep maintainer/support expectations explicit in README/docs-site surfaces.
- Any change to install/release claims must keep `CHANGELOG.md` and public release guidance synchronized in the same PR.

## Recommendation Traceability

| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Story mapping |
|---|---|---|---|---|---|
| R1 | Align release workflow signing/SBOM/scanner versions to the normative pin contract | Current release pipeline claims and actual tooling drift on critical integrity surfaces | Enforcement-first release integrity | Stronger public trust, lower release-regression risk | `W1-S01`, `W1-S02` |
| R2 | Extend hard-fail enforcement so future pin drift is caught before merge/release | Current checks enforce only a subset of the normative pin table | Contracts as executable governance | Prevents repeat drift and docs/workflow divergence | `W1-S02` |
| R3 | Pick one minimum-now launch persona and make public onboarding match it | Current public packaging dilutes the strongest wedge and overpromises local first-run experience | Security/platform-led launch clarity | Sharper category story and lower expectation mismatch | `W3-S01` |
| R4 | Keep org-scan auth and hosted-scope boundaries explicit on primary surfaces | Current copy risks implying zero-config org scans or browser-managed hosted behavior | Honest self-serve onboarding | Lower abandonment, fewer support escalations, better trust | `W3-S01`, `W3-S02` |
| R5 | Demote `/scan` to secondary/experimental bootstrap positioning | `/scan` currently creates hosted-product expectations that Wrkr does not meet | Boundary-first packaging | Protects CLI-first identity and avoids wedge dilution | `W3-S02` |
| R6 | If broader developer-first launch remains a goal, add an additive `my_setup` activation surface before promoting that promise | Current `my_setup` first-value experience is too policy-heavy to anchor a broad developer-first launch | Optional post-blocker activation improvement | Better individual-user onboarding without breaking raw contracts | `W2-S01` |

## Test Matrix Wiring

Fast lane:

- `make lint-fast`
- targeted `go test` package runs with `-count=1`
- `scripts/check_toolchain_pins.sh`

Core CI lane:

- `make prepush`
- targeted integration/e2e runs for touched flows
- docs parity/storyline checks whenever user-facing surfaces change

Acceptance lane:

- `make test-scenarios`
- targeted `go test ./internal/e2e/... -count=1`
- `scripts/test_uat_local.sh --skip-global-gates` for install/release-path changes
- explicit CLI command probes with `--json`

Cross-platform lane:

- `go test ./core/cli -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- release/install-path validation on the same OS matrix already used by CI where applicable

Risk lane:

- `make prepush-full`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make test-perf` when hot-path selection/report logic changes materially

Merge/release gating rule:

- Wave 1 is release-blocking and must merge green before any public launch copy change ships.
- Wave 2 is optional and must merge before any developer-first public promise is promoted again.
- Wave 3 is required for the recommended minimum-now security/platform-led launch and must not merge ahead of Wave 1.
- If Wave 2 is deferred, Wave 3 docs must explicitly avoid stronger developer-first claims.

## Wave 1 - Epic W1: Release Integrity Contract Alignment

Objective: remove the documented-vs-implemented release pin drift and make future drift fail fast in local/CI enforcement.

### Story W1-S01: Align release signing, SBOM, and artifact scanner pins atomically

Priority: P0
Tasks:
- Inventory all release-integrity pin surfaces in this repo for `cosign`, `Syft`, and `Grype`.
- Update `.github/workflows/release.yml` so the implemented release lane uses the exact versions required by `product/dev_guides.md`.
- Prefer explicit versioned installation/invocation over implicit version resolution where the current action wrapper obscures tool versions.
- Update any affected release-integrity docs/runbooks in the same change if the implementation mechanism changes.
- Verify `scripts/test_uat_local.sh` and release-smoke flows still reflect the published install/release contract after the pin alignment.
Repo paths:
- `.github/workflows/release.yml`
- `product/dev_guides.md`
- `docs/trust/release-integrity.md`
- `docs/install/minimal-dependencies.md`
- `scripts/test_uat_local.sh`
Run commands:
- `make lint-fast`
- `go build -o .tmp/wrkr ./cmd/wrkr`
- `scripts/check_toolchain_pins.sh`
- `scripts/test_uat_local.sh --skip-global-gates`
- scanner-specific built-artifact validation on the locally built artifact and/or release `dist/` payload
- `make prepush-full`
Test requirements:
- hygiene tests covering the aligned pin values
- release workflow contract checks for exact version presence
- built-artifact validation using the same scanner modes claimed by CI
- docs/install/release parity checks when command text changes
- no floating-version regressions in CI-critical tooling
Matrix wiring:
- Fast lane: `make lint-fast`; `scripts/check_toolchain_pins.sh`
- Core CI lane: `make prepush`
- Acceptance lane: `scripts/test_uat_local.sh --skip-global-gates`
- Cross-platform lane: existing CI matrix remains unchanged; verify no workflow/installer assumptions regress on Windows/macOS paths
- Risk lane: `make prepush-full`; `make test-contracts`; `make test-hardening`
Acceptance criteria:
- `release.yml` no longer drifts from the normative `cosign`, `Syft`, and `Grype` versions claimed in `product/dev_guides.md`.
- Release-smoke/install-path validation still passes after the change.
- Public docs and release workflow describe the same install/release contract.
Contract/API impact:
- No CLI JSON or exit-code changes.
- Release-integrity process contract becomes stricter and more explicit.
Versioning/migration impact:
- No schema/version bump.
- Existing release consumers keep the same artifact contract; only tool provenance/enforcement hardens.
Architecture constraints:
- Keep release-integrity enforcement thin and explicit; do not bury tool-version truth in multiple opaque wrappers.
- Name any new helper functions/scripts by side effect (`install_*`, `validate_*`, `scan_*`) rather than generic verbs.
- Preserve deterministic release semantics and explicit failure paths.
ADR required: yes
TDD first failing test(s):
- extend `testinfra/hygiene/toolchain_pins_test.go` for `cosign`, `Syft`, and `Grype`
- add/update release-workflow pin assertions before changing the workflow
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: release smoke and scanner validation succeed with exact documented versions.
- Fault: a pin drifts in workflow or docs.
- Expected: hygiene/enforcement fails before merge or release publication.
- Abort condition: any change introduces a hidden floating-version dependency.

### Story W1-S02: Extend hard-fail enforcement and rerun the previously failing release lane

Priority: P0
Tasks:
- Extend `scripts/check_toolchain_pins.sh` so release-critical version claims are enforced, not merely documented.
- Update or add hygiene/contract tests that fail on mismatched release pin surfaces.
- Ensure the enforcement target list covers the real release paths used by Wrkr today.
- Add scanner/signing pin checks to the same enforcement-first workflow used by `make lint-fast`.
- Rerun the equivalent local release validation lane and capture the commands as the required validation baseline for implementation PRs.
Repo paths:
- `scripts/check_toolchain_pins.sh`
- `testinfra/hygiene/toolchain_pins_test.go`
- `.github/workflows/release.yml`
- `Makefile`
- `product/dev_guides.md`
Run commands:
- `make lint-fast`
- `go test ./testinfra/hygiene -count=1`
- `go build -o .tmp/wrkr ./cmd/wrkr`
- `scripts/test_uat_local.sh --skip-global-gates`
- `make prepush-full`
Test requirements:
- negative tests proving the enforcement script fails on mismatched release pins
- hygiene coverage for the expanded enforced tool set
- built-artifact validation rerun using the same scanner class claimed in the release lane
- release-smoke rerun after enforcement changes
Matrix wiring:
- Fast lane: `make lint-fast`; `go test ./testinfra/hygiene -count=1`
- Core CI lane: `make prepush`
- Acceptance lane: `scripts/test_uat_local.sh --skip-global-gates`
- Cross-platform lane: verify new enforcement is shell-portable enough for existing CI usage
- Risk lane: `make prepush-full`; `make test-contracts`; `make test-chaos`
Acceptance criteria:
- A release pin mismatch is caught by local/CI enforcement before release publication.
- The same validation lane that previously allowed drift is rerun green after the fix.
- `product/dev_guides.md`, workflow implementation, and enforcement tests all agree on the release-critical versions.
Contract/API impact:
- No user-facing CLI contract change.
- CI/release contract becomes executable for the release-critical tool subset.
Versioning/migration impact:
- None.
Architecture constraints:
- Enforcement must remain boring and auditable.
- Keep the source of truth legible: one normative table, one enforcement surface, explicit tests.
- Do not add clever parsing that reduces maintainability of the pin contract.
ADR required: yes
TDD first failing test(s):
- negative enforcement test in `testinfra/hygiene/toolchain_pins_test.go`
- failing shell-script assertion for a deliberately mismatched release pin
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: `make lint-fast` and hygiene tests pass when docs/workflow/enforcement agree.
- Fault: a future PR changes one release pin surface but not the others.
- Expected: local/CI gate fails before merge.
- Abort condition: enforcement begins requiring network or non-deterministic state.

## Wave 2 - Epic W2: Optional Developer-First Activation Contract

Objective: if Wrkr wants to relaunch a broader developer-first story later, add an additive first-value surface for `my_setup` instead of overloading raw risk arrays.

### Story W2-S01: Add an additive `my_setup` activation surface for concrete first-run signals

Priority: P1
Tasks:
- Write an ADR deciding the additive contract shape for a `my_setup` activation surface in `scan --json` and `report --json`.
- Implement deterministic selection rules that prefer concrete tool/MCP/secret/bookkeeping signals relevant to a developer's first run and exclude policy-only items when concrete items exist.
- Scope the new surface to `target.mode=my_setup` only.
- Keep existing raw `findings`, `ranked_findings`, `top_findings`, and report risk arrays intact for compatibility.
- Update personal-hygiene/quickstart docs only if this wave is selected for implementation.
Repo paths:
- `core/cli/scan.go`
- `core/cli/report.go`
- `core/report/build.go`
- `core/report/types.go`
- `core/cli/root_test.go`
- `core/cli/report_contract_test.go`
- `internal/e2e/cli_contract/cli_contract_e2e_test.go`
- `internal/scenarios/`
- `docs/examples/personal-hygiene.md`
- `docs/examples/quickstart.md`
Run commands:
- `make lint-fast`
- `go test ./core/cli ./core/report -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `make test-scenarios`
- `go run ./cmd/wrkr scan --my-setup --json`
- `go run ./cmd/wrkr report --json`
- `make prepush-full`
- `make test-perf`
Test requirements:
- CLI contract tests for additive `my_setup` activation output
- help/usage and `--json` stability tests
- compatibility tests proving older consumers can ignore the additive field
- scenario fixtures showing concrete activation output when concrete findings exist
- empty/degraded-path tests showing deterministic absence when no qualifying findings exist
- docs/storyline smoke if docs examples change
Matrix wiring:
- Fast lane: `make lint-fast`; `go test ./core/cli ./core/report -count=1`
- Core CI lane: `make prepush`
- Acceptance lane: `make test-scenarios`; `go test ./internal/e2e/cli_contract -count=1`
- Cross-platform lane: `go test ./core/cli -count=1`
- Risk lane: `make prepush-full`; `make test-contracts`; `make test-hardening`; `make test-perf`
Acceptance criteria:
- `my_setup` runs with concrete tool/MCP/secret findings emit an additive activation surface containing concrete entries first.
- Policy-only findings do not dominate the activation surface when concrete findings exist.
- Raw ranking fields remain present and backward-compatible.
- Non-`my_setup` targets do not emit misleading activation output.
Contract/API impact:
- Additive CLI/report JSON change only.
- No exit-code or existing-field removal/retyping.
Versioning/migration impact:
- No schema-major bump.
- Docs and fixtures must explain the additive field and keep legacy fields documented until at least one release cycle after adoption.
Architecture constraints:
- Keep selection logic in focused report/CLI shaping code, not spread across detectors.
- Avoid coupling raw risk scoring to onboarding-specific projection logic.
- Preserve explicit side-effect semantics and deterministic ordering.
ADR required: yes
TDD first failing test(s):
- new failing CLI contract test for `my_setup` additive activation output
- new report summary test for deterministic activation projection
- scenario test proving concrete findings outrank policy-only items in the activation surface
Cost/perf impact: low
Chaos/failure hypothesis:
- Steady state: `my_setup` with concrete findings yields deterministic activation output.
- Fault: only policy findings exist, or no qualifying concrete findings exist.
- Expected: additive activation output is empty or explicit, not fabricated and not crashing downstream consumers.
- Abort condition: implementation starts mutating raw risk ordering shared by non-`my_setup` flows without ADR approval.

## Wave 3 - Epic W3: Launch Persona and Public Surface Realignment

Objective: make the public/docs-site story match the recommended minimum-now launch posture and remove hosted-product expectations from browser-facing surfaces.

### Story W3-S01: Reframe README, quickstart, and homepage around the security/platform wedge

Priority: P0
Tasks:
- Update `README.md` and `docs/examples/quickstart.md` so the recommended minimum-now launch posture is clearly security/platform-led.
- Keep developer local-hygiene supported, but move it to a secondary or explicitly scoped role unless Wave 2 is also shipping.
- Make hosted/org auth prerequisites explicit in primary onboarding text.
- Update `docs/examples/security-team.md`, `docs/commands/scan.md`, `docs/positioning.md`, and `docs/contracts/readme_contract.md` so contract docs and public copy agree.
- Adjust docs-site landing CTA hierarchy to reflect the same lead persona and onboarding order.
Repo paths:
- `README.md`
- `docs/examples/quickstart.md`
- `docs/examples/security-team.md`
- `docs/commands/scan.md`
- `docs/positioning.md`
- `docs/contracts/readme_contract.md`
- `docs-site/src/app/page.tsx`
- `docs-site/src/lib/navigation.ts`
- `docs-site/src/lib/docs.ts`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
- `make docs-site-install`
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`
- `scripts/run_docs_smoke.sh --subset`
Test requirements:
- docs consistency and storyline checks
- README first-screen contract checks
- docs-site smoke tests
- integration-before-internals guidance checks for touched onboarding flows
- source-of-truth mapping checks when both repo docs and docs-site are changed
Matrix wiring:
- Fast lane: `make lint-fast`; `make test-docs-consistency`
- Core CI lane: `make prepush`; `make test-docs-storyline`
- Acceptance lane: `make docs-site-install`; `make docs-site-lint`; `make docs-site-build`; `make docs-site-check`
- Cross-platform lane: docs changes rely on existing CI/docs lanes; no new platform contract
- Risk lane: `make prepush-full` only if implementation also changes CLI/report behavior in the same PR
Acceptance criteria:
- Public landing surfaces no longer imply a broad developer-first promise that the current shipped first-run experience does not satisfy.
- Org-scan auth and explicit-hosted-boundary guidance are visible on primary onboarding surfaces.
- `docs/contracts/readme_contract.md` matches the chosen public positioning.
Contract/API impact:
- Docs/public-positioning contract only.
- No CLI schema or exit-code changes.
Versioning/migration impact:
- None.
Architecture constraints:
- Preserve CLI-first authority and offline-default messaging.
- Do not introduce copy that implies hidden backend orchestration or dashboard state.
- Keep onboarding copy aligned to the actual runtime boundaries in `product/wrkr.md`.
ADR required: no
TDD first failing test(s):
- docs consistency/storyline failure for outdated onboarding order
- docs-site smoke failure for stale CTA/link expectations
Cost/perf impact: low

### Story W3-S02: Demote `/scan` to a clearly secondary read-only bootstrap surface

Priority: P1
Tasks:
- Rewrite docs-site `/scan` hero and CTA language so it reads as optional/secondary, not as the primary happy path.
- Tighten boundary copy around pasted JSON, browser projection, and no hosted scan execution.
- Reduce or relocate homepage `/scan` CTA prominence so it does not sit beside the primary launch path as an equal promise.
- Keep the shell deterministic and read-only while clarifying that the Go CLI remains authoritative.
Repo paths:
- `docs-site/src/app/page.tsx`
- `docs-site/src/app/scan/page.tsx`
- `docs-site/src/components/scan/ScanBootstrapShell.tsx`
- `docs-site/src/components/scan/ScanStatusPanel.tsx`
- `docs-site/src/components/scan/ScanStatusPanel.test.tsx`
- `docs-site/src/lib/scan-bootstrap.ts`
- `docs-site/src/lib/scan-bootstrap.test.ts`
- `docs/positioning.md`
Run commands:
- `make docs-site-install`
- `make docs-site-lint`
- `make docs-site-build`
- `make docs-site-check`
- `make test-docs-consistency`
- `make test-docs-storyline`
Test requirements:
- docs-site smoke tests for `/scan`
- copy/contract tests around bootstrap state handling if link or state expectations change
- docs consistency/storyline checks
- boundary-language verification in positioning docs
Matrix wiring:
- Fast lane: `make test-docs-consistency`
- Core CI lane: `make test-docs-storyline`
- Acceptance lane: `make docs-site-install`; `make docs-site-lint`; `make docs-site-build`; `make docs-site-check`
- Cross-platform lane: existing docs-site CI coverage
- Risk lane: not required unless runtime behavior changes are bundled
Acceptance criteria:
- `/scan` no longer reads like a hosted scan runtime or dashboard.
- Homepage no longer promotes Browser Bootstrap as a co-equal primary workflow.
- Scan bootstrap boundaries remain explicit and test-covered.
Contract/API impact:
- Docs/docs-site/UI contract only.
Versioning/migration impact:
- None.
Architecture constraints:
- Keep browser behavior thin and projection-only.
- Avoid copy that suggests the browser owns state, proof, or enforcement.
- Do not add server dependencies in this story.
ADR required: no
TDD first failing test(s):
- failing docs-site component test for outdated bootstrap labels/expectations
- failing docs storyline check for stale CTA hierarchy
Cost/perf impact: low

## Minimum-Now Sequence

Recommended minimum-now launch path:

1. Implement Wave 1 completely.
2. Implement Wave 3 completely.
3. Re-run the full audit validation set and launch only with the security/platform-led public story.
4. Explicitly defer Wave 2 unless the team wants to reintroduce a stronger developer-first promise.

Broader developer-first launch path:

1. Implement Wave 1 completely.
2. Implement Wave 2 completely.
3. Implement Wave 3 with developer-first copy only after the additive activation surface is shipped and documented.
4. Re-run the full audit validation set before launch sign-off.

Dependency notes:

- Wave 1 is mandatory before any public launch change.
- Wave 2 must precede any renewed developer-first copy.
- Wave 3 may follow Wave 1 directly only if the public positioning stays security/platform-led.

## Explicit Non-Goals

- No hosted scan backend, dashboard state store, or browser-authoritative runtime.
- No new telemetry/data-exfiltration path.
- No LLM usage in scan/risk/proof/evidence paths.
- No change to stable CLI exit codes.
- No package-vulnerability-scanner scope expansion in the Wrkr core runtime.
- No cross-product feature work for Axym or Gait beyond already documented interoperability boundaries.
- No cosmetic-only docs-site redesign unrelated to the launch blockers above.

## Definition of Done

- All selected-wave stories are implemented with matching tests, matrix wiring, docs, and ADRs where required.
- Release-integrity pins are aligned across docs, workflows, enforcement, and validation.
- Public launch surfaces accurately reflect the selected launch persona and real runtime boundaries.
- If Wave 2 is selected, additive `my_setup` activation output is documented, fixture-covered, and compatibility-tested.
- Docs and docs-site checks pass, including README first-screen/storyline expectations.
- The full audit validation matrix is rerun and captured in the implementation PR(s).
- After planning, the only intentional working-tree modification is this plan file; implementation follow-up should start from a new branch via `adhoc-implement`.

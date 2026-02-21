# PLAN Audit 1: Launch-Readiness Contract Closure

Date: 2026-02-21
Source of truth:
- User-provided recommended items (audit gap-closure list in this thread)
- Audit evidence already observed in repo/runtime:
  - `/Users/davidahmann/Projects/wrkr/product/dev_guides.md`
  - `/Users/davidahmann/Projects/wrkr/.github/workflows/pr.yml`
  - `/Users/davidahmann/Projects/wrkr/core/cli/`
  - `/Users/davidahmann/Projects/wrkr/README.md`
  - `/Users/davidahmann/Projects/wrkr/docs/commands/evidence.md`
  - `/Users/davidahmann/Projects/wrkr/docs/examples/operator-playbooks.md`
  - `/Users/davidahmann/Projects/wrkr/SECURITY.md`
Scope:
- Planning-only backlog for closing all identified audit gaps.
- No code implementation in this plan.

## Global Decisions (Locked)
- `GD-1`: Standards file remains normative for toolchain policy. Implementation should align CI to `/Users/davidahmann/Projects/wrkr/product/dev_guides.md` unless maintainers explicitly re-baseline policy docs.
- `GD-2`: CLI help behavior is a contract: `wrkr <command> --help` must return exit code `0` consistently.
- `GD-3`: Compliance coverage percentages are evidence-state signals, not product-capability completeness claims.
- `GD-4`: Wrkr contracts must remain stable: determinism, fail-closed behavior, schema stability, exit-code stability.
- `GD-5`: Optional trust hardening (`SECURITY.md`) is included as lower-priority `P2`, sequenced after launch-critical closures.

## Current Baseline (Observed)
- Toolchain pin drift exists between standards and PR workflow:
  - Standards expect `gosec v2.23.0`, `golangci-lint v2.0.1` in `/Users/davidahmann/Projects/wrkr/product/dev_guides.md`.
  - PR workflow currently installs older versions in `/Users/davidahmann/Projects/wrkr/.github/workflows/pr.yml`.
- Root help exits `0`, but several subcommand `--help` paths exit `6` due flag parsing behavior.
- `README` status section still states “Epics 1-6 are implemented” while acceptance/scenario contracts now cover broader scope.
- Docs mention evidence coverage but do not clearly frame low/0 coverage as expected gap signal from scanned evidence state.
- `SECURITY.md` is minimal and lacks response window, supported branches, and report workflow details.

Machine-readable baseline capture commands:
- `wrkr scan --path scenarios/wrkr/scan-mixed-org/repos --json`
- `wrkr evidence --frameworks eu-ai-act,soc2 --json`
- `wrkr regress init --baseline ./.wrkr/last-scan.json --json`
- `wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --json`

## Exit Criteria
- `EC-1 (P1)`: CI pin policy and enforcement aligned (single source of truth) and guarded by automated check in fast lane.
- `EC-2 (P2)`: All subcommand help flows exit `0`; tests enforce this contract.
- `EC-3 (P2)`: `README` status and maturity wording reflect current implemented scope and test coverage.
- `EC-4 (P2)`: Evidence/docs/report language clearly explains framework coverage as evidence-state signal and includes operator remediation expectations.
- `EC-5 (P2-optional)`: `SECURITY.md` provides clear private reporting path, response expectations, and supported branch policy.
- `EC-6`: `make prepush-full` passes after each epic integration; no contract regressions.

## Recommendation Traceability
| Rec ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Mapped epic/story |
|---|---|---|---|---|---|
| R1 | Fix standards/CI pin drift + add anti-drift CI check | Launch blocker; contract credibility risk | Contract-first reliability | Stronger trust in deterministic governance claims | `E1/S1.1`, `E1/S1.2`, `E1/S1.3` |
| R2 | Normalize subcommand help exits to `0` + add tests | CLI contract inconsistency causes adoption friction | DX contract hardening | Better onboarding reliability and less operator confusion | `E2/S2.1`, `E2/S2.2` |
| R3 | Update stale maturity/status docs | Prevent expectation mismatch | Messaging accuracy | Reduces launch trust debt | `E3/S3.1` |
| R4 | Clarify compliance coverage interpretation in docs/reporting | Avoid misreading low coverage as product failure | Evidence semantics clarity | Better auditor/operator alignment, lower support churn | `E4/S4.1`, `E4/S4.2` |
| R5 | Expand security policy doc | Improve external trust and vuln handling clarity | OSS trust hardening | Better security posture signaling | `E5/S5.1` |

## Test Matrix Wiring
- Fast lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
  - `scripts/validate_scenarios.sh`
  - Pin-drift checker script wired in fast lane.
- Core CI lane:
  - `core-matrix` workflow jobs on Linux/macOS/Windows.
  - Build + core tests must remain green.
- Acceptance lane:
  - `make test-integration`
  - `make test-e2e`
  - `scripts/validate_contracts.sh`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `scripts/run_v1_acceptance.sh --mode=main`
- Cross-platform lane:
  - `windows-smoke` plus matrix OS lanes in CI.
- Risk lane:
  - `make test-risk-lane`
  - `make codeql`
  - `wrkr verify --chain --json` on fixture state.
- Merge/release gating rule:
  - Merge allowed only when fast/core/acceptance/cross-platform/risk lanes pass and no exit-code/schema contract regressions are detected.

## Epic E1: Toolchain Contract Integrity (P1)
Objective:
- Eliminate standards-to-CI version drift and add durable prevention.

### Story S1.1: Align PR workflow tool versions with standards
Priority:
- P1
Tasks:
- Update `/Users/davidahmann/Projects/wrkr/.github/workflows/pr.yml` tool install versions to match `/Users/davidahmann/Projects/wrkr/product/dev_guides.md` for:
  - `gosec`
  - `golangci-lint`
- Validate no `@latest` remains in governance-critical installs.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/.github/workflows/pr.yml`
- `/Users/davidahmann/Projects/wrkr/product/dev_guides.md`
Run commands:
- `make lint-fast`
- `make test-fast`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- CI/workflow contract checks for exact versions.
- Deterministic pipeline verification (repeatable results).
Matrix wiring:
- Fast lane, Core CI lane, Risk lane.
Acceptance criteria:
- `pr.yml` versions for `gosec` and `golangci-lint` match `dev_guides.md` exactly.
- `make prepush-full` passes.
Dependencies:
- None.
Risks:
- Version bump can introduce lint/security delta; mitigate with controlled update and contract tests.

### Story S1.2: Add anti-drift pin checker in fast lane
Priority:
- P1
Tasks:
- Extend `/Users/davidahmann/Projects/wrkr/scripts/check_toolchain_pins.sh` (or add a dedicated script) to compare:
  - Normative pin table in `product/dev_guides.md`
  - Enforced versions in `/.github/workflows/*.yml` and Makefile-related invocations
- Wire script into `lint-fast` in `/Users/davidahmann/Projects/wrkr/Makefile`.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/scripts/check_toolchain_pins.sh`
- `/Users/davidahmann/Projects/wrkr/Makefile`
- `/Users/davidahmann/Projects/wrkr/.github/workflows/pr.yml`
Run commands:
- `make lint-fast`
- `make prepush`
- `make prepush-full`
Test requirements:
- Contract test for checker failure on mismatch and success on aligned pins.
- CI lane enforcement test (script runs in fast lane).
Matrix wiring:
- Fast lane, Core CI lane.
Acceptance criteria:
- Mismatched pin fixture causes non-zero failure with deterministic error message.
- Aligned pins pass in local and CI fast lane.
Dependencies:
- `S1.1` preferred first.

### Story S1.3: Document pin contract and owner workflow
Priority:
- P2
Tasks:
- Add concise maintenance note in `product/dev_guides.md` or docs section describing “how to update pinned tools safely”.
- Include rule that docs and workflows must be updated atomically.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/product/dev_guides.md`
- `/Users/davidahmann/Projects/wrkr/docs/` (if needed)
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
Test requirements:
- Docs consistency checks.
Matrix wiring:
- Fast lane, Acceptance lane.
Acceptance criteria:
- Policy update procedure is explicit, deterministic, and references enforcement script.
Dependencies:
- `S1.2`.

## Epic E2: CLI Help Exit-Code Contract Normalization (P2)
Objective:
- Make help behavior consistent and test-enforced across all subcommands.

### Story S2.1: Normalize subcommand help exit to success
Priority:
- P2
Tasks:
- Update subcommand handlers under `/Users/davidahmann/Projects/wrkr/core/cli/` to return `0` on `flag.ErrHelp`.
- Ensure no regression in machine-readable errors for true invalid input.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/cli/*.go`
Run commands:
- `go test ./core/cli -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `make test-contracts`
Test requirements:
- CLI behavior tests:
  - help/usage tests
  - exit-code contract tests
  - `--json` stability on error paths
Matrix wiring:
- Fast lane, Core CI lane, Acceptance lane.
Acceptance criteria:
- Every `wrkr <command> --help` returns exit `0`.
- Invalid input still returns deterministic non-zero error envelopes.
Dependencies:
- None.
Risks:
- Over-broad handling of parse errors; mitigate by explicit `flag.ErrHelp` branching only.

### Story S2.2: Add explicit help contract coverage matrix
Priority:
- P2
Tasks:
- Add or extend tests for at least: `scan`, `evidence`, `regress run`, `report`, `verify`, `fix`, `lifecycle`, `init` help flags.
- Add regression guard for root vs subcommand parity.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/cli/root_test.go`
- `/Users/davidahmann/Projects/wrkr/internal/e2e/cli_contract/`
Run commands:
- `go test ./core/cli -run Help -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `make prepush-full`
Test requirements:
- Exit-code contract tests.
- CLI usage stability tests.
Matrix wiring:
- Fast lane, Core CI lane, Acceptance lane.
Acceptance criteria:
- Help contract test suite fails if any subcommand help returns non-zero.
Dependencies:
- `S2.1`.

## Epic E3: Maturity/Status Messaging Accuracy (P2)
Objective:
- Align external status claims with current implementation and coverage reality.

### Story S3.1: Refresh README status and maturity wording
Priority:
- P2
Tasks:
- Update stale status text in `/Users/davidahmann/Projects/wrkr/README.md`.
- Reflect current acceptance/scenario coverage and shipped scope accurately without overstating.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/README.md`
- `/Users/davidahmann/Projects/wrkr/internal/acceptance/v1_acceptance_test.go`
- `/Users/davidahmann/Projects/wrkr/internal/scenarios/coverage_map.json`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
Test requirements:
- Docs consistency and storyline checks.
- Contract that README examples still align with CLI flags.
Matrix wiring:
- Fast lane, Acceptance lane.
Acceptance criteria:
- README status section matches implemented scope and test coverage references.
Dependencies:
- None.

## Epic E4: Compliance Coverage Semantics Clarity (P2)
Objective:
- Make evidence coverage interpretation explicit for operators, auditors, and sponsors.

### Story S4.1: Clarify evidence coverage semantics in command docs/playbooks
Priority:
- P2
Tasks:
- Update `/Users/davidahmann/Projects/wrkr/docs/commands/evidence.md` and `/Users/davidahmann/Projects/wrkr/docs/examples/operator-playbooks.md` to state:
  - Coverage is measured against available scanned proof/evidence in current state.
  - Low/0% coverage indicates documented control gaps, not scanner feature absence.
  - Include recommended next operator actions when coverage is low.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/docs/commands/evidence.md`
- `/Users/davidahmann/Projects/wrkr/docs/examples/operator-playbooks.md`
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
Test requirements:
- Docs consistency and flow-smoke checks.
Matrix wiring:
- Fast lane, Acceptance lane.
Acceptance criteria:
- Docs explicitly define coverage semantics and remediation flow.
Dependencies:
- None.

### Story S4.2: Optional report wording refinement for low coverage context
Priority:
- P2
Tasks:
- Adjust report summary phrasing in `/Users/davidahmann/Projects/wrkr/core/report/` templates to avoid ambiguity about coverage interpretation.
- Keep deterministic output structure stable.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/report/`
- `/Users/davidahmann/Projects/wrkr/docs/commands/report.md`
Run commands:
- `go test ./core/report -count=1`
- `go test ./core/cli -run Report -count=1`
- `make test-contracts`
Test requirements:
- Determinism/golden stability tests for report outputs.
- CLI JSON shape stability tests.
Matrix wiring:
- Fast lane, Core CI lane, Risk lane.
Acceptance criteria:
- Report output remains deterministic and clarifies coverage as evidence-state signal.
Dependencies:
- `S4.1` preferred first.
Risks:
- Wording change could break golden tests; mitigate with explicit fixture updates and contract assertions.

## Epic E5: Security Policy Trust Hardening (P2-optional)
Objective:
- Improve external vulnerability reporting clarity and response expectations.

### Story S5.1: Expand SECURITY.md policy
Priority:
- P2
Tasks:
- Expand `/Users/davidahmann/Projects/wrkr/SECURITY.md` with:
  - Private report channel and required fields
  - Triage acknowledgment and response expectations
  - Supported branches/versions for fixes
  - Disclosure coordination expectations
- Keep concise and OSS-appropriate.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/SECURITY.md`
- `/Users/davidahmann/Projects/wrkr/README.md` (optional link enhancement)
Run commands:
- `make test-docs-consistency`
- `make test-docs-storyline`
Test requirements:
- Docs consistency and smoke checks.
Matrix wiring:
- Fast lane, Acceptance lane.
Acceptance criteria:
- External users can follow clear private reporting path and understand expected handling timelines.
Dependencies:
- None.

## Minimum-Now Sequence
1. `E1/S1.1` -> `E1/S1.2` -> `E1/S1.3`
2. `E2/S2.1` -> `E2/S2.2`
3. `E3/S3.1`
4. `E4/S4.1` -> `E4/S4.2`
5. `E5/S5.1`

Implementation checkpoints:
- After each epic: run `make prepush-full`.
- After `E2`: run focused CLI contract subset plus `make test-contracts`.
- After docs epics (`E3-E5`): run docs consistency + storyline smoke.

## Explicit Non-Goals
- No implementation of dashboard/SaaS capabilities.
- No expansion of detector scope beyond audit-gap closures.
- No schema-breaking changes to existing CLI JSON envelopes.
- No exit-code remapping except help-contract normalization to success on help-only paths.

## Definition of Done
- Every recommendation (`R1-R5`) is fully mapped and delivered through accepted stories.
- All updated contracts are deterministic and test-enforced.
- `make prepush-full` passes on final integrated branch.
- Docs and workflows are synchronized with normative standards.
- CLI help behavior is consistent and verified by tests.
- Evidence/report wording prevents misinterpretation of framework coverage percentages.
- Security reporting policy is actionable for external reporters.

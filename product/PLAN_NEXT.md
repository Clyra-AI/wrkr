# PLAN Adhoc: hosted acquisition resilience, mixed-scope scan targets, and govern-first actionability

Date: 2026-04-13
Source of truth:
- user-provided recommendations in this run
- user-provided nightly `govulncheck` failure for `GO-2026-4947`, `GO-2026-4946`, `GO-2026-4870`, and `GO-2026-4866`
- `product/dev_guides.md`
- `product/architecture_guides.md`
Scope: Restore nightly security gating, harden hosted GitHub org acquisition against 403 rate limiting, add one-run mixed remote/local scan targeting, and sharpen govern-first path ranking/reporting without weakening determinism, fail-closed behavior, or existing single-target scan workflows.

## Global Decisions (Locked)

- Treat the nightly `govulncheck` break as Wave 1 remediation. The first fully fixed Go floor for this repo is `1.26.2`, so the uplift is atomic across runtime, CI, docs, and enforcement surfaces.
- Preserve exit code integers exactly as documented. Where rate limiting needs a sharper machine-readable contract, change the JSON error `code` and message contract without inventing a new numeric exit code.
- Add mixed-scope scans as an additive `scan --target <mode>:<value>` surface where `<mode>` is one of `repo`, `org`, `path`, or `my_setup`.
- Keep legacy single-target flags (`--repo`, `--org`, `--github-org`, `--path`, `--my-setup`) as supported shims that internally expand to a one-entry target set.
- Keep `wrkr init` and persisted `config.default_target` single-target in this plan. Multi-target defaults are explicitly deferred to avoid widening the config contract while the new scan target-set API settles.
- For multi-target scan JSON/state/source manifests, add an additive `targets[]` array and use `target.mode=multi` only when more than one explicit target is requested. Existing single-target runs keep the current `target` shape unchanged.
- `--resume` remains fail-closed and deterministic. In this plan it is supported only when every requested target is an org target; mixed target sets with `--resume` must return `invalid_input`.
- Rate-limit handling must be driven by observed status/body/header evidence, not guessed public/private repo assumptions. If GitHub returns a recognizable rate-limit `403`, Wrkr should retry from `Retry-After` or `X-RateLimit-Reset` when present and surface the observed basis clearly when retries are exhausted.
- Govern-first output should prefer the strongest operator action path available: write-capable, deploy-write, production-target-backed, identity-backed, and approval-gap-backed paths headline first; weaker non-write paths remain visible but do not displace stronger paths.
- Workflow trigger exposure remains a static posture statement only. New output may say `scheduled`, `workflow_dispatch`, or deploy-pipeline backed, but must not imply runtime observation or session capture.

## Current Baseline (Observed)

- `core/source/github/connector.go` retries `429` and `5xx` responses, honors `Retry-After` and `X-RateLimit-Reset`, but currently treats recognizable rate-limit `403` responses as non-retryable hard failures.
- `core/cli/scan.go` appends auth guidance when the hosted failure string contains `github API status 403` plus `rate limit`, but the JSON error code remains the generic `runtime_failure`.
- `core/cli/scan_helpers.go` still enforces exactly one target source (`--repo`, `--org`, `--github-org`, `--path`, or `--my-setup`) per scan invocation.
- Local path scans already cover multiple repos beneath one filesystem root, but Wrkr cannot yet combine multiple orgs, multiple local roots, or mixed remote and local targets in one deterministic scan/proof run.
- `core/detect/workflowcap/analyze.go` already derives `workflow_triggers`, `approval_source`, `deployment_gate`, and `proof_requirement`, and `core/aggregate/privilegebudget/budget.go` already turns those into approval-gap reasons, but `core/report/build.go` and govern-first summaries do not headline trigger class or ownership quality strongly enough.
- `core/risk/action_paths.go` already emits the stable `recommended_action` enum `inventory|approval|proof|control`, and synthetic tests prove all four values are reachable, but the user-observed real subset scan still collapses too many serious paths to `proof`.
- `core/owners/owners.go` currently resolves `CODEOWNERS` first and falls back deterministically to repo-derived ownership, but unresolved/conflict ownership is not yet weighted strongly enough in top govern-first path selection or report wording.
- `.github/workflows/nightly.yml`, `.tool-versions`, `go.mod`, `scripts/check_toolchain_pins.sh`, and contract tests are still pinned to `Go 1.26.1`; the provided nightly failure says called stdlib vulnerabilities are fixed in `Go 1.26.2`.

## Exit Criteria

- The nightly workflow and local binary-mode `govulncheck` are green under `Go 1.26.2`, and no `1.26.1` pin remains on enforced surfaces.
- Hosted repo/org acquisition retries recognizable rate-limit `403` and `429` responses deterministically, reports retry/cooldown progress, and emits a sharper machine-readable exhausted-rate-limit error contract when retries are spent.
- One `wrkr scan` invocation can combine multiple org and local targets deterministically in one output/proof run via additive target-set syntax, while single-target legacy flows keep working unchanged.
- Multi-target state/source manifest/report payloads expose deterministic additive `targets[]` data, and `--resume` behavior is explicit, safe, and contract-tested.
- Govern-first ranking selects the strongest alarming path first when stronger write/deploy/production/identity/approval-backed candidates exist.
- `recommended_action` meaningfully separates visibility gaps, approval gaps, proof gaps, and urgent control-first paths on realistic scan fixtures, not just synthetic unit cases.
- Reports and markdown summaries surface trigger class, identity, and ownership quality when those signals materially change governance priority.
- Validation passes on all mapped lanes:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
  - `make test-scenarios`
  - `make prepush-full`
  - `make test-hardening`
  - `make test-chaos`
  - `make test-perf`
  - `make codeql`
  - `go build -o .tmp/wrkr ./cmd/wrkr`
  - `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -mode=binary .tmp/wrkr`
  - rerun of the previously failing `nightly` workflow lane

## Public API and Contract Map

- Stable surfaces:
  - existing single-target scan flags: `--repo`, `--org`, `--github-org`, `--path`, `--my-setup`
  - existing exit code integers `0..8`
  - existing `recommended_action` enum values: `inventory|approval|proof|control`
  - existing single-target JSON/state/source-manifest `target` object shape
  - existing proof, lifecycle, and compliance artifact locations and chain behavior
- Additive stable surfaces introduced by this plan:
  - repeatable `--target <mode>:<value>` for `scan`
  - additive `targets[]` in scan payload, state snapshot, and source manifest
  - additive `target.mode=multi` only for explicit multi-target runs
  - additive rate-limit-specific JSON error `code=rate_limited` with exit code `1`
  - additive trigger-class/report facts for workflow-backed govern-first paths and exposure groups
- Internal surfaces:
  - GitHub connector retry classification logic
  - checkpoint file layout and target-set resume bookkeeping
  - govern-first ranking weights and report fact selection heuristics
  - detector correlation internals for non-human identity matching
- Shim/deprecation path:
  - legacy single-target flags remain first-class and internally map to a one-entry target set
  - `config.default_target` remains single-target; no config migration is introduced in this plan
  - no deprecation warning is added yet for single-target flags
- Schema/versioning policy:
  - remain on `state`/scan schema `v1`
  - only additive fields/values are allowed in this plan
  - single-target outputs remain byte-compatible aside from intentional Go/toolchain version fields
  - multi-target is opt-in and requires consumers to read `targets[]` when `target.mode=multi`
- Machine-readable error expectations:
  - missing hosted acquisition prerequisite: `dependency_missing`, exit `7`
  - exhausted hosted rate limit after bounded retry: `rate_limited`, exit `1`
  - unsupported `--resume` plus non-org target-set mix: `invalid_input`, exit `6`
  - non-rate-limit upstream failures: `runtime_failure`, exit `1`
  - no change to `policy_schema_violation`, `unsafe_operation_blocked`, `scan_timeout`, or `scan_canceled`

## Docs and OSS Readiness Baseline

- `README.md` and `docs/commands/scan.md` must become the source-of-truth entry points for the additive multi-target scan contract and hosted rate-limit behavior.
- `docs/commands/init.md` must explicitly state that `init` still persists one default target in this wave and that multi-target scans are driven by explicit `scan --target ...` flags.
- `product/wrkr.md` must stop claiming strict mutual exclusivity across scan target sources once the additive target-set contract ships.
- `CHANGELOG.md` must record:
  - the Go `1.26.2` security uplift
  - hosted scan rate-limit resilience/error contract updates
  - additive multi-target scan support
  - govern-first/reporting actionability improvements
- OSS trust surfaces to verify after the change:
  - `README.md`
  - `CHANGELOG.md`
  - `CONTRIBUTING.md`
  - `SECURITY.md`
- Docs must keep integration-before-internals order:
  - first explain how to run a mixed target scan
  - then explain JSON/state/report contract additions
  - then explain resume and rate-limit behavior

## Recommendation Traceability

| Recommendation | Why | Story IDs |
|---|---|---|
| Retry and classify enterprise-scale `403` GitHub rate limiting and surface the right error code | Hosted org scans currently fail too generically and do not treat recognizable `403` throttles as retryable | W1-S2, W1-S3 |
| Support one-run org, multi-org, remote, and local scans | Scan still enforces one target source per invocation | W2-S1, W2-S2, W2-S3 |
| Bias govern-first ranking toward actually alarming paths | Top path still over-selects weaker non-write surfaces when stronger write/deploy paths exist | W4-S1 |
| Make `recommended_action` meaningfully discriminate `inventory|approval|proof|control` | Real scans still flatten serious paths into `proof` too often | W4-S2 |
| Improve identity and ownership actionability | Governance wedge is stronger when path identity and ownership strength are explicit | W3-S1 |
| Surface long-running workflow trigger class explicitly | Trigger posture exists internally but is not visible enough in summaries | W3-S2 |
| Fix nightly security failure from vulnerable stdlib floor | Nightly `govulncheck` remains red until Go is lifted to the first fully fixed version | W1-S1 |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - focused package tests for touched code
  - `go build -o .tmp/wrkr ./cmd/wrkr`
- Core CI lane:
  - `make prepush`
  - `make test-contracts`
  - `make test-scenarios`
- Acceptance lane:
  - `scripts/run_v1_acceptance.sh --mode=local`
  - scenario fixtures covering hosted rate-limit recovery, additive target sets, and govern-first report output
- Cross-platform lane:
  - existing `windows-smoke` required check
  - deterministic scan contract tests that do not assume POSIX-only path behavior
- Risk lane:
  - `make prepush-full`
  - `make test-hardening`
  - `make test-chaos`
  - `make test-perf`
  - `make codeql`
  - `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -mode=binary .tmp/wrkr`
- Merge/release gating rule:
  - every story’s mapped lanes must be green
  - no multi-target schema or error-contract change merges without updated docs and contract tests
  - the previously failing `nightly` lane must be rerun and green before closing Wave 1

## Epic W1: Nightly Security and Hosted Acquisition Hard Blockers

Objective: clear the nightly vulnerability gate first, then harden hosted GitHub acquisition so large-org scans survive recognizable throttling without weakening fail-closed semantics.

### Story W1-S1: Apply atomic Go 1.26.2 uplift and rerun the nightly vuln gate

Priority: P0
Tasks:
- Update all enforced Go pin surfaces from `1.26.1` to `1.26.2`.
- Update CI workflows, local toolchain files, docs, and enforcement tests in the same branch.
- Rebuild the CLI and rerun binary-mode `govulncheck`.
- Rerun the previously failing `nightly` workflow lane after the uplift lands.
Repo paths:
- `go.mod`
- `.tool-versions`
- `.github/workflows/main.yml`
- `.github/workflows/pr.yml`
- `.github/workflows/release.yml`
- `.github/workflows/nightly.yml`
- `.github/workflows/wrkr-action-ci.yml`
- `.github/workflows/wrkr-sarif.yml`
- `scripts/check_toolchain_pins.sh`
- `testinfra/hygiene/toolchain_pins_test.go`
- `testinfra/contracts/story0_contracts_test.go`
- `CONTRIBUTING.md`
- `README.md`
- `product/dev_guides.md`
- `CHANGELOG.md`
Run commands:
- `rg -n '1\\.26\\.1|1\\.26\\.2|go-version:|go-version-file:' go.mod .tool-versions .github/workflows scripts testinfra README.md CONTRIBUTING.md product`
- `go build -o .tmp/wrkr ./cmd/wrkr`
- `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -mode=binary .tmp/wrkr`
- `make lint-fast`
- `make test-contracts`
- `gh workflow run nightly.yml --ref <branch>`
Test requirements:
- Toolchain/runtime/security scanner changes:
  - atomic pin updates across `go.mod`, local toolchain files, CI, docs, and enforcement tests
  - built-artifact validation with `govulncheck -mode=binary`
  - rerun of the previously failing workflow lane
- Docs/examples changes:
  - docs consistency checks for touched version declarations
Matrix wiring:
- Fast lane: `make lint-fast`, focused toolchain pin tests, build
- Core CI lane: `make test-contracts`
- Acceptance lane: not required beyond plan-level acceptance because behavior is unchanged
- Cross-platform lane: existing workflow matrix after pin uplift
- Risk lane: `govulncheck`, `make codeql`, rerun `nightly`
Acceptance criteria:
- No enforced pin surface remains on `1.26.1`.
- Local binary `govulncheck` reports no called stdlib vulnerabilities from the provided nightly failure set.
- The rerun `nightly` workflow is green on the uplift branch.
- CLI behavior, JSON output, schemas, and exit codes remain unchanged apart from updated version/toolchain references.
Changelog impact: required
Changelog section: Security
Draft changelog entry: Raised Wrkr's enforced Go toolchain floor to 1.26.2 across local, CI, and nightly scanner surfaces to clear called standard-library vulnerabilities flagged by nightly `govulncheck`.
Semver marker override: none
Contract/API impact:
- Developer and CI minimum Go version moves to `1.26.2`.
- Runtime CLI, JSON, and exit-code contracts remain unchanged.
Versioning/migration impact:
- No schema migration.
- Contributors and automation must use `Go 1.26.2`.
Architecture constraints:
- Treat the pin change as an atomic contract update.
- Do not weaken or bypass `govulncheck`.
- Keep the change thin; no unrelated dependency churn.
ADR required: no
TDD first failing test(s):
- Pin-enforcement tests in `testinfra/hygiene/toolchain_pins_test.go`
- branch/toolchain contract tests in `testinfra/contracts/story0_contracts_test.go`
Cost/perf impact: low
Chaos/failure hypothesis:
- If one enforced pin surface stays on `1.26.1`, nightly or contributor environments drift and the security lane remains red.

### Story W1-S2: Recognize and retry rate-limit `403` responses during hosted acquisition

Priority: P0
Tasks:
- Extend GitHub connector retry classification so recognizable rate-limit `403` responses are treated like throttling, not permanent failures.
- Reuse `Retry-After` and `X-RateLimit-Reset` parsing for both `429` and recognized `403` throttles.
- Keep header/body detection evidence-based so Wrkr does not guess public/private rate-limit class incorrectly.
- Thread status code and retry delay through org progress output for recognizable `403` retries.
Repo paths:
- `core/source/github/connector.go`
- `core/source/github/connector_test.go`
- `core/cli/scan_helpers.go`
- `core/cli/scan_progress.go`
- `core/cli/scan_progress_test.go`
- `docs/commands/scan.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/source/github ./core/cli -count=1`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- Gate/policy/fail-closed changes:
  - deterministic allow/block/retry fixtures for recognizable `403` rate-limit bodies/headers
  - fail-closed tests for non-rate-limit `403` responses so auth and permission failures do not retry
- Job runtime/state/concurrency changes:
  - retry/backoff tests
  - contention-free progress emission tests
  - chaos coverage for exhausted rate-limit windows and canceled sleeps
Matrix wiring:
- Fast lane: focused connector and CLI unit tests
- Core CI lane: `make prepush-full`
- Acceptance lane: scenario or integration fixture for org acquisition with `403` throttle recovery
- Cross-platform lane: CLI progress/error tests remain platform-neutral
- Risk lane: `make test-hardening`, `make test-chaos`
Acceptance criteria:
- Recognizable GitHub rate-limit `403` responses retry using observed `Retry-After` or `X-RateLimit-Reset` when present.
- Non-rate-limit `403` responses still fail immediately without retry.
- Org progress output shows retry attempts for recognized `403` throttles just as it does for `429`.
- Retry behavior remains deterministic and bounded.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Hosted GitHub scans now retry recognizable rate-limit `403` responses using the observed reset window instead of failing immediately as generic runtime errors.
Semver marker override: none
Contract/API impact:
- Hosted acquisition retry semantics expand to cover recognized `403` throttles.
- Exit code integers remain unchanged.
Versioning/migration impact:
- No schema migration.
- Operators may now see successful recovery where the same scan previously failed fast on `403` throttling.
Architecture constraints:
- Keep retry classification inside the hosted source boundary.
- Do not let rate-limit retries mask true authz/authn failures.
- Preserve cancellation/timeout propagation through sleeps and retries.
ADR required: no
TDD first failing test(s):
- `TestConnectorHonorsRetryAfter429` companion tests for rate-limit `403`
- CLI progress tests covering `status=403` retry lines
Cost/perf impact: low
Chaos/failure hypothesis:
- If `403` classification is too broad, Wrkr could spin on permanent auth failures; if too narrow, enterprise-scale org scans still fail on recoverable throttles.

### Story W1-S3: Emit a deterministic exhausted-rate-limit error contract for hosted scans

Priority: P0
Tasks:
- Change exhausted hosted rate-limit failures from generic `runtime_failure` to a specific JSON error code while preserving exit code `1`.
- Make the error message include observed status, retry exhaustion context, and actionable auth/reset guidance.
- Update docs and CLI contract tests for the new machine-readable error code and unchanged numeric exit behavior.
- Ensure per-repo materialization failures and whole-scan acquisition failures remain distinguishable.
Repo paths:
- `core/cli/scan.go`
- `core/cli/root.go`
- `core/cli/scan_github_auth_test.go`
- `core/cli/root_test.go`
- `docs/commands/scan.md`
- `product/architecture_guides.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/cli -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- CLI behavior changes:
  - `--json` stability tests
  - exit-code contract tests
  - machine-readable error envelope tests
- API/contract lifecycle changes:
  - public error-code map updates
  - migration expectation checks for automation consuming hosted scan failures
Matrix wiring:
- Fast lane: focused CLI unit/contract tests
- Core CI lane: `make test-contracts`, `make prepush-full`
- Acceptance lane: hosted-scan failure fixture asserting `error.code=rate_limited`
- Cross-platform lane: JSON envelope tests
- Risk lane: included in `make prepush-full`
Acceptance criteria:
- Exhausted hosted throttling emits `error.code=rate_limited` with exit code `1`.
- Missing hosted prerequisites still emit `dependency_missing` with exit code `7`.
- Non-rate-limit upstream failures still emit `runtime_failure`.
- Docs explicitly describe the new hosted rate-limit error contract.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Hosted GitHub scans now emit a dedicated `rate_limited` JSON error code after bounded retry exhaustion while keeping the documented runtime exit code unchanged.
Semver marker override: none
Contract/API impact:
- JSON error code contract changes for one hosted failure class.
- Numeric exit code remains `1`.
Versioning/migration impact:
- Additive contract tightening within schema `v1`; automation that keys on JSON error codes must accept `rate_limited` for hosted throttling.
Architecture constraints:
- Keep error specialization at the CLI boundary.
- Do not widen the generic error envelope shape in this wave.
ADR required: no
TDD first failing test(s):
- existing hosted rate-limit auth test updated from `runtime_failure` to `rate_limited`
- root-level JSON error envelope tests for exit-code stability
Cost/perf impact: low
Chaos/failure hypothesis:
- If the specialized error contract is inconsistent, automation will not know whether to retry, wait, or fail closed.

## Epic W2: Mixed-Scope Scan Target Sets

Objective: let one deterministic scan/proof run cover multiple orgs and local roots without collapsing boundaries, breaking single-target flows, or inventing unsafe resume semantics.

### Story W2-S1: Add an additive `scan --target` contract and multi-target schema surfaces

Priority: P0
Tasks:
- Add repeatable `--target <mode>:<value>` parsing to `scan`.
- Keep legacy single-target flags supported as shims and reject mixed legacy-plus-`--target` ambiguity deterministically.
- Add additive `targets[]` to scan payload, source manifest, and state snapshot.
- Define `target.mode=multi` for explicit multi-target runs while preserving the existing single-target shape.
- Update docs and contract tests for the new CLI and payload surfaces.
Repo paths:
- `core/cli/scan.go`
- `core/cli/scan_helpers.go`
- `core/source/types.go`
- `core/state/state.go`
- `core/state/state_test.go`
- `core/cli/root_test.go`
- `docs/commands/scan.md`
- `README.md`
- `product/wrkr.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/cli ./core/state -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Schema/artifact changes:
  - state/scan payload fixture updates
  - compatibility tests for existing single-target snapshots
- CLI behavior changes:
  - help/usage tests
  - `--json` stability tests
  - invalid-input tests for ambiguous target combinations
- API/contract lifecycle changes:
  - public API map updates for additive `targets[]`
Matrix wiring:
- Fast lane: focused CLI/state tests
- Core CI lane: `make test-contracts`, `make prepush-full`
- Acceptance lane: end-to-end scan payload assertion for `--target` runs
- Cross-platform lane: target parsing and JSON/state tests
- Risk lane: included in `make prepush-full`
Acceptance criteria:
- `wrkr scan --target org:acme --target path:./repos --json` is accepted.
- Legacy single-target flags still behave exactly as they do today when used alone.
- Ambiguous combinations like `--repo ... --target ...` fail closed with `invalid_input`.
- Single-target JSON/state outputs keep existing `target` behavior; explicit multi-target runs also emit deterministic `targets[]`.
Changelog impact: required
Changelog section: Added
Draft changelog entry: Added repeatable `wrkr scan --target <mode>:<value>` support so one scan can combine multiple hosted and local targets while preserving legacy single-target flags.
Semver marker override: none
Contract/API impact:
- Adds a new CLI flag family and additive payload/state fields.
- Keeps existing single-target flags and payloads stable.
Versioning/migration impact:
- No schema version bump; `targets[]` is additive.
- Consumers that invoke multi-target scans must read `targets[]` when `target.mode=multi`.
Architecture constraints:
- Keep target parsing/orchestration thin in `core/cli`.
- Do not widen persisted config scope in this wave.
- Preserve explicit side-effect semantics between parsing and acquisition.
ADR required: yes
TDD first failing test(s):
- CLI parsing tests for repeatable `--target`
- state snapshot compatibility tests proving old single-target fixtures still load
Cost/perf impact: low
Chaos/failure hypothesis:
- If multi-target state/schema is underspecified, downstream diff/report/proof consumers will see unstable target identity and drift noise.

### Story W2-S2: Implement deterministic acquisition and de-duplication across mixed target sets

Priority: P0
Tasks:
- Introduce a target-set acquisition path that executes multiple repo/org/path/my-setup targets in deterministic order.
- De-duplicate discovered repos deterministically when the same repo is reached from multiple targets.
- Keep materialized hosted repos inside managed roots and preserve local path semantics for pre-cloned repos.
- Carry per-target source failures into one manifest without hiding partial results.
- Add realistic mixed-target scenarios for remote-plus-local scan coverage.
Repo paths:
- `core/cli/scan_helpers.go`
- `core/source/github/connector.go`
- `core/source/org/acquire.go`
- `core/source/org/materialized.go`
- `core/source/local`
- `core/source/types.go`
- `core/cli/scan_progress.go`
- `core/cli/scan_progress_test.go`
- `core/cli/root_test.go`
- `scenarios/wrkr/multi-target-mixed-sources/**`
- `internal/scenarios/**`
- `CHANGELOG.md`
Run commands:
- `go test ./core/source/... ./core/cli -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go build -o .tmp/wrkr ./cmd/wrkr`
- `./.tmp/wrkr scan --target org:acme --target org:enterprise-example --target path:./scenarios/wrkr/scan-mixed-org/repos --state ./.tmp/multi-target.json --json`
- `make prepush-full`
- `make test-perf`
Test requirements:
- Job runtime/state/concurrency changes:
  - deterministic ordering tests across mixed target sets
  - duplicate-repo collapse tests
  - crash-safe/atomic-write tests for one output snapshot from many targets
- Scenario/spec tests:
  - mixed remote/local outside-in fixtures
  - partial-result/fail-closed behavior when one hosted target degrades
- Determinism/hash/sign/packaging changes:
  - repeat-run byte-stability checks for identical multi-target input sets
Matrix wiring:
- Fast lane: focused source and CLI tests
- Core CI lane: `make prepush-full`
- Acceptance lane: new multi-target scenario suite plus `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane: build and scan contract tests using portable fixture paths
- Risk lane: `make test-perf`
Acceptance criteria:
- One scan run can combine multiple org targets and at least one local path target.
- Duplicate repos discovered through overlapping targets appear once in deterministic order.
- Output proof/state/report generation still happens as one transactional generation.
- Partial-result behavior remains explicit when one target degrades without invalidating the whole scan.
Changelog impact: required
Changelog section: Added
Draft changelog entry: Wrkr can now scan multiple hosted orgs and local repository roots in one deterministic run, producing a single proof/state/report generation with explicit per-target failures when needed.
Semver marker override: none
Contract/API impact:
- Additive multi-target execution behavior for `scan`.
- Existing single-target source manifest semantics remain intact.
Versioning/migration impact:
- No schema bump beyond additive `targets[]`.
- New multi-target scenarios become part of acceptance evidence.
Architecture constraints:
- Keep source acquisition boundaries explicit; do not leak target-set orchestration into detectors or risk scoring.
- Preserve cancellation and timeout propagation across the target fan-out.
- Avoid hidden concurrency that would make repo ordering nondeterministic.
ADR required: no
TDD first failing test(s):
- mixed-target acquisition tests in `core/cli/root_test.go`
- target-set scenario fixtures under `internal/scenarios`
Cost/perf impact: medium
Chaos/failure hypothesis:
- If de-dup or ordering is unstable, repeated multi-target scans will drift even when source content has not changed.

### Story W2-S3: Add fail-closed multi-target progress and resume rules

Priority: P1
Tasks:
- Extend org progress reporting so target identity is visible when multiple orgs are in flight.
- Define and implement resume rules that permit `--resume` only for target sets composed entirely of org targets.
- Store checkpoint metadata per target set and validate trusted managed roots before reuse.
- Document unsupported target mixes for `--resume` explicitly.
Repo paths:
- `core/cli/scan_progress.go`
- `core/cli/scan_progress_test.go`
- `core/source/org/checkpoint.go`
- `core/source/org/checkpoint_test.go`
- `core/source/org/acquire_resume_test.go`
- `core/cli/scan.go`
- `docs/commands/scan.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/source/org ./core/cli -count=1`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`
Test requirements:
- CLI behavior changes:
  - progress contract tests for multi-org progress lines
  - invalid-input tests for unsupported `--resume` target mixes
- Gate/policy/fail-closed changes:
  - trusted-marker and checkpoint validation tests
  - fail-closed tests for stale or mismatched target-set checkpoints
- Job runtime/state/concurrency changes:
  - resume lifecycle tests
  - crash-safe checkpoint reuse tests
Matrix wiring:
- Fast lane: focused org checkpoint/progress tests
- Core CI lane: `make prepush-full`
- Acceptance lane: interrupted multi-org scan resume fixture
- Cross-platform lane: progress/error output contract tests
- Risk lane: `make test-hardening`, `make test-chaos`
Acceptance criteria:
- Multi-org progress lines identify the target org deterministically.
- `--resume` works for multi-org target sets when all targets are orgs and the checkpoint still matches.
- Mixed target sets with `--resume` fail closed with `invalid_input`.
- Checkpoint reuse never escapes the managed materialized root.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Multi-org scans now expose clearer per-target progress and fail-closed resume behavior, including explicit rejection of unsupported mixed-target resume combinations.
Semver marker override: none
Contract/API impact:
- Progress/output wording changes for multi-org scans.
- `--resume` validation contract becomes explicit for multi-target runs.
Versioning/migration impact:
- No schema migration.
- Operators must re-run mixed target scans from scratch if local and hosted targets are combined.
Architecture constraints:
- Keep checkpoint trust and resume rules in the source boundary.
- Do not introduce silent best-effort resume for unsupported mixes.
ADR required: no
TDD first failing test(s):
- new multi-org progress tests
- checkpoint validation tests for mismatched target sets
Cost/perf impact: low
Chaos/failure hypothesis:
- If resume rules are permissive, stale checkpoints can produce incomplete or misleading multi-target output.

## Epic W3: Identity, Ownership, and Workflow Posture Enrichment

Objective: improve the raw signals feeding govern-first decisions so Wrkr can say which durable identity is behind a risky path, who owns it, how strong that ownership is, and what static workflow posture makes the path long-running or deployment-sensitive.

### Story W3-S1: Strengthen workflow-backed identity correlation and ownership precedence

Priority: P0
Tasks:
- Expand workflow-backed non-human identity extraction so GitHub App, bot-user, and service-account hints correlate more reliably to privilege-map entries.
- Preserve stronger ownership evidence when multiple candidate owners exist and prefer explicit `CODEOWNERS` ownership over inferred fallback in merged summaries.
- Increase governance severity for unknown identity, unresolved ownership, and cross-repo ownership conflict cases.
- Update govern-first summary selection to reflect stronger explicit-owner versus weak-owner distinctions.
Repo paths:
- `core/detect/nonhumanidentity/detector.go`
- `core/detect/nonhumanidentity/detector_test.go`
- `core/owners/owners.go`
- `core/owners/owners_test.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/privilegebudget/budget_test.go`
- `core/risk/action_paths.go`
- `core/risk/govern_first.go`
- `core/risk/govern_first_test.go`
- `core/report/build.go`
- `core/report/report_test.go`
- `CHANGELOG.md`
Run commands:
- `go test ./core/detect/nonhumanidentity ./core/owners ./core/aggregate/privilegebudget ./core/risk ./core/report -count=1`
- `make prepush-full`
- `make test-hardening`
Test requirements:
- Unit:
  - detector correlation tests
  - owner resolution precedence tests
- Integration:
  - privilege-map to action-path ownership/identity propagation tests
- Scenario/spec tests:
  - realistic workflow-backed paths with explicit, inferred, unresolved, and conflicting ownership
Matrix wiring:
- Fast lane: focused package tests
- Core CI lane: `make prepush-full`
- Acceptance lane: realistic govern-first scenario fixture
- Cross-platform lane: standard Go tests
- Risk lane: `make test-hardening`
Acceptance criteria:
- Workflow-backed action paths surface the most specific known non-human identity available.
- Explicit ownership outranks fallback ownership in merged path summaries.
- Unknown identity and unresolved ownership materially raise govern-first pressure rather than being treated as neutral metadata.
- Reports identify when ownership is explicit, inferred, unresolved, or conflicting.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Govern-first summaries now highlight stronger workflow identity and ownership evidence, with unresolved or conflicting ownership treated as a higher-priority governance signal.
Semver marker override: none
Contract/API impact:
- Existing action-path/report fields keep the same names but their prioritization and wording become sharper.
Versioning/migration impact:
- No schema migration.
- Consumers should expect stronger differentiation among ownership and identity states in top summaries.
Architecture constraints:
- Keep detector parsing structured and static-only.
- Preserve source -> detection -> aggregation -> risk -> report boundaries.
- Avoid regex-only ownership or identity logic for structured workflow/config inputs.
ADR required: no
TDD first failing test(s):
- identity correlation unit tests for workflow-backed privilege entries
- owner precedence tests proving explicit beats fallback/conflict in merged action paths
Cost/perf impact: low
Chaos/failure hypothesis:
- If correlation gets stronger without deterministic precedence, the same path could oscillate between owners or identities across runs.

### Story W3-S2: Surface workflow trigger class and long-running deployment posture in action paths and reports

Priority: P1
Tasks:
- Normalize workflow trigger class for govern-first use, including `scheduled`, `workflow_dispatch`, and deploy-pipeline backed posture.
- Thread trigger/deployment posture into privilege-map-derived action paths and grouped exposure summaries.
- Update markdown/report summaries so top govern-first paths mention trigger class when it materially changes urgency.
- Keep the wording explicitly static and posture-based.
Repo paths:
- `core/detect/workflowcap/analyze.go`
- `core/detect/workflowcap/analyze_test.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/aggregate/inventory/privileges.go`
- `core/risk/action_paths.go`
- `core/risk/govern_first.go`
- `core/report/build.go`
- `core/report/render_markdown.go`
- `core/report/report_test.go`
- `docs/commands/scan.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/detect/workflowcap ./core/aggregate/privilegebudget ./core/risk ./core/report -count=1`
- `make prepush-full`
- `scripts/run_v1_acceptance.sh --mode=local`
Test requirements:
- Schema/artifact changes:
  - additive field tests if new trigger-class fields land in action paths/exposure groups
- CLI/report behavior changes:
  - markdown/report summary tests
  - `--json` stability tests for additive posture fields
- Scenario/spec tests:
  - scheduled/manual/deploy workflow fixtures
Matrix wiring:
- Fast lane: focused package tests
- Core CI lane: `make prepush-full`
- Acceptance lane: `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane: JSON/report rendering tests
- Risk lane: included in `make prepush-full`
Acceptance criteria:
- Workflow-backed action paths expose trigger class when it materially affects posture.
- Top report summaries and grouped exposures can say `scheduled`, `workflow_dispatch`, or deploy-pipeline backed without implying runtime observation.
- Existing approval/proof fields remain intact and deterministic.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Workflow-backed govern-first paths and summaries now expose static trigger posture such as scheduled, workflow-dispatch, and deploy-pipeline backed execution when it changes governance urgency.
Semver marker override: none
Contract/API impact:
- Additive action-path/report posture facts may appear in JSON and markdown output.
Versioning/migration impact:
- No schema version bump expected; treat any new trigger field as additive.
Architecture constraints:
- Keep trigger classification static-only.
- Reuse structured workflow parsing rather than brittle text matching.
ADR required: no
TDD first failing test(s):
- workflow capability tests for trigger normalization
- report rendering tests expecting trigger posture in top summaries
Cost/perf impact: low
Chaos/failure hypothesis:
- If trigger posture leaks runtime language, Wrkr will overclaim observation it does not have and weaken trust.

## Epic W4: Govern-First Ranking and Recommended Action Sharpness

Objective: take the enriched path signals and ensure the headline govern-first output points operators at the most urgent path first, while keeping non-write and proof-oriented paths visible in the ranked set.

### Story W4-S1: Reweight control-first path ranking toward alarming write and deployment paths

Priority: P0
Tasks:
- Revisit path ranking weights so write-capable, deploy-write, production-target-backed, identity-backed, and approval-gap-backed paths outrank weaker candidates when both exist.
- Preserve deterministic tie-breakers after the new weighting is applied.
- Keep weaker non-write paths in the ranked list and exposure groups instead of dropping them entirely.
- Update report assessment selection so `top_path_to_control_first` follows the stronger ranking.
Repo paths:
- `core/risk/action_paths.go`
- `core/risk/risk.go`
- `core/risk/govern_first.go`
- `core/risk/action_paths_test.go`
- `core/risk/risk_test.go`
- `core/report/build.go`
- `core/report/report_test.go`
- `CHANGELOG.md`
Run commands:
- `go test ./core/risk ./core/report -count=1`
- `make prepush-full`
- `make test-hardening`
- `make test-perf`
Test requirements:
- Unit:
  - control-first ordering tests using stronger write/deploy/production cases
- Integration:
  - deterministic ranking tests across mixed weak/strong candidates
- Scenario/spec tests:
  - realistic subset fixtures proving stronger paths headline first
- Determinism/hash/sign/packaging changes:
  - byte-stable report/action-path ordering checks
Matrix wiring:
- Fast lane: focused risk/report tests
- Core CI lane: `make prepush-full`
- Acceptance lane: realistic govern-first subset scenario
- Cross-platform lane: deterministic ordering tests
- Risk lane: `make test-hardening`, `make test-perf`
Acceptance criteria:
- When stronger write/deploy/production/identity/approval-backed paths exist, `top_path_to_control_first` selects one of them ahead of weaker non-write paths.
- Non-write paths still appear in ranked govern-first output when relevant.
- Ordering remains deterministic under ties and repeat runs.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: Govern-first ranking now prioritizes the most urgent write, deploy, production-backed, and approval-gap paths first while keeping weaker paths visible lower in the ranked output.
Semver marker override: none
Contract/API impact:
- Existing fields remain stable; ranked order and top-path selection become more urgent and actionable.
Versioning/migration impact:
- No schema migration.
- Consumers should not assume older relative ordering among equally severe path types.
Architecture constraints:
- Keep ranking logic in the risk boundary.
- Do not let report-layer presentation override risk ordering heuristics.
ADR required: no
TDD first failing test(s):
- ranking tests that currently allow a weaker non-write candidate to lead over a stronger write/deploy path
Cost/perf impact: low
Chaos/failure hypothesis:
- If the new weights are not bounded by deterministic tie-breakers, top-path output can thrash across equivalent runs.

### Story W4-S2: Make `recommended_action` discriminate visibility, approval, proof, and control gaps on real scans

Priority: P0
Tasks:
- Refine `recommendedActionForPath` so visibility-only gaps, approval gaps, proof gaps, and immediate control-first paths are separated on realistic fixtures.
- Use enriched identity, ownership, delivery, deployment, and trigger posture to keep `proof` from swallowing stronger approval/control cases.
- Update report headline facts, remediation text, and markdown wording so the sharper action classes are visible to operators.
- Add realistic fixtures proving all four action classes remain reachable outside purely synthetic unit cases.
Repo paths:
- `core/risk/action_paths.go`
- `core/risk/govern_first.go`
- `core/risk/action_paths_test.go`
- `core/risk/govern_first_test.go`
- `core/report/build.go`
- `core/report/render_markdown.go`
- `core/report/report_test.go`
- `scenarios/wrkr/govern-first-realistic/**`
- `internal/scenarios/**`
- `docs/commands/scan.md`
- `CHANGELOG.md`
Run commands:
- `go test ./core/risk ./core/report -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make prepush-full`
Test requirements:
- CLI/report behavior changes:
  - remediation wording tests
  - `--json` stability tests for `recommended_action`
- Scenario/spec tests:
  - realistic govern-first scans with one clear `inventory`, `approval`, `proof`, and `control` case
- Contract tests:
  - stable enum test for `inventory|approval|proof|control`
Matrix wiring:
- Fast lane: focused risk/report tests
- Core CI lane: `make prepush-full`
- Acceptance lane: realistic govern-first scenario suite plus `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane: stable JSON enum/output tests
- Risk lane: included in `make prepush-full`
Acceptance criteria:
- Visibility-only gaps land on `inventory`.
- Approval-model gaps land on `approval` when identity/ownership/proof are otherwise strong enough.
- Proof gaps land on `proof` only when control/approval is not yet the right headline.
- Dangerous write/deploy/production-backed paths land on `control`.
- Report and markdown summaries describe the sharper action classes clearly.
Changelog impact: required
Changelog section: Changed
Draft changelog entry: `recommended_action` now separates visibility, approval, proof, and control-first path classes more sharply on real-world govern-first scans and report summaries.
Semver marker override: none
Contract/API impact:
- Stable enum values stay the same.
- Classification thresholds and remediation wording become sharper.
Versioning/migration impact:
- No schema migration.
- Downstream automation should continue matching enum values, not prior heuristic frequency.
Architecture constraints:
- Keep action classification in the risk boundary with report-only projection above it.
- Preserve deterministic ordering and explanation facts.
ADR required: no
TDD first failing test(s):
- realistic scenario fixtures that currently collapse distinct cases to `proof`
- report tests expecting sharper remediation wording by action class
Cost/perf impact: low
Chaos/failure hypothesis:
- If `recommended_action` remains too flat, the strongest control-first path will still read like a documentation gap instead of a VP Eng escalation.

## Minimum-Now Sequence

1. Baseline and branch:
   - confirm the repo is clean except for this plan file
   - branch from updated `origin/main`
2. Wave 1a security gate recovery:
   - W1-S1
   - validate with `make lint-fast`, `make test-contracts`, `go build -o .tmp/wrkr ./cmd/wrkr`, `govulncheck -mode=binary`, rerun `nightly`
3. Wave 1b hosted acquisition resilience:
   - W1-S2
   - W1-S3
   - validate with `go test ./core/source/github ./core/cli -count=1`, `make test-hardening`, `make test-chaos`, `make prepush-full`
4. Wave 2 mixed-scope scan contract and execution:
   - W2-S1
   - W2-S2
   - W2-S3
   - validate with `make test-contracts`, `go test ./core/source/... ./core/cli ./core/state -count=1`, `go test ./internal/scenarios -count=1 -tags=scenario`, `make test-perf`, `make prepush-full`
5. Wave 3 signal enrichment:
   - W3-S1
   - W3-S2
   - validate with `go test ./core/detect/nonhumanidentity ./core/owners ./core/detect/workflowcap ./core/aggregate/privilegebudget ./core/risk ./core/report -count=1`, `make prepush-full`
6. Wave 4 ranking and action-class sharpness:
   - W4-S1
   - W4-S2
   - validate with `go test ./core/risk ./core/report -count=1`, `go test ./internal/scenarios -count=1 -tags=scenario`, `scripts/run_v1_acceptance.sh --mode=local`, `make prepush-full`
7. Full-plan closeout:
   - `make lint-fast`
   - `make test-fast`
   - `make test-contracts`
   - `make test-scenarios`
   - `make prepush-full`
   - `make test-hardening`
   - `make test-chaos`
   - `make test-perf`
   - `make codeql`
   - `go build -o .tmp/wrkr ./cmd/wrkr`
   - `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -mode=binary .tmp/wrkr`
8. Re-check Exit Criteria and update `CHANGELOG.md` `## [Unreleased]` entries from the story-level drafts.

## Explicit Non-Goals

- No weakening or bypass of `govulncheck`, CodeQL, hardening, chaos, or policy gates.
- No dashboard/UI work.
- No runtime session observation, workflow run scraping, or control-plane enforcement claims.
- No `wrkr init` redesign to persist multi-target defaults in this wave.
- No GitHub acquisition expansion beyond repo/org materialization already in scope.
- No new exit code integers.

## Definition of Done

- Every recommendation in this run is mapped to one or more shipped stories above.
- All additive CLI/schema/report changes are documented in `README.md`, `docs/commands/scan.md`, and `CHANGELOG.md`.
- Existing single-target scans continue to pass unchanged contract tests.
- Multi-target scans, rate-limit retries, and govern-first/report improvements are covered by unit, contract, integration, and scenario tests at the appropriate layer.
- Wave 1 reruns the previously failing nightly lane and records that it is green on the implementation branch.
- Risk-bearing changes pass `make prepush-full`, `make test-hardening`, and `make test-chaos`.
- Performance-sensitive acquisition/orchestration changes pass `make test-perf`.
- No hidden nondeterminism is introduced in target ordering, repo de-duplication, action-path ranking, or report output.
- The worktree after implementation contains only intended scoped changes from this plan and no unrelated dirty files.

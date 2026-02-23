# PLAN OWASP-1: Agentic Security Gap Closure

Date: 2026-02-23  
Source of truth: user-provided recommended items in this planning run; `/Users/davidahmann/Projects/wrkr/product/wrkr.md`; `/Users/davidahmann/Projects/wrkr/product/dev_guides.md`; current code baseline in `/Users/davidahmann/Projects/wrkr/core` and `/Users/davidahmann/Projects/wrkr/docs`  
Scope: planning only; no implementation in this artifact

## Global Decisions (Locked)

- Preserve deterministic defaults: offline scan/risk/proof remains deterministic; no LLM calls in scan/risk/proof.
- Preserve product boundary: no runtime enforcement, no live telemetry as primary signal, no dashboard-first scope in core.
- Add prompt poisoning coverage via static, explainable detectors only; no secret extraction or model-output inference.
- Keep `--enrich` optional and explicitly non-deterministic; offline behavior must stay unchanged.
- Keep fail-closed behavior for ambiguous high-risk conditions and maintain stable exit-code contracts.
- Keep architecture boundaries intact: source, detection, aggregation, identity, risk, proof emission, compliance mapping.
- All stories must ship with tests and CI lane wiring; no story merges without deterministic acceptance coverage.

## Current Baseline (Observed)

- Current detector registry already covers A2A, WebMCP, MCP gateway, MCP, CI agent autonomy, skills, dependencies, and secrets: `/Users/davidahmann/Projects/wrkr/core/detect/defaults/defaults.go`.
- CI autonomy detector already extracts headless execution, secret access, approval gates, and dangerous flags with stable evidence fields: `/Users/davidahmann/Projects/wrkr/core/detect/ciagent/detector.go`.
- MCP trust scoring exists, but enrich advisory lookup is still a placeholder (`advisory_lookup=not_implemented`): `/Users/davidahmann/Projects/wrkr/core/detect/mcp/detector.go`.
- Risk scoring already combines blast radius, privilege, trust deficit, and autonomy amplification with deterministic reasons: `/Users/davidahmann/Projects/wrkr/core/risk/risk.go`.
- Classification already tags network entry points for A2A/WebMCP and CI pipeline surfaces: `/Users/davidahmann/Projects/wrkr/core/risk/classify/classify.go`.
- MCP gateway posture model already produces `protected`/`unprotected`/`unknown` reasoned coverage outputs: `/Users/davidahmann/Projects/wrkr/core/detect/mcpgateway/detector.go`.
- No first-class prompt-injection/context-poisoning detector or policy rule exists in current core (search baseline had zero hits for those terms).
- Adapter parity lane is explicitly not implemented yet (`test-adapter-parity` placeholder): `/Users/davidahmann/Projects/wrkr/Makefile`.
- Product contracts explicitly disallow runtime enforcement and probabilistic scoring in these paths: `/Users/davidahmann/Projects/wrkr/README.md`.

## Exit Criteria

- `wrkr scan --json` emits deterministic prompt-channel findings with stable schema and reason codes.
- Prompt-channel findings are amplified deterministically when correlated with headless CI, secret access, and production-write exposure.
- New cross-agent attack-path model emits deterministic top-N paths with stable tie-breakers and explain payload.
- `wrkr report --json` and markdown report include attack-path summary sections without breaking existing output contracts.
- `wrkr evidence --frameworks ... --json` includes proof records and evidence references for new finding/path classes.
- `--enrich` MCP path performs advisory/registry lookups, emits `as_of` and `source` evidence fields, and preserves offline deterministic defaults when enrich is not set.
- `/Users/davidahmann/Projects/wrkr/product/report_structure.md` and `/Users/davidahmann/Projects/wrkr/product/plan-run.md` are updated so sections and runbook explicitly consume prompt-channel, attack-path, and enrich-provenance outputs.
- All CLI, schema, policy, determinism, and scenario tests pass in their required lanes.
- Merge gating enforces no regressions in exit codes, JSON keys, and deterministic replay behavior.

## Recommendation Traceability

| Recommendation ID | Recommendation | Why | Strategic direction | Expected moat/benefit | Planned coverage |
|---|---|---|---|---|---|
| R1 | Prompt injection/context poisoning static detector pack with risk amplification | Biggest OWASP-aligned gap in current Wrkr findings | Expand deterministic static detection into prompt-channel abuse patterns | Higher trust for enterprise AI security posture scans; fewer blind spots in SDLC agent risk | `OWASP-E1-S1`, `OWASP-E1-S2`, `OWASP-E1-S3`, `OWASP-E1-S4` |
| R2 | Cross-agent attack-path scoring across A2A/WebMCP/MCP/CI/secrets/production targets | Current model scores isolated findings, not composed attack chains | Add deterministic ecosystem correlation and ranked attack paths | Stronger executive signal and remediation focus; differentiates Wrkr from config-only scanners | `OWASP-E2-S1`, `OWASP-E2-S2`, `OWASP-E2-S3` |
| R3 | Finish `--enrich` MCP advisory/registry intelligence with `as_of` and source evidence | Fastest high-impact trust gain; scaffold already exists | Complete optional enrich branch while preserving deterministic offline default | Better supply-chain trust decisions and stronger enterprise adoption path | `OWASP-E3-S1`, `OWASP-E3-S2`, `OWASP-E3-S3` |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - `go test ./core/detect/... ./core/risk/... ./core/policy/... -count=1`
  - `go test ./core/cli/... -run 'TestRunScan|TestRunReport|TestRunEvidence|TestRoot' -count=1`
- Core CI lane:
  - `make test-fast`
  - `make test-contracts`
  - `make test-scenarios`
  - `./.tmp/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
- Acceptance lane:
  - Add scenario fixtures and run acceptance/scenario suites for new finding/path/enrich behaviors.
  - `make test-v1-acceptance`
- Cross-platform lane:
  - Run command-contract smoke for `scan/report/evidence/regress/verify` with new fields on Linux/macOS/Windows.
- Risk lane:
  - `make test-hardening`
  - `make test-chaos`
  - `make test-perf`
  - `make test-adapter-parity` must be implemented and wired before release gate for this plan.
- Merge/release gating rule:
  - Do not merge until Fast + Core CI + Acceptance lanes are green and contract tests show stable JSON keys, deterministic outputs, and unchanged exit-code semantics.

## Epic OWASP-E1: Prompt Channel and Context Poisoning Static Detection

Objective: add deterministic static detection for prompt-channel abuse patterns and convert those signals into actionable ranked risk without runtime model introspection.

### Story OWASP-E1-S1: Define prompt-channel finding contracts and detector scaffolding
Priority: P0
Tasks:
- Add new detector package for prompt-channel analysis with deterministic file traversal and stable ordering.
- Define canonical finding types and reason codes for instruction override, hidden/invisible text, and untrusted-context injection signals.
- Add parse/normalization helpers for text, markdown, YAML, JSON, TOML, workflow files.
- Register detector in default detector registry and ensure no behavior change when no matches exist.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/detect/promptchannel/` (new)
- `/Users/davidahmann/Projects/wrkr/core/detect/defaults/defaults.go`
- `/Users/davidahmann/Projects/wrkr/core/model/finding.go`
- `/Users/davidahmann/Projects/wrkr/core/model/finding_test.go`
Run commands:
- `go test ./core/detect/promptchannel/... -count=1`
- `go test ./core/model/... -count=1`
- `./.tmp/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
Test requirements:
- Schema/artifact: add finding schema/fixture tests and compatibility checks.
- CLI behavior: assert stable `--json` keys with no-match and match cases.
- Determinism: repeat-run byte-stability for sorted findings.
Matrix wiring:
- Fast lane; Core CI lane.
Acceptance criteria:
- New detector emits no findings on clean fixtures and deterministic findings on seeded fixtures.
- Finding types and reason codes are stable and documented.
- Existing detector behavior remains unchanged in control fixtures.

### Story OWASP-E1-S2: Implement static prompt-channel pattern extraction
Priority: P0
Tasks:
- Detect hidden Unicode control and zero-width characters in prompt-relevant surfaces (`AGENTS.md`, `CLAUDE.md`, skills, workflow scripts, instruction docs).
- Detect instruction-override patterns (for example explicit ignore/override of policy/system instructions) with deterministic token/rule matching.
- Detect untrusted-content-to-system-prompt flows in static templates and pipeline concatenation patterns.
- Emit per-finding evidence fields: `pattern_family`, `evidence_snippet_hash`, `location_class`, `confidence_class` (deterministic classes, not probabilistic).
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/detect/promptchannel/`
- `/Users/davidahmann/Projects/wrkr/core/detect/promptchannel/testdata/` (new)
- `/Users/davidahmann/Projects/wrkr/core/detect/promptchannel/detector_test.go`
- `/Users/davidahmann/Projects/wrkr/scenarios/wrkr/prompt-channel-poisoning/` (new)
Run commands:
- `go test ./core/detect/promptchannel/... -count=1`
- `./.tmp/wrkr scan --path ./scenarios/wrkr/prompt-channel-poisoning/repos --json`
- `./.tmp/wrkr report --state ./.wrkr/state.json --json`
Test requirements:
- Gate/policy/fail-closed: deterministic match/no-match fixtures and ambiguous-file parse behavior.
- Determinism/hash: stable evidence hash and deterministic ordering tests.
- Docs/examples: scenario readme and fixture rationale.
Matrix wiring:
- Fast lane; Core CI lane; Acceptance lane.
Acceptance criteria:
- Zero-width and invisible-character payloads are detected deterministically.
- Instruction override and untrusted-context injection classes are detected with stable reason codes.
- Evidence never includes raw secrets; only contextual metadata/hashes.

### Story OWASP-E1-S3: Add risk amplification and policy enforcement for prompt-channel findings
Priority: P0
Tasks:
- Add risk amplifiers when prompt-channel findings co-occur with `ci_autonomy`, `secret_presence`, and production-write exposure.
- Extend policy rules with explicit prompt-channel governance rules and remediation hints.
- Add deterministic tie-breaking and explanation entries in ranked findings for amplified cases.
- Preserve existing score ceilings and exit-code behavior.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/risk/risk.go`
- `/Users/davidahmann/Projects/wrkr/core/risk/risk_test.go`
- `/Users/davidahmann/Projects/wrkr/core/policy/rules/builtin.yaml`
- `/Users/davidahmann/Projects/wrkr/core/policy/eval/eval.go`
- `/Users/davidahmann/Projects/wrkr/core/policy/eval/eval_test.go`
Run commands:
- `go test ./core/risk/... -count=1`
- `go test ./core/policy/... -count=1`
- `./.tmp/wrkr scan --path ./scenarios/wrkr/prompt-channel-poisoning/repos --production-targets ./docs/examples/production-targets.v1.yaml --json`
Test requirements:
- Gate/policy/fail-closed: deterministic pass/fail fixtures, reason-code stability.
- CLI behavior: `--json` output stability for ranked findings and policy violations.
- Determinism/hash: repeated scan/risk outputs byte-stable.
Matrix wiring:
- Fast lane; Core CI lane; Risk lane.
Acceptance criteria:
- Amplified prompt-channel findings move upward in rank deterministically when risk conditions co-occur.
- Policy results include stable rule IDs and remediation output.
- No regressions to existing risk/report contracts.

### Story OWASP-E1-S4: Integrate prompt-channel outputs into proof/report/docs contracts
Priority: P1
Tasks:
- Map prompt-channel findings to proof records with stable event metadata.
- Extend report summaries (`--json`, markdown) with top prompt-channel risks and actionable remediations.
- Update command docs and compliance guidance for new finding classes.
- Harmonize report production docs so Section 1-10 and runbook inputs explicitly include prompt-channel outputs and claim guardrails.
- Add scenario acceptance coverage for end-to-end scan -> report -> evidence -> verify loop.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/proofmap/proofmap.go`
- `/Users/davidahmann/Projects/wrkr/core/report/build.go`
- `/Users/davidahmann/Projects/wrkr/core/report/render_markdown.go`
- `/Users/davidahmann/Projects/wrkr/docs/commands/scan.md`
- `/Users/davidahmann/Projects/wrkr/docs/commands/report.md`
- `/Users/davidahmann/Projects/wrkr/docs/compliance/eu_ai_act_audit_readiness.md`
- `/Users/davidahmann/Projects/wrkr/product/report_structure.md`
- `/Users/davidahmann/Projects/wrkr/product/plan-run.md`
Run commands:
- `go test ./core/proofmap/... ./core/report/... -count=1`
- `./.tmp/wrkr scan --path ./scenarios/wrkr/prompt-channel-poisoning/repos --report-md --report-md-path ./.tmp/prompt-channel.md --json`
- `./.tmp/wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json`
- `make test-docs-consistency`
Test requirements:
- Schema/artifact: proof/event schema compatibility tests.
- CLI behavior: report command JSON contract and markdown snapshot tests.
- Docs/examples: docs consistency and storyline checks.
Matrix wiring:
- Core CI lane; Acceptance lane; Cross-platform lane.
Acceptance criteria:
- Proof records include prompt-channel events with stable keys.
- Report outputs include deterministic prompt-channel risk sections.
- Docs and examples are aligned with CLI behavior and report structure/runbook contracts.

## Epic OWASP-E2: Cross-Agent Attack-Path Scoring (Ecosystem Correlation)

Objective: move from isolated finding ranking to deterministic, composed attack-path ranking across external entry points and internal privilege pivots.

### Story OWASP-E2-S1: Build deterministic attack-path graph model
Priority: P1
Tasks:
- Define graph entities and edges: entry points (A2A/WebMCP/client-facing), pivots (MCP servers, compiled actions, CI autonomy), targets (secrets, production-write, privileged skills).
- Build deterministic graph extraction from existing findings/inventory without runtime calls.
- Encode trust boundaries and edge rationale fields for explainability.
- Add canonical serialization for graph snapshots.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/aggregate/attackpath/` (new)
- `/Users/davidahmann/Projects/wrkr/core/aggregate/inventory/`
- `/Users/davidahmann/Projects/wrkr/core/model/`
- `/Users/davidahmann/Projects/wrkr/core/cli/scan.go`
Run commands:
- `go test ./core/aggregate/attackpath/... -count=1`
- `./.tmp/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
Test requirements:
- Schema/artifact: graph schema validation and fixture/golden tests.
- Determinism/hash: stable graph serialization across repeat runs.
- Job/runtime: deterministic behavior under concurrent repo scans.
Matrix wiring:
- Fast lane; Core CI lane.
Acceptance criteria:
- Attack graph is generated deterministically from the same finding set.
- Each edge has an explicit rationale and source finding linkage.
- Graph generation adds no nondeterministic dependencies.

### Story OWASP-E2-S2: Implement deterministic attack-path scoring and top-path ranking
Priority: P1
Tasks:
- Add path score formula that composes entry exposure, privilege escalation potential, autonomy amplification, and trust deficit.
- Add deterministic path ranking with stable tie-breakers and bounded top-N output.
- Add explain fields showing per-edge and per-path contribution.
- Ensure compatibility with existing `top_findings` and repo risk envelopes.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/risk/attackpath/` (new)
- `/Users/davidahmann/Projects/wrkr/core/risk/risk.go`
- `/Users/davidahmann/Projects/wrkr/core/risk/risk_test.go`
- `/Users/davidahmann/Projects/wrkr/core/cli/score.go`
Run commands:
- `go test ./core/risk/... -count=1`
- `./.tmp/wrkr scan --path ./scenarios/wrkr/attack-path-correlation/repos --json`
- `./.tmp/wrkr score --json`
Test requirements:
- Determinism/hash: repeat-run ranking identity and score stability.
- CLI behavior: score JSON key stability and explain contract tests.
- Perf: bounded runtime tests for large graph fixtures.
Matrix wiring:
- Fast lane; Core CI lane; Risk lane.
Acceptance criteria:
- Top attack paths are stable for identical input.
- Score explanation fields are deterministic and auditable.
- Existing score/report contracts remain backward compatible.

### Story OWASP-E2-S3: Expose attack paths in report, evidence, and regression gates
Priority: P1
Tasks:
- Add attack-path sections to `wrkr report --json` and markdown output.
- Include attack-path artifacts and proof records in evidence bundle.
- Add regress-drift logic for path-level criticality changes with stable reason codes.
- Extend campaign and appendix mapping contracts so attack-path rows are available for report sections and benchmark narrative.
- Add scenario suite for client-facing entry to internal target chain examples.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/report/build.go`
- `/Users/davidahmann/Projects/wrkr/core/evidence/evidence.go`
- `/Users/davidahmann/Projects/wrkr/core/proofmap/proofmap.go`
- `/Users/davidahmann/Projects/wrkr/core/cli/regress.go`
- `/Users/davidahmann/Projects/wrkr/scenarios/wrkr/attack-path-correlation/` (new)
- `/Users/davidahmann/Projects/wrkr/product/plan-run.md`
- `/Users/davidahmann/Projects/wrkr/product/report_structure.md`
Run commands:
- `go test ./core/report/... ./core/evidence/... ./core/proofmap/... -count=1`
- `./.tmp/wrkr report --state ./.wrkr/state.json --json`
- `./.tmp/wrkr evidence --frameworks eu-ai-act,soc2 --state ./.wrkr/state.json --output ./.tmp/evidence --json`
- `./.tmp/wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.wrkr/state.json --json`
Test requirements:
- CLI behavior: report/evidence/regress output and exit-code contract tests.
- Schema/artifact: evidence manifest/golden updates and compatibility checks.
- Voice/context-proof: scenario acceptance tests for composed chain risk.
Matrix wiring:
- Core CI lane; Acceptance lane; Cross-platform lane.
Acceptance criteria:
- Reports and evidence include deterministic attack-path summaries.
- Regress command can detect critical attack-path drift with stable reason fields.
- Campaign/report mapping docs explicitly describe attack-path artifact usage.
- End-to-end scenario passes with stable artifacts.

Dependencies:
- Depends on `OWASP-E2-S1` and `OWASP-E2-S2`.
Risks:
- Contract churn risk if new path fields are not gated by compatibility tests.

## Epic OWASP-E3: Complete MCP `--enrich` Advisory and Registry Intelligence

Objective: finish optional enrich path for MCP trust decisions with explicit source-at-time evidence while preserving offline deterministic defaults.

### Story OWASP-E3-S1: Implement enrich clients and response normalization
Priority: P1
Tasks:
- Add enrich provider adapters for advisory and MCP registry lookups with explicit timeout/retry bounds.
- Normalize enrich responses into deterministic evidence shape (`source`, `as_of`, `package`, `version`, `advisory_count`, `registry_status`).
- Add strict error mapping so enrich failures degrade gracefully without affecting offline scan defaults.
- Keep enrich execution explicitly opt-in from `--enrich`.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/detect/mcp/enrich/` (new)
- `/Users/davidahmann/Projects/wrkr/core/detect/mcp/detector.go`
- `/Users/davidahmann/Projects/wrkr/core/cli/scan.go`
Run commands:
- `go test ./core/detect/mcp/... -count=1`
- `./.tmp/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --enrich --github-api https://api.github.com --json`
- `./.tmp/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
Test requirements:
- SDK/adapter boundary: wrapper error mapping and adapter conformance tests.
- CLI behavior: enrich flag behavior and dependency-missing error contract tests.
- Determinism/hash: assert offline mode unchanged with and without enrich code present.
Matrix wiring:
- Fast lane; Core CI lane; Risk lane.
Acceptance criteria:
- `--enrich` emits normalized MCP advisory/registry evidence with `as_of`.
- Offline scan outputs are unchanged when `--enrich` is not supplied.
- Enrich failures do not break baseline scan path.

### Story OWASP-E3-S2: Integrate enrich evidence into scoring/reporting/proof contracts
Priority: P1
Tasks:
- Use enrich evidence to adjust MCP trust deficit in enrich mode only.
- Add report annotations for enrich-derived supply-chain risk changes.
- Include enrich evidence metadata in proof map and evidence bundle outputs.
- Document deterministic/offline vs enrich/non-deterministic behavior clearly.
- Add report/runbook guardrails so enrich claims require `as_of` and `source` provenance in exported tables.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/core/risk/risk.go`
- `/Users/davidahmann/Projects/wrkr/core/proofmap/proofmap.go`
- `/Users/davidahmann/Projects/wrkr/core/report/build.go`
- `/Users/davidahmann/Projects/wrkr/docs/commands/scan.md`
- `/Users/davidahmann/Projects/wrkr/docs/commands/evidence.md`
- `/Users/davidahmann/Projects/wrkr/product/plan-run.md`
- `/Users/davidahmann/Projects/wrkr/product/report_structure.md`
Run commands:
- `go test ./core/risk/... ./core/proofmap/... ./core/report/... -count=1`
- `./.tmp/wrkr report --state ./.wrkr/state.json --json`
- `./.tmp/wrkr evidence --frameworks eu-ai-act,soc2 --state ./.wrkr/state.json --json`
- `make test-docs-consistency`
Test requirements:
- Schema/artifact: proof/report JSON schema stability with enrich fields.
- CLI behavior: `--json` contract tests for enrich and non-enrich runs.
- Docs/examples: docs consistency + storyline checks.
Matrix wiring:
- Core CI lane; Acceptance lane.
Acceptance criteria:
- Enrich-derived fields are present only in enrich runs and versioned in contracts.
- Trust scoring differences are explainable and deterministic within one enrich dataset snapshot.
- Publish-path docs enforce provenance requirements for enrich-derived claims.
- Evidence and report outputs remain backward compatible.

Dependencies:
- Depends on `OWASP-E3-S1`.
Risks:
- External source volatility; mitigate by recording `as_of` and source IDs in output.

### Story OWASP-E3-S3: Add enrich scenario fixtures and CI matrix hooks
Priority: P2
Tasks:
- Add deterministic simulated enrich fixtures for advisories/registry responses.
- Wire enrich simulation into scenario and risk lanes.
- Replace `test-adapter-parity` placeholder with actionable adapter parity checks for enrich providers.
- Add release-gate checks ensuring enrich code paths do not leak into offline deterministic assertions.
Repo paths:
- `/Users/davidahmann/Projects/wrkr/scenarios/wrkr/mcp-enrich-supplychain/` (new)
- `/Users/davidahmann/Projects/wrkr/internal/scenarios/`
- `/Users/davidahmann/Projects/wrkr/Makefile`
- `/Users/davidahmann/Projects/wrkr/scripts/` (new parity scripts as needed)
Run commands:
- `make test-scenarios`
- `make test-risk-lane`
- `make test-adapter-parity`
Test requirements:
- SDK/adapter boundary: adapter parity/conformance tests.
- Risk lane: chaos/perf resilience checks for enrich simulation.
- Determinism: offline vs enrich split assertions.
Matrix wiring:
- Core CI lane; Risk lane; Merge/release gate.
Acceptance criteria:
- Adapter parity checks are implemented and enforced.
- Enrich simulation is reproducible in CI and does not introduce flaky behavior.
- Release gates assert offline deterministic guarantees remain intact.

## Minimum-Now Sequence

1. Execute `OWASP-E1-S1` and `OWASP-E1-S2` to establish core detection primitives.
2. Execute `OWASP-E1-S3` to convert detections into ranked/policy signal.
3. Execute `OWASP-E3-S1` to complete enrich plumbing in parallel with late E1 work.
4. Execute `OWASP-E3-S2` to surface enrich outputs in risk/report/proof contracts.
5. Execute `OWASP-E2-S1` to build graph primitives on top of stabilized finding contracts.
6. Execute `OWASP-E2-S2` to rank composed attack paths.
7. Execute `OWASP-E2-S3` to integrate attack paths into report/evidence/regress.
8. Execute `OWASP-E1-S4` for prompt-channel proof/report/docs closure.
9. Execute `OWASP-E3-S3` to harden enrich matrix wiring and release gates.
10. Run full matrix and release gating validation before implementation handoff closure.

## Explicit Non-Goals

- No runtime prompt filtering, runtime enforcement, or live agent telemetry ingestion.
- No LLM-based probabilistic classifier or generative risk reasoning in scan/risk/proof path.
- No new dashboard/web UI work in this backlog.
- No expansion into Axym/Gait product logic beyond existing proof/policy contracts.
- No weakening of offline-first deterministic behavior for default scan mode.

## Definition of Done

- Every recommendation in this plan maps to merged stories with passing acceptance criteria.
- Every story includes implemented tests at the declared layer and lane wiring in CI.
- All new CLI outputs preserve `--json` contract stability and exit-code stability.
- Determinism checks prove same input -> same output for offline mode.
- Enrich path is explicit, optional, source-attributed, and does not alter offline defaults.
- Docs and examples are updated and validated with docs consistency/storyline checks.
- Release gates pass with no contract regressions, no policy-rule drift, and no unresolved blocker risks.

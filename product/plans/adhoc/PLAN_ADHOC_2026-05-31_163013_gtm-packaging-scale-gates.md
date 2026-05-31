# Adhoc Plan: GTM, Packaging, And Scale Gates

Date: 2026-05-31
Profile: `wrkr`
Slug: `gtm-packaging-scale-gates`
Recommendation source: user-provided Sprint 5 recommendations covering large-org executive rollups, customer-controlled deployment modes, public-surface demo mapping, product-led website assets, governed-usage packaging metrics, precision calibration fixtures, and enterprise-scale product pressure tests.

All paths in this plan are repo-relative. User-provided absolute checkout paths have been normalized to repo-relative paths. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, scenario, docs, release, or website changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control loop. This plan must not add Axym compliance-engine behavior, Gait runtime enforcement, scan-time LLM calls, live private-system probing, or default scan-data exfiltration.
- Local/private operation remains the default. Any customer-controlled, connected SaaS metadata, managed-platform, or public-surface mode must be explicit, reflected in machine-readable artifacts, and unable to weaken the default `local_only` posture.
- Large-org reporting is an additive executive rollup derived from existing deterministic facts: action paths, Agent Action BOM items, control backlog items, scan quality, evidence states, ownership state, credential authority, production target classification, contradictions, and closure requirements.
- Packaging metrics are non-sensitive counters, not pricing enforcement. They must never include raw repo contents, secret values, prompts, source snippets, private URLs, or customer-identifying names under redacted share profiles.
- Public-surface demo mapping is an opt-in assessment path for public evidence only. It must label evidence as observed public fact, inferred public context, unsupported claim, or customer-private evidence absent; it must not overclaim private reachability from public marketing/docs signals.
- Website-ready samples must be generated from curated public/demo fixtures and stable synthetic data. No customer scan outputs, private proof chains, private join maps, or transient reports may be committed.
- Precision fixtures and enterprise-scale gates are product quality controls. They should turn repeated design-partner pain into deterministic scenario, acceptance, contract, hardening, and performance tests without storing customer data.
- Existing API contracts remain locked: deterministic outputs, no secret extraction, signed proof chain integrity, portable evidence artifacts, `--json` machine output, `--explain` rationale, `--quiet` CI operation, and exit codes `0` through `8`.
- Changelog entries are required for implementation PRs because this work changes public report JSON, schemas, CLI/docs behavior, evidence manifests, demo artifacts, assessment outputs, and release-facing product claims.

## Current Baseline (Observed)

- `core/report/build.go` composes report summaries from scan, inventory, risk, lifecycle, regress, proof, source privacy, runtime evidence, evidence packets, Control Path Graph, workflow chains, control backlog, and Agent Action BOM data.
- `core/report/agent_action_bom.go` already exposes rich item-level fields such as action classes, target class, risk zone, credential authority, evidence states, owner evidence, contradictions, boundary labels, closure requirements, governance disposition, runtime/proof refs, and scan-quality summaries. It does not yet expose an explicit large-org executive rollup grouped by action class, target class, risk zone, credential authority, production target, evidence state, owner state, repo cluster, detector confidence, contradiction state, and closure action.
- `core/aggregate/controlbacklog/controlbacklog.go` already models queues, recommended actions, evidence states, owner state, contradictions, closure requirements, and governance disposition. It does not yet publish rollup buckets that let an executive report compress hundreds of items into action-oriented groups.
- `core/evidence/evidence.go` builds evidence output directories, verifies proof chains, emits manifest paths, report artifact paths, source privacy metadata, runtime summaries, evidence packet summaries, and Agent Action BOM data. It does not yet carry a deployment/data-mode contract across evidence and report artifacts.
- `core/cli/scan.go` supports local paths, GitHub repo/org targets, `--target`, `--source-retention`, optional hosted source materialization, `--enrich`, JSON output, report artifacts, SARIF, profiles, and fail-closed dependency checks. It does not yet expose deployment/data-mode metadata or a public-surface assessment target.
- `core/source/types.go` models scan targets, repo manifests, source failures, and deterministic sorting. It does not yet model public-surface source evidence, source class, inference basis, public URL provenance, or public/private claim boundaries.
- `core/report/redaction.go`, report tests, and `internal/acceptance/report_overclaim_acceptance_test.go` already enforce share-profile redaction and overclaim controls. The same discipline needs to cover deployment modes, packaging metrics, public-surface evidence, and website-ready artifacts.
- `schemas/v1/report/report-summary.schema.json` and `schemas/v1/agent-action-bom.schema.json` already define many report/BOM contract surfaces, including share profiles, evidence states, target classes, confidence lanes, contradiction states, governed path views, scan quality, and source privacy. They need additive schema fields for executive rollups, governed-usage metrics, deployment mode, and public-surface evidence.
- Scenario fixtures exist under `scenarios/wrkr/**`, with focused coverage for Agent Action BOM demo, buyer-action registry hardening, control evidence state, scan mixed org, target classification, workflow capabilities, and other product paths. They do not yet include small labeled precision-calibration fixtures for the Sprint 5 known-outcome list or a recurring 300+ repo enterprise pressure fixture.
- User-facing docs already include command docs for `scan`, `report`, `evidence`, `assess`, `regress`, and trust docs for schemas, security/privacy, deterministic guarantees, and detection coverage. They do not yet explain customer deployment/data modes, public-surface demo assessment, governed-usage metrics, website asset generation, or enterprise-scale quality gates.

## Exit Criteria

- Reports include a deterministic large-org executive rollup that compresses hundreds of repo findings into ranked buckets by action class, target class, risk zone, credential authority, production target, evidence state, owner state, repo cluster, detector confidence, contradiction state, and closure action.
- Agent Action BOM, report summary, control backlog, and markdown templates all present rollup groups with stable IDs, counts, top example refs, evidence-state summaries, closure recommendations, and deterministic sorting.
- Evidence manifests, report artifacts, source privacy metadata, and docs expose customer-controlled deployment/data modes: `local_only`, `customer_controlled_storage`, `connected_saas_metadata`, and `managed_platform`. `local_only` remains the default.
- Public-surface assessment mode can consume explicitly selected public repos/docs/SDK/blog/release-note/status-page/workflow evidence or curated public fixtures, labels evidence as public or inferred, and avoids private-environment claims unless private evidence is later supplied.
- Website-ready assets are generated from stable public/demo fixtures: sample BOM, sample action-control graph, sample redacted report, interactive lab data, architecture boundary page data, and local/private data posture explanation.
- Governed-usage packaging metrics emit deterministic, non-sensitive counters for active monitored action paths, governed paths, evidence packs, audit exports, approval decisions, connected runtimes, governed agents/workflows, verified-control paths, unknown-control paths, and contradictory paths.
- Precision calibration fixtures cover owner evidence present, approval outside repo, declared non-prod with production-secret contradiction, old source only, dependency-only AI package, CI automation without agent, actual AI-assisted deploy path, branch protection present/absent, and runtime evidence present.
- Enterprise-scale pressure tests exercise large-org summarization, redaction, scan-quality compaction, control-state consistency, evidence-state wording, proof completeness, graph size, BOM readability, and drift output on 300+ repo synthetic/anonymized fixtures.
- Scenario, contract, schema, hardening, chaos, performance, docs parity, release-smoke, and acceptance lanes cover every new public contract, failure mode, and buyer-facing claim.

## Public API and Contract Map

- CLI contracts:
  - Preserve exit codes: `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, and `8` unsafe operation blocked.
  - `wrkr scan --json` gains additive deployment/data-mode metadata. The default is `local_only`; any flag/config name for alternate modes must follow existing CLI patterns and reject unknown modes with exit `6`.
  - `wrkr report --json`, `wrkr report --md`, `wrkr report --pdf`, and `wrkr report --evidence-json` gain additive executive rollup and governed-usage metrics. Existing fields remain backward compatible.
  - `wrkr evidence --frameworks <ids> --json` gains additive deployment/data-mode metadata and governed-usage metrics in manifests without changing proof-chain verification prerequisites.
  - Public-surface assessment is added as an explicit target or assessment mode, for example `--target public-surface:<manifest>` or an equivalent pattern chosen during implementation. It must not run as part of default local scans.
  - Unknown public source classes, malformed public-surface manifests, unsafe output paths, and attempts to include private join maps or raw fetched payloads in shareable assets must fail with exit `6` or `8` as appropriate.
- JSON and schema contracts:
  - Extend `schemas/v1/report/report-summary.schema.json` additively with `executive_rollup`, `governed_usage_metrics`, and deployment/data-mode metadata.
  - Extend `schemas/v1/agent-action-bom.schema.json` additively with rollup summaries and governed-usage counters while preserving existing `summary` and `items` fields.
  - Extend evidence bundle or assessment schemas under `schemas/v1/evidence` and `schemas/v1/assess` when manifests carry deployment mode, public-surface evidence, generated website asset refs, or packaging counters.
  - Add canonical enums only through v1-compatible additive fields: deployment modes `local_only`, `customer_controlled_storage`, `connected_saas_metadata`, `managed_platform`; public evidence labels `public_observed`, `public_inferred`, `unsupported_public_claim`, `private_evidence_absent`; and rollup dimensions matching this plan.
  - Stable IDs for rollup buckets and packaging counters must be deterministic from normalized dimension values, not display text.
- Detection, source, aggregation, and risk contracts:
  - Source layer owns public-surface inputs and evidence provenance. Detection remains responsible for tool/config signals. Aggregation owns rollups and packaging counters. Risk owns action path, target class, risk zone, evidence state, contradiction, and closure semantics. Report/evidence layers render and package.
  - Public pages, public docs, status pages, and public workflows are evidence sources, not proof of private deployment reach. Public inferred evidence must never become verified control evidence without a stronger source.
  - Deployment/data-mode metadata must not alter risk scoring unless an explicit policy/story later defines that behavior.
- Proof and evidence output contracts:
  - Governed-usage metrics and executive rollups may reference existing proof records and evidence refs, but they must not mint new proof semantics without explicit schema/version discussion.
  - Proof record types remain consistent with existing Wrkr usage: `scan_finding`, `risk_assessment`, `approval`, and `lifecycle_transition`.
  - Evidence bundles must remain portable and auditable, with no raw secrets, raw customer source, private URLs, or unredacted owner names in redacted/public modes.
- Documentation contracts:
  - Docs must explain deployment/data modes, public-surface evidence labels, executive rollup dimensions, governed-usage metrics, website asset generation, precision fixtures, and enterprise pressure gates.
  - Examples must use fake orgs, repos, owners, provider URLs, public pages, status pages, release notes, workflows, credentials, runtime refs, and proof refs.
  - Machine-readable evidence examples must use profile command anchors such as `wrkr scan --json`, `wrkr regress run --baseline <baseline-path> --json`, and `wrkr score --json`.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/commands/assess.md`
  - `docs/examples/`
  - `docs/trust/contracts-and-schemas.md`
  - `docs/trust/detection-coverage-matrix.md`
  - `docs/trust/security-and-privacy.md`
  - `docs/trust/deterministic-guarantees.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Product/demo assets impacted:
  - `internal/scenarios`
  - `scenarios/wrkr`
  - `docs/examples`
  - `docs-site/public/llms.txt`
  - `docs-site/public/llm/`
- Scenario and contract docs impacted:
  - `internal/scenarios/coverage_map.json`
  - `internal/acceptance`
  - `core/report/report_test.go`
  - `core/cli/report_contract_test.go`
  - detector tests under `core/detect`
  - schemas under `schemas/v1`
- OSS trust baseline:
  - Do not commit customer scan outputs, private proof chains, generated binaries, private join maps, raw session exports, credential material, public-site scrape caches, or transient reports.
  - Public-surface fixtures must use fake or clearly public evidence and include provenance labels so docs cannot imply private access.
  - Website-ready artifacts must be reproducible from checked-in fixtures and generation commands; screenshots/sample JSON must be byte-stable or intentionally updated with tests.
  - Redacted reports must remain useful for buyer review while stripping owners, repos, locations, credential subjects, proof refs, graph refs, source URLs, and provider IDs according to the selected share profile.
- Docs must answer:
  - What each deployment/data mode means and which mode is the default.
  - Which evidence leaves the customer boundary in each mode.
  - How executive rollups map to underlying BOM/control-backlog rows.
  - What governed-usage metrics count and what they deliberately do not count.
  - How public-surface demo mapping differs from a private customer scan.
  - How website samples are generated and why they are safe to publish.
  - How precision fixtures and enterprise pressure gates protect against noisy, inconsistent, or overclaiming output.

## Recommendation Traceability

| Recommendation / Finding | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| 48. Large-Org Executive Rollup | P0 | Story 1.1 | A 337-repo scan proves scale, but users need grouped decisions instead of a long list. | Derive stable executive buckets from existing action, risk, evidence, owner, repo, confidence, contradiction, and closure facts. | Buyers can understand hundreds of repos in minutes and route work by action class. |
| 49. Customer-Controlled Deployment Modes | P0 | Story 2.1 | Sensitive source, secrets, raw evidence, and graph data must stay customer-controlled by default. | Add explicit data-posture metadata across scan/report/evidence artifacts and docs. | Customers can reason about where data lives and trust the default local/private posture. |
| 50. Public-Surface Demo Mapper | P1 | Story 2.2 | Cold outbound and demos should not depend on fake repos or private claims. | Add opt-in public-surface assessment with public/inferred evidence labels and claim discipline. | Demos become credible while avoiding overclaims about private environments. |
| 51. Product-Led Website Assets | P1 | Story 3.1 | The website should act like the first sales engineer. | Generate stable sample BOMs, graph data, redacted reports, lab data, architecture boundary assets, and local/private posture copy from fixtures. | Website, docs, and outbound materials can show the real product surface safely. |
| 52. Governed-Usage Packaging Metrics | P0 | Story 1.2 | Packaging should map to governed usage, not seats. | Emit deterministic non-sensitive counters in reports, BOM, evidence manifests, and schemas. | Pricing and value conversations align with governed paths, evidence packs, approvals, runtimes, and control states. |
| 53. Precision Calibration Fixtures | P0 | Story 4.1 | IBM-scale or other enterprise scans are useful, but precision needs controlled known outcomes. | Add small labeled fixtures and expected outputs for owner, approval, contradiction, source age, dependency-only, CI-only, deploy path, branch protection, and runtime evidence cases. | Detector/report precision can improve without relying on anecdotal customer scans. |
| 54. Enterprise-Scale Product Pressure Tests | P0 | Story 4.2 | Manual, noisy, inconsistent, or hard-to-explain enterprise scan behavior should become productized. | Turn 300+ repo synthetic/anonymized design-partner patterns into recurring acceptance and quality gates. | Large-org report quality becomes repeatable release evidence, not manual inspection. |

## Test Matrix Wiring

- Fast lane:
  - Focused unit tests for executive rollup bucketing, governed-usage counters, deployment mode parsing/metadata, public-surface manifest parsing, public evidence labels, demo asset generation, precision fixture expected outcomes, and deterministic sorting.
  - Candidate command: `go test ./core/report ./core/aggregate/controlbacklog ./core/evidence ./core/source ./core/cli ./core/risk ./core/detect -count=1`.
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `scripts/run_v1_acceptance.sh --mode=local`
- Cross-platform lane:
  - Windows smoke must cover path normalization for public-surface manifests, demo asset output paths, redacted report asset paths, large fixture traversal, CRLF fixture files, and stable sorted rollup IDs.
- Risk lane:
  - `make test-hardening` for malformed data modes, unknown public source classes, unsafe output paths, raw secret-like fixture values, redaction misses, public/private evidence overclaiming, and generated asset leaks.
  - `make test-chaos` for partial public-surface evidence, missing status pages, corrupt manifests, stale fixture outputs, conflicting evidence labels, oversized graph summaries, and interrupted evidence asset generation.
  - `make test-perf` for large-org rollups, 300+ repo pressure fixtures, graph size bounds, report markdown rendering, and BOM readability checks.
- Release/UAT lane:
  - `make test-release-smoke`
  - `scripts/run_v1_acceptance.sh --mode=release` when schemas, CLI flags, docs examples, evidence manifests, report JSON, or website assets change.
- Gating rule:
  - Wave 1 rollup and packaging metrics must land before docs or website assets claim enterprise-scale executive value metrics.
  - Wave 2 deployment modes must land before public-surface or website docs describe data posture guarantees.
  - Wave 2 public-surface evidence labels must land before demos use public webpages or public workflows as evidence.
  - Wave 3 generated website assets must come from deterministic fixtures, not hand-edited screenshots or private scan outputs.
  - Wave 4 precision and enterprise-scale gates must land before release notes claim improved scale readiness or calibration.

## Minimum-Now Sequence

- Wave 1 - Enterprise rollups and packaging counters:
  - Story 1.1 adds deterministic large-org executive rollup model, report JSON, BOM summary fields, control backlog grouping, markdown rendering, and schema coverage.
  - Story 1.2 adds governed-usage packaging metrics to reports, Agent Action BOM, evidence manifests, schemas, and docs.
- Wave 2 - Data posture and public-surface assessment:
  - Story 2.1 adds customer-controlled deployment/data-mode metadata across scan, report, evidence, redaction, docs, and tests.
  - Story 2.2 adds opt-in public-surface demo mapping, public/inferred evidence labels, source provenance, buyer projection constraints, docs, and fixtures.
- Wave 3 - Product-led demo and website assets:
  - Story 3.1 adds reproducible website-ready sample artifacts, fixture generation commands, redacted report outputs, interactive lab data, architecture boundary asset data, and docs/examples.
- Wave 4 - Calibration and scale gates:
  - Story 4.1 adds small labeled precision calibration fixtures and expected outcomes.
  - Story 4.2 adds enterprise-scale 300+ repo pressure tests, report readability gates, graph size checks, redaction pressure, proof completeness checks, drift output checks, and release/UAT wiring.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No hosted SaaS backend, account system, billing enforcement, seat counting, or managed-platform runtime implementation.
- No default network calls during local/private scans.
- No scan-time, risk-time, proof-time, report-time, evidence-time, or docs-generation-time LLM calls.
- No extraction, logging, serialization, hashing-for-identification, or fixture commits of raw secret values.
- No customer scan outputs, private screenshots, private proof chains, private join maps, raw prompt/session payloads, or generated transient reports committed as website assets.
- No live endpoint probing, runtime enforcement, or Gait policy execution.
- No Axym product logic or compliance-engine behavior in Wrkr.
- No removal of existing v1 JSON fields without an explicit versioned migration.
- No public-surface inference treated as verified private control evidence.
- No performance gate that requires private customer repositories to reproduce.

## Epic 1: Enterprise Rollups And Governed-Usage Metrics

Objective: turn large-org scan data into executive-readable decisions and non-sensitive value metrics.
Traceability: Recommendations 48 and 52.

### Story 1.1: Add Large-Org Executive Rollup Model And Report Rendering

Priority: P0
Recommendation coverage: 48

Tasks:
- Add a deterministic executive rollup model that groups report/BOM/control-backlog facts by action class, target class, risk zone, credential authority, production target, evidence state, owner state, repo cluster, detector confidence, contradiction state, and closure action.
- Derive rollup rows from existing report summary, action paths, Agent Action BOM items, control backlog items, scan quality, and evidence completeness without rescanning or crossing architecture boundaries.
- Assign stable rollup IDs from normalized dimensions and include counts, top example refs, highest priority, evidence-state summary, closure action, and rationale strings.
- Add rollup data to report JSON and Agent Action BOM summary as additive fields.
- Render the rollup in markdown before verbose appendices so large org reports lead with action classes and closure decisions.
- Add deterministic sorting rules: highest severity and unresolved closure first, then production/credential authority, then contradiction, then count, then stable ID.

Repo paths:
- `core/report/build.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/templates/templates.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`

Run commands:
- `go test ./core/report ./core/aggregate/controlbacklog -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-perf`
- `make prepush-full`

Test requirements:
- Add unit tests for every rollup dimension, stable ID generation, stable sorting, empty-state output, contradiction grouping, closure action grouping, repo cluster grouping, and redacted share-profile behavior.
- Add report contract tests proving existing JSON consumers remain compatible and new rollup fields validate against v1 schemas.
- Add markdown golden tests for compact executive rollup placement before appendices.
- Add performance tests that render large synthetic rollups without changing item-level ordering or graph/BOM references.

Matrix wiring:
- Fast lane: focused `core/report` and `controlbacklog` rollup tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario validation with a large-org rollup fixture.
- Cross-platform lane: Windows smoke for path normalization and stable sort order.
- Risk lane: `make test-hardening` for redaction and overclaim cases; `make test-perf` for large-org rendering.

Acceptance criteria:
- A report with hundreds of action paths includes compact executive rollups with stable IDs, counts, top refs, evidence-state summaries, and closure actions.
- Markdown and JSON lead with grouped decisions without dropping item-level detail from appendices/evidence JSON.
- Redacted share profiles keep rollup usefulness while removing private owner, repo, location, credential, proof, and graph details.
- Rollup generation is deterministic across repeated runs with the same input.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added large-organization executive rollups that group Agent Action BOM and control-backlog evidence by action, target, risk, authority, evidence, owner, contradiction, and closure dimensions.
Semver marker override: [semver:minor]
Contract/API impact: Additive report summary and Agent Action BOM schema fields for executive rollups; no removal of existing JSON fields.
Versioning/migration impact: v1-compatible additive schema update; consumers can ignore new fields.
Architecture constraints: Aggregation/report layers may summarize existing facts, but detection, source, risk, proof, and compliance boundaries must remain separate.
ADR required: yes
TDD first failing test(s): Add failing `core/report` rollup tests for dimension bucketing, stable IDs, redacted rollups, and markdown placement.
Cost/perf impact: medium
Chaos/failure hypothesis: A huge or contradictory action-path set should produce bounded deterministic rollups and explicit reduced-confidence summaries instead of noisy or unstable output.

### Story 1.2: Emit Governed-Usage Packaging Metrics

Priority: P0
Recommendation coverage: 52

Tasks:
- Add deterministic non-sensitive governed-usage counters for active monitored action paths, governed paths, evidence packs, audit exports, approval decisions, connected runtimes, governed agents/workflows, verified-control paths, unknown-control paths, and contradictory paths.
- Source counters from report summary, Agent Action BOM, control backlog, evidence manifests, runtime evidence, proof/control status, and regress data instead of creating a separate pricing model.
- Add metrics to report JSON, Agent Action BOM summary, evidence manifests, and any assessment manifest fields needed for repeated runs.
- Apply share-profile redaction rules so counters remain safe while private exemplars are omitted or pseudonymized.
- Document the metric definitions and explicitly state that they are value/packaging indicators, not billing enforcement or seat counts.

Repo paths:
- `core/report/build.go`
- `core/report/agent_action_bom.go`
- `core/evidence/evidence.go`
- `core/cli/report_artifacts.go`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/evidence/evidence-bundle.schema.json`
- `docs/commands/report.md`
- `docs/commands/evidence.md`

Run commands:
- `go test ./core/report ./core/evidence ./core/cli -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-docs-consistency`
- `make prepush-full`

Test requirements:
- Unit tests for each counter source, zero states, redacted profiles, contradictory paths, verified-control paths, unknown-control paths, and connected runtime counts.
- Contract tests for schema validation and stable JSON key names.
- Scenario tests proving counters match fixture expectations and do not count item-level appendix noise twice.
- Docs consistency tests for metric definitions and command examples.

Matrix wiring:
- Fast lane: focused packaging metric tests in report/evidence/CLI packages.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixtures with known governed-path and evidence-pack counts.
- Cross-platform lane: stable manifest path handling for evidence pack counters.
- Risk lane: `make test-hardening` for redaction leaks and contradictory/unknown state handling.

Acceptance criteria:
- Reports and evidence manifests emit deterministic governed-usage metrics with stable names and documented definitions.
- Metrics are reproducible from the same state and do not include raw source, secret values, owner names, private URLs, or raw proof details under redacted profiles.
- Schema and docs updates make the metrics safe for product, GTM, and buyer conversations without implying billing enforcement.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added governed-usage metrics for monitored paths, governed paths, evidence packs, audit exports, approvals, connected runtimes, governed agents/workflows, verified controls, unknown controls, and contradictions.
Semver marker override: [semver:minor]
Contract/API impact: Additive JSON/schema fields in reports, BOM summaries, and evidence manifests.
Versioning/migration impact: v1-compatible additive schema update with docs defining counter semantics.
Architecture constraints: Metrics must be derived in aggregation/report/evidence layers from existing deterministic facts; no pricing or hosted billing logic in core runtime.
ADR required: yes
TDD first failing test(s): Add failing governed-usage counter tests for a fixture with verified, unknown, contradictory, runtime-connected, and evidence-pack states.
Cost/perf impact: low
Chaos/failure hypothesis: Missing runtime or proof evidence should lower/unknown relevant counters deterministically instead of silently inflating governed usage.

## Epic 2: Data Posture And Public-Surface Assessment

Objective: make customer-controlled data boundaries explicit and support credible public-surface demos without private overclaims.
Traceability: Recommendations 49 and 50.

### Story 2.1: Add Customer-Controlled Deployment And Data Mode Metadata

Priority: P0
Recommendation coverage: 49

Tasks:
- Define canonical deployment/data modes: `local_only`, `customer_controlled_storage`, `connected_saas_metadata`, and `managed_platform`.
- Add mode metadata to scan output, report artifacts, evidence build results, artifact manifests, source privacy summaries, and redaction metadata where relevant.
- Keep `local_only` as the default for CLI behavior and docs. Alternate modes must be explicit and validated.
- Extend docs to explain what data is read, stored, emitted, and excluded in each mode.
- Ensure deployment mode metadata does not itself enable network calls, source retention, or hosted upload behavior.
- Add redaction tests proving public/customer-redacted outputs preserve mode labels while excluding sensitive raw evidence and private paths.

Repo paths:
- `core/cli/scan.go`
- `core/cli/report_artifacts.go`
- `core/evidence/evidence.go`
- `core/report/redaction.go`
- `core/report/build.go`
- `core/sourceprivacy`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/evidence/evidence-bundle.schema.json`
- `docs/trust/security-and-privacy.md`
- `docs/commands/scan.md`
- `docs/commands/evidence.md`

Run commands:
- `go test ./core/cli ./core/evidence ./core/report ./core/sourceprivacy -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-docs-consistency`
- `make prepush-full`

Test requirements:
- Unit tests for default mode, explicit valid modes, invalid modes, JSON metadata, report artifacts, evidence manifests, redacted share profiles, and docs examples.
- Contract tests for additive schema fields and stable enum names.
- Hardening tests for attempts to combine default local-only claims with connected/managed behaviors.

Matrix wiring:
- Fast lane: focused CLI/report/evidence data-mode tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: local-only and customer-redacted scenario outputs with expected metadata.
- Cross-platform lane: artifact path and manifest metadata stability on Windows.
- Risk lane: `make test-hardening` for invalid modes, redaction leaks, and default-posture regressions.

Acceptance criteria:
- All relevant machine-readable artifacts declare the deployment/data mode.
- `local_only` is emitted by default and no alternate mode is inferred silently.
- Docs explain data posture clearly enough for customer security review.
- Redacted artifacts preserve data-posture explanation without exposing private evidence.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added customer-controlled deployment and data-mode metadata across scan, report, and evidence artifacts, with `local_only` as the default posture.
Semver marker override: [semver:minor]
Contract/API impact: Additive CLI/config validation and JSON/schema fields for deployment/data mode.
Versioning/migration impact: v1-compatible additive fields; invalid mode handling uses existing invalid-input exit semantics.
Architecture constraints: Data posture metadata must live in CLI/source privacy/report/evidence surfaces and must not weaken deterministic offline scan behavior.
ADR required: yes
TDD first failing test(s): Add failing CLI/evidence tests proving default `local_only`, invalid mode rejection, and redacted artifact metadata behavior.
Cost/perf impact: low
Chaos/failure hypothesis: A malformed or conflicting mode declaration should fail closed with stable error output, not silently publish misleading data-posture metadata.

### Story 2.2: Add Public-Surface Demo Mapper With Claim Discipline

Priority: P1
Recommendation coverage: 50

Tasks:
- Add an opt-in public-surface assessment input model for public repos, docs, SDKs, engineering blogs, release notes, status pages, and public workflows.
- Represent public evidence provenance in the source layer with source class, URL/path, captured-at metadata where applicable, evidence label, confidence, and inference rationale.
- Add mapping logic that can produce buyer-safe public-surface findings and projections while clearly labeling public observed facts versus inferred context.
- Wire public-surface summaries into report JSON and markdown without treating public evidence as verified private deployment/control evidence.
- Add docs/examples that show how public-surface mapping supports outbound/demo workflows and how it differs from private scans.
- Add overclaim tests so public/inferred labels cannot become private verified evidence without private artifacts.

Repo paths:
- `core/cli/scan.go`
- `core/source`
- `core/report/build.go`
- `core/cli/report.go`
- `core/risk/buyer_projection.go`
- `core/report/redaction.go`
- `docs/examples`
- `schemas/v1/report/report-summary.schema.json`

Run commands:
- `go test ./core/source ./core/cli ./core/report ./core/risk -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-hardening`
- `make prepush-full`

Test requirements:
- Unit tests for public-surface manifest parsing, source class validation, evidence label assignment, inference rationale, unsupported claim handling, redaction, and deterministic sorting.
- Scenario fixture with public repo/docs/workflow/status-page examples and expected report output.
- Hardening tests for malformed public URLs, unsupported source classes, attempts to pass private paths as public evidence, and overclaiming private reachability.

Matrix wiring:
- Fast lane: focused source, CLI, report, and buyer projection tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: public-surface scenario fixture and report contract tests.
- Cross-platform lane: manifest path handling and stable ordering for local public fixture files.
- Risk lane: `make test-hardening` and `make test-chaos` for missing/partial/conflicting public evidence and overclaim prevention.

Acceptance criteria:
- Public-surface assessment is opt-in and never part of default local/private scans.
- Reports distinguish `public_observed`, `public_inferred`, `unsupported_public_claim`, and absent private evidence.
- Public-surface outputs are useful for demos while avoiding claims about private credentials, runtime behavior, approval state, or production control unless private evidence is provided.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added an opt-in public-surface assessment path for public repos, docs, SDKs, release notes, status pages, and workflows with explicit public/inferred evidence labels.
Semver marker override: [semver:minor]
Contract/API impact: Additive source target/input contract and report/schema fields for public-surface evidence.
Versioning/migration impact: v1-compatible additive fields; new input validation uses existing invalid-input and unsafe-operation exits.
Architecture constraints: Source owns public provenance; risk/report may project buyer context but must not convert public inference into verified private control evidence.
ADR required: yes
TDD first failing test(s): Add failing source/report tests proving public evidence labels and overclaim rejection.
Cost/perf impact: medium
Chaos/failure hypothesis: Partial or stale public evidence should produce explicit unsupported/unknown public labels rather than confident private findings.

## Epic 3: Product-Led Website And Demo Assets

Objective: make Wrkr's website/docs demonstrate the real product surface safely and repeatably.
Traceability: Recommendation 51.

### Story 3.1: Generate Website-Ready Sample BOM, Graph, Redacted Report, And Lab Data

Priority: P1
Recommendation coverage: 51

Tasks:
- Add curated demo fixtures that generate a stable sample Agent Action BOM, action-control graph, redacted report, interactive lab data, architecture boundary page data, and local/private data posture explanation.
- Reuse existing scenario and report generation paths instead of hand-authoring sample JSON.
- Add generation commands or scripts that write deterministic docs/example artifacts from fixtures and fail when generated files drift.
- Ensure sample artifacts use fake orgs, repos, owners, credentials, proof refs, graph refs, URLs, workflows, and public evidence.
- Update docs/examples and docs-site LLM/public assets so website copy can point to real product artifacts.
- Add tests that generated examples do not contain raw secret-looking values, developer-specific paths, private URLs, or unredacted owners under public profiles.

Repo paths:
- `internal/scenarios`
- `scenarios/wrkr`
- `docs/examples`
- `docs-site/public/llms.txt`
- `docs-site/public/llm/`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/report_test.go`
- `internal/acceptance`

Run commands:
- `go test ./core/report ./internal/scenarios ./internal/acceptance -count=1`
- `scripts/validate_scenarios.sh`
- `make test-scenarios`
- `make test-docs-consistency`
- `make docs-site-check`
- `make prepush-full`

Test requirements:
- Scenario tests for stable generated BOM, graph, redacted report, and lab data.
- Golden output tests for docs/examples artifacts.
- Hygiene tests for no machine-local absolute paths, no raw secret-like values, no private proof refs in public assets, and no hand-edited drift.
- Docs-site checks for referenced example files and LLM-facing asset consistency.

Matrix wiring:
- Fast lane: focused scenario/report generation tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario validation and acceptance checks for public/redacted artifacts.
- Cross-platform lane: stable generated paths and line endings.
- Risk lane: `make test-hardening` for redaction leaks and unsafe generated asset output.

Acceptance criteria:
- Website-ready artifacts are reproducible from checked-in fixtures and generation commands.
- Sample BOM, graph, redacted report, and lab data match public/redacted share-profile expectations.
- Docs and docs-site references stay aligned with generated artifacts.
- Generated assets explain Wrkr's architecture boundary and local/private posture without overstating control/enforcement.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added reproducible website-ready demo artifacts, including sample BOM, action-control graph, redacted report, lab data, architecture boundary assets, and local/private data posture examples.
Semver marker override: [semver:minor]
Contract/API impact: Additive docs/examples and fixture generation contracts; no required runtime API changes beyond referenced report/evidence fields.
Versioning/migration impact: Generated examples must update in the same PR as schema/report changes they demonstrate.
Architecture constraints: Demo assets must be produced through Wrkr's existing deterministic scan/report/evidence paths and must not introduce a website-only data model.
ADR required: no
TDD first failing test(s): Add failing scenario/golden tests for expected sample BOM, graph, redacted report, and lab data outputs.
Cost/perf impact: low
Chaos/failure hypothesis: Drifted or unsafe generated demo assets should fail docs/example checks before release instead of silently publishing misleading samples.

## Epic 4: Calibration And Enterprise-Scale Gates

Objective: turn precision and scale learning into repeatable quality gates.
Traceability: Recommendations 53 and 54.

### Story 4.1: Add Precision Calibration Fixtures With Known Expected Outcomes

Priority: P0
Recommendation coverage: 53

Tasks:
- Add small labeled fixtures for owner evidence present, approval outside repo, declared non-prod with production-secret contradiction, old source only, dependency-only AI package, CI automation without agent, actual AI-assisted deploy path, branch protection present/absent, and runtime evidence present.
- Define expected scan/report/BOM/control-backlog/evidence-state outcomes for each fixture.
- Wire fixtures into scenario, unit, detector, report, and acceptance tests so precision regressions are visible.
- Add coverage-map entries and docs comments explaining what each fixture calibrates.
- Ensure fixtures use fake data and no raw secrets while still exercising secret-reference and contradiction behavior.

Repo paths:
- `internal/scenarios`
- `scenarios/wrkr`
- `internal/acceptance`
- `core/report/report_test.go`
- detector tests under `core/detect`
- `core/risk`
- `core/aggregate/controlbacklog`
- `internal/scenarios/coverage_map.json`

Run commands:
- `go test ./core/detect/... ./core/report ./core/risk ./core/aggregate/controlbacklog -count=1`
- `scripts/validate_scenarios.sh`
- `make test-scenarios`
- `make test-contracts`
- `make prepush-full`

Test requirements:
- Detector tests for dependency-only versus actual agent usage, CI automation without agent versus AI-assisted deploy, branch protection present/absent, and old source-only signals.
- Report/risk tests for owner evidence, external approval evidence, production-secret contradictions, runtime evidence present, evidence-state wording, and stable top-risk ordering.
- Scenario expected outputs for each labeled case.
- Contract tests ensuring no raw secret values or fake private customer data leak.

Matrix wiring:
- Fast lane: focused detector/risk/report/control-backlog calibration tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario validation and acceptance scorecard updates.
- Cross-platform lane: fixture path normalization and stable golden outputs.
- Risk lane: `make test-hardening` for secret-looking values, contradiction handling, and branch-protection evidence gaps.

Acceptance criteria:
- Each labeled fixture has a documented expected outcome and a failing test if Wrkr overclaims, underclaims, or misclassifies the case.
- Precision fixtures distinguish context-only evidence from confirmed action paths.
- Contradictions and evidence states remain stable in scan, report, BOM, and control-backlog surfaces.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added precision calibration fixtures for ownership, approval evidence, non-production contradictions, stale source, dependency-only packages, CI automation, AI-assisted deploy paths, branch protection, and runtime evidence.
Semver marker override: [semver:minor]
Contract/API impact: Additive scenario/acceptance coverage; may expose corrected evidence-state or confidence outputs as behavior changes if bugs are found.
Versioning/migration impact: Fixture expected outputs become release-quality gates; any intentional output drift requires explicit golden updates and changelog rationale.
Architecture constraints: Detectors classify source signals, risk/report aggregate and explain them, and proof/evidence surfaces remain portable and deterministic.
ADR required: no
TDD first failing test(s): Add one failing fixture test per known-outcome case before changing detector/risk/report behavior.
Cost/perf impact: low
Chaos/failure hypothesis: Ambiguous fixture inputs should produce explicit unknown/review states rather than confident false positives.

### Story 4.2: Add Enterprise-Scale Product Pressure Tests

Priority: P0
Recommendation coverage: 54

Tasks:
- Build a synthetic or anonymized 300+ repo pressure fixture that exercises large-org summarization, redaction, scan-quality compaction, control-state consistency, evidence-state wording, proof completeness, graph size, BOM readability, and drift output.
- Add acceptance gates that run the pressure fixture in bounded time and emit a quality scorecard for release review.
- Add graph-size and markdown readability checks so reports stay compact and navigable.
- Add redaction pressure tests for customer-redacted, design-partner, external-redacted, investor-safe, and public profiles.
- Add proof completeness checks that ensure proof refs, evidence refs, and chain integrity remain explainable at scale.
- Add drift pressure outputs for new paths, removed paths, changed authority, changed evidence, changed target class, new contradictions, resolved gaps, worsened paths, and paths ready for control.
- Document how to update the fixture safely when product behavior intentionally changes.

Repo paths:
- `internal/acceptance`
- `internal/scenarios`
- `scenarios/wrkr`
- `core/report/report_test.go`
- `core/cli/report_contract_test.go`
- `core/regress`
- `schemas/v1`
- `docs/trust/wave-gates.md`
- `docs/trust/detection-coverage-matrix.md`

Run commands:
- `go test ./internal/acceptance ./internal/scenarios ./core/report ./core/cli ./core/regress -count=1`
- `scripts/validate_scenarios.sh`
- `make test-scenarios`
- `make test-perf`
- `make test-hardening`
- `make test-chaos`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make prepush-full`

Test requirements:
- Acceptance test for 300+ repo synthetic/anonymized scan/report/evidence/regress workflow.
- Performance thresholds for scan/report/render/graph/BOM generation with stable deterministic order.
- Redaction tests proving private values are absent across share profiles.
- Contract tests for schema validity and stable summary fields.
- Chaos tests for partial repo failures, reduced detector confidence, corrupt baseline/drift inputs, missing proof refs, and interrupted output generation.

Matrix wiring:
- Fast lane: focused large-fixture helpers and summary tests where possible.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: full enterprise pressure fixture and release scorecard.
- Cross-platform lane: Windows smoke for large fixture traversal, path sorting, and markdown artifacts.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf` for scale, redaction, proof, drift, and graph-size behavior.
- Release/UAT lane: `make test-release-smoke` and `scripts/run_v1_acceptance.sh --mode=release` when pressure gates become release-blocking.

Acceptance criteria:
- Enterprise pressure tests run reproducibly without customer data and catch noisy, inconsistent, overclaiming, unreadable, or incomplete report output.
- Large-org reports stay compact, ranked, redacted, schema-valid, proof-explainable, and drift-aware.
- Release/UAT docs explain how pressure gates should be interpreted and updated.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added enterprise-scale pressure tests for large-org reporting, redaction, scan quality, control-state consistency, evidence wording, proof completeness, graph size, BOM readability, and drift output.
Semver marker override: [semver:minor]
Contract/API impact: Additive acceptance/release gates; may enforce existing public contracts more strictly.
Versioning/migration impact: Pressure-fixture expected outputs become release evidence; intentional drift requires explicit fixture and changelog updates.
Architecture constraints: Scale gates must validate the existing source -> detection -> aggregation -> risk -> proof/evidence/report boundaries instead of adding shortcut summary paths.
ADR required: yes
TDD first failing test(s): Add failing enterprise pressure acceptance test that captures current large-org readability, redaction, proof, graph, BOM, and drift gaps.
Cost/perf impact: high
Chaos/failure hypothesis: A 300+ repo scan with partial failures and contradictory evidence should remain bounded, sorted, redacted, proof-explainable, and readable rather than timing out or producing unreadable bulk output.

## Definition of Done

- The generated plan remains the only file changed by this workflow before implementation begins.
- Every recommendation 48-54 maps to at least one story and one acceptance path.
- All implementation PRs follow TDD: failing tests first, minimal implementation, refactor with tests green.
- All new JSON/report/evidence/schema fields are additive or explicitly versioned.
- `local_only` remains the default data posture and no new default exfiltration path is introduced.
- Public-surface evidence is labeled and cannot overclaim private reachability, approval, runtime behavior, credential authority, or verified control.
- Large-org rollups and governed-usage metrics are deterministic, non-sensitive, redaction-aware, and schema-covered.
- Website-ready assets are reproducible from fixtures and contain no customer data, raw secrets, machine-local paths, or private proof refs.
- Precision and enterprise pressure fixtures are documented, deterministic, and wired into scenario/acceptance gates.
- Docs, command help, schemas, examples, and changelog entries update in the same PR as user-visible behavior.
- Required validation lanes for implementation include focused tests, `make test-contracts`, `make test-scenarios`, relevant risk lanes, docs checks, and `make prepush-full` for architecture/risk/contract changes.

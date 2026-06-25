# Adhoc Plan: Control Resolution Loop

Date: 2026-06-25
Profile: `wrkr`
Slug: `control-resolution-loop`
Recommendation source: user-provided recommendations for closing the loop after customer review, including durable control declarations, stable resolution keys, provider evidence imports, evidence-scoped language, authority-aware recommendations, customer review lifecycle, redacted/internal artifact pairing, one-page Agent Action BOM views, closure guidance, governed CI classification, drift/reopen behavior, declaration export workflow, and enterprise-shaped regression fixtures.

All paths in this plan are repo-relative. User-provided absolute checkout paths have been normalized to repo-relative paths. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, scenario, or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control sequence. This plan must not add Axym compliance-engine behavior, Gait runtime enforcement, scan-time LLM calls, live provider API dependency, hidden telemetry, or default network enrichment.
- Customer review context is evidence, not suppression. A reviewed path may move out of primary unresolved control-first output only when the report preserves the path, scope, issuer, rationale, evidence refs, freshness, and review state in JSON and appendix output.
- Existing Wrkr evidence-state and external-evidence primitives are the baseline. New work must extend `core/risk/evidence_state.go`, `core/config/control_declarations.go`, `core/attribution/control_metadata.go`, `core/ingest/external_schema.go`, and report/contract schemas rather than creating parallel control logic in report layers.
- Stable resolution identity is required before declarations can govern recurring scans. `path_id` remains a direct reference, but a new stable resolution key and selector match result must survive report ordering, path ranking, and harmless detector churn where the underlying evidence source is equivalent.
- Declaration files stay local and deterministic. `.wrkr/control-declarations.yaml` and compatible governance-repo imports must parse with structured YAML, fail closed on invalid input, avoid raw secret extraction, and never make network calls.
- Provider evidence imports are file-based first. GitHub, GitLab, Azure DevOps, app catalog, branch protection, PR review, environment approval, required check, workflow permission, and merge metadata evidence must enter Wrkr as schema-backed local sidecars or exports.
- Evidence language must be scoped to what Wrkr observed or imported. Buyer-facing surfaces must say "not imported or observed" for unknown evidence and reserve absence claims for verified absence with coverage.
- Authority-aware recommendations are mandatory. Static API/target context, unknown credential scope, no linked credential, referenced credential, and confirmed standing credential paths require different recommended actions and risk language.
- Standard governed CI must not be treated like agentic delegated production authority. CI classification must distinguish governed CI, broad standing authority, untrusted PR reachability, workflow/release mutation, agentic CI, and production/release action paths.
- Redacted/internal artifact pairing is part of the customer loop. Shareable artifacts must stay safe by default, while internal artifacts or a local-only join map retain remediation detail. The join map is never included in shareable bundles unless an explicit unsafe operation is approved and gated.
- Drift, expiry, and contradiction reopen resolved paths. Expired accepted risk, changed workflow evidence, changed credential family, non-prod declarations contradicted by production evidence, and disappeared imported controls must re-enter the unresolved review flow with explicit reopen reasons.
- Every implementation PR from this plan must include changelog intent, tests at the right layer, docs parity for public behavior, and deterministic validation receipts. Changelog entries are required for every story because all stories touch public report, schema, docs, CLI, or OSS trust semantics.

## Current Baseline (Observed)

- `core/config/control_declarations.go` already loads `wrkr-control-declarations.yaml` and `.wrkr/control-declarations.yaml`, validates schema version `v1`, supports owner, target, and control declarations, checks RFC3339 timestamps, validates evidence refs/redaction modes, merges inputs deterministically, and uses `gopkg.in/yaml.v3`.
- `core/attribution/control_metadata.go` already loads `.wrkr/provenance/control-metadata.json`, `.wrkr/provenance/control-declarations.json`, and typed external-control evidence into control metadata. It can project declared/external controls, freshness, contradictions, owner/target declarations, and wildcard declaration matches.
- `schemas/v1/evidence/external-control-evidence.schema.json` already defines a provider-neutral `external_control` sidecar with source type, source, issuer, repo/service/workflow/environment/path selectors, evidence class, freshness, redaction hints, status, refs, owner, branch, and required checks.
- `core/risk/evidence_state.go` already defines control resolution states `detected_control`, `declared_control`, `external_control_reference`, `no_visible_control`, `not_applicable`, and `contradictory_control`, plus evidence states `verified`, `declared`, `inferred`, `unknown`, and `contradictory`.
- `core/risk/action_paths.go` already carries action-path evidence states, control resolution fields, target class, action path type, closure requirements, evidence completeness, credential authority refs, authority bindings, action lineage, and control-first summary counters.
- `core/risk/action_lineage.go` already builds deterministic lineage segments for intent, task, human, repo, PR, workflow, workflow run, agent, action, credential, target, owner, approval, control, deployment, outcome, proof, and evidence.
- `core/regress/action_path_drift.go` already snapshots action-path identity and drift fields, including control resolution state and evidence-state dimensions. It does not yet expose a customer review lifecycle state or declaration-specific reopen reason model.
- `core/aggregate/controlbacklog/controlbacklog.go` already emits accepted-risk queues, governance dispositions, lifecycle queues, closure criteria, closure requirements, evidence completeness, control resolution state, evidence states, target/action path types, and canonical projection refs.
- `core/report/agent_action_bom.go`, `core/report/primary_view.go`, `core/report/executive_rollup.go`, `core/report/artifact_pairing.go`, and `core/report/render_markdown.go` already support Agent Action BOM primary views, executive grouping, internal/customer-redacted variants, private join maps, evidence-state wording, and canonical ref stripping.
- `core/cli/report.go`, `core/cli/report_artifacts.go`, and `core/cli/export.go` already have report/export surfaces where paired artifacts, share profiles, focus paths, and declaration/export workflows can be extended without bypassing CLI exit-code contracts.
- `docs/commands/ingest.md`, `docs/commands/report.md`, `docs/commands/export.md`, `docs/commands/evidence.md`, and `docs/trust/contracts-and-schemas.md` already document evidence-state, external-control, artifact pairing, and schema contracts, but they do not yet describe the full scan -> review -> declare/import -> rerun -> reopen loop as a first-class operator workflow.
- Existing scenario and acceptance tests cover evidence-state projection, external-control evidence, report overclaim language, sprint-0 size/signal budgets, Agent Action BOM, buyer projection parity, control backlog governance, action-path semantics, delivery-chain correlation, workflow capabilities, and artifact pairing. New regression fixtures should extend those harnesses instead of inventing another test tier.

## Exit Criteria

- A customer can add a single `.wrkr/control-declarations.yaml` entry against a stable resolution key or selector, rerun Wrkr, and see the same path moved out of unresolved control-first output into a resolved/declared appendix with clear audit context.
- A declaration can match by `path_id`, stable resolution key, finding key, repo/workflow/location selector, evidence location, action class, target class, credential family, and control category. Every match reports confidence and mismatch reasons.
- Invalid declarations fail closed with deterministic error text and exit `6` or `3` as appropriate. Declarations never silently suppress findings, never extract raw secrets, and never produce hidden network access.
- Review lifecycle states are first-class across action paths, control backlog, Agent Action BOM, report summaries, evidence JSON, schemas, regress snapshots, and docs. Required states are `open`, `confirmed`, `declared_controlled`, `covered_by_imported_control`, `accepted_risk`, `not_applicable`, `false_positive`, `needs_runtime_evidence`, `expired`, and `reopened_by_drift`.
- Expired, contradicted, or drifted declarations reopen paths with a specific reopen reason and enough evidence refs to understand what changed.
- Imported provider evidence can resolve matching approval, branch protection, required check, CODEOWNERS, environment approval, deployment gate, workflow permission, and merge metadata gaps without live provider API calls.
- Buyer-facing wording no longer says approval, proof, owner, or control is missing unless verified absence exists. Unknown evidence renders as not imported/observed.
- Top recommendations are authority-aware. Static API/target context asks for caller correlation; unknown credential scope asks for credential authority correlation; confirmed standing release/production authority keeps strong control recommendations.
- Standard governed CI flows with imported or declared branch protection and review evidence are downgraded from top unresolved control-first output unless broad standing authority, untrusted PR reachability, workflow/release mutation, agentic CI, or production/release action path evidence remains.
- Default Agent Action BOM Markdown leads with a bounded top-five action view covering what can change, authority used, visible controls, unresolved evidence, recommended closure action, and confidence label, with full detail in appendix/evidence JSON.
- Redacted and internal artifacts are generated as a paired bundle with a local-only join map, and tests prove the join map is excluded from shareable bundles by default.
- Synthetic enterprise-shaped fixtures prevent regressions in size, wording, redaction, evidence-state, lifecycle, governed CI, declaration, expiry, contradiction, and one-page lead behavior.

## Public API and Contract Map

- CLI contracts:
  - Preserve exit codes: `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, and `8` unsafe operation blocked.
  - Extend `wrkr scan --json` and `wrkr report --json` only with additive local-file declaration/provider evidence loading and additive lifecycle/resolution fields.
  - Extend `wrkr report --md` with bounded top-five lead behavior and resolved/declared appendix visibility.
  - Extend `wrkr export --json` or a report-adjacent export mode to emit suggested declaration snippets or patch artifacts, without pushing or opening GitHub PRs by default.
  - Preserve `--quiet` CI behavior and `--explain` rationale where existing command surfaces expose them.
- JSON and schema contracts:
  - Additive fields include `resolution_key`, `resolution_selector`, `resolution_match_confidence`, `resolution_mismatch_reasons`, `review_lifecycle_state`, `review_lifecycle_reasons`, `review_rationale`, `review_owner`, `review_source`, `review_observed_at`, `review_valid_until`, `review_scope`, `resolved_visibility`, `reopen_state`, `reopen_reasons`, `reopen_evidence_refs`, `ci_flow_class`, `ci_flow_reasons`, and declaration snippet metadata.
  - Add or extend schemas under `schemas/v1/evidence`, `schemas/v1/agent-action-bom.schema.json`, `schemas/v1/report/report-summary.schema.json`, `schemas/v1/risk/risk-report.schema.json`, `schemas/v1/regress/regress-result.schema.json`, and `schemas/v1/control-path-graph.schema.json` where the fields are serialized.
  - Existing compatibility fields such as `path_id`, `control_resolution_state`, `approval_evidence_state`, `closure_requirements`, accepted-risk queue fields, and `missing_*` compatibility counters must remain derived from canonical state, not maintained independently.
- Detection, risk, and aggregation contracts:
  - `core/risk` owns stable resolution key derivation, authority-aware recommendation selection, CI flow classification, lifecycle/reopen projection, and control-state consistency.
  - `core/attribution` and `core/config` own structured declaration/provider input parsing and normalization.
  - `core/aggregate/controlbacklog` owns queue placement, resolved/declared appendix visibility, lifecycle queues, closure requirements, and governance disposition output.
  - Report packages consume projected state and must not parse raw declarations or re-derive lifecycle decisions.
- Proof and evidence contracts:
  - Proof record types stay aligned with `Clyra-AI/proof` primitives: `scan_finding`, `risk_assessment`, `approval`, and `lifecycle_transition`.
  - Review lifecycle changes should emit or map to proof/evidence refs where current proof emission supports it, without breaking chain verification.
  - Evidence bundles should include internal/customer-redacted report artifacts and local-only join-map metadata while preserving portable, verifiable artifacts.
- Documentation contracts:
  - Docs must explain the operator loop: scan, inspect top paths, import or declare evidence, rerun, see resolved appendix, and reopen on expiry/drift/contradiction.
  - Docs must use profile commands such as `wrkr scan --json`, `wrkr regress run --baseline <baseline-path> --json`, and `wrkr score --json` when machine-readable examples are needed.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/report.md`
  - `docs/commands/ingest.md`
  - `docs/commands/export.md`
  - `docs/commands/evidence.md`
  - `docs/commands/regress.md`
  - `docs/trust/contracts-and-schemas.md`
  - `docs/state_lifecycle.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Contract and scenario docs impacted:
  - `internal/scenarios/coverage_map.json`
  - scenario fixtures under `scenarios/wrkr/**`
  - acceptance expectations under `internal/acceptance`
  - contract tests under `testinfra/contracts`
- OSS trust baseline:
  - Example declarations, provider exports, PR review evidence, branch protection evidence, join maps, and enterprise-shaped fixtures must use fake orgs, repos, owners, teams, services, tickets, URLs, hashes, workflow names, and provider IDs.
  - No generated customer reports, private scan outputs, proof chains, raw provider exports, local join maps, credentials, binaries, or transient state files may be committed outside deterministic fixtures.
  - Public docs must state that Wrkr consumes local evidence exports and declarations by default; it does not query provider APIs or mutate GitHub unless a future explicit command is invoked.
  - Redacted examples must preserve structure and remediation flow without leaking owner, repo, workflow, path, service, or ticket identifiers.
- Docs must answer:
  - Which declaration states are supported and when each one moves an item out of unresolved control-first output.
  - How stable resolution keys and selectors are constructed and how match confidence is reported.
  - How imported provider evidence differs from declared evidence and inferred evidence.
  - What causes expiry, contradiction, or drift reopening.
  - How to use internal artifacts or the local join map to remediate after sharing a redacted report.

## Recommendation Traceability

| Recommendation | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| Customer control declarations | P0 | Stories 1.2, 2.1, 4.2 | Customers need a durable way to feed reviewed context back into Wrkr. | Extend declarations into review dispositions with scope, issuer, rationale, expiry, resolved appendix visibility, and snippet generation. | Follow-up scans become quieter while preserving audit evidence. |
| Stable resolution keys for paths and findings | P0 | Story 1.1 | `path_id` alone can churn when code moves or report ordering changes. | Add deterministic resolution keys and selector fallback with match confidence. | Customer decisions survive reruns and harmless implementation churn. |
| Provider control evidence import | P0 | Story 3.1 | Enterprise controls often live outside scanned source. | Correlate local provider evidence sidecars to stable resolution keys and lifecycle state. | Reports can say approval evidence was imported instead of not observed. |
| Evidence-state terminology migration | P0 | Stories 4.1, 5.1 | Buyer-facing overclaims damage credibility. | Enforce evidence-scoped wording in reports, schemas, docs, and fixtures. | Reports stay precise about what Wrkr knows. |
| Authority-aware recommendations | P0 | Story 3.2 | Generic remediation text inflates risk when authority is none or unknown. | Split recommendations by authority confidence and static-context status. | Top findings become more actionable and less noisy. |
| Customer review lifecycle | P0 | Stories 2.1, 2.2 | Customers need to know what happens after review. | Add lifecycle states, appendix visibility, history refs, and reopen reasons. | Review once, encode decision, rerun, and detect drift. |
| Internal and redacted artifact pairing with join map | P1 | Story 4.3 | Redacted reports are share-safe but insufficient for remediation. | Harden paired internal/redacted artifacts and local-only join-map rules. | Customers can share safely and still remediate locally. |
| One-page executive action view | P1 | Story 4.1 | Large reports are not buyer-ready by default. | Lead with bounded top-five action paths and move detail to appendix/evidence JSON. | Buyers understand top risks in under 60 seconds. |
| Path-specific closure guidance | P1 | Stories 4.2, 3.2 | Generic "go confirm" guidance does not tell operators what to do next. | Generate closure actions based on evidence gap, authority type, and path class. | Customers can turn findings into declarations/imports without Clyra support. |
| Standard CI flow classification | P0 | Story 3.2 | Credential-bearing CI is not automatically an agentic high-risk path. | Classify governed CI, broad standing authority, untrusted PR reachability, workflow/release mutation, agentic CI, and production/release action paths. | Standard enterprise CI stops dominating top findings. |
| Drift, expiry, and reopen logic | P0 | Story 2.2 | Controls drift and decisions expire. | Reopen resolved items when evidence expires, changes materially, or disappears. | Resolved paths stay quiet only while evidence remains valid. |
| GitHub declaration PR workflow | P1 | Story 4.2 | Customers need a practical way to add reviewed context back to source. | Generate snippets or patch files, with no automatic push/PR by default. | The scan -> review -> declare -> rerun loop becomes concrete. |
| Regression fixtures from latest enterprise scans | P0 | Story 5.1 | Recent size, wording, redaction, and signal improvements need guardrails. | Add synthetic fixtures that preserve enterprise shapes without customer data. | Future releases do not reintroduce giant reports or overclaiming language. |

## Test Matrix Wiring

- Fast lane:
  - Focused unit tests for resolution-key derivation, selector matching, declaration validation, lifecycle projection, reopen reason selection, provider evidence correlation, authority-aware recommendation templates, CI flow classification, primary-view line budgets, snippet generation, redaction pairing, and report wording helpers.
  - Candidate command: `go test ./core/config ./core/attribution ./core/risk ./core/aggregate/controlbacklog ./core/report ./core/cli ./core/regress -count=1`.
- Core CI lane:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
- Acceptance lane:
  - `scripts/validate_scenarios.sh`
  - `make test-scenarios`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `go test ./internal/acceptance -run 'Test.*ActionBOM|Test.*ExternalControl|Test.*Overclaim|Test.*Size|Test.*Projection|Test.*Redaction' -count=1`
- Cross-platform lane:
  - Windows smoke must cover declaration path normalization, selector matching, provider sidecar paths, generated patch paths, join-map path behavior, Markdown rendering, JSON schema validation, and stable sorting without POSIX-only assumptions.
- Risk lane:
  - `make test-hardening` for invalid declarations, unsafe patch paths, expired evidence, contradiction reopening, raw-secret-looking payload rejection, join-map exclusion, and fail-closed schema behavior.
  - `make test-chaos` for unreadable declaration files, corrupt provider sidecars, partial artifact-pair writes, disappeared imported controls, stale regress baselines, and large fixture report generation.
  - `make test-perf` for large-org fixture size and primary-view/report budget changes.
  - `make codeql` if implementation adds parsing, file mutation, CI workflow, dependency, or security-sensitive scanner logic.
- Release/UAT lane:
  - `scripts/run_v1_acceptance.sh --mode=local`
  - `make test-release-smoke` when docs examples, schemas, or report examples change.
- Gating rule:
  - Wave 1 must land before lifecycle, provider import, or snippet workflows depend on resolution selectors.
  - Wave 2 must land before reports can claim review decisions are durable or reopen-safe.
  - Wave 3 must land before top recommendations or CI classification are advertised as authority-aware.
  - Wave 4 must land before docs claim a one-page executive BOM, declaration export workflow, or share-safe remediation bundle.
  - Wave 5 must land before release notes claim enterprise-size, redaction, wording, lifecycle, or governed-CI regression protection.

## Minimum-Now Sequence

- Wave 1 - Stable resolution and declaration contract:
  - Story 1.1 adds stable resolution keys and selector matching.
  - Story 1.2 extends control declarations into review dispositions and lifecycle input.
- Wave 2 - Lifecycle, resolved visibility, and reopen:
  - Story 2.1 applies review lifecycle decisions to action paths, backlog, BOM, evidence JSON, and appendices.
  - Story 2.2 adds expiry, drift, contradiction, and disappeared-control reopen logic.
- Wave 3 - Imported controls and calibrated recommendations:
  - Story 3.1 correlates provider evidence sidecars to resolution keys and lifecycle state.
  - Story 3.2 adds authority-aware recommendations and governed-CI classification.
- Wave 4 - Buyer/operator output loop:
  - Story 4.1 ships the bounded top-five Agent Action BOM lead view and evidence-scoped language lint.
  - Story 4.2 generates path-specific closure actions and declaration snippets/patches.
  - Story 4.3 hardens paired internal/redacted artifacts and join-map contracts.
- Wave 5 - Enterprise-shaped guardrails:
  - Story 5.1 adds synthetic fixtures and regression gates for the full customer review loop.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No default live API calls to GitHub, GitLab, Azure DevOps, Jira, ServiceNow, Backstage, cloud providers, CI providers, or customer systems.
- No automatic GitHub mutation, push, branch creation, or PR opening from core Wrkr by default.
- No Axym product logic, Gait enforcement implementation, runtime interception, or policy enforcement side effects in Wrkr.
- No LLM-based classification, model-generated findings, or non-deterministic scan/risk/proof decisions.
- No extraction, display, hashing, or persistence of raw secret values.
- No hidden suppression or deletion of findings without appendix/evidence visibility.
- No incompatible removal of existing v1 JSON fields without explicit versioned migration and compatibility handling.
- No developer-specific checkout paths, private customer names, real provider exports, private owners, or generated transient reports in committed artifacts.

## Definition of Done

- Every story starts with failing unit, contract, scenario, or acceptance tests that encode the intended behavior.
- New fields are additive, schema-validated, deterministic, documented, and redaction-safe.
- Stable resolution keys and selector matches are byte-stable across repeated runs and insensitive to report ordering.
- Declaration, provider, and lifecycle inputs fail closed on invalid shape, invalid scope, unsafe paths, expired evidence, contradiction, or unsupported schema versions.
- Resolved, accepted-risk, false-positive, not-applicable, and imported-control items remain visible in appendix/evidence JSON and never disappear from audit context.
- Reopened paths identify expiry, drift, contradiction, changed credential family, target escalation, or disappeared imported control with deterministic reason codes.
- Buyer-facing reports avoid unsupported "missing approval/proof/owner/control" phrasing and distinguish not imported/observed from verified absence.
- Redacted artifacts are share-safe, internal artifacts are remediation-ready, and local-only join maps are excluded from shareable bundles by default.
- Validation receipts include focused commands, `make lint-fast`, `make test-fast`, `make test-contracts`, scenario/acceptance lanes, risk lanes, docs checks, and any release/UAT commands required by the touched surface.

## Epic 1: Stable Resolution And Declaration Contract

Objective: make customer review decisions attach to stable, explainable keys instead of transient presentation IDs.
Traceability: Recommendations 1, 2, 6, 11, and 12.

### Story 1.1: Stable Resolution Keys And Selector Matching

Priority: P0
Recommendation coverage: 2, 11

Tasks:

- Add a canonical `resolution_key` to `risk.ActionPath`, Agent Action BOM items, control backlog items, report summaries, risk report paths, regress snapshots, and relevant schemas.
- Derive the key from stable components where available: org, repo, normalized workflow/config path, detector source, finding key, credential reference family, action classes, target class, evidence location, and canonical lineage segment refs.
- Preserve `path_id` as the strongest direct reference, but add selector fallback matching for declarations and provider evidence when `path_id` changes.
- Add `resolution_selector`, `resolution_match_confidence`, and `resolution_mismatch_reasons` to report/evidence output where a declaration or provider sidecar matches through a fallback selector.
- Normalize path separators, case where provider semantics require it, generated-file suppression effects, and empty values deterministically.
- Ensure resolution key generation lives in `core/risk` or an adjacent risk helper, with report, attribution, regress, and backlog layers consuming it rather than reimplementing it.
- Add additive schema fields and compatibility notes under `schemas/v1` and `docs/trust/contracts-and-schemas.md`.

Repo paths:

- `core/risk/action_paths.go`
- `core/risk/action_lineage.go`
- `core/risk/canonical_projection.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/report/primary_view.go`
- `core/regress/action_path_drift.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/regress/regress-result.schema.json`
- `docs/trust/contracts-and-schemas.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk -run 'Test.*ResolutionKey|Test.*ActionLineage|Test.*Selector' -count=1`
- `go test ./core/report ./core/aggregate/controlbacklog ./core/regress -run 'Test.*ResolutionKey|Test.*Selector|Test.*Drift' -count=1`
- `make test-contracts`
- `make prepush-full`

Test requirements:

- Unit tests prove the same fixture emits the same `resolution_key` across repeated runs.
- Unit tests prove report ordering, ranking changes, and unrelated path additions do not change the key.
- Selector tests prove a declaration can match when `path_id` changes but repo, workflow/config path, detector source, credential family, action class, target class, and evidence location remain equivalent.
- Negative tests emit mismatch reasons when repo, credential family, target class, or evidence source changes materially.
- Contract tests validate additive fields and prove old `path_id` consumers still receive stable output.

Matrix wiring:

- Fast lane: focused `core/risk`, `core/report`, `core/aggregate/controlbacklog`, and `core/regress` tests for keys and selectors.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: scenario fixture with a moved workflow path that still matches by stable selector.
- Cross-platform lane: Windows path normalization and case/drive-free key derivation.
- Risk lane: `make test-hardening` for ambiguous selector collisions and unsafe path normalization.

Acceptance criteria:

- Every governable action path and report item has a deterministic `resolution_key`.
- A declaration that references a prior `path_id` can still match by selector when the underlying evidence source is equivalent.
- Ambiguous selector matches do not resolve silently; they report deterministic mismatch or ambiguity reasons.
- Existing public `path_id` behavior remains compatible.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added stable resolution keys and selector matching so reviewed action paths can survive harmless path-id churn across reruns.
Semver marker override: [semver:minor]
Contract/API impact: Adds public JSON/schema fields for resolution keys, selectors, match confidence, and mismatch reasons.
Versioning/migration impact: Additive v1 fields; existing `path_id` remains supported as a direct reference.
Architecture constraints: Keep key derivation in the Risk boundary and consume it from Aggregation, Regress, and Report layers.
ADR required: yes
TDD first failing test(s): `TestResolutionKeyStableAcrossReportOrdering`, `TestDeclarationSelectorMatchesPathIDChurn`, and `TestResolutionSelectorAmbiguityFailsClosed`.
Cost/perf impact: low
Chaos/failure hypothesis: Ambiguous or malformed selector input fails closed and leaves the path unresolved with mismatch reasons instead of suppressing it.

### Story 1.2: Review Disposition Declarations

Priority: P0
Recommendation coverage: 1, 6, 11, 12

Tasks:

- Extend `.wrkr/control-declarations.yaml` to support review dispositions in addition to the current owner, target, and control declarations.
- Define supported declaration states: `declared_controlled`, `accepted_risk`, `not_applicable`, `false_positive`, `needs_runtime_evidence`, and `confirmed`.
- Require each disposition to include source, issuer or owner, rationale, observed_at, optional valid_until or max_age, scope, and either `path_id`, `resolution_key`, `finding_key`, or selector fields.
- Add schema coverage for control declarations under `schemas/v1/evidence/control-declarations.schema.json` or an equivalent v1 evidence schema path.
- Load declarations through the existing `core/config/control_declarations.go` path and project normalized metadata through `core/attribution/control_metadata.go`.
- Preserve current owner/target/control declaration compatibility and deterministic merge ordering.
- Add explicit unsupported-state, duplicate-scope, expired-at-load, invalid-time-window, unsafe-path, and raw-secret-looking payload failures.
- Update docs with examples for repo-local and governance-repo declaration files.

Repo paths:

- `core/config/control_declarations.go`
- `core/config/control_declarations_test.go`
- `core/attribution/control_metadata.go`
- `core/attribution/attribution_test.go`
- `core/risk/evidence_state.go`
- `schemas/v1/evidence/control-declarations.schema.json`
- `schemas/v1/evidence/external-control-evidence.schema.json`
- `schemas/v1/README.md`
- `docs/commands/scan.md`
- `docs/commands/report.md`
- `docs/trust/contracts-and-schemas.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/config ./core/attribution ./core/risk -run 'Test.*ControlDeclaration|Test.*ReviewDisposition|Test.*DeclarationState|Test.*Expired|Test.*Contradict' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make prepush-full`

Test requirements:

- Unit tests prove declaration files load deterministically from both supported locations.
- Schema tests prove each supported review disposition validates and unsupported states fail.
- Invalid declaration tests return clear deterministic errors.
- Expired declarations are represented as expired or reopened input, not as active resolution.
- Contradictory declarations, such as non-prod scope with production credential evidence, project contradiction metadata.

Matrix wiring:

- Fast lane: focused declaration parser, normalizer, and attribution tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: scenario fixture with one declared controlled path, one accepted risk, one false positive, one expired declaration, and one contradiction.
- Cross-platform lane: declaration lookup and selector path normalization on Windows.
- Risk lane: `make test-hardening` and `make test-chaos` for unreadable files, unsafe paths, corrupt YAML, duplicate scopes, and expired evidence.

Acceptance criteria:

- A customer can add one review disposition declaration and rerun Wrkr without changing scan inputs.
- Invalid declarations fail with deterministic errors and no partial state mutation.
- Active dispositions can be consumed by lifecycle projection, while expired or contradictory declarations cannot silently resolve a path.
- Declaration examples contain no real customer data or secrets.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added review disposition declarations for controlled, accepted-risk, not-applicable, false-positive, runtime-evidence-needed, and confirmed action paths.
Semver marker override: [semver:minor]
Contract/API impact: Adds public declaration schema and additive normalized declaration fields in report/evidence outputs.
Versioning/migration impact: Existing v1 owner, target, and control declarations remain valid; review dispositions are additive.
Architecture constraints: Keep structured YAML parsing in Config/Attribution; report and risk layers consume normalized declaration metadata only.
ADR required: yes
TDD first failing test(s): `TestReviewDispositionDeclarationValidates`, `TestInvalidReviewDispositionFailsClosed`, and `TestExpiredDeclarationDoesNotResolvePath`.
Cost/perf impact: low
Chaos/failure hypothesis: Corrupt or conflicting declaration files fail closed and preserve previous report behavior without hidden suppression.

## Epic 2: Lifecycle, Visibility, And Reopen Semantics

Objective: make reviewed findings durable, auditable, and safe to reopen when evidence changes.
Traceability: Recommendations 1, 6, and 11.

### Story 2.1: Review Lifecycle Projection And Resolved Appendix

Priority: P0
Recommendation coverage: 1, 6

Tasks:

- Add canonical `review_lifecycle_state` values: `open`, `confirmed`, `declared_controlled`, `covered_by_imported_control`, `accepted_risk`, `not_applicable`, `false_positive`, `needs_runtime_evidence`, `expired`, and `reopened_by_drift`.
- Project review lifecycle state onto `risk.ActionPath`, control backlog items, Agent Action BOM items, primary/appendix report JSON, risk report output, and evidence bundle report artifacts.
- Move active resolved states out of unresolved control-first top output while preserving them in a resolved/declared appendix and evidence JSON.
- Preserve `accepted_risk_queue` and governance disposition behavior, but connect it to the canonical review lifecycle state rather than only approval-state aliases.
- Add visibility fields such as `resolved_visibility`, `resolved_appendix_refs`, and `review_audit_context` where needed.
- Ensure `false_positive` and `not_applicable` remain visible with issuer, rationale, scope, evidence refs, and validity.
- Update Markdown rendering to show resolved counts, not hide them as absent work.

Repo paths:

- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/executive_rollup.go`
- `core/report/types.go`
- `core/evidence/control_evidence_test.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report -run 'Test.*ReviewLifecycle|Test.*ResolvedAppendix|Test.*AcceptedRisk|Test.*FalsePositive|Test.*NotApplicable' -count=1`
- `go test ./core/evidence ./core/cli -run 'Test.*ReviewLifecycle|Test.*ReportContract|Test.*Evidence' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:

- Unit tests prove active accepted risk with future expiry is not emitted as a top unresolved control-first item.
- Unit tests prove false positives and not-applicable paths remain visible in appendix/evidence JSON.
- Contract tests prove lifecycle fields validate across Agent Action BOM, report summary, risk report, and evidence outputs.
- Scenario tests prove a declared controlled path moves to resolved appendix while preserving audit context.
- Markdown tests prove resolved counts and appendix pointers render clearly.

Matrix wiring:

- Fast lane: focused risk, backlog, report, CLI contract, and evidence tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: scenario fixture covering every lifecycle state and appendix visibility.
- Cross-platform lane: resolved appendix artifact path behavior on Windows.
- Risk lane: `make test-hardening` for hidden suppression attempts and invalid state transitions.

Acceptance criteria:

- A declared controlled path no longer appears as unresolved control-first, but appears in a resolved/declared appendix with issuer, rationale, scope, evidence refs, and validity.
- Accepted risk, false-positive, and not-applicable decisions never remove audit evidence from JSON or Markdown.
- Lifecycle state is consistent across BOM, backlog, risk report, report summary, and evidence artifacts.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed reviewed action-path handling so controlled, accepted-risk, not-applicable, and false-positive paths move to auditable resolved appendices instead of disappearing or staying as unresolved top findings.
Semver marker override: [semver:minor]
Contract/API impact: Adds public lifecycle and resolved-appendix fields to report, BOM, risk, and evidence contracts.
Versioning/migration impact: Existing accepted-risk queue fields remain; lifecycle fields become the canonical read model.
Architecture constraints: Risk owns lifecycle projection; report layers render projected state without interpreting raw declarations.
ADR required: yes
TDD first failing test(s): `TestDeclaredControlledPathMovesToResolvedAppendix`, `TestFalsePositiveVisibleInAuditAppendix`, and `TestAcceptedRiskFutureExpiryNotTopControlFirst`.
Cost/perf impact: low
Chaos/failure hypothesis: If lifecycle projection cannot determine state safely, the path remains `open` and unresolved with a reason instead of being suppressed.

### Story 2.2: Expiry, Drift, Contradiction, And Reopen Logic

Priority: P0
Recommendation coverage: 6, 11

Tasks:

- Add reopen state and reason projection for expired declarations, material workflow/config change, credential family change, target class escalation, production credential evidence after non-prod declaration, disappeared imported provider control, and contradicted owner/approval/proof evidence.
- Extend regress action-path snapshots to compare `resolution_key`, selector components, evidence fingerprints, declaration validity, imported-control refs, credential family, target class, and control resolution state.
- Emit `reopen_state`, `reopen_reasons`, `reopen_evidence_refs`, and `previous_review_lifecycle_state` in report/evidence outputs where a path reopens.
- Route reopened paths to unresolved control-first or review queue according to severity and authority, not to resolved appendices.
- Use exit `5` only for regression drift command behavior where existing regress policy expects drift; scan/report should show reopen reasons without treating valid user input as runtime failure.
- Add hardening tests for clock-sensitive expiry by injecting deterministic time in tests.

Repo paths:

- `core/regress/action_path_drift.go`
- `core/regress/regress.go`
- `core/risk/action_paths.go`
- `core/risk/evidence_state.go`
- `core/risk/buyer_projection.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/state/state.go`
- `schemas/v1/regress/regress-result.schema.json`
- `docs/commands/regress.md`
- `docs/state_lifecycle.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/regress ./core/risk ./core/aggregate/controlbacklog ./core/report ./core/state -run 'Test.*Reopen|Test.*Expired|Test.*Drift|Test.*Contradict|Test.*DisappearedControl' -count=1`
- `go test ./internal/e2e/regress -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`

Test requirements:

- Expired accepted risk returns to unresolved or reopened state with reason `declaration_expired`.
- Non-prod declaration plus production secret or production target evidence becomes contradictory and reopens.
- Removed branch protection or disappeared imported approval evidence reopens the control gap.
- Material workflow/path evidence change reopens; unrelated report order changes do not.
- Regress output remains deterministic and uses exit `5` only for policy-defined drift.

Matrix wiring:

- Fast lane: focused regress, risk, state, backlog, and report tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: scenario fixture with baseline, resolved rerun, expired rerun, contradiction rerun, and removed-control rerun.
- Cross-platform lane: deterministic path fingerprinting and state snapshot comparison on Windows.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf` for large rerun fixtures.

Acceptance criteria:

- Resolved findings stay quiet only while declaration/import evidence remains valid and non-contradictory.
- Reopened paths explain the exact expiry, drift, contradiction, target escalation, credential change, or disappeared-control reason.
- Reopen behavior is deterministic under fixed test time and stable inputs.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added expiry, drift, contradiction, and disappeared-control reopening for reviewed action paths.
Semver marker override: [semver:minor]
Contract/API impact: Adds reopen fields to report, risk, regress, and evidence contracts.
Versioning/migration impact: Additive v1 fields; existing regress drift output remains compatible.
Architecture constraints: Regress compares snapshots; Risk decides reopen semantics; Report renders reasons without mutating state.
ADR required: yes
TDD first failing test(s): `TestExpiredAcceptedRiskReopens`, `TestNonProdDeclarationContradictedByProductionSecretReopens`, and `TestRemovedImportedBranchProtectionReopensControlGap`.
Cost/perf impact: medium
Chaos/failure hypothesis: Corrupt or missing prior state keeps the current path open with a state-quality warning instead of trusting stale resolution.

## Epic 3: Imported Controls And Calibrated Recommendations

Objective: reduce noisy or overstated findings by recognizing imported controls and matching recommendations to credential authority.
Traceability: Recommendations 3, 5, 9, and 10.

### Story 3.1: Provider Control Evidence Correlation

Priority: P0
Recommendation coverage: 3

Tasks:

- Extend the existing external-control evidence model to cover PR reviews, branch protection, required checks, CODEOWNERS, environment approvals, deployment gates, workflow permissions, merge metadata, and provider-specific source refs from GitHub, GitLab, and Azure DevOps exports.
- Correlate imported records to repo, workflow, path, branch, environment, action path, resolution key, graph node, graph edge, and finding key.
- Project matching imported evidence into `covered_by_imported_control` lifecycle state when evidence is fresh, scoped, and non-contradictory.
- Preserve non-matching provider evidence as unmatched diagnostics rather than resolving unrelated paths.
- Apply customer-redacted profile behavior to imported people/team/provider identifiers in report and evidence artifacts.
- Keep live provider API calls out of scan/risk/report paths.

Repo paths:

- `core/ingest/external_schema.go`
- `core/attribution/provider_metadata.go`
- `core/attribution/control_metadata.go`
- `core/risk/introduced_by.go`
- `core/risk/action_lineage.go`
- `core/risk/action_paths.go`
- `core/report/agent_action_bom.go`
- `core/report/gait_coverage.go`
- `core/report/redaction.go`
- `schemas/v1/evidence/external-control-evidence.schema.json`
- `docs/commands/ingest.md`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/ingest ./core/attribution ./core/risk ./core/report -run 'Test.*ExternalControl|Test.*Provider|Test.*BranchProtection|Test.*ImportedApproval|Test.*Redact' -count=1`
- `go test ./internal/acceptance -run 'Test.*ExternalControl|Test.*Redaction|Test.*Projection' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make prepush-full`

Test requirements:

- Imported branch protection changes a matching path from unknown control evidence to imported/covered control.
- Imported PR approval resolves approval evidence for a matching workflow path.
- Non-matching provider evidence does not resolve unrelated paths and appears in unmatched diagnostics.
- Redacted reports remove cleartext people/team/provider identifiers while preserving deterministic refs.
- Invalid provider records fail closed without partial resolution.

Matrix wiring:

- Fast lane: focused ingest, attribution, risk, report, and redaction tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: provider sidecar scenario for branch protection, PR review, required check, environment approval, and non-match diagnostics.
- Cross-platform lane: provider sidecar path and line-ending normalization on Windows.
- Risk lane: `make test-hardening` and `make test-chaos` for corrupt, stale, partial, and contradictory provider exports.

Acceptance criteria:

- A report can say approval evidence was imported from a provider export for a matching workflow path.
- Imported evidence never resolves unrelated paths.
- Redacted outputs remain share-safe while internal outputs preserve remediation detail.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added provider-control evidence correlation for local PR review, branch protection, required check, environment approval, deployment gate, workflow permission, and merge metadata exports.
Semver marker override: [semver:minor]
Contract/API impact: Extends external-control sidecar schema and report/evidence lifecycle fields additively.
Versioning/migration impact: Existing external-control sidecars remain valid; new evidence classes are additive enum values.
Architecture constraints: Ingest and Attribution own provider normalization; Risk owns control projection; Report owns redacted/internal rendering.
ADR required: no
TDD first failing test(s): `TestImportedBranchProtectionCoversMatchingPath`, `TestImportedPRApprovalResolvesWorkflowApprovalEvidence`, and `TestNonMatchingProviderEvidenceDoesNotResolvePath`.
Cost/perf impact: medium
Chaos/failure hypothesis: Partial provider exports preserve unmatched diagnostics and leave unresolved paths open instead of pretending controls are absent or verified.

### Story 3.2: Authority-Aware Recommendations And Governed CI Classification

Priority: P0
Recommendation coverage: 5, 9, 10

Tasks:

- Add CI flow classes: `standard_governed_ci`, `ci_with_broad_standing_authority`, `ci_reachable_from_untrusted_pr`, `ci_editing_release_or_workflow_path`, `agentic_ci_flow`, and `production_or_release_action_path`.
- Classify CI paths from workflow capabilities, branch protection/imported controls, environment approvals, trigger class, credential authority, write path classes, action path type, production target status, and workflow/release file mutation.
- Split recommendation templates for confirmed standing credential, referenced credential with unknown scope, no credential linked, static API/target context, workflow/action path needing caller correlation, and governed CI.
- Ensure static API/OpenAPI/route findings recommend caller correlation rather than credential remediation.
- Ensure no standing-credential remediation text appears when credential authority is `none`, `unknown`, or only static target context.
- Keep high-confidence standing credential plus release/production reach visible with strong control recommendations.
- Update closure requirement generation so each top BOM item has at least one concrete closure action aligned with evidence gap and authority type.

Repo paths:

- `core/detect/workflowcap/analyze.go`
- `core/risk/action_paths.go`
- `core/risk/buyer_projection.go`
- `core/risk/path_type_guidance.go`
- `core/risk/action_binding.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/report/primary_view.go`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/detect/workflowcap ./core/risk ./core/aggregate/controlbacklog ./core/report -run 'Test.*CIFlow|Test.*Authority|Test.*Recommendation|Test.*Closure|Test.*StaticContext' -count=1`
- `go test ./internal/scenarios -run 'Test.*Workflow|Test.*ControlBacklog|Test.*ActionPath|Test.*Precision' -count=1 -tags=scenario`
- `make test-contracts`
- `make test-scenarios`
- `make test-perf`
- `make prepush-full`

Test requirements:

- Normal CI with imported branch protection is not top control-first by default.
- CI with broad standing authority remains top control-first.
- Agentic CI with credential and release reach remains high priority.
- Static API findings recommend caller correlation, not credential remediation.
- Confirmed workflow credential paths still get strong control recommendations.
- Every top BOM item has at least one concrete closure action.

Matrix wiring:

- Fast lane: focused workflowcap, risk, backlog, and report recommendation tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: governed CI, broad standing authority CI, static API correlation, and agentic CI scenarios.
- Cross-platform lane: workflow path classification and Markdown output on Windows.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf` for classification edge cases and large CI fixture sets.

Acceptance criteria:

- Wrkr stops treating every credential-bearing CI flow as equally urgent.
- Recommendation text matches the authority confidence and evidence gap.
- Static context stays in correlation guidance until executable or credential authority evidence exists.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed top action recommendations to account for credential authority confidence, static context, and governed CI controls.
Semver marker override: [semver:minor]
Contract/API impact: Adds CI flow classification fields and changes buyer-facing recommendation semantics.
Versioning/migration impact: Additive JSON fields; recommendation wording changes require docs and changelog notes.
Architecture constraints: Detection extracts workflow facts, Risk classifies authority/CI semantics, Report renders the selected recommendation.
ADR required: no
TDD first failing test(s): `TestGovernedCIDoesNotRankAsTopControlFirst`, `TestUnknownAuthorityAvoidsStandingCredentialRemediation`, and `TestStaticAPIFindingRecommendsCallerCorrelation`.
Cost/perf impact: medium
Chaos/failure hypothesis: Ambiguous CI control evidence routes to review/correlation guidance instead of downgrading a path as governed.

## Epic 4: Buyer And Operator Output Loop

Objective: make the first report page understandable, the next action concrete, and the shareable/internal artifact pair safe.
Traceability: Recommendations 4, 7, 8, 9, and 12.

### Story 4.1: Bounded Top-Five Agent Action BOM Lead View And Evidence Language Gate

Priority: P1
Recommendation coverage: 4, 8

Tasks:

- Extend the existing Agent Action BOM primary view from a single selected path into a bounded top-five lead view for default Markdown.
- For each lead path, show what can change, authority used, visible controls, unresolved evidence, recommended closure/action contract, and confidence label.
- Demote hash IDs from human-facing primary labels when better repo/workflow/action labels exist.
- Keep full path details, graph refs, evidence refs, and hashes in appendix/evidence JSON.
- Add Markdown line/section budget tests for large-org reports.
- Add report wording lint tests that reject unsupported phrases such as "approval missing", "proof missing", "owner missing", "approval is missing", "control absent", or "uncontrolled" unless verified absence exists.
- Update docs and examples to describe the one-page lead and evidence-scoped wording.

Repo paths:

- `core/report/primary_view.go`
- `core/report/render_markdown.go`
- `core/report/agent_action_bom.go`
- `core/report/executive_rollup.go`
- `core/report/render_markdown_test.go`
- `core/report/primary_view_test.go`
- `core/cli/report_contract_test.go`
- `internal/acceptance/report_overclaim_acceptance_test.go`
- `internal/acceptance/sprint0_size_signal_acceptance_test.go`
- `schemas/v1/agent-action-bom.schema.json`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/report ./core/cli -run 'Test.*PrimaryView|Test.*TopFive|Test.*LineBudget|Test.*Overclaim|Test.*AgentActionBOM' -count=1`
- `go test ./internal/acceptance -run 'Test.*Overclaim|Test.*Size|Test.*AgentActionBOM' -count=1`
- `make test-contracts`
- `make test-scenarios`
- `make test-perf`
- `make prepush-full`

Test requirements:

- Default Markdown lead section stays under a defined line budget for large-org fixtures.
- Top five contains unresolved control-first paths when present, then review-queue paths by deterministic ranking.
- Hash IDs are demoted from primary labels when readable repo/workflow/action labels exist.
- Wording linter rejects overclaiming phrases unless verified absence evidence is present.
- Full detail remains available in appendix/evidence JSON.

Matrix wiring:

- Fast lane: focused report rendering, primary-view, CLI contract, and wording lint tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: large-org BOM acceptance, report-overclaim acceptance, and size/signal acceptance.
- Cross-platform lane: Markdown rendering and line-budget checks on Windows.
- Risk lane: `make test-hardening` and `make test-perf` for wording, redaction, and report-size budgets.

Acceptance criteria:

- A large-org scan produces a readable one-page lead plus appendix.
- Buyer-facing reports no longer accuse absence from incomplete scan context.
- Top-five lead items remain deterministic and useful under repeated runs.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Changed Agent Action BOM Markdown to lead with a bounded top-five evidence-scoped action view.
Semver marker override: [semver:minor]
Contract/API impact: Changes report Markdown structure and adds lead-view schema fields where serialized.
Versioning/migration impact: JSON additions are additive; Markdown consumers should treat the lead section as changed output.
Architecture constraints: Report rendering must consume projected evidence/recommendation state and keep detailed refs in appendix/evidence JSON.
ADR required: no
TDD first failing test(s): `TestAgentActionBOMTopFiveLeadLineBudget`, `TestReportRejectsUnsupportedMissingApprovalPhrase`, and `TestPrimaryLeadDemotesHashIDs`.
Cost/perf impact: medium
Chaos/failure hypothesis: If no promotable top paths exist, the lead renders a bounded empty-state with coverage context instead of fabricating findings.

### Story 4.2: Path-Specific Closure Actions And Declaration Snippet Export

Priority: P1
Recommendation coverage: 1, 9, 12

Tasks:

- Extend closure requirements to include exact closure actions: import PR review evidence, import branch protection, import environment approval, declare repo owner, declare non-prod target, declare approved credential use, attach policy/proof reference, reduce standing credential, accept risk with expiry, mark not applicable, mark false positive, or request runtime evidence.
- Generate declaration snippets or patch files for `.wrkr/control-declarations.yaml` based on selected BOM/backlog items and internal artifacts.
- Ensure generated snippets validate against the declaration schema and use `resolution_key` or selector fields when safer than transient `path_id`.
- Ensure snippets generated from customer-redacted artifacts do not leak real identifiers or generate unusable pseudonym-only declarations without an explicit warning.
- Add CLI/report/export docs for repo-local declaration mode and governance-repo declaration mode.
- Do not push, commit, or open GitHub PRs automatically from core Wrkr.

Repo paths:

- `core/risk/path_type_guidance.go`
- `core/risk/evidence_context.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/cli/report.go`
- `core/cli/export.go`
- `docs/commands/report.md`
- `docs/commands/export.md`
- `schemas/v1/agent-action-bom.schema.json`
- `schemas/v1/report/report-summary.schema.json`
- `CHANGELOG.md`

Run commands:

- `go test ./core/risk ./core/aggregate/controlbacklog ./core/report ./core/cli -run 'Test.*Closure|Test.*DeclarationSnippet|Test.*Patch|Test.*RedactedSnippet|Test.*Export' -count=1`
- `go test ./internal/scenarios -run 'Test.*Closure|Test.*Ticket|Test.*Control' -count=1 -tags=scenario`
- `make test-contracts`
- `make test-hardening`
- `make prepush-full`

Test requirements:

- Each top BOM item has at least one concrete closure action.
- Closure action aligns with evidence gap, authority type, CI flow class, and path class.
- Generated declaration snippets validate against schema.
- Snippets from internal artifacts preserve remediation identifiers.
- Customer-redacted mode does not leak real identifiers and warns when pseudonyms cannot produce directly applicable declarations.
- Unsafe patch output paths are rejected with exit `8`.

Matrix wiring:

- Fast lane: focused closure guidance, snippet generation, CLI/export, and report tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: closure-guidance and declaration-export scenario.
- Cross-platform lane: patch path generation and YAML path escaping on Windows.
- Risk lane: `make test-hardening` for unsafe paths, redacted leaks, invalid snippets, and raw-secret-looking payloads.

Acceptance criteria:

- A customer can turn a finding into a declaration/import action without asking Clyra.
- Generated declaration snippets validate and can resolve the item on the next scan when evidence is still valid.
- Core Wrkr never mutates GitHub by default.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added path-specific closure actions and declaration snippet export for reviewed action paths.
Semver marker override: [semver:minor]
Contract/API impact: Adds closure action and declaration-snippet fields/artifacts to report/export contracts.
Versioning/migration impact: Additive fields and optional artifacts; no existing report/export mode is removed.
Architecture constraints: Risk/backlog generate closure intent; CLI/export handles artifact writing with safe-output checks.
ADR required: no
TDD first failing test(s): `TestTopBOMItemHasConcreteClosureAction`, `TestGeneratedDeclarationSnippetValidates`, and `TestRedactedArtifactSnippetDoesNotLeakInternalIdentifiers`.
Cost/perf impact: low
Chaos/failure hypothesis: If a snippet cannot be generated safely from redacted input, export emits a deterministic warning and no unsafe patch.

### Story 4.3: Paired Internal/Redacted Artifacts And Join Map Hardening

Priority: P1
Recommendation coverage: 7

Tasks:

- Confirm report and evidence workflows emit paired internal and customer-redacted artifacts for Agent Action BOM Markdown, Agent Action BOM evidence JSON, and report/evidence JSON where the mode requests paired output.
- Ensure local-only `redaction-join-map.json` includes stable joins for path IDs, resolution keys, repo, workflow/location, BOM item IDs, evidence refs, and provider/declaration refs where safe.
- Enforce that the join map is excluded from shareable bundles by default and is marked `internal_only` in metadata.
- Add docs language telling users to use the internal artifact or local join map for remediation after sharing a redacted report.
- Add redaction tests for cleartext repo, owner, path, workflow, team, provider, ticket, and declaration rationale leakage.
- Add atomic-write and partial-failure tests for paired artifact generation.

Repo paths:

- `core/report/artifact_pairing.go`
- `core/report/artifacts.go`
- `core/report/redaction.go`
- `core/report/redaction_summary.go`
- `core/report/report_artifacts.go`
- `core/cli/report_artifacts.go`
- `core/cli/report_pairing_test.go`
- `core/report/artifact_pairing_test.go`
- `core/report/output_finalizer_test.go`
- `docs/commands/report.md`
- `docs/commands/evidence.md`
- `CHANGELOG.md`

Run commands:

- `go test ./core/report ./core/cli -run 'Test.*ArtifactPair|Test.*JoinMap|Test.*Redaction|Test.*OutputFinalizer|Test.*Paired' -count=1`
- `go test ./internal/acceptance -run 'Test.*Redaction|Test.*AgentActionBOM|Test.*Evidence' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`

Test requirements:

- Redacted artifact has no cleartext repo, owner, path, workflow, provider, team, ticket, declaration rationale, or service leaks.
- Internal artifact preserves remediation details.
- Join map is never emitted under customer-redacted/shareable bundle unless an explicit unsafe path is approved by a future separate workflow.
- Partial paired-artifact write failure does not leave a misleading shareable bundle.
- Metadata labels internal vs shareable artifacts correctly.

Matrix wiring:

- Fast lane: focused report artifact, CLI artifact, redaction, and output finalizer tests.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: redacted/internal artifact acceptance and Agent Action BOM evidence acceptance.
- Cross-platform lane: join-map path behavior and atomic write semantics on Windows.
- Risk lane: `make test-hardening` and `make test-chaos` for redaction leaks, unsafe paths, partial writes, and join-map exclusion.

Acceptance criteria:

- Customers can safely share redacted output and still remediate locally with internal artifacts or the join map.
- Join maps cannot be included in shareable bundles by default.
- Artifact metadata clearly identifies shareability and pair relationships.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Fixed paired internal/redacted artifact handling so local join maps remain remediation-useful but excluded from shareable bundles by default.
Semver marker override: [semver:patch]
Contract/API impact: Tightens artifact metadata, shareability, and join-map output contracts.
Versioning/migration impact: Additive metadata and stricter safety behavior; no shareable artifact should depend on join-map inclusion.
Architecture constraints: Report owns artifact pairing and redaction; CLI owns safe file output and error mapping.
ADR required: no
TDD first failing test(s): `TestJoinMapExcludedFromCustomerRedactedBundle`, `TestInternalArtifactPreservesResolutionKeys`, and `TestPairedArtifactPartialFailureDoesNotCreateShareableBundle`.
Cost/perf impact: low
Chaos/failure hypothesis: If internal artifact generation succeeds but redacted generation fails, the command reports failure and does not publish a partial shareable bundle.

## Epic 5: Enterprise-Shaped Regression Guardrails

Objective: keep the customer review loop, report size, redaction, terminology, and governed-CI precision from regressing.
Traceability: Recommendation 13.

### Story 5.1: Synthetic Enterprise Review-Loop Fixtures

Priority: P0
Recommendation coverage: 13

Tasks:

- Add synthetic fixtures that preserve shape and failure modes from recent enterprise scans without customer data.
- Cover a 300+ repo org, standard CI with credential and imported PR controls, confirmed standing credential release path, static OpenAPI target needing caller correlation, redacted/internal join-map pair, declared controlled path, expired declaration, contradictory declaration, false positive, accepted risk with future expiry, removed branch protection, and broad standing authority CI.
- Assert artifact size, Markdown line budgets, top-five lead budget, redaction leak budget, evidence-state wording, lifecycle state, reopen reasons, governed-CI classification, closure actions, and schema validity.
- Extend scenario coverage map and acceptance tests so these fixtures gate future release claims.
- Add docs notes that fixtures are synthetic and contain no customer data.

Repo paths:

- `internal/scenarios`
- `internal/scenarios/coverage_map.json`
- `internal/acceptance`
- `scenarios/wrkr`
- `core/report/report_contract_test.go`
- `core/report/primary_view_test.go`
- `core/report/render_markdown_test.go`
- `core/aggregate/controlbacklog/controlbacklog_test.go`
- `core/risk/action_paths_test.go`
- `docs/trust/contracts-and-schemas.md`
- `CHANGELOG.md`

Run commands:

- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./internal/acceptance -count=1`
- `go test ./core/report ./core/risk ./core/aggregate/controlbacklog -run 'Test.*Enterprise|Test.*Size|Test.*Redaction|Test.*Overclaim|Test.*Lifecycle|Test.*GovernedCI' -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-perf`
- `make prepush-full`

Test requirements:

- State, evidence JSON, Markdown, and artifact-size budgets are enforced.
- Redaction leak tests pass for repo, owner, workflow, provider, ticket, declaration rationale, and path identifiers.
- One-page lead view stays within budget.
- Overclaim phrase linter passes.
- Expired and contradictory declarations reopen with deterministic reasons.
- Standard governed CI is not top control-first, while broad standing authority CI remains visible.

Matrix wiring:

- Fast lane: focused report/risk/backlog unit tests and fixture contract checks.
- Core CI lane: `make lint-fast`, `make test-fast`, and `make test-contracts`.
- Acceptance lane: full `internal/scenarios` and `internal/acceptance` suites for the new fixture set.
- Cross-platform lane: large fixture path normalization and report generation on Windows smoke.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf` for size, redaction, fail-closed behavior, and large-org performance.
- Release/UAT lane: `scripts/run_v1_acceptance.sh --mode=local` and `make test-release-smoke` before release notes claim enterprise review-loop readiness.

Acceptance criteria:

- Latest enterprise learnings are covered by deterministic tests without committing customer data.
- Size, redaction, wording, lifecycle, reopen, and governed-CI regressions fail before release.
- Changelog/release-note claims about size, privacy, redaction, customer-safe sharing, or readability include measured artifact-size deltas and fixture/test receipts.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added synthetic enterprise review-loop fixtures that guard report size, redaction, lifecycle, reopen, wording, and governed-CI behavior.
Semver marker override: [semver:minor]
Contract/API impact: Adds scenario/acceptance fixtures and may tighten report-size, redaction, and wording gates.
Versioning/migration impact: No public JSON migration by itself; fixture expectations become release-blocking contracts.
Architecture constraints: Keep fixtures synthetic, deterministic, and outside runtime logic; do not loosen scenario expected-output review rules.
ADR required: no
TDD first failing test(s): `TestEnterpriseReviewLoopFixtureBudgets`, `TestEnterpriseFixtureGovernedCINotTopControlFirst`, and `TestEnterpriseFixtureExpiredDeclarationReopens`.
Cost/perf impact: high
Chaos/failure hypothesis: Large synthetic fixtures expose report-size or performance regressions before customer-shaped scans produce unusable artifacts.

# Adhoc Plan: Remaining Redaction, Canonicalization, And Parser Gates

Date: 2026-06-13
Profile: `wrkr`
Slug: `remaining-redaction-canonicalization-parser-gates`
Recommendation source: user-provided remaining-work recommendations focused on nested owner redaction leaks, cross-writer canonicalization, clone-removal contracts, JS/TS detector scope, parser robustness verification, and the temporary freeze gate.

All paths in this plan are repo-relative. Developer-specific checkout roots from the source recommendations have been normalized. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, report, evidence, docs, release, or workflow changes.

## Global Decisions (Locked)

- This is a follow-up Sprint 0 subtractive plan. It narrows to the remaining work that must be green before Wrkr reopens new scan/report surface expansion.
- Release-blocking privacy work lands before canonicalization follow-through, and both land before JS/TS detector breadth or customer-scale parser verification.
- Default and shareable artifacts remain customer-safe by default. If ownership-like data cannot be redacted confidently, the output path must fail closed or omit the field rather than emit a best-effort cleartext value.
- Canonical refs remain the only stable cross-artifact join contract for repeated endpoint and authority projections: `mutable_endpoint_semantic_refs`, `credential_authority_ref`, and `authority_binding_refs`.
- Embedded clone objects may still exist inside internal construction paths, but public/default/shareable writers must finalize to one canonical store plus refs before serialization.
- Output canonicalization is a contract owned by shared finalization code, not a writer-by-writer courtesy step.
- Parse failures on JS/TS-heavy repos are coverage facts unless a specific config contract failed. Reports must surface reduced coverage honestly without turning parser noise into security findings.
- The temporary freeze gate stays closed until recursive redaction and cross-writer clone-strip contracts are green.
- Every story in this plan changes user-visible behavior, public/shareable output semantics, detector scope, governance guidance, or release gating. Changelog review is required for each implementation PR.

## Current Baseline (Observed)

- The broader Sprint 0 subtractive work is already captured in `product/plans/adhoc/PLAN_ADHOC_2026-06-12_104332_sprint-0-subtractive-fixes.md`; this plan focuses only on the remaining gaps called out after that planning pass.
- Shareable-owner coverage already exists in `core/cli/sprint0_report_contract_test.go` and `internal/acceptance/sprint0_size_signal_acceptance_test.go`, but the source recommendations show those checks remain shallow enough for nested owner-like values to leak through redacted artifacts.
- Canonical ref joins already exist in inventory and selected report projections, and selected save/finalization paths already strip embedded clones, but the recommendations identify writer coverage gaps across `scan --json`, `report --json`, evidence bundles, paired artifacts, assess output, and saved state.
- The repo already documents the temporary freeze gate in `AGENTS.md` and `CONTRIBUTING.md`, but the source recommendations indicate the gate still needs executable proof for recursive redaction and universal clone stripping.
- JS/TS parser noise is already surfaced through `scan_quality` and detector parse paths, but remaining detector scope and verification gaps can still inflate parse-failure volume on enterprise-shaped repos.
- The recommendation set explicitly names nested leak candidates such as `production_context.owner`, `evidence_decisions[].selected_value`, rejected owner candidates, and repeated embedded endpoint or authority clones that can reappear when a writer serializes objects before finalization.
- Relevant implementation and contract files already exist in the expected boundaries:
  - Report/redaction: `core/report/redaction_summary.go`, `core/report/agent_action_bom.go`, `core/report/build.go`, `core/report/artifacts.go`, `core/report/canonical_projection.go`
  - Aggregation/risk/state: `core/aggregate/controlbacklog/controlbacklog.go`, `core/aggregate/attackpath/graph.go`, `core/risk/wave4_types.go`, `core/state/state.go`
  - CLI/public writers: `core/cli/jsonmode.go`, `core/cli/scan.go`, `core/cli/report.go`, `core/cli/report_artifacts.go`, `core/cli/assess.go`
  - Acceptance/governance: `internal/acceptance/sprint0_size_signal_acceptance_test.go`, `core/cli/sprint0_report_contract_test.go`, `core/cli/report_contract_test.go`, `testinfra/hygiene/wave31_focus_and_gate_test.go`
  - Detection/parser scope: `core/detect/parse.go`, `core/detect/detect.go`, `core/detect/pathfilter.go`, `core/detect/webmcp/detector.go`, `core/detect/promptchannel/detector.go`, `core/detect/agentframework/source.go`, `core/detect/mcp/candidates.go`

## Exit Criteria

- Customer-redacted and other shareable/default artifacts recursively redact nested owner-like values across JSON, Markdown, paired artifacts, and evidence sidecars, including selected and rejected ownership candidates.
- Default/shareable artifacts fail if fixture owner handles, emails, local paths, repo names, PR URLs, unredacted credential subjects, raw provider refs, or unredacted owner fields appear anywhere outside allowed redaction tokens.
- Every public/default writer routes through one shared output finalizer that preserves canonical stores, backfills refs, strips embedded clone payloads when refs exist, and applies deterministic caps before bytes are written.
- `scan --json`, `scan --json-path`, `report --json`, report evidence JSON, paired artifact writing, `assess --json`, and saved state all honor the same clone-strip and redaction guarantees.
- Contract tests fail whenever repeated projections emit `mutable_endpoint_semantics`, `credential_authority`, or `authority_bindings` while corresponding canonical refs are present outside the canonical store.
- The temporary freeze gate blocks new scan/report fields, sidecars, detector breadth, report sections, or context dimensions until recursive redaction and cross-writer clone-strip tests are green.
- JS/TS-touching detectors skip generated, bundled, vendored, lockfile-like, or otherwise low-signal files; structured parsing remains targeted to high-signal sources.
- Sanitized enterprise-shaped JS/TS fixtures prove parser-failure volume is bounded, detector coverage is honestly reported through `scan_quality`, and parser limitations do not surface as security findings.

## Public API and Contract Map

- Share-profile and artifact safety contracts:
  - `customer-redacted`, `external-redacted`, `design-partner`, and any default shareable flows must recursively mask owner-like, credential-subject, provider-ref, repo, and path-sensitive values.
  - Explicit internal profiles may retain cleartext ownership context, but only through intentional operator selection.
  - Paired internal/external artifact flows must produce a redacted external surface plus deterministic private join metadata without leaking redacted values back into the shareable side.
- JSON and canonicalization contracts:
  - Public/default repeated projections keep canonical ref joins and omit embedded full endpoint/authority payloads when canonical refs exist.
  - The only allowed place for full repeated endpoint or authority objects in public artifacts is the canonical store itself when the schema requires one retained canonical copy.
  - Writer-level serialization order must remain deterministic and portable across checkout paths.
- Scan-quality and parser contracts:
  - Parser failures remain explicit `scan_quality` coverage facts with deterministic status and reason metadata.
  - Reduced or unsupported coverage must not be silently dropped and must not be promoted to risk findings unless a real policy or config rule failed.
- Governance and freeze-gate contracts:
  - `AGENTS.md`, `CONTRIBUTING.md`, `product/PLAN_NEXT.md`, and hygiene tests must agree on what stays frozen until the redaction and clone-strip gates are green.
  - Release-note or changelog claims about privacy, redaction, customer-safe sharing, or bounded artifacts require measured receipts in the same implementation PR.

## Docs and OSS Readiness Baseline

- User-facing or governance docs likely impacted by implementation:
  - `CHANGELOG.md`
  - `CONTRIBUTING.md`
  - `AGENTS.md`
  - `product/PLAN_NEXT.md`
  - `docs/commands/report.md`
  - `docs/commands/evidence.md`
  - `docs/commands/assess.md`
  - `docs/commands/scan.md`
- Contract and acceptance surfaces likely impacted:
  - `internal/acceptance`
  - `internal/scenarios`
  - `core/cli/sprint0_report_contract_test.go`
  - `core/cli/report_contract_test.go`
  - `testinfra/hygiene/wave31_focus_and_gate_test.go`
- OSS trust baseline:
  - No implementation PR under this plan may commit real owner handles, real repo names, real PR URLs, raw credential subjects, or live enterprise repo contents.
  - Sanitized parser-verification fixtures must use fake orgs, fake handles, fake repos, and generated bundles or source trees that model the failure class without copying customer code.
  - Shareable example artifacts and docs must demonstrate that redaction is recursive and canonicalization is enforced across writers, not merely top-level report summaries.

## Recommendation Traceability

| Recommendation | Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| 1. Close the nested owner-redaction leak | P0 | Story 1.1 | A redacted artifact that leaks owner handles is a release blocker. | Redact nested owner-like values in report, BOM, backlog, evidence, and summary projections. | Shareable artifacts become customer-safe by default. |
| 2. Centralize output canonicalization across all writers | P0 | Story 2.1 | Partial writer coverage allows repeated clone payloads back into artifacts. | One shared output finalizer for scan, report, evidence, assess, and state writers. | Artifact size and structure stay bounded across all public outputs. |
| 3. Harden the clone-removal contract in tests | P0 | Story 2.2 | Without deep contract tests, a future writer can bypass finalization silently. | Public/default outputs fail if embedded clones appear where refs exist. | Regressions are blocked before release. |
| 4. Deepen redaction coverage tests | P0 | Story 1.2 | Top-level checks miss the exact class of leak still remaining. | Recursive path-aware walkers across JSON, Markdown, paired artifacts, and bundles. | Privacy regressions become obvious and deterministic. |
| 5. Verify JS/TS parser robustness on real repos | P1 | Story 3.2 | Buyer trust depends on proven behavior on enterprise-shaped inputs. | Sanitized real-shaped fixture set plus parser-failure ceilings and coverage receipts. | Next customer-scale scans have grounded coverage expectations. |
| 6. Scope JS/TS-touching detectors more deliberately | P1 | Story 3.1 | High parse volume often comes from low-signal files being parsed unnecessarily. | High-signal path selection plus lightweight extraction for general source. | Lower parse noise without losing discovery value. |
| 7. Keep the freeze gate closed until Items 1-4 are green | P0 | Story 2.2 | New surface area can reintroduce exactly these regressions. | Hygiene and docs gate new scan/report expansion until privacy and canonicalization proofs are green. | Sprint 0 subtractive work remains protected from scope creep. |

## Test Matrix Wiring

- Fast lane:
  - `make lint-fast`
  - `make test-fast`
  - Focused `go test` commands listed under each story.
- Core CI lane:
  - `make prepush-full` for architecture, risk, schema, writer, detector, or fail-closed behavior changes.
  - `make test-contracts` for share-profile, schema, JSON-shape, canonicalization, and freeze-gate contracts.
- Acceptance lane:
  - `go test ./internal/acceptance -count=1`
  - `go test ./internal/scenarios -count=1 -tags=scenario`
  - `scripts/run_v1_acceptance.sh --mode=local` when buyer-facing artifact behavior changes.
- Cross-platform lane:
  - Required for path redaction, Markdown rendering, deterministic artifact ordering, and saved-state or artifact path normalization.
- Risk lane:
  - `make test-hardening` for fail-closed redaction and unsafe-output behavior.
  - `make test-chaos` when writer finalization or artifact persistence paths change.
  - `make test-perf` for large fixture canonicalization or parser-scope changes.
  - `make codeql` when detector logic, workflow logic, or security-sensitive writer behavior changes.
- Release/UAT lane:
  - `make test-release-smoke`
  - `scripts/run_v1_acceptance.sh --mode=release` when release-note wording or external contract docs change.
- Gating rule:
  - Story 1.1 and Story 1.2 must land before any PR claims customer-safe shareable output.
  - Story 2.1 and Story 2.2 must land before the Sprint 0 freeze gate reopens scan/report surface expansion.
  - Story 3.1 should land before Story 3.2 so enterprise-shaped verification measures the intended detector scope.
  - Story 3.2 must be green before the next customer-scale JS/TS-heavy scan is treated as a validation receipt.

## Minimum-Now Sequence

- Wave 1 - Privacy closure:
  - Story 1.1 closes nested owner-redaction leaks.
  - Story 1.2 deepens redaction coverage tests.
- Wave 2 - Canonicalization closure and freeze protection:
  - Story 2.1 centralizes output canonicalization across all writers.
  - Story 2.2 turns clone stripping and the freeze gate into explicit contracts.
- Wave 3 - JS/TS signal and verification:
  - Story 3.1 narrows detector parsing to high-signal files and lightweight extraction elsewhere.
  - Story 3.2 verifies parser robustness on sanitized enterprise-shaped repos and fixtures.

## Explicit Non-Goals

- No implementation in this plan-only PR.
- No edits to `product/PLAN_NEXT.md` in this plan-only PR.
- No new scan/report sidecars, buyer-facing sections, detector families, or product surfaces unrelated to closing these remaining Sprint 0 gates.
- No live customer repo acquisition, network scanning, or nondeterministic hosted dependency in the default verification path.
- No LLM calls in scan, risk, proof, report, evidence, canonicalization, or parser paths.
- No commitment of private scan artifacts, real owner data, or transient measurement outputs.
- No reopening of the temporary freeze gate before recursive redaction and universal writer canonicalization are proven.

## Definition of Done

- Every recommendation maps to at least one story and at least one deterministic acceptance check.
- Wave 1 implementation proves nested owner-like leaks are redacted across all shareable/default surfaces, not just top-level BOM owner fields.
- Wave 2 implementation proves every public/default writer finalizes through the same canonicalization path and blocks embedded clone regressions.
- Wave 3 implementation proves JS/TS detector scope is intentional and parser failures are represented as honest scan-quality coverage.
- Every story includes repo paths, commands, tests, changelog intent, contract impact, versioning or migration impact, architecture constraints, ADR decision, TDD-first tests, cost/perf notes, and a failure hypothesis.
- Implementation PRs under this plan run the required fast, contract, acceptance, risk, and architecture lanes for their scope.

## Wave 1: Privacy Closure

Objective: close the release-blocking nested owner leak and prove recursive redaction across every shareable/default artifact surface.
Traceability: Recommendations 1 and 4.

### Story 1.1: Close Nested Owner-Redaction Leaks Across Shareable Artifacts

Priority: P0
Recommendation coverage: 1
Tasks:
- Add recursive owner-redaction handling for nested `ProductionContext.Owner`-like fields in Agent Action BOM items, action-path projections, control backlog items, primary view summaries, evidence bundles, and report summary payloads.
- Redact ownership-like `EvidenceDecisions` fields when `decision.field == "owner"` or the selected source/status clearly represents ownership context.
- Redact rejected owner candidates as well as selected owner values so decision histories do not leak shareable handles.
- Ensure paired internal/external artifact generation keeps cleartext ownership only in the intentional internal surface or private join material, never in the customer-redacted surface.
- Fail closed when a shareable writer cannot classify an ownership-like nested value confidently enough to sanitize.
Repo paths:
- `core/report/redaction_summary.go`
- `core/report/agent_action_bom.go`
- `core/report/build.go`
- `core/risk/wave4_types.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/cli/report_artifacts.go`
- `core/report/artifacts.go`
Run commands:
- `go test ./core/report -run 'Test.*Redaction|Test.*Owner|Test.*Summary' -count=1`
- `go test ./core/cli -run 'Test.*Shareable|Test.*ReportContract|Test.*Assess' -count=1`
- `go test ./internal/acceptance -run 'Test.*Sprint0.*Redaction|Test.*AgentActionBOM' -count=1`
- `make test-contracts`
Test requirements:
- Tier 1 units for nested redaction helpers and owner-like decision classification.
- Tier 3 CLI contract tests for share-profile behavior across report and assess writers.
- Tier 4 acceptance tests for paired internal/external artifacts and evidence-bundle redaction.
- Tier 9 contract checks for redaction metadata and forbidden-token absence.
Matrix wiring:
- Fast lane: focused `core/report` and `core/cli` tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: `go test ./internal/acceptance -count=1`.
- Risk lane: `make test-hardening` because ambiguity must fail closed.
Acceptance criteria:
- Customer-redacted artifacts never expose fixture owner handles in nested JSON or Markdown fields.
- Evidence decision payloads redact both selected and rejected owner candidates on shareable surfaces.
- Paired artifact flows keep the redacted artifact free of cleartext ownership while preserving intentional internal joins separately.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Closed remaining nested owner redaction leaks so shareable report, evidence, and Agent Action BOM artifacts mask ownership context recursively by default.
Semver marker override: [semver:patch]
Contract/API impact: Strengthens share-profile redaction guarantees for nested owner-like fields across report, assess, and evidence outputs.
Versioning/migration impact: No versioned schema break intended, but shareable output values become more aggressively redacted.
Architecture constraints: Redaction remains in report/evidence serialization and must not mutate authoritative saved state, proof chains, or source-layer facts.
ADR required: yes
TDD first failing test(s): `TestShareableArtifactsDoNotLeakNestedOwners`, `TestEvidenceDecisionOwnerCandidatesAreRedacted`, and `TestPairedArtifactsDoNotLeakOwnerLikeFields`.
Cost/perf impact: low
Chaos/failure hypothesis: A nested owner value routed through a shareable artifact path should be masked or dropped deterministically even when the same internal run keeps cleartext context elsewhere.

### Story 1.2: Replace Shallow Owner Assertions With Recursive Artifact Leak Contracts

Priority: P0
Recommendation coverage: 4
Tasks:
- Add a recursive JSON and Markdown walker for redacted artifacts that inspects all string values plus path-aware keys.
- Maintain a small allowlist for deterministic redaction tokens such as `owner-<hash>` while rejecting fixture handles, emails, raw provider refs, local paths, repo names, and PR URLs.
- Run the recursive leak contract against report JSON, evidence JSON, Markdown, paired external artifacts, and backlog CSV when generated.
- Keep the recursive leak checks fixture-driven so future artifact surfaces can be added without bespoke one-off assertions.
Repo paths:
- `internal/acceptance/sprint0_size_signal_acceptance_test.go`
- `core/cli/sprint0_report_contract_test.go`
- `core/cli/report_contract_test.go`
- `core/report/report_test.go`
- `core/cli/report_artifacts.go`
Run commands:
- `go test ./core/cli -run 'Test.*Shareable.*Leak|Test.*ReportContract' -count=1`
- `go test ./core/report -run 'Test.*Redaction|Test.*Recursive' -count=1`
- `go test ./internal/acceptance -run 'Test.*Sprint0.*Leak|Test.*SizeSignal' -count=1`
- `make test-contracts`
Test requirements:
- Tier 3 CLI contract coverage for report and assess artifact JSON.
- Tier 4 acceptance coverage for rendered Markdown and paired artifacts.
- Tier 9 contract fixtures for forbidden token recursion and allowlist behavior.
Matrix wiring:
- Fast lane: focused `core/cli` and `core/report` tests.
- Core CI lane: `make test-contracts`.
- Acceptance lane: `go test ./internal/acceptance -count=1`.
- Cross-platform lane: required for path and URL normalization checks.
Acceptance criteria:
- Recursive leak tests fail on any cleartext fixture handle or unredacted provider/path token in shareable artifacts.
- New shareable surfaces can plug into the same recursive leak harness without reimplementing owner-specific assertions.
- The contract distinguishes allowed hashed redaction tokens from real leaked owner values deterministically.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Expanded recursive shareable-artifact leak tests to catch nested owner, provider, path, and credential-subject exposure across JSON and Markdown outputs.
Semver marker override: [semver:patch]
Contract/API impact: Converts shareable redaction expectations from shallow field checks into recursive artifact-level contracts.
Versioning/migration impact: No artifact version change intended; this is a stronger test contract over existing surfaces.
Architecture constraints: Acceptance and contract tests must validate public artifact behavior without introducing test-only production shortcuts.
ADR required: no
TDD first failing test(s): `TestShareableArtifactsDoNotLeakOwnersRecursively` and `TestCustomerRedactedMarkdownDoesNotExposeFixtureHandles`.
Cost/perf impact: low
Chaos/failure hypothesis: A newly added nested string field in a redacted artifact should fail the recursive contract immediately rather than pass because no bespoke assertion was added.

## Wave 2: Canonicalization Closure And Freeze Protection

Objective: make clone stripping universal across writers, then keep the subtractive freeze gate closed until the privacy and canonicalization proofs are green.
Traceability: Recommendations 2, 3, and 7.

### Story 2.1: Centralize Output Canonicalization Across All Writers

Priority: P0
Recommendation coverage: 2
Tasks:
- Introduce one shared output finalizer such as `CanonicalizeForOutput` or `FinalizeForArtifact` that all public/default writers call before serialization.
- Route `scan --json`, `scan --json-path`, `report --json`, report artifact writing, evidence bundle writing, paired artifact writing, `assess --json`, and saved-state writes through the shared finalizer.
- Backfill canonical refs where needed, preserve one canonical store, strip embedded `mutable_endpoint_semantics`, `credential_authority`, and `authority_bindings` when corresponding refs exist, and then apply deterministic caps.
- Keep internal builder hydration separate from public serialization so report or CLI code does not own clone-stripping rules independently.
- Update docs and schema notes if any public/default field availability changes as part of universal canonicalization.
Repo paths:
- `core/state/state.go`
- `core/cli/jsonmode.go`
- `core/cli/scan.go`
- `core/cli/report.go`
- `core/cli/assess.go`
- `core/report/artifacts.go`
- `core/report/canonical_projection.go`
- `core/aggregate/attackpath/graph.go`
- `core/report/build.go`
Run commands:
- `go test ./core/cli -run 'Test.*Scan.*JSON|Test.*Report.*Contract|Test.*Assess' -count=1`
- `go test ./core/report -run 'Test.*Canonical|Test.*Artifact|Test.*Projection' -count=1`
- `go test ./core/state -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 2 integration coverage for shared finalizer invocation across CLI and artifact writers.
- Tier 3 CLI contract coverage for `scan`, `report`, and `assess` JSON outputs.
- Tier 9 contract and schema checks for canonical ref preservation and embedded clone removal.
- Tier 11 scenario coverage for repeated projection outputs on large scans.
Matrix wiring:
- Fast lane: focused `core/cli`, `core/report`, and `core/state` tests.
- Core CI lane: `make prepush-full` and `make test-contracts`.
- Acceptance lane: targeted scenario or acceptance commands when artifact outputs change.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf` because writer finalization touches hot artifact paths.
Acceptance criteria:
- Every public/default writer emits canonical refs and omits embedded endpoint or authority clones when refs exist.
- Saved state, scan JSON, report JSON, evidence JSON, and assess JSON share one finalization contract rather than ad hoc stripping logic.
- Deterministic caps are applied after ref backfill and clone stripping, not before.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Unified output canonicalization across scan, report, evidence, assess, and saved-state writers so shareable/default artifacts consistently emit canonical refs without repeated embedded payload clones.
Semver marker override: [semver:patch]
Contract/API impact: Unifies and tightens the public/default serialization contract for repeated endpoint and authority projections across all writer surfaces.
Versioning/migration impact: May require compatibility notes or additive metadata if previously emitted embedded fields disappear from certain public/default outputs.
Architecture constraints: Aggregation and risk may build internal projections, but the shared finalizer owns public serialization semantics; report and CLI layers must consume it instead of re-deriving rules.
ADR required: yes
TDD first failing test(s): `TestScanJSONUsesSharedCanonicalFinalizer`, `TestAssessJSONUsesSharedCanonicalFinalizer`, and `TestSavedStateOmitsEmbeddedClonesWhenRefsExist`.
Cost/perf impact: medium
Chaos/failure hypothesis: A writer that previously serialized pre-finalized projections should fail contract tests immediately and should not be able to bypass shared finalization through a custom code path.

### Story 2.2: Turn Clone-Stripping And The Freeze Gate Into Explicit Contracts

Priority: P0
Recommendation coverage: 3, 7
Tasks:
- Extend acceptance and contract tests to deep-walk outputs from `scan --json`, `scan --json-path`, `report --json`, report evidence JSON, assess output, and paired artifact flows.
- Fail when `mutable_endpoint_semantics`, `credential_authority`, or `authority_bindings` appear in repeated projections while corresponding refs exist outside the canonical store.
- Keep the canonical store itself as the only allowed location for full retained objects when the schema requires them.
- Update `testinfra/hygiene/wave31_focus_and_gate_test.go` so new scan/report surface expansion remains blocked until recursive redaction and clone-strip contracts are green.
- Align `AGENTS.md`, `CONTRIBUTING.md`, and `product/PLAN_NEXT.md` wording with the executable gate and scope exception rules.
Repo paths:
- `internal/acceptance/sprint0_size_signal_acceptance_test.go`
- `core/cli/sprint0_report_contract_test.go`
- `core/cli/report_contract_test.go`
- `testinfra/hygiene/wave31_focus_and_gate_test.go`
- `AGENTS.md`
- `CONTRIBUTING.md`
- `product/PLAN_NEXT.md`
Run commands:
- `go test ./core/cli -run 'Test.*Canonical|Test.*Shareable|Test.*ReportContract' -count=1`
- `go test ./internal/acceptance -run 'Test.*Sprint0.*Canonical|Test.*SizeSignal' -count=1`
- `go test ./testinfra/hygiene -run 'Test.*Wave31|Test.*Freeze|Test.*Canonical' -count=1`
- `make test-contracts`
- `make prepush-full`
Test requirements:
- Tier 4 acceptance coverage for public artifact flows and paired outputs.
- Tier 9 contract coverage for canonical-store-only retained objects and gate enforcement.
- Tier 11 scenario coverage when new scenario fixtures are needed to prove repeated projection shape at scale.
Matrix wiring:
- Fast lane: focused `core/cli` and hygiene tests.
- Core CI lane: `make test-contracts` and `make prepush-full`.
- Acceptance lane: `go test ./internal/acceptance -count=1`.
- Risk lane: `make test-hardening`.
Acceptance criteria:
- Contract tests fail if any public/default writer leaks embedded clone fields while canonical refs are present.
- Hygiene tests block new scan/report surface expansion until Wave 1 and Wave 2 contracts are green.
- Governance docs and executable checks say the same thing about the temporary freeze gate.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Added universal clone-strip artifact contracts and tightened the temporary freeze gate so new scan/report surface expansion stays blocked until privacy and canonicalization tests are green.
Semver marker override: [semver:patch]
Contract/API impact: Makes clone stripping and Sprint 0 surface-freeze behavior explicit release-blocking contracts.
Versioning/migration impact: No schema version change intended; this story enforces the contract around existing and newly finalized outputs.
Architecture constraints: Hygiene and docs gates reinforce existing boundaries; they must not invent new product scope or bypass authoritative contract tests.
ADR required: no
TDD first failing test(s): `TestPublicArtifactsDoNotEmbedCanonicalClones` and `TestWave31FreezeGateRequiresRecursiveRedactionAndCloneStripGreen`.
Cost/perf impact: low
Chaos/failure hypothesis: A new writer or field expansion that bypasses shared finalization should fail in acceptance or hygiene before it reaches a release branch.

## Wave 3: JS/TS Signal And Verification

Objective: lower unnecessary parser noise and then prove the resulting scan-quality behavior on enterprise-shaped JS/TS inputs before the next customer-scale scan.
Traceability: Recommendations 5 and 6.

### Story 3.1: Scope JS/TS-Touching Detectors To High-Signal Files

Priority: P1
Recommendation coverage: 6
Tasks:
- Add explicit file selection rules for high-signal MCP configs, package scripts, route declarations, agent framework entrypoints, workflow files, `.well-known` declarations, and known tool config locations.
- Skip generated, minified, bundled, vendored, lockfile-like, and build-output paths in JS/TS-touching detectors unless a high-signal allow rule applies.
- Prefer lightweight import/package/URL extraction for broad source scans where full structured parsing is unnecessary.
- Keep detector scope deterministic and explainable through path filters or scan-quality reasons, not hidden heuristics.
- Ensure detection changes preserve existing high-priority Wrkr surfaces such as WebMCP, prompt-channel, MCP candidates, and agent framework entrypoints.
Repo paths:
- `core/detect/pathfilter.go`
- `core/detect/webmcp/detector.go`
- `core/detect/promptchannel/detector.go`
- `core/detect/agentframework/source.go`
- `core/detect/mcp/candidates.go`
- `core/detect/detect.go`
- `core/detect/parse.go`
Run commands:
- `go test ./core/detect/... -run 'Test.*PathFilter|Test.*WebMCP|Test.*PromptChannel|Test.*AgentFramework|Test.*Parse' -count=1`
- `go test ./internal/scenarios -run 'Test.*ScanQuality|Test.*WebMCP|Test.*PromptChannel' -count=1 -tags=scenario`
- `make test-hardening`
- `make test-perf`
- `make prepush-full`
Test requirements:
- Tier 1 path-filter and detector-scope unit tests.
- Tier 2 integration coverage for detector registration and allow/skip routing.
- Tier 5 hardening tests for fail-closed behavior on ambiguous or unsupported files.
- Tier 7 perf checks for reduced parse fan-out on large JS/TS fixture trees.
- Tier 11 scenario coverage for supported high-signal declarations still being discovered.
Matrix wiring:
- Fast lane: focused `core/detect` tests.
- Core CI lane: `make prepush-full`.
- Acceptance lane: scenario coverage for detector discovery.
- Risk lane: `make test-hardening` and `make test-perf`.
- Release/UAT lane: not required unless public docs or release claims change.
Acceptance criteria:
- Generated, minified, or irrelevant JS/TS files no longer drive broad structured parsing attempts by targeted detectors.
- High-signal MCP, WebMCP, prompt-channel, and agent-framework declarations are still discovered deterministically.
- Detector scope changes are explainable through stable rules and test fixtures.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Reduced unnecessary JS/TS detector parsing by narrowing structured analysis to high-signal files and using lighter extraction for broad source scans.
Semver marker override: [semver:patch]
Contract/API impact: Changes scan-quality and detector-coverage behavior for JS/TS-heavy repositories while preserving Wrkr discovery contracts.
Versioning/migration impact: No artifact version bump expected, but scan-quality summaries and detector counts may change on affected repos.
Architecture constraints: Detection owns path selection and parsing strategy; risk and report consume explicit coverage outputs without reclassifying detector internals.
ADR required: yes
TDD first failing test(s): `TestWebMCPSkipsGeneratedBundles`, `TestPromptChannelScopesStructuredParsing`, and `TestAgentFrameworkSourceUsesHighSignalPathSelection`.
Cost/perf impact: medium
Chaos/failure hypothesis: A repo with thousands of bundled or generated JS artifacts should produce bounded parse work and explicit reduced-coverage notes instead of noisy failure volume.

### Story 3.2: Verify Parser Robustness On Sanitized Enterprise-Shaped Repos

Priority: P1
Recommendation coverage: 5
Tasks:
- Create or update sanitized JS-heavy fixtures that model modern ESM, `.mjs`, `.cjs`, Yarn PnP, generated bundles, unsupported syntax edges, and detector-relevant high-signal files.
- Use only sanitized enterprise-shaped fixture sets in committed validation and record deterministic parse-failure counts, affected detectors, extension mix, generated-file share, and resulting scan-quality status from those fixtures.
- If teams optionally replay a private customer-shaped repo set outside the repository for extra confidence, keep that replay out of committed artifacts, docs claims, and release receipts.
- Assert parser-failure ceilings and verify reduced coverage is surfaced in report summaries without becoming security findings.
- Preserve explicit receipts for before/after parser-failure volume so future customer-scale runs can be compared to a known baseline.
- Keep all verification artifacts synthetic, reviewable, and safe to commit.
Repo paths:
- `internal/scenarios`
- `core/detect/parse.go`
- `core/detect/detect.go`
- `core/detect/webmcp/detector.go`
- `core/detect/promptchannel/`
- `internal/acceptance/sprint0_size_signal_acceptance_test.go`
- `docs/commands/scan.md`
Run commands:
- `scripts/validate_scenarios.sh`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `go test ./internal/acceptance -run 'Test.*ScanQuality|Test.*Parser' -count=1`
- `make test-perf`
- `scripts/run_v1_acceptance.sh --mode=local`
Test requirements:
- Tier 4 acceptance checks for scan-quality honesty in customer-visible outputs.
- Tier 7 perf checks for parser-failure ceilings on enterprise-shaped fixtures.
- Tier 9 contract checks for scan-quality status and non-finding classification.
- Tier 11 scenario coverage for modern JS/TS repo shapes.
Matrix wiring:
- Fast lane: targeted scenario and acceptance subsets while iterating on fixtures.
- Core CI lane: `make test-contracts` if scan-quality schema or docs change.
- Acceptance lane: `go test ./internal/scenarios -count=1 -tags=scenario` and `scripts/run_v1_acceptance.sh --mode=local`.
- Cross-platform lane: required if fixture paths or generated-file detection vary by platform.
- Risk lane: `make test-perf`.
Acceptance criteria:
- Sanitized enterprise-shaped fixtures stay under an explicit parse-failure ceiling with clear scan-quality output.
- Unsupported or reduced coverage appears as scan-quality context, not security findings.
- The repo gains deterministic receipts that can be reused before the next customer-scale JS/TS-heavy scan.
Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Added sanitized enterprise-shaped JS/TS parser verification fixtures and scan-quality receipts so reduced coverage is reported honestly without noisy security findings.
Semver marker override: [semver:patch]
Contract/API impact: Strengthens scan-quality and report honesty contracts for JS/TS-heavy repositories.
Versioning/migration impact: No versioned migration expected; parser-verification fixtures and scan-quality expectations become stricter.
Architecture constraints: Detection emits parse and coverage facts; report and CLI render them; no live customer repo dependency or network path is introduced.
ADR required: no
TDD first failing test(s): `TestJSEnterpriseFixtureParseFailureCeiling` and `TestReducedCoverageDoesNotBecomeSecurityFinding`.
Cost/perf impact: medium
Chaos/failure hypothesis: Unsupported modern syntax and generated bundles should degrade to bounded scan-quality signals, not explode parse volume or create false-positive risk findings.

## Implementation Handoff

- Expected follow-up command:
  - `Use $plan-implement with plan_path: product/plans/adhoc/PLAN_ADHOC_2026-06-13_094023_remaining-redaction-canonicalization-parser-gates.md`
- Expected first implementation wave:
  - Land Story 1.1 and Story 1.2 together or in immediate sequence so release-blocking privacy gaps close before any canonicalization or parser-scope work claims safety.
- Recommended first validation bundle for the first implementation PR:
  - `make lint-fast`
  - `make test-fast`
  - `make test-contracts`
  - `go test ./internal/acceptance -count=1`

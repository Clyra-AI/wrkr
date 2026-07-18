# Adhoc Plan: Portable Action Contract Interoperability

Date: 2026-07-18
Profile: `wrkr`
Slug: `action-contract-interop`
Recommendation source: Google Doc `Wrkr July 17`, covering portable proposed Action Contract artifacts, explicit authority requirements, typed readiness and effect preconditions, confirmation and compensation requirements, revision lifecycle, a buyer-facing packet, exact-byte cross-product fixtures, equivalent-outcome control parity, and bounded multi-stage cross-system contracts.

Story paths and commands resolve from `$REPO_ROOT`. The source recommendations are normalized to Wrkr's current architecture and intentionally exclude Gait and Axym product implementation.

## Global Decisions (Locked)

- Wrkr proposes and reports Action Contracts; it does not activate contracts, grant authority, issue credentials, approve actions, execute effects, or enforce runtime policy. Gait remains authoritative for runtime binding, activation, rejection, execution, and effect enforcement. Axym remains authoritative for reconstructing and verifying the resulting evidence chain.
- The public name remains `proposed_action_contract`. All new contract artifacts keep `report_only: true`; imported Gait or Axym state is evidence about downstream activity, never a Wrkr-owned runtime state transition.
- Introduce `proposed_action_contract` contract version `3` for the richer typed model. Freeze the current version `2` schema and fixtures for compatibility, emit version `3` after migration, and keep readers able to validate both. Do not silently rewrite a version `2` contract into version `3`.
- Add `schemas/v1/proposed-action-contract-v3.schema.json` instead of changing the meaning of the existing version `2` schema in place. Public embedding schemas accept the explicit versioned alternatives.
- Contract family identity is stable over the durable resolution key and outcome family. A contract ID identifies one immutable revision. Revision defaults to `1` when no prior-family evidence exists and increments only from an explicitly supplied, validated predecessor; wall-clock time or scan order must never infer revision order.
- The portable artifact envelope has its own schema version and identity. Its canonical content digest covers normalized contract content and durable references, excludes explicitly documented volatile presentation timestamps, and uses the shared `github.com/Clyra-AI/proof/core/canon` RFC 8785 JCS domain rather than a second local canonicalizer.
- Required and satisfied are different fields. A requirement may be `verified`, `declared`, `inferred`, `unknown`, or `contradictory`, with separate freshness and evidence references. An inferred requirement is never presented as a verified grant.
- Authority, readiness, confirmation, approval, credential, effect, and compensation requirements are structured data. Prose is a rendering of the typed contract, not an input Gait must parse.
- Equivalent-outcome control parity is monotonic. It may maintain or raise the weaker route to the most restrictive peer control or a fixed policy floor; it may never lower a control. Peer controls are snapshotted before parity so reciprocal grouping cannot create feedback loops.
- The exact parity reason is `composition:equivalent_outcome_control_parity`. Any raised recommendation must rebuild the affected proposed contract and identify a stable escalation source.
- Static reachability remains distinct from observed execution. Three-to-five-stage paths are bounded deterministic hypotheses with stage evidence and trust-boundary correlation; they are never proof that the path executed.
- New packet and artifact output is opt-in. The default scan stdout, primary report, and finding count do not expand. Every public field and buyer-facing rendering must refresh the existing green Sprint 0 freeze-gate receipt with measured size, redaction, recursive-redaction, clone-strip, readability, and noise evidence.
- Cross-product fixtures are generated from a real Wrkr scan/state/export pipeline. Committed expected bytes are reviewed goldens; no hand-authored Gait or Axym projection may masquerade as the exported handoff contract.
- All list ordering, IDs, digests, reason codes, artifact filenames, and Markdown sections are deterministic. No scan-time LLM, network call, secret extraction, payload inspection, or implicit data egress is allowed.

## Current Baseline (Observed)

- `core/risk/proposed_action_contract.go` emits contract version `2` nested inside composed action paths. It has deterministic IDs, allowed/prohibited/approval-required transitions, target constraints, credential mode, delegation depth, evidence requirement strings, countersigners, expected outcome class, a compensation-required boolean, source digests, readiness, reason codes, and `report_only: true`.
- `schemas/v1/proposed-action-contract.schema.json` is closed with `additionalProperties: false` and accepts only contract version `2`; it has no artifact envelope, family ID, revision, typed authority requirement, typed precondition, structured confirmation/compensation, or downstream lifecycle evidence.
- Version `2` contract identity is locally assembled with SHA-256. The repo already depends on `github.com/Clyra-AI/proof v0.4.6`, whose stable `core/canon` package provides RFC 8785 JCS canonicalization and digest primitives suitable for the portable artifact.
- `core/risk/composition.go` builds bounded pairwise compositions and calls `annotateEquivalentOutcomeSignals` after each path recommendation is chosen. Equivalent-outcome metadata identifies weaker peers but does not raise their recommended control, so approval-evasion alternatives can remain less restrictive.
- The existing composition engine is source/sink and pairwise-pattern oriented. It can cap output and sort deterministically, but it does not model bounded ordered three-to-five-stage paths across repo, CI, cloud, package, SaaS, and communications boundaries.
- `core/risk/action_paths.go` already carries owner and approval evidence states, credential authority, action lineage, policy/Gait coverage, delivery control context, sandbox/test/validation requirements, and proof/evidence references. These are inputs to the richer contract, not reasons to invent a parallel detector pipeline.
- `core/aggregate/inventory/authority_binding.go` and `credential_authority.go` model discovered bindings and credential posture, but not the full requesting identity, business-owner, affected-system-owner, permitted-role, policy-authority, delegation-root, subject-constraint, or segregation-of-duties requirement model.
- Canonical evidence states already exist in `core/risk/evidence_state.go`: `verified`, `declared`, `inferred`, `unknown`, and `contradictory`. Freshness states already exist in `core/evidencepolicy`. New requirement status reuses these vocabularies.
- `core/detect/gaitpolicy/constraints.go`, `core/config/control_declarations.go`, and delivery-control projections already expose checks, security gates, sandbox/test/validation, approval, credential, and policy evidence. They do not yet produce typed validation/effect contract references, acceptable producers, freshness bounds, expected/forbidden effect classes, or per-precondition state.
- `core/cli/export.go` supports inventory, appendix, tickets, and declarations. There is no `wrkr export action-contracts` command and no standalone portable Action Contract artifact.
- `core/proofmap` and evidence bundles carry composition and proposed-contract references but do not emit a contract-creation evidence link or a portable artifact envelope.
- `core/report` and buyer Markdown expose the nested proposal and composition context. There is no opt-in Action Contract packet with JSON and Markdown projections from one shared model.
- `scenarios/wrkr/composed-action-paths/expected/composition-contract-fixtures.json` and `scenarios/cross-product/composed-action-contracts/expected/` contain illustrative, hand-authored projections. Tests validate shape and references rather than regenerating the exact bytes through Wrkr and passing those same bytes to consumer contract suites.
- `testinfra/contracts/fixtures/freeze-gate/story-0.1-receipt.json` is currently green for the existing public surface, including size, redaction, recursive-redaction, clone-strip, readability, and noise checks. Its scope must be refreshed for each artifact or packet surface introduced here.
- `docs/decisions/wave53-composed-action-path-contracts.md` records the current report-only composition/PAC boundary. The richer contract version, portable artifact, downstream lifecycle evidence, and multi-stage reachability require explicit follow-on decisions rather than reinterpretation of that ADR.

## Exit Criteria

- `wrkr export action-contracts` deterministically emits standalone versioned envelopes containing an immutable version `3` proposed contract, stable artifact/contract/family IDs, revision, producer metadata, source scan and composition refs, resolution key, creation evidence, and an RFC 8785 JCS canonical content digest.
- Version `2` contract fixtures remain valid and readable. Version `3` emission has an explicit compatibility matrix, additive embedding migration, and no silent in-place rewrite.
- Every emitted version `3` contract distinguishes required authority from observed evidence and covers originating intent/task, requester identity requirements, business and affected-system owners, agent roles, policy authority, delegation root, credential subject constraints, and separation-of-duties requirements.
- Readiness and effect preconditions are typed and independently stateful, including validation/effect contract refs, checks, producers, freshness, environment/target/sandbox constraints, policy digest, credential mode, and expected/forbidden effect classes.
- Confirmation, approval, and compensation are structured requirements with modes, roles, counts, separation rules, scope digest, validity, reapproval triggers, compensation procedure/target/window/verification/evidence, and fail-closed behavior for missing or contradictory requirements.
- Proposed revisions are immutable and explicitly linked. Imported Gait activation/rejection/execution evidence and Axym verification refs are preserved without Wrkr claiming authority for those events.
- Equivalent-outcome grouping raises weaker routes monotonically, records the canonical parity reason and escalation source, rebuilds the proposed contract, and is deterministic under input order, duplicate peers, and reciprocal alternatives.
- The opt-in Action Contract packet renders the same normalized model as schema-valid JSON and bounded Markdown, covering path, authority, source/sink, asset, credentials, checks, effects, confirmation, compensation, gaps, imported Gait status, and next action.
- Canonical customer-data-to-egress, workflow-to-deploy, secret-to-network, package-to-release, excessive-child-authority, failed-effect-validation, approval-expiry, compensation, and supersession fixtures are generated through real Wrkr code. Tests regenerate to a temporary directory and byte-compare the exact exported artifacts.
- Gait and Axym conformance lanes can consume the exact committed artifact bytes unchanged through explicit external consumer entrypoints. Missing consumers fail as dependency-missing in Tier 12 rather than triggering local hand-authored substitutes.
- The P1 engine finds only configured bounded three-to-five-stage cross-system paths, carries ordered stage/trust-boundary evidence and stable IDs, remains within measured performance/noise budgets, and labels possible reachability separately from observed execution.
- Docs, CLI help, schemas, changelog, compatibility matrices, ADRs, generated fixtures, proof/evidence refs, redaction, and freeze-gate receipts agree with executable behavior.

## Public API and Contract Map

- Proposed Action Contract:
  - Preserve `schemas/v1/proposed-action-contract.schema.json` as the version `2` compatibility contract.
  - Add `schemas/v1/proposed-action-contract-v3.schema.json` with typed `authority_requirements`, `preconditions`, `confirmation_requirement`, `approval_requirement`, `compensation_requirement`, immutable family/revision fields, and imported lifecycle evidence.
  - Emit version `3` from new scans after all P0 contract stories land; accept version `2` and `3` in saved-state/report/export readers.
  - Keep `recommended_action_contract` compatibility fields until a separately planned major removal.
- Portable artifact envelope:
  - Add `schemas/v1/proposed-action-contract-artifact.schema.json` with `schema_id`, `schema_version`, `artifact_id`, `contract_id`, `contract_family_id`, `revision`, `producer`, `source_scan_refs`, `composition_refs`, `resolution_key`, `creation_evidence`, `canonical_content_digest`, contract content, variant/redaction metadata, and `report_only: true`.
  - Canonical digest input and excluded volatile fields are documented and contract-tested. Shared proof JCS is the only canonicalization implementation.
  - Redacted artifacts receive distinct deterministic identities and declare the applied share profile; redaction never leaves a digest that claims to identify unredacted content.
- CLI:
  - Add `wrkr export action-contracts --state <path> [--contract-id <id>] [--output-dir <dir>] [--share-profile <profile>] --json`.
  - With no selector, export all contracts in stable contract ID order. With no output directory, write a machine-readable collection to stdout. With an output directory, use stable filenames and atomic writes, reject collisions or unsafe traversal, and return a JSON manifest.
  - Preserve exit codes: `0` success, `1` runtime failure, `3` schema/policy violation, `6` invalid selector/input, `7` missing Tier 12 consumer, and `8` unsafe output blocked.
- Requirement model:
  - Each authority binding and precondition has a stable requirement ID, typed kind, required value/constraint, observed value where available, canonical evidence state, freshness state, evidence refs, and reason codes.
  - Unknown, inferred, stale, or contradictory evidence remains visible and cannot become a verified authority grant or satisfied precondition.
- Revision/lifecycle:
  - Contract content is immutable per `contract_id` and `revision`.
  - New content under a known family requires a validated predecessor, `revision = predecessor + 1`, and `supersedes_ref`; absent predecessor evidence yields revision `1` and no invented history.
  - Lifecycle observations reference proposal, activation request/receipt, rejection reason, supersession, execution/effect, and Axym bundle evidence. Gait/Axym observations are imported references, not Wrkr transitions.
- Proof and evidence:
  - Reuse sanctioned proof record types. Contract creation is linked from the existing risk-assessment/decision-trace proof projection; do not invent a Wrkr-only proof record type.
  - Evidence bundles add explicit artifact, family, revision, predecessor, and downstream evidence refs without embedding secrets or runtime payloads.
- Buyer packet:
  - Add opt-in `wrkr report --template action-contract-packet --contract-id <id> --json` and Markdown rendering from one normalized packet model.
  - The packet is not added to default scan output or the default first-screen report. Missing evidence is rendered as a gap, never omitted or inferred.
- Conformance fixtures:
  - Add a versioned fixture manifest with producer/schema versions, canonical artifact digests, scenario IDs, and external consumer entrypoints.
  - Wrkr regeneration tests own artifact production; Gait/Axym suites consume the same bytes unchanged. Consumer projections, if needed, are derived in those product repos.
- Multi-stage composition:
  - Extend `composed_action_path.stages[]` and transitions without adding a parallel graph API.
  - New path IDs cover pattern, ordered durable stage identities/roles, trust boundaries, target/outcome family, and material constraints; volatile path instance IDs and timestamps are excluded.
- Freeze and compatibility:
  - Refresh `testinfra/contracts/fixtures/freeze-gate/story-0.1-receipt.json` with measured deltas and named fixtures before each public artifact/packet release.
  - Any field removal, rename, type change, digest-profile change, or altered ID domain requires a separately approved major-version plan.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/export.md`
  - `docs/commands/report.md`
  - `docs/commands/scan.md`
  - `docs/commands/evidence.md`
  - `docs/commands/ingest.md`
  - `docs/contracts/compatibility_matrix.md`
  - `docs/examples/security-team.md`
  - `docs/examples/operator-playbooks.md`
  - `docs/map.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Architecture decisions:
  - Extend `docs/decisions/wave53-composed-action-path-contracts.md` only for non-semantic clarification; create follow-on ADRs for contract version `3` and the portable envelope, imported lifecycle evidence, parity ordering, and bounded multi-stage reachability.
- Docs must explain:
  - Wrkr proposal versus Gait authority versus Axym verification.
  - Version `2`/`3` compatibility, immutable family/revision semantics, canonical digest profile, redacted artifact identities, and migration behavior.
  - Required versus satisfied evidence, canonical states/freshness, and why inference is not a grant.
  - How to export, select, validate, redact, and reproduce an artifact or packet without network access.
  - Possible reachability versus observed execution and the bounded set of supported multi-stage patterns.
  - How exact-byte cross-product fixtures are regenerated and how external consumers report receipts.
- OSS/release gates:
  - No example contains local absolute paths, secret values, or customer identifiers.
  - CLI help, docs, schemas, examples, and changelog pass parity/consistency checks.
  - Changelog size/privacy/readability claims cite measured artifact deltas, named redaction tests, and fixture receipts in the same PR.
  - Generated goldens remain human-reviewed and byte-stable; regeneration is explicit, never an unnoticed test side effect.

## Recommendation Traceability

| Source recommendation | Priority | Planned coverage |
|---|---:|---|
| 1. Portable Proposed Action Contract Artifact | P0 | Story 2.1 |
| 2. Explicit Authority Requirement Model | P0 | Story 1.2 |
| 3. Typed Readiness and Effect Preconditions | P0 | Story 1.3 |
| 4. Confirmation, Approval, Compensation Contract | P0 | Story 1.4 |
| 5. Contract Activation and Revision Lifecycle | P0 | Story 2.2 |
| 6. Buyer-Facing Action Contract Packet | P0 | Story 3.1 |
| 7. Cross-Product Conformance Fixtures | P0 | Story 3.2 |
| 8. Equivalent-Outcome Control Parity | P0 | Story 1.1 |
| 9. Bounded Multi-Stage and Cross-System Contracts | P1 | Story 4.1 |

## Test Matrix Wiring

- Fast lane: focused Go unit tests for parity, contract builders, requirement state/freshness, canonical digesting, revision validation, packet normalization, bounded traversal, stable ordering, and CLI parsing, plus `make lint-fast`.
- Core CI lane: `make test-fast`, `make test-contracts`, schema/golden validation, saved-state compatibility, export safety, proof/evidence mapping, JSON/Markdown equivalence, and docs/CLI parity.
- Acceptance lane: `make test-scenarios`, `scripts/validate_scenarios.sh`, scenario-tagged real-pipeline regeneration, and `scripts/run_v1_acceptance.sh --mode=local` after each completed P0 wave.
- Cross-platform lane: Linux, macOS, and Windows validation of output paths, atomic writes, JSON/Markdown newlines, stable filenames/digests, fixture regeneration, and CLI exit codes; keep the profile-required `windows-smoke` check green.
- Risk lane: `make test-risk-lane`, `make test-hardening`, `make test-chaos`, `make test-perf`, and `make codeql` for fail-closed requirements, malformed evidence, unsafe export paths, parity monotonicity, bounded graph expansion, redaction, and artifact integrity.
- Release/UAT lane: `make prepush-full`, exact-byte cross-product consumer receipts, schema compatibility checks, docs-site checks, release smoke, and local UAT before version promotion.
- Gating rule: no story is complete until its first failing tests exist, declared lanes pass with `-count=1` where required, public schemas/docs/changelog move together, freeze-gate receipts are current, golden updates are explicitly reviewed, and no local absolute path or volatile nondeterminism appears in an artifact.

## Minimum-Now Sequence

- Wave 1 - Correctness and typed contract spine:
  - Story 1.1: enforce monotonic equivalent-outcome control parity before contract construction.
  - Story 1.2: introduce version `3` and explicit authority requirements.
  - Story 1.3: add typed readiness and effect preconditions.
  - Story 1.4: add structured confirmation, approval, and compensation requirements.
- Wave 2 - Portable identity and lifecycle:
  - Story 2.1: add the standalone JCS-digested artifact envelope and export command.
  - Story 2.2: add immutable revision and imported downstream lifecycle evidence.
- Wave 3 - Buyer and cross-product assurance:
  - Story 3.1: add the opt-in Action Contract packet from a shared JSON/Markdown model.
  - Story 3.2: replace hand-authored handoff projections with real-pipeline exact-byte conformance fixtures.
- Wave 4 - Bounded reachability expansion:
  - Story 4.1: add configured three-to-five-stage cross-system compositions after P0 contracts and output budgets are green.

## Explicit Non-Goals

- No runtime enforcement, activation service, approval workflow, credential issuer, policy decision point, effect executor, compensating-action runner, or session monitor in Wrkr.
- No Gait or Axym product logic beyond portable shared contracts, references, fixtures, and external conformance entrypoints.
- No automatic activation, inferred authority grant, implicit delegation, or claim that a declared policy is runtime-proven.
- No universal guarantee that a proposed contract is sufficient or correct for every downstream environment.
- No generalized runtime, complex-event-processing engine, arbitrary graph query language, or unbounded path enumeration.
- No raw secret/payload collection, secret hashing, default network call, live tool execution, or scan-data exfiltration.
- No default-report expansion or broader finding inventory; packet and artifact outputs remain explicit opt-in surfaces.
- No removal of version `2`, `recommended_action_contract`, existing action paths, workflow chains, composition refs, or existing CLI modes in this plan.

## Definition of Done

- A security team can export a deterministic, portable, evidence-backed proposed Action Contract that Gait can validate without prose parsing and Axym can later correlate through explicit proof/evidence references.
- The contract fully describes required authority, preconditions, confirmation/approval, credential/effect constraints, compensation, revision history, and evidence state while preserving the Wrkr/Gait/Axym authority boundary.
- Equivalent-outcome alternatives cannot keep a weaker recommendation than their restrictive peer or floor, and contract artifacts reflect the raised control deterministically.
- JSON, Markdown, schemas, CLI help, saved state, proof/evidence bundles, buyer packet, and docs agree on identifiers, revisions, state, redaction, and compatibility.
- Real-pipeline goldens cover all nine required scenarios and are consumed unchanged by declared cross-product contract lanes.
- Multi-stage composition remains bounded, explainable, measured, and clearly labeled as possible versus observed.
- `make prepush-full`, required GitHub checks, passive latest-head Codex review, merge, and post-merge main monitoring complete successfully.

## Epic 1: Correctness and Typed Contract Spine

Objective: close the approval-evasion gap first, then replace prose-like version `2` requirements with a versioned, evidence-backed typed proposal.

### Story 1.1: Enforce equivalent-outcome control parity

Priority: P0
Recommendation coverage: 8. Equivalent-Outcome Control Parity
Strategic direction: Apply parity after outcome grouping and before final proposed-contract construction so every exported contract contains the effective monotonic control.
Expected benefit: Alternate routes to the same consequential outcome cannot evade a stricter approval or blocking control already required by an equivalent peer.

Tasks:
- Add first-failing table tests around `annotateEquivalentOutcomeSignals` for weaker alternate route, equal peer, stronger route, duplicate peer, reciprocal peers, input permutations, unsupported outcome, and missing recommendation.
- Define one canonical control restrictiveness ordering by reusing the existing recommendation taxonomy; reject unknown controls rather than guessing a rank.
- Snapshot each eligible composition's pre-parity recommendation and stable peer key before applying any change.
- For each outcome group, compute the maximum of the most restrictive eligible peer and any configured fixed floor, then apply it only when it raises the current control.
- Add reason `composition:equivalent_outcome_control_parity`, stable escalation-source metadata, and the peer/floor reference that caused the raise. Deduplicate and sort all refs/reasons.
- Rebuild the affected proposed Action Contract and any escalation/closure projection after parity. Do not let post-parity peers feed a second reciprocal pass.
- Preserve current approval-evasion and materiality annotations for equal/stronger routes without adding a false raise reason.
- Document the ordering, snapshot algorithm, unknown-control fail-closed rule, and Wrkr/Gait boundary in a parity ADR.

Repo paths:
- `core/risk/composition.go`
- `core/risk/composition_test.go`
- `core/risk/proposed_action_contract.go`
- `core/risk/proposed_action_contract_test.go`
- `schemas/v1/composed-action-path.schema.json`
- `docs/decisions/`
- `docs/commands/report.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*EquivalentOutcome|Test.*ApprovalEvasion|Test.*ProposedActionContract' -count=1`
- `go test ./testinfra/contracts -run 'Test.*Composition|Test.*ActionContract' -count=1`
- `make lint-fast`
- `make test-fast`

Test requirements:
- First failing tests prove the current weaker alternate remains weaker and that a reciprocal pair would be order-sensitive without a snapshot.
- Property/permutation tests prove parity never lowers a recommendation and output is identical under reordered or duplicated inputs.
- Negative tests cover unknown controls, no eligible peer, incomparable outcome groups, and a floor below the current control.
- Contract tests prove raised control, canonical reason, escalation source, and rebuilt contract agree.

Matrix wiring:
- Fast lane: focused risk/PAC unit tests and `make lint-fast`.
- Core CI lane: `make test-fast`, composition schemas, and report contract tests.
- Acceptance lane: approval-evasion scenario in `make test-scenarios`.
- Cross-platform lane: stable JSON/golden ordering in Linux and Windows smoke.
- Risk lane: hardening for unknown controls and chaos/permutation tests.
- Gating rule: no parity output ships unless monotonicity, snapshot determinism, contract rebuild, docs, ADR, and existing composition goldens pass.

Acceptance criteria:
- A weaker equivalent-outcome route is raised to the most restrictive eligible peer/floor and records `composition:equivalent_outcome_control_parity` exactly once.
- Equal or stronger routes are unchanged; no route is ever lowered.
- The result, escalation source, reason list, and proposed contract bytes are stable across input ordering and reciprocal alternatives.

Changelog impact: required
Changelog section: Fixed
Draft changelog entry: Raised weaker equivalent-outcome routes to the deterministic peer control floor so approval-evasion alternatives cannot retain a less restrictive proposed Action Contract.
Semver marker override: [semver:patch]
Contract/API impact: Existing recommendation, reason-code, escalation-source, and nested contract values can become more restrictive for equivalent outcomes; no field is removed.
Versioning/migration impact: Behavioral patch only; baselines may report intentional risk/control drift and must be reviewed rather than silently rebased.
Architecture constraints: Parity stays in the risk/composition layer after grouping; detection and rendering must not recompute it.
ADR required: Yes - lock control ordering, snapshot timing, fixed-floor semantics, and fail-closed handling.
TDD first failures: Weaker peer not raised; reciprocal pair changes with input order; contract retains the pre-parity recommendation.
Cost/performance impact: One bounded group scan over capped compositions; benchmark must show no material regression against the existing pairwise fixture.
Chaos/failure hypothesis: Duplicate peers, unknown controls, or shuffled maps could create oscillation or nondeterminism; snapshot-once and stable sorting must prevent it.

### Story 1.2: Add version 3 explicit authority requirements

Priority: P0
Recommendation coverage: 2. Explicit Authority Requirement Model
Strategic direction: Make the authority needed for activation explicit while preserving the difference between discovery evidence and an actual downstream grant.
Expected benefit: Gait can evaluate who and what must authorize a proposed action without interpreting owner prose or treating Wrkr inference as permission.

Tasks:
- Add first-failing builder/schema tests for absent owner, conflicting owners, human requester, service identity, delegated identity, shared credential, excessive child authority, segregation-of-duties conflict, unknown evidence, and inferred-versus-verified authority.
- Define version `3` types for stable requirement IDs, requirement kind, required constraint, observed value, evidence state, freshness state, evidence refs, and reason codes.
- Project originating intent/task refs, requesting human/service identity requirements, business owner, affected-system owner, permitted agent roles, policy authority ref, delegation root, credential subject constraints, and segregation-of-duties requirements from existing action lineage, owner, policy, credential, and authority-binding evidence.
- Reuse canonical `verified`, `declared`, `inferred`, `unknown`, and `contradictory` states plus existing freshness semantics. Do not add `satisfied` as an evidence synonym.
- Add deterministic missing/contradiction reasons and a derived authority readiness summary that cannot be `ready` when a required binding is missing, stale beyond policy, unknown, inferred-only where verification is required, or contradictory.
- Add `schemas/v1/proposed-action-contract-v3.schema.json`; preserve the version `2` schema and fixtures, update embedding schemas to accept explicit version alternatives, and add version `2` read-compat tests.
- Make family and revision fields present in version `3` with deterministic revision `1` until Story 2.2 supplies validated predecessor evidence.
- Update saved-state/report decoders, docs, compatibility matrix, and create the contract-version ADR.

Repo paths:
- `core/risk/proposed_action_contract.go`
- `core/risk/proposed_action_contract_test.go`
- `core/risk/action_lineage.go`
- `core/aggregate/inventory/authority_binding.go`
- `core/aggregate/inventory/credential_authority.go`
- `schemas/v1/proposed-action-contract.schema.json`
- `schemas/v1/proposed-action-contract-v3.schema.json`
- `schemas/v1/risk/risk-report.schema.json`
- `schemas/v1/agent-action-bom.schema.json`
- `core/state/`
- `testinfra/contracts/`
- `docs/contracts/compatibility_matrix.md`
- `schemas/v1/README.md`
- `docs/decisions/`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*AuthorityRequirement|Test.*ProposedActionContractV3|Test.*ContractV2Compatibility' -count=1`
- `go test ./core/aggregate/inventory -run 'Test.*AuthorityBinding|Test.*CredentialAuthority' -count=1`
- `go test ./core/state ./testinfra/contracts -run 'Test.*ActionContract|Test.*Schema|Test.*SavedState' -count=1`
- `make test-contracts`
- `make lint-fast`

Test requirements:
- First failing tests cover every authority category and prove inferred/unknown evidence is not a grant.
- Schema goldens validate both frozen version `2` and new version `3`; malformed mixed-version documents fail closed.
- Determinism tests reorder owners, bindings, evidence refs, roles, and credential subjects without changing requirement IDs or bytes.
- Redaction tests remove personal/customer identifiers recursively while preserving requirement state and producing distinct redacted identities later consumed by Story 2.1.

Matrix wiring:
- Fast lane: builder/state unit tests and `make lint-fast`.
- Core CI lane: schemas, saved-state compatibility, redaction contracts, and `make test-fast`.
- Acceptance lane: service, delegated, shared-credential, and SoD scenario cases.
- Cross-platform lane: versioned JSON goldens on Linux, macOS, and Windows smoke.
- Risk lane: malformed/mixed-version hardening, recursive redaction, and CodeQL.
- Gating rule: version `3` cannot become the emitted default until version `2` compatibility, all authority cases, docs, ADR, changelog, and refreshed freeze receipt pass.

Acceptance criteria:
- Version `3` expresses every required authority binding with stable IDs, typed constraints, evidence/freshness state, refs, and reason codes.
- Missing, stale, inferred-only, unknown, and contradictory authority fail readiness without Wrkr claiming an actual grant.
- Version `2` remains schema-valid/readable and no existing field is silently reinterpreted.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added proposed Action Contract version 3 with typed, evidence-backed authority requirements while retaining version 2 compatibility.
Semver marker override: [semver:minor]
Contract/API impact: Adds an explicit version `3` public schema and new typed fields; embedding readers accept versions `2` and `3`.
Versioning/migration impact: Emitters migrate to version `3` only after the full P0 contract wave; readers remain dual-version and version `2` artifacts are immutable.
Architecture constraints: Authority is projected in risk from normalized aggregation/identity evidence; detectors do not emit product-level grants and reports do not infer them.
ADR required: Yes - lock version split, family identity, evidence-state vocabulary, readiness derivation, and compatibility policy.
TDD first failures: Missing owner treated as ready; inferred service identity appears verified; mixed v2/v3 object validates; input order changes requirement IDs.
Cost/performance impact: Linear projection over already bounded path evidence; add allocation/size benchmarks and keep default report growth at zero because fields are opt-in/nested only.
Chaos/failure hypothesis: Conflicting owner sources, shared subjects, stale declarations, or malformed refs could be collapsed into a false grant; typed state and contradiction-preserving merge must fail closed.

### Story 1.3: Add typed readiness and effect preconditions

Priority: P0
Recommendation coverage: 3. Typed Readiness and Effect Preconditions
Strategic direction: Represent what must be proven before activation and what effects are allowed as machine-checkable requirements, not evidence strings.
Expected benefit: Gait can validate readiness and effect constraints directly and explain exactly which required evidence is missing, stale, failed, or unsupported.

Tasks:
- Add first-failing tests for missing check, stale check, failed check, unknown producer, absent validation/effect contract, unsupported environment, target mismatch, missing sandbox, standing credential conflict, contradictory evidence, and fully satisfied inputs.
- Define typed precondition kinds for validation contract, effect contract, required check, producer, freshness, environment, target, sandbox, policy digest, credential mode, expected effect, and forbidden effect.
- Model requirement and observation separately: stable requirement ID, required constraint, acceptable producers, max age/validity, observed result, evidence/freshness state, evidence refs, and reason codes.
- Project available check/security-gate/sandbox/test/validation/policy/credential evidence from delivery control context, Gait constraints, declarations, action paths, and compositions; emit explicit unknown/missing state where the source is absent.
- Add a deterministic aggregate readiness result derived from required preconditions. Unknown producers, failed required checks, stale evidence, unsupported environments, and contradictions cannot be satisfied.
- Add effect-class vocabulary and validation rules without inspecting runtime payloads; document unsupported/custom class behavior as unknown and fail closed when required.
- Extend version `3` schema, JSON/report projections, redaction, and compatibility tests additively.

Repo paths:
- `core/risk/proposed_action_contract.go`
- `core/risk/proposed_action_contract_test.go`
- `core/risk/action_paths.go`
- `core/risk/wave4_enterprise_context.go`
- `core/detect/gaitpolicy/constraints.go`
- `core/config/control_declarations.go`
- `schemas/v1/proposed-action-contract-v3.schema.json`
- `testinfra/contracts/`
- `docs/commands/report.md`
- `docs/contracts/compatibility_matrix.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*Precondition|Test.*Readiness|Test.*EffectContract' -count=1`
- `go test ./core/detect/gaitpolicy ./core/config -run 'Test.*Constraint|Test.*ControlDeclaration' -count=1`
- `go test ./testinfra/contracts -run 'Test.*ActionContract|Test.*Redaction|Test.*Schema' -count=1`
- `make test-contracts`
- `make test-fast`

Test requirements:
- First failing tests cover every named negative case and a fully satisfied control case.
- State tables prove `required` does not imply `satisfied` and inferred/declared evidence cannot become verified by rendering or serialization.
- Determinism tests reorder checks, producers, effects, and refs without changing IDs/digests.
- Schema and redaction tests cover long/custom values, missing refs, contradictory states, and recursive nested evidence.

Matrix wiring:
- Fast lane: precondition projection/state-table tests and lint.
- Core CI lane: contract/schema/redaction tests and `make test-fast`.
- Acceptance lane: failed effect validation, standing credential, stale approval/check, and satisfied scenario cases.
- Cross-platform lane: stable serialized durations, paths, and newlines.
- Risk lane: malformed producer, freshness boundary, contradiction, and fail-closed chaos tests.
- Gating rule: no precondition is labeled satisfied unless typed state, acceptable producer, freshness, and evidence checks all pass; docs/schema/goldens must agree.

Acceptance criteria:
- Version `3` carries all required typed readiness and effect fields with separate required/observed state.
- Missing, failed, stale, unknown-producer, unsupported-target/environment, standing-credential, and contradictory cases fail readiness deterministically.
- Fully satisfied evidence produces a stable, explainable ready result without a runtime-execution claim.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added typed readiness and effect preconditions to proposed Action Contract version 3, including producer, freshness, environment, credential, and effect constraints.
Semver marker override: [semver:minor]
Contract/API impact: Additive version `3` fields and enums; version `2` remains unchanged.
Versioning/migration impact: Existing evidence strings remain readable for version `2`; version `3` derives typed entries and never backfills unverifiable satisfaction.
Architecture constraints: Detection/config layers expose normalized evidence; the risk contract builder owns requirement evaluation; Gait owns runtime enforcement.
ADR required: Yes - append to the version `3` ADR or add a focused decision for precondition/effect vocabularies and fail-closed state derivation.
TDD first failures: Missing effect contract omitted instead of marked missing; stale check passes; unknown producer passes; required and satisfied collapse into one boolean.
Cost/performance impact: Linear over bounded checks/effects; cap list sizes, measure artifact-byte deltas, and preserve zero default-report growth.
Chaos/failure hypothesis: Malformed durations, cyclic refs, contradictory producers, and huge effect lists could cause nondeterminism or memory growth; validate, cap, sort, and fail closed.

### Story 1.4: Structure confirmation, approval, and compensation requirements

Priority: P0
Recommendation coverage: 4. Confirmation, Approval, Compensation Contract
Strategic direction: Replace flags and prose with typed activation and recovery requirements that downstream systems can evaluate without interpretation.
Expected benefit: High-impact actions have explicit confirmation, approval scope, expiry/reapproval, segregation, and recovery obligations before runtime activation.

Tasks:
- Add first-failing tests for absent confirmation, insufficient approvers, requester-as-approver SoD violation, expired approval, scope-digest mismatch, reapproval trigger, missing compensation, unsupported compensation kind, unverifiable recovery, and satisfied requirements.
- Define confirmation modes and structured approval fields: approver roles, minimum approvals, SoD constraints, approval scope digest, validity window, and deterministic reapproval triggers.
- Define compensation requirement fields: kind, procedure reference, target, execution window, verification requirement, acceptable evidence/producers, current evidence state, and reason codes.
- Derive requirements from canonical recommendation, target/effect class, approval evidence, policy constraints, and existing compensation signal. Preserve `compensation_required` as a compatibility projection, not the version `3` source of truth.
- Canonicalize approval scope over immutable contract content using the same documented JCS domain used for later artifact content; exclude approval observation and volatile timestamps from the scope digest.
- Fail readiness for missing/expired/insufficient/SoD-conflicting approval or required compensation evidence. Never perform the compensation procedure.
- Extend schema, report language, compatibility docs, fixtures, redaction, and freeze receipt with measured packet/artifact deltas.

Repo paths:
- `core/risk/proposed_action_contract.go`
- `core/risk/proposed_action_contract_test.go`
- `core/risk/evidence_state.go`
- `core/config/control_declarations.go`
- `schemas/v1/proposed-action-contract-v3.schema.json`
- `testinfra/contracts/`
- `testinfra/contracts/fixtures/freeze-gate/story-0.1-receipt.json`
- `docs/commands/report.md`
- `docs/contracts/compatibility_matrix.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*Confirmation|Test.*ApprovalRequirement|Test.*Compensation|Test.*ScopeDigest' -count=1`
- `go test ./testinfra/contracts -run 'Test.*ActionContract|Test.*Freeze|Test.*Redaction' -count=1`
- `make test-contracts`
- `make test-risk-lane`

Test requirements:
- First failing tests cover each missing, expired, mismatched, insufficient, conflicting, and satisfied case.
- Digest tests prove scope changes alter the approval digest while observation timestamps and input order do not.
- Compatibility tests prove the version `2` boolean remains readable and version `3` renders one canonical structured source.
- Redaction and long-value tests cover procedure/target/evidence refs without secret or customer leakage.

Matrix wiring:
- Fast lane: focused confirmation/approval/compensation tests and lint.
- Core CI lane: schema, compatibility, redaction, and digest goldens.
- Acceptance lane: approval expiry, compensation required, missing recovery evidence, and successful controlled path scenarios.
- Cross-platform lane: duration/time parsing and canonical digest stability.
- Risk lane: expiry-boundary, SoD, digest mismatch, malformed procedure, and fail-closed chaos tests.
- Gating rule: no contract can report ready when a required confirmation, approval, SoD, validity, or compensation condition is unresolved; refreshed freeze receipt is mandatory.

Acceptance criteria:
- Version `3` exposes structured confirmation, approval, and compensation requirements with stable IDs, scope digest, state, freshness, refs, and reasons.
- Approval expiry, scope mismatch, insufficient approvals, SoD conflicts, and missing compensation evidence fail readiness deterministically.
- Compatibility projection and buyer prose are derived from the typed model and cannot disagree.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added structured confirmation, approval validity, separation-of-duties, reapproval, and compensation requirements to proposed Action Contract version 3.
Semver marker override: [semver:minor]
Contract/API impact: Additive version `3` objects/enums plus a canonical approval-scope digest; existing version `2` boolean remains supported.
Versioning/migration impact: Version `3` becomes authoritative for structured requirements; version `2` consumers continue receiving their legacy projection during the compatibility window.
Architecture constraints: Wrkr describes requirements and evidence only; it never approves, confirms, compensates, or treats procedure references as executable instructions.
ADR required: Yes - lock digest boundary, confirmation/approval enum semantics, validity/reapproval, and compensation safety boundary.
TDD first failures: Expired approval passes; requester satisfies independent approver; scope mismatch ignored; required compensation represented only as `true`.
Cost/performance impact: Small bounded objects and one JCS digest per contract; measure allocations/bytes and retain zero default-report growth.
Chaos/failure hypothesis: Boundary timestamps, duplicate approvers, self-approval aliases, malformed durations, and recursive procedure refs could bypass checks; normalize identities, cap refs, and fail closed.

## Epic 2: Portable Artifact Identity and Lifecycle

Objective: turn the complete proposal into a standalone, canonically identified handoff artifact with explicit immutable revision and downstream evidence semantics.

### Story 2.1: Export a portable proposed Action Contract artifact

Priority: P0
Recommendation coverage: 1. Portable Proposed Action Contract Artifact
Strategic direction: Promote the nested version `3` projection into a self-contained envelope without making Wrkr runtime-authoritative.
Expected benefit: Wrkr, Gait, and Axym can exchange and verify the same artifact bytes and digest without scraping a full report or reproducing Wrkr's discovery logic.

Tasks:
- Add first-failing canonicalization tests for map/list permutations, duplicate refs, source-evidence change, contract-content change, volatile timestamp change, redacted content, malformed schema, and unsupported canonicalization domain.
- Define the version `1` artifact envelope and JSON schema with the fields locked in the Public API and Contract Map.
- Implement envelope building under a dedicated export package. Use `proof/core/canon` RFC 8785 JCS for content and identity digests; do not copy or fork canonicalization code.
- Document the digest projection, domains, field inclusion/exclusion, stable filename, redacted variant identity, and producer/schema version rules.
- Add `wrkr export action-contracts` with state completeness checks, stable all/selected ordering, `--contract-id`, `--output-dir`, existing share profiles, JSON manifest/stdout mode, atomic writes, collision detection, traversal/symlink defenses, and established exit codes.
- Link creation evidence through existing risk-assessment/decision-trace proof projections and add artifact refs to evidence bundles without inventing a proof record type.
- Add version `2` input behavior: validate/read for compatibility but require an explicit migration/re-scan path before exporting as a version `3` artifact; never silently change its identity.
- Update help, export/evidence docs, schema index, examples, redaction contracts, freeze receipt, and ADR.

Repo paths:
- `core/export/actioncontracts/`
- `core/cli/export.go`
- `core/cli/export_test.go`
- `core/proofmap/`
- `core/evidence/`
- `schemas/v1/proposed-action-contract-artifact.schema.json`
- `schemas/v1/evidence-bundle.schema.json`
- `testinfra/contracts/`
- `testinfra/contracts/fixtures/freeze-gate/story-0.1-receipt.json`
- `docs/commands/export.md`
- `docs/commands/evidence.md`
- `docs/contracts/compatibility_matrix.md`
- `schemas/v1/README.md`
- `docs/decisions/`
- `CHANGELOG.md`

Run commands:
- `go test ./core/export/actioncontracts ./core/cli -run 'Test.*ActionContract|Test.*Export|Test.*Canonical|Test.*OutputDir' -count=1`
- `go test ./core/proofmap ./core/evidence -run 'Test.*ActionContract|Test.*ArtifactRef' -count=1`
- `go test ./testinfra/contracts -run 'Test.*ActionContractArtifact|Test.*Redaction|Test.*Freeze' -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- First failing tests prove the current nested object is not standalone and local digest assembly does not satisfy the documented envelope contract.
- Golden tests validate exact bytes, JCS digest, artifact/contract/family linkage, stable ordering/filenames, source-evidence sensitivity, and volatile timestamp exclusion.
- CLI tests cover all/selected/missing selector, incomplete state, stdout/output directory, collision, unwritable directory, traversal, symlink race defense, interruption, and exit codes.
- Recursive redaction tests prove sensitive values are absent and redacted content receives a distinct valid digest/identity.

Matrix wiring:
- Fast lane: builder/canonicalization/CLI parsing tests and lint.
- Core CI lane: schemas, exact-byte goldens, proof/evidence refs, export safety, and `make test-fast`.
- Acceptance lane: standalone export from saved scenario state with schema verification.
- Cross-platform lane: stable filenames, separators, atomic writes, permissions, newlines, and digests on Linux/macOS/Windows.
- Risk lane: traversal/symlink/collision/interruption hardening, malformed state chaos, redaction, perf, and CodeQL.
- Gating rule: artifact export cannot ship until shared JCS equivalence, schema, CLI safety, proof refs, redaction, docs, ADR, freeze receipt, and cross-platform goldens are green.

Acceptance criteria:
- The CLI emits schema-valid standalone artifacts with stable identities/digests and exact required envelope fields.
- Same normalized input yields the same bytes and digest; material contract/evidence changes alter identity; documented volatile timestamps do not.
- Redacted artifacts are self-consistent and cannot claim the unredacted identity.
- No version `2` contract is silently promoted to version `3`.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added `wrkr export action-contracts` for standalone, RFC 8785 JCS-digested proposed Action Contract artifacts with deterministic selection, redaction, and proof references.
Semver marker override: [semver:minor]
Contract/API impact: New CLI subcommand, envelope schema, manifest, artifact identity/digest domain, and evidence/proof reference fields.
Versioning/migration impact: Envelope starts at schema version `1`; contract version `3` is exportable; version `2` requires explicit re-scan/migration and remains readable.
Architecture constraints: Export renders normalized risk/state data and shared proof primitives; it must not detect, rescore, activate, call a network, or mutate saved state.
ADR required: Yes - lock envelope schema, digest domain/projection, artifact variants, state completeness, atomic-write safety, and proof mapping.
TDD first failures: No standalone command; order changes digest; timestamp changes content identity; traversal/output collision not rejected; redacted bytes keep original digest.
Cost/performance impact: O(number of bounded contracts plus bytes canonicalized); add throughput/memory benchmarks and cap artifact collection/output sizes.
Chaos/failure hypothesis: Partial writes, symlink swaps, corrupt state, duplicate IDs, huge refs, or interruption could yield unverifiable artifacts; validate first, write atomically, cap, and fail closed.

### Story 2.2: Add immutable revision and downstream lifecycle evidence

Priority: P0
Recommendation coverage: 5. Contract Activation and Revision Lifecycle
Strategic direction: Preserve proposal-to-activation-to-verification history through explicit evidence references without letting Wrkr own downstream state.
Expected benefit: Gait can activate or reject a precise immutable revision and Axym can reconstruct which contract/effect was executed and verified.

Tasks:
- Add first-failing tests for new family, unchanged content, valid successor, skipped revision, missing predecessor, family mismatch, predecessor digest mismatch, rejection, activation receipt, supersession, executed effect, conflicting downstream states, and Axym bundle linkage.
- Add deterministic `contract_family_id`, numeric `revision`, optional `supersedes_ref`, and immutable-content validation to the builder/export model.
- Accept prior-family evidence only through explicit validated saved baseline or imported evidence. Default to revision `1` without a predecessor; never derive revision from timestamps, filenames, or scan order.
- Define typed lifecycle observations for proposal creation, activation request/receipt, rejection reason codes, supersession, executed contract/effect refs, and Axym bundle refs with producer, evidence/freshness state, observed time, and proof/evidence refs.
- Treat Gait/Axym observations as imported evidence. Conflicts remain contradictory; Wrkr does not resolve or perform transitions and does not rewrite the immutable contract content.
- Ensure lifecycle observations are outside the immutable approval/content digest but inside the artifact envelope identity where documented, so evidence updates create a new artifact variant without changing the contract revision.
- Extend state ingest, evidence bundle, packet/report, schemas, compatibility matrix, regress comparison, and lifecycle ADR.

Repo paths:
- `core/risk/proposed_action_contract.go`
- `core/risk/proposed_action_contract_test.go`
- `core/export/actioncontracts/`
- `core/state/`
- `core/ingest/`
- `core/regress/`
- `core/proofmap/`
- `schemas/v1/proposed-action-contract-v3.schema.json`
- `schemas/v1/proposed-action-contract-artifact.schema.json`
- `schemas/v1/evidence-bundle.schema.json`
- `testinfra/contracts/`
- `docs/commands/ingest.md`
- `docs/commands/regress.md`
- `docs/contracts/compatibility_matrix.md`
- `docs/decisions/`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk ./core/export/actioncontracts -run 'Test.*Revision|Test.*Lifecycle|Test.*Supersed' -count=1`
- `go test ./core/state ./core/ingest ./core/regress ./core/proofmap -run 'Test.*ActionContract|Test.*Lifecycle|Test.*Artifact' -count=1`
- `go test ./testinfra/contracts -run 'Test.*ActionContract|Test.*EvidenceBundle|Test.*Compatibility' -count=1`
- `make test-contracts`
- `make test-risk-lane`

Test requirements:
- First failing tests prove current contracts cannot preserve predecessor or downstream lifecycle evidence.
- Revision tables reject skipped/nonpositive revisions, mismatched families, missing/digest-invalid predecessors, mutation under one contract ID, and contradictory authoritative observations.
- Digest tests prove lifecycle evidence can update envelope identity without mutating contract content/scope digest or revision.
- Regress tests classify contract revision, activation evidence, rejection, execution/effect, and verification-reference drift without claiming execution from static reachability.

Matrix wiring:
- Fast lane: revision/lifecycle/state unit tests and lint.
- Core CI lane: schema, ingest, regress, proof/evidence compatibility, and exact-byte goldens.
- Acceptance lane: supersession, rejection, activation receipt, effect execution ref, and Axym bundle scenarios.
- Cross-platform lane: baseline/artifact path neutrality and timestamp parsing.
- Risk lane: conflicting producer, replay, skipped revision, corrupt predecessor, stale receipt, and fail-closed chaos tests.
- Gating rule: no revision/lifecycle field ships until immutable-content validation, dual-version compatibility, imported-authority boundary, regress behavior, docs, and ADR pass.

Acceptance criteria:
- Contracts in one family form an explicit validated immutable revision chain; no history is inferred when predecessor evidence is absent.
- Imported Gait/Axym observations are typed, evidence-backed, contradiction-preserving, and never represented as Wrkr actions.
- Contract content/scope digest stays stable when only lifecycle evidence changes, while the containing artifact identity updates as documented.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added immutable proposed Action Contract revision chains and evidence-backed Gait activation, rejection, execution, effect, and Axym verification references.
Semver marker override: [semver:minor]
Contract/API impact: Additive version `3` revision/lifecycle fields, artifact identity rules, ingest/state/evidence refs, and regress categories.
Versioning/migration impact: Existing version `3` contracts without predecessor evidence remain revision `1`; later revisions require an explicit validated predecessor and never mutate prior artifacts.
Architecture constraints: Identity/risk own deterministic family/revision derivation; ingest preserves downstream evidence; Gait/Axym remain authoritative for their observations.
ADR required: Yes - lock immutable boundary, predecessor validation, lifecycle evidence vocabulary, conflict behavior, and digest layering.
TDD first failures: Content mutates under same ID; revision increments from time; skipped revision accepted; conflicting activation/rejection collapses; lifecycle timestamp changes contract digest.
Cost/performance impact: Bounded predecessor lookup by indexed family ID and linear lifecycle normalization; benchmark baseline comparison and cap observation counts.
Chaos/failure hypothesis: Replay, forked revisions, stale activation receipts, producer disagreement, and cyclic supersession could fabricate history; validate chains, preserve contradictions, cap depth, and fail closed.

## Epic 3: Buyer Output and Cross-Product Assurance

Objective: make the complete contract understandable to buyers and prove that downstream products can consume the exact exported bytes.

### Story 3.1: Add an opt-in buyer-facing Action Contract packet

Priority: P0
Recommendation coverage: 6. Buyer-Facing Action Contract Packet
Strategic direction: Render one concise paid-assessment deliverable from the same normalized artifact model, not a separate narrative truth.
Expected benefit: Security and business owners can review one bounded packet that explains authority, controls, gaps, imported activation status, and the next concrete action.

Tasks:
- Add first-failing JSON/Markdown goldens for every required packet section, missing evidence, multiple contracts, long values, contradictory state, redaction, supersession, and imported Gait status.
- Define one packet model containing contract/artifact identity, composed path, source/transform/sink, affected asset, authority requirements, credential posture, readiness checks, expected/forbidden effects, confirmation/approval, compensation, evidence gaps, imported Gait/Axym observations, and next step.
- Add `wrkr report --template action-contract-packet --contract-id <id> --json`; render bounded Markdown from that same model and preserve current report output modes/exit codes.
- Use deterministic section and item ordering. Select one contract explicitly; for collections, require a separate manifest/index rather than silently choosing the first.
- Render missing/unknown/inferred/contradictory/stale evidence as visible gaps and keep static reachability language distinct from observed execution.
- Apply existing share profiles recursively, recompute packet/artifact identity as required, truncate only presentation values with explicit markers, and never emit raw secrets.
- Keep packet opt-in and outside default scan/primary report. Refresh size, Markdown length, redaction, recursive-redaction, clone-strip, readability, and noise receipts with measured deltas and fixture names.
- Update report docs/examples, schema, help, compatibility matrix, and changelog.

Repo paths:
- `core/report/action_contract_packet.go`
- `core/report/action_contract_packet_test.go`
- `core/report/render_markdown.go`
- `core/cli/report.go`
- `core/cli/report_test.go`
- `schemas/v1/report/action-contract-packet.schema.json`
- `testinfra/contracts/`
- `testinfra/contracts/fixtures/freeze-gate/story-0.1-receipt.json`
- `docs/commands/report.md`
- `docs/examples/security-team.md`
- `docs/examples/operator-playbooks.md`
- `docs/contracts/compatibility_matrix.md`
- `CHANGELOG.md`

Run commands:
- `go test ./core/report ./core/cli -run 'Test.*ActionContractPacket|Test.*ReportTemplate' -count=1`
- `go test ./testinfra/contracts -run 'Test.*Packet|Test.*Redaction|Test.*Clone|Test.*Freeze|Test.*Markdown' -count=1`
- `make test-focused-docs`
- `make test-contracts`
- `make test-perf`

Test requirements:
- First failing goldens cover all packet sections and prove JSON/Markdown currently have no shared packet contract.
- A projection-equivalence test parses JSON and compares every semantic field with the Markdown rendering model.
- Redaction/long-value tests cover nested authority, credential, effect, compensation, and lifecycle refs; clone-strip tests prove customer-safe sharing.
- Size/readability tests enforce bounded sections, stable sorting, explicit truncation markers, and no default report/finding-count growth.

Matrix wiring:
- Fast lane: packet normalization/render unit tests and lint.
- Core CI lane: JSON schema, Markdown goldens, CLI help, redaction, clone-strip, docs parity, and `make test-fast`.
- Acceptance lane: paid-assessment scenario produces both views and validates semantic equivalence.
- Cross-platform lane: line endings, wrapping, Unicode, paths, and byte-stable JSON.
- Risk lane: recursive redaction, oversized values, malformed lifecycle refs, output caps, perf, and CodeQL.
- Gating rule: packet does not ship until schema/Markdown equivalence, all required sections, opt-in behavior, refreshed freeze receipt, measured size/readability, docs, and redaction pass.

Acceptance criteria:
- One explicit contract ID yields schema-valid JSON and bounded Markdown with the same semantics and all required buyer sections.
- Missing or weak evidence is visible; no packet implies activation or execution from static evidence.
- Default scan/report output size and finding count remain unchanged.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added an opt-in JSON and Markdown Action Contract packet for buyer review of authority, checks, effects, approvals, compensation, gaps, and downstream evidence.
Semver marker override: [semver:minor]
Contract/API impact: New report template, selector, JSON schema, Markdown contract, and documented size/redaction budgets.
Versioning/migration impact: Packet schema starts at version `1`; future additive fields remain optional and renderers must preserve unknown-field compatibility where applicable.
Architecture constraints: Report code projects normalized contract/artifact data only; it does not rescore, infer grants, or become the canonical contract source.
ADR required: Yes - public buyer contract and opt-in/default-output boundary; may be combined with the artifact ADR if decisions remain explicit.
TDD first failures: JSON and Markdown select different facts; missing evidence disappears; long values break budgets; redaction leaves nested identities; default report grows.
Cost/performance impact: O(selected contract size) with explicit item/length caps; measure JSON and Markdown bytes, render latency, and allocations.
Chaos/failure hypothesis: Deep nested refs, Unicode, huge values, malformed IDs, or contradictory status could leak data or produce unreadable output; normalize, cap, escape, redact, and fail closed.

### Story 3.2: Generate exact-byte cross-product conformance fixtures

Priority: P0
Recommendation coverage: 7. Cross-Product Conformance Fixtures
Strategic direction: Replace illustrative hand-authored handoff projections with artifacts produced by the real Wrkr pipeline and consumed unchanged by explicit downstream contract lanes.
Expected benefit: Schema or digest drift fails before release and Wrkr no longer proves interoperability against JSON that production code never emits.

Tasks:
- Add first-failing tests that regenerate current hand-authored composition contract fixtures through Wrkr and demonstrate byte/digest mismatch.
- Create canonical scenario inputs for customer data to egress, workflow mutation to deploy, secret to network, package to release, excessive child authority, failed effect validation, approval expiry, compensation, and supersession.
- Add one explicit regeneration script that builds/runs Wrkr against scenario inputs, creates saved state, exports version `3` artifacts and packet views to a temporary directory, validates schemas/digests, and updates committed goldens only behind an explicit update flag.
- Replace Gait/Axym hand-authored expected projections with the exact exported artifact bytes plus a manifest containing scenario ID, producer version, schema versions, digest, contract/family/revision, and expected external consumer entrypoints.
- Add unit/contract tests that always regenerate to temporary storage and byte-compare. Tests must never mutate committed goldens by default.
- Add a Tier 12 wrapper that passes unchanged artifact paths to configured Gait and Axym consumer commands. Missing consumer dependencies return the established dependency-missing outcome; do not synthesize local consumer behavior.
- Capture consumer version/digest/pass receipts without copying Gait/Axym implementation into Wrkr. Release gating requires valid receipts for the pinned fixture version.
- Document fixture review/update procedure, compatibility promise, downstream ownership, and no-hand-authored-projection rule.

Repo paths:
- `scenarios/wrkr/composed-action-paths/`
- `scenarios/cross-product/action-contract-interop/`
- `scenarios/cross-product/composed-action-contracts/`
- `scripts/generate_action_contract_conformance.sh`
- `scripts/test_action_contract_interop.sh`
- `testinfra/contracts/`
- `docs/contracts/compatibility_matrix.md`
- `docs/commands/export.md`
- `schemas/v1/README.md`
- `CHANGELOG.md`

Run commands:
- `scripts/generate_action_contract_conformance.sh --check`
- `go test ./testinfra/contracts -run 'Test.*ActionContract.*Conformance|Test.*ExactBytes' -count=1`
- `scripts/validate_scenarios.sh`
- `make test-scenarios`
- `scripts/test_action_contract_interop.sh`

Test requirements:
- First failing test proves at least one current hand-authored expected file is not the exact output of the real builder/export path.
- Every required scenario regenerates byte-identically under input permutations and repeated runs, except documented explicit version/timestamp fields excluded from goldens.
- Schema and digest verification run before byte comparison; tampered bytes, producer/schema mismatch, stale manifest, and changed source evidence fail.
- Tier 12 tests pass the exact file path unchanged to external consumers and record versioned receipts; no Wrkr-only stub can satisfy the consumer gate.

Matrix wiring:
- Fast lane: manifest/parser and generator unit checks.
- Core CI lane: real-pipeline regeneration-to-temp, schema/digest verification, exact-byte comparison, and `make test-contracts`.
- Acceptance lane: all nine scenario packs in `make test-scenarios`.
- Cross-platform lane: regenerate/check on Linux and Windows smoke with platform-neutral bytes/paths; macOS covered before release.
- Risk lane: tamper, truncation, stale manifest, missing consumer, mismatched version, perf, and CodeQL/script hardening.
- Gating rule: committed artifacts change only via explicit regeneration and human-reviewed diffs; release requires exact-byte Wrkr tests and current Gait/Axym consumer receipts.

Acceptance criteria:
- All required scenario artifacts originate from production Wrkr code, validate against pinned schemas/digests, and regenerate byte-identically.
- The same files are passed unchanged to external Gait/Axym conformance entrypoints.
- Hand-authored consumer projections no longer serve as the authoritative handoff fixture.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Replaced illustrative Action Contract handoff projections with real-pipeline, exact-byte conformance fixtures and versioned downstream consumer receipts.
Semver marker override: none
Contract/API impact: Pins fixture manifest/bytes as release-level interoperability contracts; runtime public fields are unchanged by this validation story.
Versioning/migration impact: Fixture manifests are versioned and tied to producer/schema versions; deliberate golden updates require reviewed compatibility notes.
Architecture constraints: Wrkr owns production and validation of its bytes; Gait/Axym own their consumers; shared fixture references are the only cross-product implementation surface here.
ADR required: No - governed by the artifact/version ADR and existing Tier 12 test policy; document the fixture contract in the compatibility matrix.
TDD first failures: Hand-authored bytes differ from real export; changed evidence does not invalidate expected digest; missing consumer passes; test updates goldens implicitly.
Cost/performance impact: Scenario generation is CI/acceptance work, not scan overhead; measure runtime and shard/cap fixtures to stay within profile timeouts.
Chaos/failure hypothesis: Tampered bytes, partial regeneration, stale manifests, absent consumers, or platform path/newline differences could create false confidence; validate in temp, compare exact bytes, and fail explicit.

## Epic 4: Bounded Cross-System Reachability

Objective: extend the proven typed contract to a deliberately small set of three-to-five-stage cross-system paths without becoming an unbounded graph or runtime engine.

### Story 4.1: Add bounded multi-stage and cross-system contracts

Priority: P1
Recommendation coverage: 9. Bounded Multi-Stage and Cross-System Contracts
Strategic direction: Generalize current pairwise patterns only after P0 contract/fixture gates are green, using explicit templates, stage limits, trust-boundary evidence, and hard output budgets.
Expected benefit: Buyers can see consequential authority chains that cross repo, CI, cloud, package, SaaS, and communications systems while preserving deterministic, explainable evidence.

Tasks:
- Add first-failing scenarios for supported three-, four-, and five-stage paths, alternate routes, missing middle-stage evidence, cross-repo correlation, trust-boundary mismatch, duplicate/cycle candidates, over-five-stage truncation, cap exhaustion, and observed-runtime evidence.
- Replace the pair-only pattern shape with explicit ordered pattern templates containing allowed stage roles/system classes, minimum/maximum stages, required transition evidence, trust-boundary constraints, and outcome family.
- Implement bounded deterministic traversal over existing action-path, workflow-chain, composition, graph, and imported evidence refs. Do not traverse arbitrary raw files or unconstrained graph edges.
- Correlate across systems only through stable explicit keys/evidence refs; missing correlation yields no match or an explicit incomplete hypothesis according to the pattern, never a guessed join.
- Extend composition stages/transitions with system class, trust boundary, correlation refs, alternate-route refs, stage evidence state/freshness, and `reachability_state`; keep `observed_execution` separately evidence-backed.
- Derive stable IDs from pattern plus ordered durable stage/transition/target/outcome semantics, excluding timestamps and volatile path IDs. Deduplicate cycles and route aliases before cap/rank.
- Apply existing control recommendation, equivalent-outcome parity, version `3` contract builder, artifact export, packet, proof/evidence refs, and regress logic after the final bounded path set is stable.
- Add per-pattern/path/depth/candidate caps, deterministic truncation metadata, performance budgets, no-new-finding/no-default-size gates, chaos tests, fixtures, docs, and ADR.

Repo paths:
- `core/risk/composition.go`
- `core/risk/composition_test.go`
- `core/risk/proposed_action_contract.go`
- `core/aggregate/attackpath/graph.go`
- `core/risk/workflow_chain.go`
- `core/regress/`
- `core/report/`
- `core/proofmap/`
- `schemas/v1/composed-action-path.schema.json`
- `schemas/v1/proposed-action-contract-v3.schema.json`
- `scenarios/wrkr/composed-action-paths/`
- `scenarios/cross-product/action-contract-interop/`
- `testinfra/contracts/fixtures/freeze-gate/story-0.1-receipt.json`
- `docs/commands/report.md`
- `docs/commands/export.md`
- `docs/decisions/`
- `CHANGELOG.md`

Run commands:
- `go test ./core/risk -run 'Test.*MultiStage|Test.*CrossSystem|Test.*CompositionID|Test.*Reachability' -count=1`
- `go test ./core/aggregate/attackpath ./core/regress ./core/report ./core/proofmap -run 'Test.*Composition|Test.*ActionContract' -count=1`
- `make test-scenarios`
- `make test-risk-lane`
- `make test-chaos`
- `make test-perf`

Test requirements:
- First failing tests prove current pairwise matching cannot represent a three-to-five-stage path and that naive traversal can cycle or exceed caps.
- ID/property tests cover input permutations, duplicate/cyclic candidates, harmless volatile-ID churn, material stage/effect changes, and alternate routes.
- Evidence tests prove possible/static/incomplete/observed states remain distinct and that observed requires imported runtime proof.
- Perf/chaos tests cover high fan-out, missing joins, malformed refs, cycles, cap truncation, repeated trust boundaries, and deterministic partial results.

Matrix wiring:
- Fast lane: pattern/traversal/ID/reachability unit tests and lint.
- Core CI lane: schema, regress, packet/artifact, proof/evidence, freeze receipt, and `make test-fast`.
- Acceptance lane: three-to-five-stage cross-system scenarios plus exact-byte artifact regeneration.
- Cross-platform lane: stable IDs/order/truncation and platform-neutral goldens on Linux/macOS/Windows.
- Risk lane: high-fan-out hardening, cycle/cap chaos, perf budgets, redaction, and CodeQL.
- Gating rule: multi-stage output stays internal until P0 fixtures pass, caps/perf/noise/freeze gates are green, static-versus-observed semantics are proven, and ADR/docs/changelog are complete.

Acceptance criteria:
- Supported templates produce deterministic ordered three-to-five-stage paths with explicit trust-boundary/correlation/stage evidence and stable IDs.
- Unsupported, uncorrelated, cyclic, over-depth, or over-cap inputs fail or truncate explicitly without guessed joins, hangs, or nondeterministic output.
- The resulting version `3` contracts, parity, artifacts, packets, proof/evidence refs, and regress states all agree.
- Possible reachability is never described as observed execution without imported runtime evidence.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added bounded three-to-five-stage cross-system composed Action Contracts with explicit trust-boundary evidence, stable identities, and possible-versus-observed reachability states.
Semver marker override: [semver:minor]
Contract/API impact: Additive composition stage/transition fields, reachability enums, supported pattern IDs, contract content, packet/export fields, and regress categories.
Versioning/migration impact: Existing pairwise patterns/IDs remain supported; new pattern IDs are additive, and any ID-domain change requires fixture migration notes and compatibility review.
Architecture constraints: Aggregation/risk perform bounded correlation over normalized evidence; detection remains tool-specific, report/export remain projections, and no arbitrary graph/runtime engine is introduced.
ADR required: Yes - lock supported templates, traversal/correlation boundary, caps, stable ID domain, truncation, and possible-versus-observed semantics.
TDD first failures: Pair-only model cannot encode middle stages; naive traversal cycles; missing correlation guesses a join; cap truncation varies by map order; static path appears observed.
Cost/performance impact: Highest-risk story; enforce explicit depth/fan-out/candidate/output caps and benchmark representative/high-fan-out fixtures against profile budgets before public exposure.
Chaos/failure hypothesis: Cycles, path explosion, adversarial fan-out, duplicate aliases, corrupt refs, and cross-boundary ambiguity could exhaust resources or overclaim; bounded templates, stable pruning, caps, evidence gates, and explicit truncation must contain them.

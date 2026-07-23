# Changelog

All notable changes to Wrkr are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions align with repository release tags.

## [Unreleased]

### Added

- [semver:minor] Added a deterministic `composed_action_path` artifact that identifies bounded multi-stage authority paths from existing action paths and workflow chains without claiming observed execution.
- [semver:minor] Added report-only proposed Action Contract v2 output linked to composed action paths for downstream Gait/control workflows.
- [semver:minor] Added explicit composition, proposed contract, workflow-chain, and resolution-key references to decision traces and evidence exports for stable Gait and Axym correlation.
- [semver:minor] Added canonical composed action-path fixtures and contract tests covering sensitive egress, secret-to-network, deploy, release, standing credential, incomplete outcome, and controlled transition scenarios.
- [semver:minor] Added delegated authority relationship projection for composed action paths so reports can identify narrowed, equal, broadened, unknown, and contradictory authority transitions.
- [semver:minor] Added bounded equivalent-outcome signals for composed paths that can reach the same deploy, egress, privileged mutation, or release outcome with weaker controls.
- [semver:minor] Added composition drift detection for introduced, changed, newly ungoverned, evidence-degraded, coverage-degraded, and alternate-route composed authority paths.
- [semver:minor] Added proposed Action Contract version 3 with typed, evidence-backed authority requirements while retaining version 2 compatibility.
- [semver:minor] Added typed readiness and effect preconditions to proposed Action Contract version 3, including producer, freshness, environment, credential, and effect constraints.
- [semver:minor] Added structured confirmation, approval validity, separation-of-duties, reapproval, and compensation requirements to proposed Action Contract version 3.
- [semver:minor] Added `wrkr export action-contracts` for standalone, RFC 8785 JCS-digested proposed Action Contract artifacts with deterministic selection, redaction, and proof references.
- [semver:minor] Added immutable proposed Action Contract revision chains and evidence-backed Gait activation, rejection, execution, effect, and Axym verification references.
- [semver:minor] Added an opt-in JSON and Markdown Action Contract packet for buyer review of authority, checks, effects, approvals, compensation, gaps, and downstream evidence.
- [semver:minor] Added bounded three-to-five-stage cross-system composed Action Contracts with explicit trust-boundary evidence, stable identities, and possible-versus-observed reachability states.
- [semver:minor] Added scoped containment evidence for stop requests, covered-action denials, capability and descendant invalidation, external revocation acknowledgements, containment receipts, and unresolved boundaries.

### Changed

- Documented the Sprint 0 public-surface freeze gate that composition work must satisfy before exposing new scan/report/schema fields.
- [semver:minor] Projected existing evidence state, freshness, policy coverage, and Gait coverage onto composed action-path stages so reports distinguish static reachability from runtime-proven control.
- [semver:minor] Updated Agent Action BOM reporting to lead with the highest-risk composed authority path, current evidence posture, control gap, and proposed Action Contract.
- [semver:minor] Applied canonical control recommendations across composed action paths with transition-level rationale and most-restrictive rollups.
- Replaced illustrative Action Contract handoff projections with real-pipeline, exact-byte conformance fixtures and versioned downstream consumer receipts.
- Clarified buyer-facing reports with explicit `confirmed CI path`, `inferred relationship`, and `agent surface only` labels, and made dense appendix and executive-rollup fields easier to scan. The regenerated customer-redacted sample fell from 40,745 to 38,556 bytes (-2,189 bytes; -5.4%), while its typed-evidence control-path graph grew by 108 bytes; coverage receipts are `TestActionPathTopRisksGroupWorkflowRowsAndHonorTop`, `TestBuyerArtifactQABlocksPrimaryInternalTokensAndRepeatedEvidenceGaps`, `TestValidateShareableArtifactsChecksJSONValuesNotSchemaKeys`, and `TestScenarioBuyerActionRegistryHardening`.
- [semver:patch] Assessment profiles now remove scenario, fixture, sample, test, generated, and vendored findings before risk, scan-quality, MCP, backlog, posture, and compliance analysis while retaining the unfiltered findings in saved scan state.
- [semver:patch] `summary.top_risks` now groups repeated rows for the same repo/workflow and obeys the requested `--top` count; detailed action paths remain available in structured report fields.

### Deprecated

- (none yet)

### Removed

- (none yet)

### Fixed

- [semver:patch] Raised weaker equivalent-outcome routes to the deterministic peer control floor so approval-evasion alternatives cannot retain a less restrictive proposed Action Contract.
- [semver:patch] Hardened redacted Action Contract artifact export so saved contract selectors are applied before redaction, report presentation caps do not suppress exported contracts, and output collisions are preflighted before any artifact file is written.
- Made the local CodeQL runner resource-aware on high-memory hosts so the full security-and-quality suite can complete without relaxing query coverage.
- [semver:patch] Prevented workflow inputs such as `cache-dependency-path`, `artifact-path`, `restore-keys`, and `persist-credentials` from becoming credential subjects or GitHub PAT findings; covered by `TestAnalyzeDoesNotPromoteOrdinaryActionInputsToCredentials` and `TestAssessmentScanKeepsFixturesRawWithoutPromotingFalseCredentials`.
- [semver:patch] Kept write-capability booleans, action classes, deploy/merge flags, mutable endpoint semantics, and buyer summary counts on one canonical invariant.
- [semver:patch] Kept blocked standing-credential paths on remediation-first guidance across action paths, control backlog items, and lifecycle queues instead of downgrading them to approval or evidence-only actions.
- [semver:patch] Treated GitHub's empty-repository tree response as a successful typed `content_status=empty` source result instead of a partial scan failure.
- [semver:patch] Validated shareable JSON residuals against string values rather than schema keys and excluded generic false credential subjects; covered by `TestValidateShareableArtifactsChecksJSONValuesNotSchemaKeys`.
- [semver:patch] Separated workflow secret storage references from credential authority: GitHub's built-in token remains JIT, `id-token: write` is modeled as OIDC workload authority, and role ARNs, usernames, and notification recipients remain raw audit evidence without becoming standing credentials. The 23-repo Clyra-AI dogfood scan completed 644/644 detector executions with zero source failures; newly visible OIDC workflows increased action paths from 66 to 71 while standing paths fell from 23 to 16 and standing-credential blocks fell from 21 to 12. Coverage includes `TestAnalyzeSeparatesSecretStorageFromCredentialAuthority`, `TestSecretsDetectorUsesStructuredWorkflowCredentialSemantics`, and `TestAssessmentScanKeepsFixturesRawWithoutPromotingFalseCredentials`.
- [semver:patch] Scoped workflow credential and authority attribution by repository and location so identically named workflows cannot inherit sibling-repository credentials, and classified COSIGN and PyPI subjects against their signing and package-registry targets.
- [semver:patch] Canonicalized CI workflow action paths and required explicit graph joins or shared artifacts before emitting attack paths, preventing duplicate `ci_agent`/`compiled_action` rows and same-repository correlation-only attack chains.
- [semver:patch] Made executive-rollup remediation language credential-authority-aware so JIT and workload groups no longer receive standing-credential replacement guidance; covered by `TestExecutiveClosureRecommendationMatchesCredentialAuthority`.

### Security

- (none yet)

## Changelog maintenance process

1. Update `## [Unreleased]` in every PR that changes user-visible behavior, contracts, or governance process.
2. Before release tagging, run `python3 scripts/finalize_release_changelog.py --json` to promote releasable `Unreleased` entries into a dated versioned section and publish that change through a short-lived release-prep PR.
3. Validate the prepared release changelog with `python3 scripts/validate_release_changelog.py --release-version vX.Y.Z --json` on merged `main` before or during the tag workflow.
4. Keep entries concise and operator-facing: what changed, why it matters, and any migration/action notes.
5. Link release notes and tag artifacts to the finalized changelog section.
6. The Sprint 0 v1.7.3 clarification workflow item must record measured artifact-size deltas, redaction test names, and fixture coverage before release notes claim size, privacy, redaction, customer-safe, or readability hardening.

## [v1.11.2] - 2026-07-10
<!-- release-semver: patch -->

### Security

- Raised the pinned Go toolchain to `1.26.5` to clear standard-library advisory `GO-2026-5856` in binary `govulncheck` CI lanes.

## [v1.11.1] - 2026-06-27
<!-- release-semver: patch -->

### Changed

- Agent Action BOM Markdown now groups repeated top action paths in the buyer lead while preserving full detail in appendices and evidence JSON.
- First-run Agent Action BOM reports now summarize approval/proof evidence gaps as onboarding context instead of repeating raw unknown evidence fields throughout the lead.
- Reports now explain attack-path non-generation when high-impact action paths exist but attack-path graph prerequisites were not available.

### Fixed

- Report QA now blocks buyer-hostile primary Markdown patterns such as weak blocked-credential remediation, internal token leakage, repeated raw evidence gaps, and oversized lead lines.

### Security

- Blocked standing-credential report guidance now leads with reducing, replacing, revoking, rotating, or moving authority to JIT/brokered access before any accept-risk option.

## [v1.11.0] - 2026-06-26
<!-- release-semver: minor -->

### Added

- Added stable `resolution_key` action-path, BOM, report, and regress-baseline joins plus selector-fallback match metadata so reviewed paths can survive harmless `path_id` churn across reruns.
- Added review disposition declarations in `wrkr-control-declarations.yaml` / `.wrkr/control-declarations.yaml` for controlled, accepted-risk, not-applicable, false-positive, runtime-evidence-needed, and confirmed paths.
- Added expiry, contradiction, disappeared-import, credential-family, and target-escalation reopen tracking for reviewed action paths in reports and regress baselines.
- Added provider-control evidence correlation for local PR review, branch protection, required-check, environment approval, workflow permission, merge metadata, and owner evidence exports, including direct `resolution_key` joins.
- Added path-specific closure actions plus deterministic declaration snippet export for reviewed BOM and backlog items, including repo-local and governance-repo declaration modes.
- Added synthetic enterprise review-loop fixtures that gate closure actions, lifecycle reopen behavior, governed-CI ranking, and declaration/report wording.

### Changed

- Changed reviewed action-path handling so declared, imported, accepted-risk, not-applicable, and false-positive paths move to auditable appendix visibility with explicit lifecycle and reopen metadata instead of remaining in unresolved top output.
- Changed top action recommendations to account for credential authority confidence, static caller context, and governed CI control evidence before suggesting stronger credential remediation.

### Fixed

- Fixed paired artifact join handling so local outputs preserve stable `resolution_key` and evidence joins across related artifacts.

## [v1.10.0] - 2026-06-23
<!-- release-semver: minor -->

### Added

- Added `wrkr report --evidence-json-scope` so Agent Action BOM evidence can default to a buyer-facing lead bundle while still allowing explicit full graph/workflow evidence export.
- Added workstation detection for local agentic factory and handoff artifacts such as `.agents/skills`, `factory/skills`, Bob config, local PR provenance, and runtime-session sidecars.

### Changed

- Changed Agent Action BOM markdown and evidence output to keep the lead view focused on the primary path and compact top paths, with appendices/full evidence available through explicit output scope.
- Changed control guidance for standard CI credential references to request imported PR review, branch protection, deployment, or owner-map evidence instead of implying approval or proof is absent from source alone.

### Fixed

- Fixed standard non-agentic CI credential paths so they remain inventory hygiene unless agentic influence or high-impact release/production evidence makes them control-first.
- Fixed buyer-facing report labels so approval and runtime gaps render as evidence not observed in the scanned/imported context instead of unsupported missing-control claims.

## [v1.9.1] - 2026-06-22
<!-- release-semver: patch -->

### Fixed

- Hardened large-org Agent Action BOM scan/report output by grouping endpoint-derived graph targets, demoting static API-spec context from primary Top Action Paths, bounding repeated endpoint/evidence projections in saved state and reports, adding stale scan-status diagnostics, and adding source artifact SHA-256 digests to report metadata. Validation receipts include a 40-repo endpoint-heavy mock scan reducing saved state from ~142 MB to ~38 MB, `TestScanStatusFlagsStaleRunningSidecarAsLikelyInterrupted`, `TestBuildArtifactMetadataIncludesSourceArtifactDigests`, endpoint graph cap tests, and primary-view static-context tests.

## [v1.9.0] - 2026-06-18
<!-- release-semver: minor -->

### Added

- Added scan `phase_substep` progress events plus optional `--progress-heap` receipts so long analysis runs can identify inventory, graph, workflow-chain, backlog, state-finalization, and artifact-write phases without corrupting stdout JSON.
- Added Target Surface Context and agent instruction control-surface modeling so unbound OpenAPI/routes/source context and instruction files are separated from executable govern-first paths in BOM and report output.
- Added focused evidence bundles for `--focus-path` and focus-preset report workflows so bounded shareable evidence can follow one selected path or a compact top-path set without shipping the full graph and workflow export.

### Changed

- Changed interactive `--json` output for large scan, report, evidence, and assess commands to emit compact TTY-safe summaries by default while preserving the full machine-readable payload for pipes, redirects, `--json-path`, and explicit `--json-stdout=full`.
- Unified report and evidence serialization metadata with shared suppression and artifact-budget hints so shareable/default outputs advertise caps, appendix availability, and focused/detail handoff paths consistently.
- Updated Agent Action BOM and control-backlog closure guidance so OpenAPI, route, instruction, MCP config, dependency, CI, and release workflow surfaces use path-type-specific remediation language.
- Reworked Agent Action BOM Markdown to lead with buyer-facing inspect-first diagnostics, keep appendix-heavy refs later, and promote recent PR review into a named workflow instead of appendix-style output.
- Reworked the default Agent Action BOM buyer view to start with inspect-first cards, keep the primary path plus top five eligible paths on the first page, and move machine-heavy BOM metadata into appendices and evidence artifacts.
- Clarified scan, report, evidence, assess, README, and docs-site guidance so manual large-scan workflows center `--state` plus durable artifacts while `--json` examples stay explicitly labeled for automation and CI.

### Fixed

- Canonicalized published Agent Action BOM example refs after opaque-ID redaction so generated site assets remain byte-stable even if upstream raw path IDs reorder.
- Added endpoint-dense enterprise-pressure fixtures and bounded-artifact receipts so route-heavy scans regress in deterministic tests before they bloat saved state, graph output, or BOM artifacts.
- Replaced endpoint-heavy graph, BOM, and action-surface fanout with grouped endpoint receipts (`endpoint_ref_group_id`, counts, route groups, operation counts, and bounded samples) so report/shareable surfaces stop cloning thousands of endpoint refs per node or item.
- Removed analysis-time embedded authority and endpoint payload clones from graph, action-path, BOM, and control-backlog projections so enterprise-shaped scans use ref-only defaults before artifact serialization.
- Tightened action-path eligibility and authority correlation so static context surfaces no longer inherit governable workflow status from repo-wide credential or deploy signals without a real binding.
- Tightened OpenAPI and route authority correlation so static target context no longer inherits unrelated repo-wide workflow credentials or broad repo-derived binding metadata as governable action-path proof.
- Kept parse-limited JS/TS WebMCP surfaces in scan-quality coverage receipts instead of surfacing them as scan findings or govern-first action paths.

### Security

- Added fail-closed residual-token validation plus recursive shareable output redaction for nested owner, repo, provider, PR URL, and filesystem-path evidence strings before customer-safe artifacts are written.

## [v1.8.0] - 2026-06-14
<!-- release-semver: minor -->

### Changed

- Required measured receipts for size, redaction, privacy, and customer-safe release claims, and added a Sprint 0 temporary freeze gate for new scan/report surface expansion until the size, redaction, and readability gates are green.
- Changed saved-state, report, control-backlog, graph, and Agent Action BOM projections to keep canonical endpoint and authority refs while omitting repeated embedded payload clones from shareable/default artifacts.
- Tightened the Agent Action BOM lead view into a bounded buyer-readable rollup with concise top action paths up front and detailed workflow, policy, assessment, and detector context moved into explicit appendices.

### Fixed

- Persisted saved-scan completeness markers and made report, evidence, export, and regress handoff commands reject incomplete source states with `invalid_input` until the scan reruns cleanly.
- Replaced broad major release/docs workflow aliases for GitHub Pages and Anchore helper actions with immutable commit refs and removed their now-unneeded action-ref exceptions.
- Reduced unnecessary JS/TS detector parsing by scoping WebMCP, MCP-candidate, prompt-channel, and source-framework source inspection to explicit high-signal entrypoints while suppressing generated and low-signal JS-family paths.
- Added synthetic enterprise-shaped JS/TS scan-quality receipts and acceptance coverage so parser-edge repos degrade to reduced coverage context instead of surfacing as ranked security findings.
- Closed remaining nested owner leaks so shareable report, evidence, paired-artifact, and Agent Action BOM outputs redact owner decisions, rejected owner candidates, and production-context owner fields recursively.
- Unified scan/report/evidence/assess/saved-state canonicalization so writer outputs keep canonical endpoint and authority refs while stripping repeated embedded clones before serialization.
- Added real-scan-shaped size, signal, redaction, and BOM readability regression fixtures to block artifact bloat and shareable-output leaks before release.
- Bounded persisted derived scan/report/evidence projections with explicit suppression metadata, switched large JSON artifact writes to streaming file sinks, and grouped repeated policy outcomes in saved state and score inputs so posture/readout noise no longer scales linearly with repo fanout.
- Grouped repeated policy-check and policy-violation fanout in proof emission by stable policy outcome id while preserving affected-scope metadata, reducing proof-chain size for enterprise-shaped scans without dropping non-policy finding records.
- Qualified WebMCP and MCP negative-claim posture with primary-view coverage status so parse-limited or unsupported JS/TS surfaces stay in scan-quality context instead of reading like authoritative clean negatives.

### Security

- Made customer-safe report and assessment output the default share posture for report-style workflows; cleartext owner, reviewer, account-like, and local-path detail now requires an explicit `--share-profile internal` selection.

## [v1.7.2] - 2026-06-12
<!-- release-semver: patch -->

### Fixed

- Fixed Linux release-only Homebrew UAT to disable the Homebrew sandbox on hosted runners where rootless user namespaces are unavailable, so release acceptance and published install-path parity can complete on GitHub Actions.

## [v1.7.1] - 2026-06-11
<!-- release-semver: patch -->

### Fixed

- Fixed the Linux release runner to install `bubblewrap` before Homebrew-backed acceptance and pre-publish install-path UAT, so tag workflows no longer fail before artifact publication.

## [v1.7.0] - 2026-06-11
<!-- release-semver: minor -->

### Added

- Added `agentic_delivery_system_change` projection fields to govern-first action paths and Agent Action BOM items so instruction, skillpack, MCP, and tool-config edits surface as delivery-system changes with authority impact, review state, and buyer-safe reachability context.
- Added authority-aware ranking for delivery-system changes so publish, deploy, credential, and review-bypass reachability outrank bare prompt or config trivia in focused BOM workflows.
- Added bounded `decision_trace` proof records plus `decision_trace_refs` in reports and `proof-records/decision-traces.jsonl` in evidence bundles for high-impact action paths.
- Added privacy-safe `repeat_usage_signals` to report summaries and Agent Action BOM summaries using only local baseline, assess, regress, evidence, ticket-export, and action-contract artifacts.
- Added a bounded design-partner control validation workflow for before/after focused-BOM reviews using `wrkr assess`, regress baselines, and deterministic local artifacts.
- Added provider-neutral runtime, model, host, execution-environment, state-retention, agent-identity, precedent, and delivery-control context fields across ingest sidecars, govern-first paths, report summaries, and Agent Action BOM output.
- Added optional local `decision-precedents.json` lookup beside saved scan state so recurring high-impact paths can carry clearly labeled prior decision context without introducing a mutable decision database.

### Changed

- Changed `wrkr scan --json` to prefer a bounded stdout summary with scan-quality, grouped policy outcomes, suppression counts, and full-artifact handoff through `--state`.
- Changed first-run docs to lead with one repo-first path: scan a repo, render the focused Agent Action BOM, and review the top workflow/action path before widening scope.
- Added product governance gates for focused BOM clarity, repeat use, evidence quality, and output/noise budgets across new buyer-facing surfaces.

### Fixed

- Fixed scan JSON stdout budgeting so large scans emit bounded previews with `suppressed_counts` while full findings, inventory, risk, action paths, and backlog detail remain in saved state.
- Fixed Wrkr proof emission so static scan, risk, approval, and lifecycle records no longer claim `permissions_enforced` without enforcement evidence.
- Added canonical endpoint, credential-authority, and authority-binding reference ids so govern-first paths, BOM items, graph nodes, and backlog rows can join to one deterministic per-scan store.
- Reduced Wave 1 output noise by keeping low-signal source parse failures in `scan_quality`, preserving actionable config parse failures, and surfacing grouped policy outcomes with bounded repo examples.
- Hardened share-profile redaction and progress rendering so interactive `--json` scans can show stderr liveness without corrupting stdout and shared report artifacts redact newly added grouped-path refs consistently.
- Fixed buyer-projection parity so focused BOM, backlog, graph, evidence artifacts, and markdown consume the same canonical action-path semantics.

### Security

- Added a merge-blocking `codeql-security` PR check wired to `make codeql` and the required-check contracts.
- Added retained-state posture handling that stores refs and digests only, rejects raw prompt/tool-result/memory payloads at ingest time, and redacts host/model/state context in share profiles by default.

## [v1.6.0] - 2026-06-05
<!-- release-semver: minor -->

### Added

- Added provider-neutral PR/MR provenance sidecars for changed files, reviewers, approvals, checks, deployments, merge metadata, branch protection, and environment gates.
- Added typed Agentic SDLC evidence packets for consequential AI-assisted changes, including proof refs and missing-evidence status.
- Added a local recent PR/MR review workflow for ranking bounded AI-assisted or automation-assisted delivery paths from provider metadata sidecars.
- Added workflow chain artifacts that group delegated SDLC paths by repo, PR/MR, workflow, tool, credential, owner, approval, target, evidence, and outcome.
- Added Control Path Graph V2 nodes and edges for delegated SDLC intent, human, agent team, PR/MR, approval, deployment, asset, evidence, and outcome paths.
- Added intent-to-outcome action lineage segments for delegated SDLC workflows.
- Added high-stakes path presets for release automation, production paths, credentials, IaC, identity/auth code, package publishing, payment flows, regulated customer workflows, external egress, MCP/tool configs, and mutable endpoints.
- Added Agentic SDLC autonomy tiers, delegation readiness states, and recommended control outcomes to govern-first action paths, Agent Action BOM items, control backlog items, and markdown report rollups.
- Added draft recommended action contracts plus today-versus-governed path views for control-first and high-stakes action paths in report and backlog artifacts.
- Added canonical control resolution and evidence confidence fields for action paths, reports, backlog items, and v1 schemas so control gaps are evidence-scoped instead of inferred from local absence.
- Added target classification for action paths so reports distinguish production-impacting, release-adjacent, customer-data-adjacent, internal tooling, developer productivity, test/demo/sandbox, and unknown targets.
- Added action path type classification so reports distinguish AI-assisted workflows, agent frameworks, automation bots, CI/CD workflows, legacy scripts, plain source code, and unknown executable paths.
- Added report QA coverage that blocks unsupported overclaiming and prevents non-agent action paths from being labeled as agents in generated buyer artifacts.
- Added schema-backed external control evidence sidecars for local ownership, approval, provider, branch, deployment, and policy evidence.
- Added deterministic correlation for external ownership, approval, app catalog, ticket, policy, and provider evidence.
- Added branch protection, protected environment, deployment approval, required check, freeze window, and kill switch evidence for control reports.
- Added freshness and expiry metadata for imported and declared evidence across reports, backlog, and evidence bundles.
- Added versioned customer control declarations for owner mappings, target classes, accepted tooling, exceptions, non-prod declarations, and evidence links.
- Added contradiction detection for customer declarations, production targets, credentials, workflows, deployment constraints, and policy evidence.
- Added accepted-risk and suppression governance with expiry, ownership, scope, evidence state, rescan behavior, and appendix visibility.
- Added lifecycle and ownership control queues for ownerless, inferred-owner, stale-lifecycle, and credential-bearing governance gaps.
- Added path-specific closure evidence guidance across control backlog, Agent Action BOM, markdown reports, and exports.
- Added per-path evidence completeness scoring for discovery, authority, blast radius, control, runtime evidence, and proof sufficiency.
- Added documentation, schemas, scenarios, and acceptance coverage for Sprint 2 enterprise evidence ingest, contradiction handling, accepted-risk visibility, lifecycle queues, closure guidance, and completeness scoring.
- Added a focused one-page Agent Action BOM view for a single workflow/action path with appendix details for raw findings, graph refs, proof details, and detector diagnostics.
- Documented Sprint 3 Agent Action BOM focused-path contracts and schema coverage for primary workflow BOM output, evidence bundles, and local review workflows.
- Added first-class GitLab CI/CD detection for local pipelines, safe local includes, jobs, stages, variables, manual gates, deploy/release authority, secrets by reference, AI agent execution, and MCP/tool invocation.
- Added GitLab CI/CD workflow authority to action paths, privilege budget, Agent Action BOM, control backlog, graph, evidence packets, and scan quality summaries.
- Added first-class Azure DevOps pipeline detection for local pipelines, safe local templates, stages, jobs, service connections, variable groups, environments, approvals/check hints, agent pools, deployment jobs, secrets by reference, AI agent execution, and MCP/tool invocation.
- Added Azure DevOps pipeline authority to action paths, privilege budget, Agent Action BOM, control backlog, graph, evidence packets, and scan quality summaries.
- Added deterministic local coding-agent session ingest for Codex-style agents, Claude Code, Cursor, Copilot, Gait traces, and future runtime exports.
- Added runtime session evidence correlation into graph refs, evidence packets, Agent Action BOM coverage, report summaries, and evidence bundles.
- Added paired internal and customer-redacted report artifacts with deterministic joins and a local-only private join map.
- Added portable evidence bundle manifests with stable artifact metadata, redaction profiles, proof-chain refs, source privacy metadata, evidence-state summaries, and boundary labels.
- Added a repeatable `wrkr assess` workflow that stitches scan, optional ingest, report, evidence, export, optional ticket payloads, and optional drift review into one deterministic output directory and manifest.
- Added low-click report focus presets for BOM review, release-adjacent AI paths, write/deploy reach, approval and owner evidence gaps, evidence gaps, contradictions, drift review, and recommendations.
- Added first-class drift review categories and fail-closed comparison metadata across regress, report, Agent Action BOM, and assessment artifacts for new write/deploy paths, credentials, evidence movement, contradictions, and paths ready for control.
- Added large-organization executive rollups that group Agent Action BOM and control-backlog evidence by action, target, risk, authority, evidence, owner, contradiction, and closure dimensions.
- Added governed-usage metrics for monitored paths, governed paths, evidence packs, audit exports, approvals, connected runtimes, governed agents/workflows, verified controls, unknown controls, and contradictions.
- Added customer-controlled deployment and data-mode metadata across scan, report, and evidence artifacts, with `local_only` as the default posture.
- Added an opt-in public-surface assessment path for public repos, docs, SDKs, release notes, status pages, and workflows with explicit public/inferred evidence labels.
- Added reproducible website-ready demo artifacts, including sample BOM, action-control graph, redacted report, lab data, architecture boundary assets, and local/private data posture examples.
- Added precision calibration fixtures for ownership, approval evidence, non-production contradictions, stale source, dependency-only packages, CI automation, AI-assisted deploy paths, branch protection, and runtime evidence.
- Added enterprise-scale pressure tests for large-org reporting, redaction, scan quality, control-state consistency, evidence wording, proof completeness, graph size, BOM readability, and drift output.

### Changed

- Changed report and schema terminology to present approval, owner, proof, policy, runtime, target, and credential findings as evidence states rather than unsupported missing-control claims.
- Changed buyer-facing report, backlog, and remediation wording to use evidence-scoped language for approval, ownership, proof, policy, runtime, target, and credential states.
- Changed MCP absence reporting to use coverage-qualified statuses so reduced coverage, unsupported declarations, parse-failed candidates, and unscanned repos do not render as absolute missing-server claims.
- Changed buyer-facing reports and Agent Action BOM summaries to lead with compact scan coverage summaries while preserving detector-level scan-quality details in appendix and evidence JSON.
- Changed runtime evidence reporting so static-only scans render runtime evidence as not collected or not applicable unless runtime evidence is required or needed for a control claim.
- Changed evidence resolution to use deterministic source precedence with conflict reasons across ownership and control outputs.
- Changed production-data and mutable-endpoint projection so uncorrelated route/OpenAPI surfaces stay appendix-only while correlated paths render workflow, credential, deployment, target, and evidence context.
- Changed the default Agent Action BOM presentation to lead with one workflow/action path and move raw findings, graph refs, proof refs, scan quality, and detector diagnostics to appendices.
- Changed buyer-facing reports to lead with workflow chain highlights, authority, evidence state, proof/runtime status, boundary labels, and next-step recommendations before raw appendix detail.
- Updated command, trust, and schema documentation for evidence-state control resolution, target classification, action path type classification, coverage-qualified absence, runtime evidence framing, and report QA guardrails.

### Fixed

- Fixed lifecycle transition proof emission and evidence-bundle exports so identity lifecycle events use the canonical `lifecycle_transition` record type with schema, contract, and JSONL artifact coverage.
- Fixed govern-first projection so control state, queue, review burden, risk tier, and remediation stay semantically consistent for critical, contradictory, and control-first paths.

### Security

- Added fail-closed validation that flags unsafe low-risk classifications when workflow, infra, credential, approval, or proof evidence contradicts a supposedly low-risk delegated path.
- Added cloud role, workload identity, deployment-path, and service-connection authority correlation for workflow credentials, graph nodes, and buyer-facing action paths.
- Added SaaS service-token target-system and likely-scope classification for SDLC paths without extracting or serializing secret values.
- Extended customer-safe redaction to session metadata, prompts, reviewers, changed files, provider URLs, evidence packet fields, proof refs, graph refs, and credential subjects.
- Raised the pinned Go toolchain to `1.26.4` across repo contracts to clear standard-library `govulncheck` findings in binary-scanning CI lanes.

## [v1.5.0] - 2026-05-12
<!-- release-semver: minor -->

### Added

- Added deterministic evidence confidence lanes so govern-first action paths, Agent Action BOM output, top-risk sections, and linked control-backlog rows distinguish confirmed action paths from likely paths, semantic review candidates, and context-only evidence.
- Added normalized `credential_authority` posture across inventory privilege maps, govern-first action paths, control-path graph nodes, and Agent Action BOM output without exposing secret values.
- Added purpose plus version/config metadata on supported workflow, MCP, and agent-config action paths so buyers can see why a path exists and which local config introduced it.
- Added explicit `action_lineage` segments from repo and workflow through credential, target, owner, approval, and proof joins in buyer-facing report artifacts.
- Added static mutable endpoint semantics across OpenAPI, route, and MCP declaration surfaces so action paths, control graphs, and Agent Action BOM output can distinguish payment, refund, user-admin, data-export, deploy, delete, and production-mutation claims without live probing.
- Added an `action_surface_registry` artifact to report and evidence JSON so grouped workflows, servers, routes, and API schemas expose owner, purpose, version/config, credential authority, reachable actions, proof status, confidence lane, and graph joins in one deterministic view.
- Added a buyer-ready `design-partner-summary` report mode with path-specific remediation playbooks, proof-gap framing, and registry-backed static action summaries for external design-partner conversations.
- Added outside-in buyer action registry hardening scenarios covering mutable endpoints, credential authority, lineage, registry output, design-partner reports, and redacted customer-safe artifacts.

### Changed

- Updated buyer-facing report, evidence, schema, and README docs to describe design-partner summaries, expanded share profiles, redaction-field metadata, and Wrkr's static-only action-registry boundary language.
- Updated docs-site and release-trust guidance for safe Markdown rendering, production dependency advisory handling, and profile high-risk surface validation.

### Fixed

- Fixed govern-first report and Agent Action BOM projection consistency so empty-state status, risk/control posture, and buyer-facing path summaries are derived once and stay aligned across report JSON, markdown, evidence bundles, and redacted share profiles.
- Fixed purpose metadata extraction so explicit repo-local `wrkr:purpose` annotations take precedence over workflow, MCP, script, symbol, and location-derived fallbacks.
- Fixed Wrkr Factory profile high-risk MCP surface mapping and added lightweight validation so profile-driven reviews do not drift from the current repository layout.

### Security

- Added configurable report redaction selectors and expanded `design-partner`, `customer-redacted`, `external-redacted`, and `investor-safe` share profiles for safer buyer, customer, and investor artifact sharing.
- Hardened docs-site Markdown rendering so unsafe HTML, unsafe attributes, and unsafe link schemes are blocked or escaped while preserving deterministic static docs output.
- Added explicit docs-site production advisory governance so moderate production dependency advisories either fail the audit gate or require an owner-scoped expiring exception.

## [v1.4.0] - 2026-05-09
<!-- release-semver: minor -->

### Added

- Added an explicit `wrkr scan --progress auto|bar|plain|events|none` contract so operators can choose interactive, log-friendly, machine-readable, or disabled progress output without breaking JSON consumers.
- Added additive scan-status progress metadata including `progress_percent`, `progress_message`, `last_progress_at`, `phase_progress`, `repo_progress`, and `detector_progress` so long-running scans can be inspected through `wrkr scan status --json`.
- Added TTY-aware scan progress rendering, heartbeat updates, and detector-phase detail so long org and path scans stay visibly alive across source, detector, analysis, and artifact phases.
- Added buyer-facing backlog queue, visibility, and remediation fields so report and evidence outputs separate `control_first`, `review_queue`, `inventory_hygiene`, and `debug_only` work without hiding appendix/debug context.
- Added attack-path join refs and deterministic exclusion items across govern-first action paths, control-path graphs, and Agent Action BOM output so top attack paths are represented or explicitly excluded instead of silently dropped.
- Added detector-health `scan_quality` coverage rows to report and Agent Action BOM output so clean negative MCP/WebMCP results are distinguishable from partial, reduced, or blocked coverage.
- Added MCP candidate extraction and `wrkr mcp-list` miss diagnostics for package scripts, package dependencies, workspace hints, source literals, repo filtering, and expected-server checks from saved state.
- Added framework-candidate findings plus source-level confidence and evidence-strength labels so dependency-only framework inventory is separated from active tool-binding and credential-bearing agent paths.
- Added buyer-facing BOM summary metadata for scan scope, source privacy, operational exposure, governance readiness, coverage confidence, and customer-share redaction policy details.
- Added a `customer-redacted` share profile for report, BOM, and report evidence artifacts with deterministic pseudonyms for sensitive customer identifiers while preserving intra-artifact joins.
- Added cross-detector BOM reachability fields for endpoints and deployment targets plus confidence-aware reachability joins between source-bound tools and saved MCP server declarations.
- Added additive `credentials[]`, `path_context`, `tool_family_id`, and `tool_instance_id` fields across privilege maps, govern-first action paths, risk reports, and Agent Action BOM output.
- Added demo-ready action-path provenance, buyer-facing `control_state` / `risk_zone` / `review_burden`, path-level Gait coverage projection, semantic skill/instruction action hints, and a distinct `github_workflow_token` credential classification across scan, report, and Agent Action BOM output.

### Changed

- Clarified focused local validation guidance for narrow documentation and scan-status/progress changes while preserving required CI and release gates.
- Improved scan completion and failure footers so progress-enabled runs explain the last phase, partial-result state, detector/repo counts, artifact paths, and resume hint without polluting stdout contracts.
- Aligned govern-first ranking, risk tiers, and recommended actions so source-level MCP and agent paths with stronger governable signals outrank dependency-only inventory.
- Changed report and BOM proof refs to distinguish global proof-chain metadata from path-specific proof coverage and remediation.
- Split lifecycle gap reason output further into missing approval, inferred/unresolved owner, stale identity, and true orphaned identity states.

### Fixed

- Fixed scan managed artifact commits so interrupted proof, lifecycle, state, and manifest writes recover deterministically or fail closed.
- Fixed identity and inventory lifecycle mutations to share crash-consistent proof, lifecycle, state, and manifest commits.
- Fixed Go validation gates to test only first-party Wrkr packages even when docs-site dependencies are installed locally.
- Restored full Apache-2.0 license text for OSS scanner and evaluator compatibility.
- Fixed pinned install and release-smoke examples so documented first-value commands install a compatible Wrkr release.
- Fixed scan status so completed scans with source failures remain marked as partial instead of appearing complete to automation.
- Fixed hosted scan progress counters so failed repo materialization is counted once and pending progress remains accurate.
- Fixed workflow credential classification so multiple secret references on one CI action path keep subject-specific PAT, cloud-admin, cloud-access, deploy-key, and generic secret kinds instead of inheriting the first aggregate match.
- Fixed repo-level attack-path score spillover so high attack-path scores attach only to matching govern-first paths instead of every candidate path in the same repo.
- Fixed tolerant detector parsing for additive third-party `package.json` metadata and reduced modern JS/WebMCP parse noise by recovering positive fallback signals while keeping diagnostics out of ranked risk surfaces.
- Fixed remaining open detector manifests and MCP-adjacent configs to tolerate additive metadata instead of treating unknown fields as parse failures.

### Security

- Tightened release and docs workflow action-ref governance with immutable pins or expiring owner-scoped exceptions.
- Raised Wrkr's active Go toolchain pin to `1.26.3` and updated `golang.org/x/net` to `v0.53.0` to clear `govulncheck` findings in binary-scanning CI lanes.

## [v1.3.0] - 2026-04-30
<!-- release-semver: minor -->

### Added

- Added explicit `source_privacy` metadata to scan state, scan JSON, scan status, reports, evidence bundle metadata, and SARIF output so operators can prove hosted source retention and cleanup behavior.
- Added a versioned `control_path_graph` artifact linking identities, credentials, tools, workflows, repos, governance controls, targets, and action capabilities across saved state, reports, and evidence bundles.
- Added typed `credential_provenance` classification across inventory privilege maps, govern-first action paths, control backlog items, reports, and proof mapping while preserving existing boolean compatibility fields.
- Added a versioned `agent_action_bom` artifact in report and evidence outputs so operators can review risky agent actions, graph refs, proof refs, runtime evidence correlation, and next-action priority from one deterministic object.
- Added an `agent-action-bom` report template that leads with the canonical Agent Action BOM command path and evidence export.
- Added deterministic credential-kind classification for PATs, GitHub App keys, deploy keys, cloud keys, workload identity, delegated OAuth, JIT credentials, inherited human credentials, and unknown durable secrets without exposing secret values.
- Added built-in production-target packs for common deploy, Terraform/IaC, Kubernetes, package-publishing, release-automation, database-migration, and customer-impacting workflows while keeping custom production-target files authoritative when supplied.
- Added per-action-path and Agent Action BOM policy coverage status so reports can distinguish uncovered, declared, matched, runtime-proven, stale, and conflicting Gait evidence without claiming enforcement.
- Added normalized runtime control evidence classes and richer correlation keys so `wrkr ingest`, `wrkr report`, and `wrkr evidence` can join policy decisions, approvals, and proof verification back to one BOM item.
- Added buyer-facing MCP/A2A reachability projections on Agent Action BOM items, including reachable servers, tools, APIs, agents, trust-depth metadata, and evidence refs.
- Added optional `introduced_by` attribution on govern-first action paths and Agent Action BOM items using deterministic local git history when repository metadata is available.
- Added the deterministic `agent-action-bom-demo` before/after fixture pack, demo runner script, and acceptance coverage for the static-to-runtime evidence storyline.

### Changed

- Hosted source manifests now serialize logical repository references while detector execution uses private scan roots and source-code materialization is opt-in.
- Clarify that GitHub App install inventory is future/additive platform scope, not part of the current default OSS scan path.
- Align required-check and Go toolchain governance docs with the executable branch-protection and `go.mod` sources of truth.
- Normalized action classes and standing-privilege reasoning across privilege maps, govern-first action paths, control backlog views, reports, and Agent Action BOM items.

### Fixed

- Fixed `wrkr report --json` to emit the documented top-level `runtime_evidence` field when runtime correlation data is available from the selected saved state.
- Fixed Agent Action BOM proof coverage to reflect missing path-level approval and control proof instead of treating any attached proof chain as complete coverage.

### Security

- Hosted repository and organization scans now default to ephemeral source materialization with explicit retention modes and cleanup status.
- Scan artifacts, proof mapping, reports, evidence, and SARIF now redact hosted materialized paths from shareable outputs.
- Added privacy regression coverage and operator documentation proving hosted scans do not retain or serialize source code by default.
- Correlated CI secret references into credential provenance so risky headless or workflow-backed agent paths classify standing/static credential authority from deterministic repo/workflow evidence instead of remaining `unknown`.
- Reject root-escaping Gait policy symlinks as deterministic `unsafe_path` parse diagnostics instead of reading or emitting external policy files as repository evidence.
- Prevent release assets and Homebrew tap updates from publishing until checksum, SBOM, vulnerability scan, signing, provenance, and verification gates pass.
- Reject symlinked detector inputs that resolve outside the selected scan root to preserve source-boundary and proof-record integrity.
- Harden walked detector inputs so symlinked files outside the selected repo root cannot be read or recorded as repo-local evidence.

## [v1.2.0] - 2026-04-23
<!-- release-semver: minor -->

### Added

- Added the versioned control backlog contract for governance-first scan output while preserving existing raw finding JSON surfaces.
- Added deterministic recommended-action, evidence-quality, confidence, and SLA fields to governance backlog items.
- Added explicit engineering write-path classification and governance control mappings across scan, inventory, risk, and proof outputs.
- Added inventory governance commands for approvals, evidence attachments, accepted risk, deprecation, exclusion, and time-bound review state.
- Added proof and evidence lifecycle mapping so governance controls can show verifiable approval, least-privilege, rotation, deployment-gate, and review evidence.
- Added enterprise ownership resolution with explicit, inferred, conflicting, and missing owner states plus ownership confidence in governance outputs.
- Added large-org scan progress, phase timing, partial-result status, and scan status inspection without changing JSON stdout contracts.
- Added customer-ready CISO, AppSec, platform, audit, and customer-draft report templates led by the governance control backlog.
- Added offline-first ticket export payloads for Jira, GitHub Issues, and ServiceNow from top governance backlog items.

### Changed

- Improved the no-target `wrkr scan` experience with deterministic next-step guidance for hosted org setup, evaluator-safe fallback scanning, and local-machine hygiene while preserving existing exit codes.
- Added deterministic handoff guidance to `wrkr report --json` and `wrkr evidence --json` so operators can move from saved scan state to buyer- and audit-ready artifacts more directly.
- Clarified the public launch docs to distinguish hosted org posture from evaluator-safe and local-machine fallback paths and to explain risky sample outputs and low first-run evidence coverage more directly.
- Aligned the security-team, operator, and integration docs around a single artifact-led handoff path for audit, buyer, and GRC use using existing report, evidence, and verification outputs.
- Made governance scan mode the default, added quick/deep scan modes, and moved generated/package noise into a deterministic scan-quality appendix.
- Changed scan output to lead with a prioritized control backlog while keeping raw findings available for compatibility.
- Expanded security visibility into governance-native states for approved, unapproved, accepted-risk, deprecated, revoked, and needs-review control paths.
- Flagged deprecated tool reappearance as deterministic regress drift alongside revoked tool reappearance.
- Changed regress and inventory drift to focus on new or changed AI/automation control paths, approval expiry, owner changes, and risk increases from approved baselines.

### Fixed

- Fixed manual identity and inventory mutations to update the saved scan snapshot in the same rollback-safe transaction as manifest and proof artifacts.
- Fixed saved-state posture calculations so score, report, and regress immediately reflect approval mutations without requiring a fresh scan.
- Fixed lifecycle reconciliation so newly discovered tools persist as `discovered` until explicitly reviewed or approval state requires review.

### Security

- Refined secret-bearing automation semantics so Wrkr distinguishes secret references, leaked values, ownership/scope gaps, and rotation evidence gaps without exposing secret values.
- Hardened stateful CLI commands to fail closed on symlinked `--state` paths so scan, manifest, and proof artifacts cannot split across directories.

## [v1.1.3] - 2026-04-21
<!-- release-semver: patch -->

### Fixed

- Release version tooling now ignores unrelated non-ancestor semantic tags when falling back to historic release tags, limiting fallback selection to the documented changelog release lineage.
- `wrkr scan --path` now preserves nested local repositories named `build`, `dist`, or `target` instead of pruning those valid repo roots as generated directories.

## [v1.1.2] - 2026-04-21
<!-- release-semver: patch -->

### Changed

- Clarified the `wrkr score` command contract so malformed saved state is documented as a fail-closed runtime failure while valid cached-score output remains unchanged.

### Fixed

- `wrkr score` now validates the full saved scan snapshot before reusing cached posture scores, so malformed state files fail closed instead of returning stale success output.

## [v1.1.1] - 2026-04-14
<!-- release-semver: patch -->

### Added

- Added repeatable `wrkr scan --target <mode>:<value>` support so one scan can combine multiple hosted and local targets while preserving legacy single-target flags.
- Wrkr can now scan multiple hosted orgs and local repository roots in one deterministic run, producing a single proof/state/report generation with explicit per-target failures when needed.

### Changed

- Release prep now lands finalized changelog updates through a short-lived release-prep PR before tagging when `main` is protected.
- Hosted GitHub scans now emit a dedicated `rate_limited` JSON error code after bounded retry exhaustion while keeping the documented runtime exit code unchanged.
- Multi-org scans now expose clearer per-target progress and fail-closed resume behavior, including explicit rejection of unsupported mixed-target resume combinations.
- Govern-first summaries now highlight stronger workflow identity and ownership evidence, with unresolved or conflicting ownership treated as a higher-priority governance signal.
- Workflow-backed govern-first paths and summaries now expose static trigger posture such as scheduled, workflow-dispatch, and deploy-pipeline backed execution when it changes governance urgency.
- Govern-first ranking now prioritizes the most urgent write, deploy, production-backed, and approval-gap paths first while keeping weaker paths visible lower in the ranked output.
- `recommended_action` now separates visibility, approval, proof, and control-first path classes more sharply on real-world govern-first scans and report summaries.
- Clarified repo-local contributor and agent guidance so Wrkr now delegates Go toolchain authority to the enforced 1.26.2 floor in `go.mod` and the development standards.
- Added config-backed hosted GitHub API base support to `wrkr init` and `wrkr scan` so org-first onboarding can be configured once without weakening the existing fail-closed hosted-scan contract.
- Added explicit `coverage_note` guidance to `wrkr evidence --json` so low first-run framework coverage is framed as an evidence gap rather than unsupported framework parsing.
- Reconciled the public launch docs so hosted org posture is the primary first-screen path, with the evaluator-safe scenario preserved as the explicit fallback and demo flow.
- Updated first-run evidence docs and docs-site mirrors so evidence-gap guidance sits directly beside the first evidence workflows instead of appearing later as a separate clarification.

### Fixed

- Hosted GitHub scans now retry recognizable rate-limit `403` responses using the observed reset window instead of failing immediately as generic runtime errors.
- Blocked scan sidecar output paths from aliasing managed state and proof artifacts, so invalid configurations now fail fast instead of corrupting saved scan state.
- Made `wrkr scan --path` honor single-repo root inputs while preserving deterministic repo-set scans for scenario bundles and local multi-repo roots.

### Security

- Raised Wrkr's enforced Go toolchain floor to 1.26.2 across local, CI, and nightly scanner surfaces to clear called standard-library vulnerabilities flagged by nightly `govulncheck`.

## [v1.1.0] - 2026-03-31
<!-- release-semver: minor -->

### Added

- Added an `assessment` scan profile that sharpens govern-first action-path output for customer readouts while keeping raw findings and proof artifacts unchanged.
- Added an AI-first assessment summary to report output so customer readouts lead with governable paths, top control targets, and offline proof location.
- Added identity exposure summaries and first-review or first-revoke recommendations for non-human execution identities backing risky govern-first paths.
- Action paths now classify the business state they can change and flag shared or standing-privilege identity reuse on repeated risky paths.
- Added grouped `exposure_groups` summaries so repeated risky paths can be reviewed as stable report clusters without hiding raw path detail.

### Changed

- Release prep now uses `scripts/finalize_release_changelog.py` to promote `## [Unreleased]` entries into a dated versioned section and reset `Unreleased` for the next cycle.
- Tag workflows now use `scripts/validate_release_changelog.py` to fail closed when the prepared versioned changelog section does not match the release tag.
- `scripts/resolve_release_version.py` now validates explicit release versions against the changelog-derived semver bump instead of accepting mismatched manual versions.
- Planning skills now require every story to declare changelog impact, target changelog section, and draft `Unreleased` entry so release semver can be derived deterministically from implemented work.
- Implementation skills now apply those planned changelog fields to `CHANGELOG.md` `## [Unreleased]` instead of re-deciding release-note scope during implementation.
- Org scans now stream deterministic progress events to stderr during execution while preserving stdout JSON contracts.
- Scan and report summaries now prioritize govern-first AI action paths ahead of generic supporting findings when risky paths are present.
- Govern-first `recommended_action` output now differentiates inventory, approval, proof, and control based on path context instead of collapsing most paths to approval.
- Clarified the public `action_paths[*].path_id` contract and aligned docs and contract tests with the shipped deterministic identifier format.
- Clarified scan and report wording so Wrkr's customer-facing output stays explicitly scoped to static posture, risky paths, and offline-verifiable proof.
- Govern-first summaries now highlight ownership quality and ownerless exposure so unresolved or conflicting ownership is explicit in top action paths.
- Updated scan, evidence, campaign, and extension-detector docs plus regression coverage to match the hardened contract and boundary behavior.

### Fixed

- Deduplicated govern-first `action_paths` so each deterministic action path emits one unique `path_id` row per scan.
- Priority detectors now surface permission and stat failures consistently in scan output so incomplete visibility is explicit.
- Made scan artifact publication transactional so failed late writes no longer leave mixed state, proof, and manifest generations on disk.
- `wrkr campaign aggregate` now rejects non-scan JSON and incomplete artifacts with stable `invalid_input` errors instead of summarizing them as posture evidence.
- Repo-local extension detectors now stay on additive finding surfaces by default and no longer create implicit tool identities, action paths, or regress state.

## [v1.0.11] - 2026-03-26
<!-- release-semver: patch -->

### Changed

- Public contract wording changes now count as changelog-worthy changes under `Unreleased`, even when JSON, exit-code, and schema contracts stay unchanged.
- README, quickstart, docs-site, and PRD onboarding now lead with the evaluator-safe scenario path and explicitly explain repo-root fixture noise before widening to hosted org posture.
- `wrkr fix` now supports explicit `--apply` mode for supported repo-file changes, additive `--max-prs` deterministic PR grouping, and additive machine-readable publication details while preserving preview mode semantics.
- Wrkr now ships a repo-root `action.yml` composite action that wraps the CLI, emits deterministic outputs, and supports explicit repo-targeted scheduled remediation dispatch.
- `wrkr report --pdf` now wraps and paginates executive output deterministically, and the board-ready claim is backed by explicit executive report acceptance fixtures.

### Fixed

- `wrkr evidence` now verifies the saved proof chain before bundle staging and fails closed on malformed or tampered proof state instead of publishing a new bundle.
- `wrkr identity approve|review|deprecate|revoke` now restore the prior committed manifest, lifecycle, and proof state when a downstream lifecycle or proof write fails.
- Hosted `wrkr scan --resume` now rejects symlink-swapped checkpoint files and reused materialized repo roots instead of trusting them as in-scope detector roots.
- Invalid `wrkr scan --report-md-path` or `--sarif-path` inputs are now rejected before managed `.wrkr` state and proof artifacts are written.
- `wrkr scan` now tolerates additive Claude/Codex vendor fields in supported configs instead of treating them as parse errors when known fields still parse cleanly.
- `wrkr scan` and `wrkr mcp-list` now emit explicit MCP-visibility warnings when known MCP-bearing declaration files fail to parse and posture may be incomplete.
- Hosted `wrkr scan --repo/--org` now resolves GitHub auth from `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`, and rate-limit failures now point operators at that auth path.
- `wrkr verify --chain` now always performs structural chain verification even when attestation or signature material is present.
- Invalid or unreadable verifier-key material now fails closed instead of silently downgrading to structural-only verification.
- `wrkr regress run` now reconciles legacy `v1` baselines created before instance identities when the current identity is equivalent.

### Security
- Hardened managed output and scan-owned directory ownership checks so forged marker files can no longer authorize destructive reuse of caller-selected paths.

# Adhoc Plan: Platform Breadth, Runtime Proof, And Product Workflow

Date: 2026-05-27
Profile: `wrkr`
Slug: `platform-breadth-runtime-proof-product-workflow`
Recommendation source: user-provided Sprint 4 recommendations covering GitLab CI coverage, Azure DevOps Pipeline coverage, coding-agent session ingest, buyer-facing Agentic SDLC control reporting, internal/external redaction pairing, customer-safe evidence and prompt redaction, portable evidence bundles, boundary labels and claim discipline, repeatable assessment workflow, low-click review workflows, and drift review loops.

All paths in this plan are repo-relative. User-provided absolute checkout paths have been normalized to repo-relative paths. This is a planning artifact only; it does not implement runtime, schema, CLI, detector, scenario, or documentation changes.

## Global Decisions (Locked)

- Wrkr remains the deterministic "See" product in the See -> Prove -> Control loop. This plan must not add Axym compliance-engine behavior, Gait runtime enforcement, scan-time LLM calls, live endpoint probing, or default network enrichment.
- GitLab CI/CD and Azure DevOps coverage are first-class CI authority surfaces, not command-string-only heuristics. Structured YAML parsing, deterministic local include/template resolution, stable reason codes, and no secret extraction are mandatory.
- CI platform coverage must flow through the same contract surfaces as GitHub Actions and Jenkins: detector findings, workflow capabilities, inventory privileges, privilege budget, action paths, Control Path Graph, Agent Action BOM, evidence packets, control backlog, scan quality, schemas, reports, and drift.
- Local includes/templates may be resolved only when they stay inside the scan root, are regular files, and do not require network, remote project, package registry, provider API, or credential access. Unresolved remote/dynamic includes must produce explicit quality/evidence states, not silent gaps.
- Coding-agent session ingest is local-file ingest. Provider-specific readers may understand Codex, Claude Code, Cursor, Copilot, Gait, and future runtime exports, but they must normalize into Wrkr-owned runtime evidence/session records before risk/report/proof layers consume them.
- Session ingest must redact and classify sensitive content before persistence. Prompts, transcripts, changed files, authors, reviewers, URLs, repo paths, proof refs, graph refs, credential subjects, and provider identifiers must be covered by deterministic field-level controls.
- Internal and external artifacts are paired outputs from the same scan/report graph. Internal artifacts keep remediation detail; customer-redacted artifacts keep enough joins and evidence state to be useful; the private join map stays local and is excluded from shareable bundles.
- Boundary labels are required for every meaningful path/artifact claim. Canonical values are `discovery_only`, `report_only`, `approval_capable`, and `enforcement_capable`. Wrkr cannot imply approval or enforcement unless the evidence boundary supports that claim.
- Portable evidence bundles must have a stable manifest, stable file names, schema versions, redaction profile metadata, proof-chain refs, source privacy metadata, boundary labels, and evidence-state summaries. Bundles must be forwardable without losing meaning.
- Buyer-facing reports lead with agentic SDLC workflow chains and control state, not raw detector findings. Raw findings, parser diagnostics, graph internals, proof details, and scan quality stay available as appendices/evidence.
- Repeatable assessment workflow is a product surface. `wrkr assess` or an equivalent documented command sequence must produce one predictable output directory and manifest from import/connect, scan, report, optional ingest, export, action assignment, and drift review.
- Low-click workflows are named buyer jobs, not a new risk model. Focus presets filter and render existing deterministic facts such as release-adjacent AI paths, write/deploy reach, owner/approval evidence gaps, evidence gaps, contradictions, and recommendations.
- Drift review is recurring infrastructure. New/removed/changed authority, changed evidence, changed target class, new control-first paths, resolved gaps, worsened paths, and contradictions must be explicit, stable, and contract-tested.
- Existing API contracts remain locked: deterministic outputs, no secret extraction, no scan-data exfiltration by default, signed proof chain integrity, `--json` machine output, `--explain` rationale, `--quiet` CI-friendly operation, and exit codes `0` through `8`.
- Changelog entries are required for implementation PRs because this work changes public detector coverage, report JSON, evidence bundle contracts, schemas, CLI/report/export behavior, markdown presentation, redaction semantics, drift semantics, and user-facing docs.

## Current Baseline (Observed)

- `core/detect/ciagent/detector.go` currently scans `.github/workflows/*` and `Jenkinsfile`, then emits `ci_autonomy` findings with autonomy, approval-gate, secret-access, dangerous-flag, credential-provenance, and workflow capability evidence. It does not scan `.gitlab-ci.yml`, `.gitlab/ci/*.yml`, `azure-pipelines.yml`, or Azure template paths as first-class files.
- `core/detect/workflowcap/analyze.go` parses GitHub Actions workflow YAML with `gopkg.in/yaml.v3`, including workflow name, triggers, permissions, jobs, steps, job environments, secret refs, approval source, deployment gates, proof requirements, cloud/deploy commands, MCP/tool hints, and authority bindings. It contains Azure command/action heuristics such as `azure/login` and `azure/k8s-deploy`, but it does not parse Azure DevOps pipeline schema, service connections, variable groups, deployment jobs, approvals/checks, templates, stages, or agent pools.
- `core/detect/ciagent/detector_test.go` covers GitHub workflow headless agent cases, approval steps, and workflow capability evidence. There are no equivalent GitLab CI/CD or Azure DevOps scenario fixtures and parser contract tests.
- `core/aggregate/inventory/privileges.go`, `core/aggregate/privilegebudget/budget.go`, and `core/risk/action_paths.go` already consume workflow credentials, authority bindings, production targets, deployment/write semantics, autonomy tiers, evidence states, control recommendations, and high-stakes presets. They need platform-neutral CI authority inputs for GitLab and Azure.
- `core/report/agent_action_bom.go` already exposes Agent Action BOM items with path IDs, credential authority, authority bindings, target class, action path type, autonomy tier, delegation readiness, recommended controls, risk classification validation, evidence packet refs, runtime/proof refs, workflow chain refs, graph refs, action lineage, and focused primary-view support. It needs GitLab/Azure authority sources, boundary labels, report-first workflow ordering, and internal/external paired artifact metadata.
- `core/report/render_markdown.go`, `core/report/templates/templates.go`, and `core/cli/report.go` already support multiple report templates, `--template agent-action-bom`, `--focus-path`, `--recent-pr-review`, markdown/PDF/JSON evidence artifacts, share profiles, and redaction fields. They do not yet offer named buyer focus presets such as release, write-deploy, approval-evidence-unknown, owner-evidence-unknown, evidence-gaps, or contradictions.
- `core/ingest/ingest.go` already models `runtime` and `external_control` records with evidence classes such as policy decisions, approvals, JIT credentials, freeze windows, kill switches, action outcomes, proof verification, owner assignment, policy records, branch protection, protected environments, deployment approvals, required checks, and security gates. `core/cli/ingest.go` accepts one local `--input`, auto-detects evidence packet JSON by top-level `packets`, and writes managed runtime/evidence-packet artifacts. It does not yet provide provider-specific coding-agent session readers.
- `core/ingest/evidence_packets.go`, `core/ingest/evidence_packet_schema.go`, `core/report/evidence_packets_test.go`, and `schemas/v1/evidence/agentic-evidence-packets.schema.json` already provide Agentic SDLC evidence-packet normalization/correlation. Session ingest should reuse these contracts instead of inventing a separate evidence path.
- `core/evidence/evidence.go` already builds compliance-ready evidence directories with inventory, risk report, attack paths, evidence packets, Agent Action BOM, proof-record exports, source privacy metadata, output-directory safety checks, and a `manifest.json`. It needs a richer portable artifact manifest that enumerates all meaningful outputs, internal/external variants, redaction profile, boundary labels, evidence-state summaries, and private join-map exclusion.
- `core/report/redaction.go` already supports share profiles and deterministic redaction fields for owners, repos, paths, credential subjects, authors, filesystem paths, providers, proof refs, and graph refs. It does not yet cover session metadata, prompts/transcripts, reviewers, changed files, provider URLs, declarations, evidence packet fields, boundary labels, or paired internal/external join maps.
- `core/report/artifacts.go` already builds a JSON report evidence bundle with control backlog, Control Path Graph, workflow chains, action surface registry, runtime evidence, evidence packets, Agent Action BOM, compliance summary, proof refs, and next actions. It needs stable artifact-manifest metadata and internal/external bundle pairing.
- `core/cli/export.go` currently exports `inventory`, `appendix`, and dry-run ticket payloads. It does not yet export one portable assessment/evidence pack with BOM, evidence packets, proof refs, executive summary, recommendations, backlog CSV, redacted variants, and evidence-state metadata.
- `core/cli/root.go` has no `assess` subcommand today. The current user workflow is a sequence across `scan`, `ingest`, `report`, `evidence`, `export`, `action`, and `regress`, with docs in `docs/commands`.
- `core/regress/regress.go` and `core/regress/inventory_diff.go` already model drift for inventory, approvals, secret-bearing workflows, critical attack paths, and control path drift. They do not yet expose Sprint 4 drift categories such as `new_write_paths`, `new_deploy_paths`, `new_credentials`, `new_unknown_approval_evidence`, `resolved_gaps`, `worsened_paths`, `new_contradictions`, and `paths_ready_for_control`.

## Exit Criteria

- GitLab CI/CD detection parses `.gitlab-ci.yml` and safe local includes, extracts stages, jobs, variables, environments, manual gates, protected/release/deploy jobs, secrets by reference, AI agent execution, MCP/tool invocation, and authority/action signals, and feeds workflow capabilities, action paths, graph, BOM, backlog, scan quality, and schemas.
- Azure DevOps detection parses `azure-pipelines.yml` and safe local templates, extracts stages, jobs, deployment jobs, variable groups, service connections, environments, approvals/check hints, agent pools, secrets by reference, package/release/deploy operations, AI agent execution, MCP/tool invocation, and authority/action signals, and feeds the same downstream contracts.
- CI platform authority is provider-neutral enough that GitHub, Jenkins, GitLab, and Azure action paths share stable fields for workflow, job, stage, environment, approval source, credential subject, authority binding, target class, action class, secret ref, platform, and parser confidence.
- Provider-specific coding-agent session readers normalize local Codex-style, Claude Code, Cursor, Copilot, Gait, and future runtime artifacts into schema-backed Wrkr session/runtime evidence without persisting raw secret values or unsafe prompt payloads under customer-safe profiles.
- Runtime evidence from sessions correlates to graph nodes, workflow chains, evidence packets, Agent Action BOM items, proof refs, changed files, PR/MR provenance, action outcomes, and missing-evidence summaries with deterministic IDs and stable ordering.
- Reports can generate paired internal and external artifacts from one scan/report build, with a local private join map that is never included in shareable bundles and is rejected from unsafe output locations.
- Redaction profiles cover evidence packets, sessions, prompts/transcripts, authors, reviewers, repo paths, changed files, proof refs, graph refs, credential subjects, provider URLs, declarations, and boundary labels with deterministic pseudonyms and field-level controls.
- Portable evidence bundles include BOM, evidence packets, proof refs, executive summary, control recommendations, backlog CSV, internal/external variants, evidence-state metadata, source privacy metadata, artifact manifest, stable file names, schema versions, redaction profile, boundary labels, and proof-chain refs.
- Every path and artifact claim carries `boundary_label` with one of `discovery_only`, `report_only`, `approval_capable`, or `enforcement_capable`. Markdown and JSON do not imply enforcement for report-only or discovery-only surfaces.
- Buyer-facing control reports lead with top workflow chains and include path type, target class, tier, authority, blast radius, evidence states, approval path, proof status, runtime evidence, recommendation, plain-language explanation, and boundary label before raw findings.
- A first-class `wrkr assess` command or documented equivalent creates one deterministic assessment directory and manifest across scan, report, optional evidence ingest, export pack, action assignment, and drift review.
- Named low-click workflow presets exist for generate BOM, release-adjacent AI paths, write/deploy reach, unknown owner evidence, unknown approval evidence, evidence pack generation, drift review, recommendations, evidence gaps, and contradictions.
- Drift review emits first-class summaries for new paths, removed paths, changed authority, changed evidence, changed target class, new control-first paths, resolved gaps, worsened paths, new contradictions, and paths ready for control.
- Scenario, contract, schema, hardening, chaos, performance, docs parity, and acceptance lanes cover all new public contracts and fail-closed behavior.

## Public API and Contract Map

- CLI contracts:
  - Preserve exit codes: `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, and `8` unsafe operation blocked.
  - `wrkr scan --json` gains additive GitLab CI/CD and Azure DevOps detector output by default for local files inside scan roots. No new network behavior is introduced.
  - `wrkr ingest --json --input <path>` remains compatible with existing runtime and evidence-packet inputs. Additive session input can be introduced as `--type session --provider <codex|claude-code|cursor|copilot|gait|auto>` or equivalent after existing flag patterns are inspected; invalid provider or malformed session input must fail with exit `6` or `3` as appropriate.
  - `wrkr report --json`, `wrkr report --md`, `wrkr report --pdf`, and `wrkr report --evidence-json` gain additive fields for platform CI authority, session runtime proof, boundary labels, workflow-first summaries, focus presets, artifact pairing, redaction summaries, and drift categories.
  - Add a first-class `wrkr assess` command or a documented sequence that produces one deterministic output directory and manifest. If a command is added, it must support `--json`, `--quiet`, `--explain`, `--state`, `--output-dir`, `--share-profile`, optional `--runtime-input`, optional `--baseline`, and focus preset flags without changing existing commands.
  - Add named focus presets to `wrkr report` and/or `wrkr assess`, using values such as `release`, `write-deploy`, `approval-evidence-unknown`, `owner-evidence-unknown`, `evidence-gaps`, `contradictions`, and `recommendations`. Unknown presets fail with exit `6`.
  - `wrkr export` gains a portable pack format or an equivalent `wrkr assess --export-pack` path. Unsafe output directories and accidental inclusion of the private join map in shareable bundles must fail with exit `8`.
- JSON and schema contracts:
  - Extend v1 schemas additively for GitLab and Azure workflow capability facts, platform-neutral CI authority fields, session evidence, artifact manifests, paired artifact metadata, private join-map metadata, redaction summaries, boundary labels, focus presets, assessment manifests, export packs, and drift review summaries.
  - New or extended schemas should live under `schemas/v1`, with evidence bundle additions under `schemas/v1/evidence` and regress additions under `schemas/v1/regress`.
  - Canonical enum additions include CI platform values `github_actions`, `jenkins`, `gitlab_ci`, `azure_devops`; boundary labels `discovery_only`, `report_only`, `approval_capable`, `enforcement_capable`; session providers `codex`, `claude_code`, `cursor`, `copilot`, `gait`, and `unknown`; and drift categories listed in this plan.
  - Existing Agent Action BOM, report summary, risk report, regress result, and evidence bundle consumers remain compatible. New fields are additive and optional when the input evidence is absent.
- Detection and aggregation contracts:
  - Structured YAML parsing with `gopkg.in/yaml.v3` is required for GitLab and Azure YAML. Regex-only scanning is allowed only for unstructured command/script bodies after typed pipeline structure is parsed.
  - Detectors own platform parsing and normalized findings. `workflowcap` owns platform-neutral workflow/action capability projection. Inventory aggregation owns privileges and authority rollups. Risk owns action path, blast radius, tier/readiness, and drift semantics. Report/evidence layers render and package.
  - Secrets and variables are references only. Detectors must never extract, log, serialize, or fingerprint raw secret values.
- Proof and evidence output contracts:
  - Session evidence and platform CI facts reference existing Wrkr proof record types where possible: `scan_finding`, `risk_assessment`, `approval`, and `lifecycle_transition`. New proof record types require explicit schema/version discussion before implementation.
  - Evidence packets and portable bundles reference proof chains by refs/digests and do not replace chain verification.
  - Boundary labels describe what Wrkr can claim from observed evidence. They are not enforcement.
- Documentation contracts:
  - Docs must explain GitLab/Azure CI coverage, local include/template resolution limits, session ingest formats, internal/external paired artifacts, redaction fields, portable bundle manifest, boundary labels, `wrkr assess`, focus presets, and drift review categories.
  - Examples must use fake orgs, repos, users, provider URLs, service connections, variable groups, credentials, prompts, PR/MR IDs, environments, and assets.
  - Public examples must use profile command anchors where machine-readable evidence examples are needed: `wrkr scan --json`, `wrkr regress run --baseline <baseline-path> --json`, and `wrkr score --json`.

## Docs and OSS Readiness Baseline

- User-facing docs impacted:
  - `README.md`
  - `docs/commands/scan.md`
  - `docs/commands/ingest.md`
  - `docs/commands/report.md`
  - `docs/commands/export.md`
  - `docs/commands/evidence.md`
  - `docs/commands/regress.md`
  - `docs/commands/action.md`
  - new or updated `docs/commands/assess.md` if a command is added
  - `docs/trust/contracts-and-schemas.md`
  - `docs/trust/detection-coverage-matrix.md`
  - `schemas/v1/README.md`
  - `CHANGELOG.md`
- Scenario and contract docs impacted:
  - `internal/scenarios/coverage_map.json`
  - scenario fixtures under `scenarios/wrkr/**`
  - CLI/report/schema acceptance tests under `internal/acceptance`
  - contract tests under `testinfra/contracts`
- OSS trust baseline:
  - GitLab/Azure examples must use fake project names, pipeline names, environments, service connections, variable groups, agent pools, URLs, users, approvals, packages, deployment targets, and credentials.
  - Session examples must use fake prompts, fake response snippets, fake file paths, fake PR/MR metadata, fake run IDs, and fake provider URLs, with raw secret-like values rejected or replaced.
  - Do not commit generated customer reports, local scan outputs, private join maps, runtime session exports, proof chains, credential material, provider private payloads, or transient state files outside deterministic fixtures.
  - Docs must state that Wrkr consumes local files and sidecars by default; it does not query GitLab, Azure DevOps, GitHub, cloud providers, ticketing systems, coding-agent providers, or customer systems in scan/report/ingest paths unless a future opt-in command says otherwise.
  - Redacted exports must preserve audit usefulness while removing customer-specific owners, reviewers, prompts, repo paths, changed files, URLs, deployment names, credential subjects, proof refs, graph refs, and provider IDs according to the selected share profile.
- Docs must answer:
  - How GitLab and Azure pipeline authority differs from GitHub Actions coverage.
  - What local includes/templates are resolved and what unresolved remote/dynamic references mean.
  - How to prepare coding-agent session artifacts for ingest.
  - How internal/external artifact pairs and private join maps work.
  - Which redaction profile to use for internal remediation versus customer sharing.
  - What boundary labels mean and what Wrkr is not claiming.
  - How to run one repeatable assessment and re-run it for drift.
  - How to use low-click focus presets without understanding every detector.

## Recommendation Traceability

| Recommendation / Finding | Source Priority | Planned Coverage | Why | Strategic Direction | Expected Benefit |
|---|---:|---|---|---|---|
| 37. GitLab CI Coverage | P0 | Stories 1.1, 1.2 | GitLab pipeline authority must reach parity with GitHub Actions. | Parse GitLab YAML/includes and project authority into platform-neutral workflow capabilities. | GitLab-heavy buyers see deploy/write/agent risk without custom assessment work. |
| 38. Azure DevOps Pipeline Coverage | P0 | Stories 1.3, 1.4 | Azure deploy commands are currently heuristic, not pipeline-aware. | Parse Azure pipelines/templates and model service connections, variable groups, environments, and deployment jobs. | Azure buyers get first-class pipeline authority coverage and evidence. |
| 39. Coding-Agent Session Ingest | P0 | Stories 2.1, 2.2 | Static scan shows what can happen; session ingest proves what did happen. | Normalize local provider exports into runtime/session evidence, graph refs, evidence packets, and BOM coverage. | Reports can join observed agent actions to static authority and proof gaps. |
| 40. Buyer-Facing Agentic SDLC Control Report | P0 | Story 3.1 | Buyers need a five-minute workflow answer, not raw findings. | Lead with workflow chains, authority, evidence, proof status, runtime evidence, and recommendation. | Control conversations become executive-readable and action-oriented. |
| 41. Internal / External Redaction Pairing | P0 | Story 2.3 | Redacted reports need safe sharing while internal teams need remediation detail. | Generate paired artifacts with a local-only private join map. | Customers can share externally without losing internal actionability. |
| 42. Customer-Safe Evidence And Prompt Redaction | P0 | Stories 2.3, 2.4 | Evidence packs and prompts are valuable and sensitive. | Extend redaction profiles and deterministic pseudonyms to session/evidence fields. | Shared bundles preserve meaning while protecting sensitive data. |
| 43. Portable Evidence Bundle | P0 | Story 2.5 | Artifacts must be forwarded internally without losing meaning. | Add a stable artifact manifest and bundle all meaningful outputs with metadata. | Evidence packs become durable, auditable deliverables. |
| 44. Boundary Labels And Claim Discipline | P0 | Story 2.5 | Wrkr should not imply enforcement it does not own or observe. | Add boundary labels to BOM, graph, evidence packets, exports, and markdown. | Buyers understand discovery/report/approval/enforcement boundaries clearly. |
| 45. Repeatable Assessment Workflow | P0 | Story 3.2 | Wrkr should not feel like a custom assessment. | Productize scan/report/ingest/export/action/drift into one workflow command or sequence. | Teams can repeat assessments with stable output directories and manifests. |
| 46. Low-Click Review Workflows | P1 | Story 3.3 | Users should get value without knowing detector internals. | Add named focus presets, templates, and filters for common buyer jobs. | Product usage becomes faster and less expert-dependent. |
| 47. Drift Review Loop | P0 | Stories 4.1, 4.2 | Drift is where Wrkr becomes recurring infrastructure. | Add first-class drift categories and review/report workflow surfaces. | Re-runs reveal new authority, worsening evidence, resolved gaps, and paths ready for control. |

## Test Matrix Wiring

- Fast lane:
  - Focused unit tests for GitLab parser/include resolution, Azure parser/template resolution, platform-neutral workflow capability projection, CI authority binding, privilege budget rollups, session reader normalization, redaction selectors, artifact manifest generation, boundary label derivation, focus presets, assess orchestration, and drift category derivation.
  - Candidate command: `go test ./core/detect/ciagent ./core/detect/workflowcap ./core/aggregate/inventory ./core/aggregate/privilegebudget ./core/risk ./core/ingest ./core/evidence ./core/report ./core/cli ./core/regress -count=1`.
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
  - Windows smoke must cover GitLab/Azure path normalization, include/template path safety, CRLF YAML, session artifact path normalization, private join-map exclusion, redaction pseudonym stability, artifact manifest paths, and drift sorting.
- Risk lane:
  - `make test-hardening` for unsafe includes/templates, malformed YAML, invalid session artifacts, raw-secret-looking session payloads, redaction misses, unsafe output paths, shareable bundle join-map leaks, boundary-label overclaiming, unknown focus presets, and invalid drift baselines.
  - `make test-chaos` for partial includes/templates, cyclic includes, missing templates, conflicting provider session metadata, stale runtime evidence, corrupt proof refs, conflicting boundary evidence, and mixed fresh/stale drift inputs.
  - `make test-perf` when pipeline include resolution, session ingest, bundle generation, or drift comparison materially changes scan/report runtime.
- Release/UAT lane:
  - `make test-release-smoke`
  - `scripts/run_v1_acceptance.sh --mode=release` when schemas, CLI flags, docs examples, bundle manifests, or report examples change.
- Gating rule:
  - Wave 1 GitLab/Azure parsers must land before reports claim platform CI parity.
  - Wave 2 session/redaction/bundle contracts must land before buyer reports render runtime proof from session artifacts.
  - Wave 3 workflow/report surfaces must land before docs advertise `wrkr assess` or low-click focus presets.
  - Wave 4 drift categories must land before recurring assessment docs claim drift review coverage.
  - Wave 5 schemas, scenarios, docs, and changelog must ship before release notes advertise Sprint 4 behavior.

## Minimum-Now Sequence

- Wave 1 - Platform CI authority breadth:
  - Story 1.1 adds GitLab CI/CD parser, local include resolver, and detector findings.
  - Story 1.2 wires GitLab authority into workflow capabilities, inventory, risk, BOM, backlog, graph, and scan quality.
  - Story 1.3 adds Azure DevOps parser, local template resolver, and detector findings.
  - Story 1.4 wires Azure authority into workflow capabilities, inventory, risk, privilege budget, BOM, backlog, graph, and scan quality.
- Wave 2 - Runtime proof, redaction, and portable artifacts:
  - Story 2.1 adds coding-agent session ingest providers and normalized session model.
  - Story 2.2 correlates session evidence into runtime evidence, graph, evidence packets, and BOM coverage.
  - Story 2.3 generates paired internal/external artifacts and a local-only private join map.
  - Story 2.4 extends redaction profiles to session/evidence/prompt/provider fields.
  - Story 2.5 adds portable bundle manifests and boundary labels.
- Wave 3 - Product workflow and buyer reporting:
  - Story 3.1 refines buyer-facing control reports around workflow chains.
  - Story 3.2 adds `wrkr assess` or an equivalent first-class documented assessment sequence.
  - Story 3.3 adds low-click focus presets for common buyer jobs.
- Wave 4 - Drift review infrastructure:
  - Story 4.1 adds first-class drift category model and regress/schema output.
  - Story 4.2 adds drift review report/CLI workflow and paths-ready-for-control summaries.
- Wave 5 - Contracts, scenarios, docs, and release readiness:
  - Story 5.1 updates schemas, scenarios, docs, changelog, examples, and acceptance coverage across the Sprint 4 surface.

## Explicit Non-Goals

- No implementation in this plan file.
- No changes to `product/PLAN_NEXT.md` or rolling roadmap files.
- No default network calls to GitLab, Azure DevOps, GitHub, Jira, ServiceNow, Backstage, cloud providers, CI providers, coding-agent providers, observability tools, ticketing systems, or customer SaaS systems.
- No live endpoint probing, runtime enforcement, or Gait policy execution.
- No Axym product logic or compliance-engine behavior in Wrkr.
- No scan-time, risk-time, proof-time, report-time, or ingest-time LLM calls.
- No extraction, logging, serialization, hashing-for-identification, or fixture commits of raw secret values.
- No remote GitLab include fetches, Azure template fetches, package downloads, or provider API lookups during default scan.
- No removal of existing v1 JSON fields without an explicit versioned migration.
- No hosted UI or web service requirement for the repeatable assessment workflow.
- No automatic remediation PRs or ticket submissions as part of assess, report, export, or drift review.

## Epic 1: Platform CI Authority Breadth

Objective: give GitLab CI/CD and Azure DevOps first-class deterministic authority coverage equivalent to GitHub Actions surfaces.
Traceability: Recommendations 37 and 38.

### Story 1.1: Add GitLab CI/CD Parser, Include Resolver, And Detector Findings

Priority: P0
Recommendation coverage: 37

Tasks:
- Add a GitLab CI parser for `.gitlab-ci.yml` plus conventional local include paths such as `.gitlab/ci/*.yml` when referenced by safe local includes.
- Model GitLab top-level `stages`, `variables`, `include`, `workflow`, `default`, `before_script`, `after_script`, and job definitions while preserving unknown/dynamic fields as parser diagnostics where useful.
- Resolve local includes only when the include path stays inside the scan root, is a regular file, is not symlink-escaped, and can be parsed deterministically. Mark remote/project/template/component/dynamic includes as unresolved local evidence gaps.
- Extract job names, stage names, script/before/after script, image/services, variables by name only, environments, `when: manual`, `rules`, `only/except`, deploy/release keywords, artifacts, dependencies, needs, protected/ref hints, secret refs, AI agent invocations, MCP/tool invocation, and package/release/deploy commands.
- Emit `ci_autonomy` or platform-specific detector findings with `ci_platform=gitlab_ci`, parser confidence, include resolution status, workflow/job/stage evidence, and no raw secret values.

Repo paths:
- `core/detect/ciagent/detector.go`
- `core/detect/ciagent/detector_test.go`
- `core/detect/workflowcap/analyze.go`
- new package under `core/detect` for GitLab pipeline parsing if it keeps boundaries clearer
- `testinfra/contracts`
- `scenarios/wrkr`

Run commands:
- `go test ./core/detect/ciagent ./core/detect/workflowcap -count=1`
- `make test-contracts`
- `scripts/validate_scenarios.sh`

Test requirements:
- Unit tests for minimal pipeline, multi-stage pipeline, manual gate, environment deploy job, release job, variable references, AI agent script, MCP invocation, local include, missing include, cyclic include, unsupported remote include, malformed YAML, and symlink escape.
- Golden finding tests proving stable finding ordering, stable reason codes, and no raw secret value serialization.
- Scenario fixture for a GitLab repo with headless AI execution, secrets by reference, deploy/release authority, manual approval gate, and unresolved remote include.

Matrix wiring:
- Fast lane: focused GitLab parser and ciagent detector tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario validation plus GitLab CI fixture coverage.
- Cross-platform lane: Windows path normalization, CRLF YAML, and include path safety.
- Risk lane: `make test-hardening` for unsafe include paths, cyclic includes, malformed YAML, secret-looking values, and unsupported remote includes.

Acceptance criteria:
- `.gitlab-ci.yml` produces deterministic CI agent findings when AI/headless/tool/deploy authority is present.
- Safe local includes are resolved and unresolved include classes are visible in evidence.
- Manual gates, environments, deploy/release jobs, variables, and secret refs appear as structured evidence without raw values.
- GitLab parser errors are deterministic and fail closed only when required by existing parse-error policy.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added first-class GitLab CI/CD detection for local pipelines, safe local includes, jobs, stages, variables, manual gates, deploy/release authority, secrets by reference, AI agent execution, and MCP/tool invocation.
Semver marker override: [semver:minor]
Contract/API impact: Additive detector evidence, workflow capability fields, scenario fixtures, and schemas for `gitlab_ci` platform output.
Versioning/migration impact: Existing GitHub/Jenkins findings remain unchanged; downstream consumers should tolerate the new CI platform enum.
Architecture constraints: Detection owns GitLab YAML parsing; workflow capability projection consumes normalized parser facts; no network include resolution.
ADR required: no
TDD first failing test(s): Add failing GitLab parser fixtures for local include resolution, manual gates, deploy jobs, and unsafe includes before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Missing, cyclic, or unsafe includes produce deterministic unresolved/blocked evidence states instead of silently dropping pipeline authority.

### Story 1.2: Wire GitLab Authority Into Workflow Capabilities, Risk, BOM, And Scan Quality

Priority: P0
Recommendation coverage: 37

Tasks:
- Extend workflow capability projection with platform-neutral fields for GitLab workflow/job/stage/environment, manual gate, deploy/release job, secret refs, variable refs, AI agent execution, MCP/tool invocation, and include resolution status.
- Map GitLab CI authority into inventory privileges, credential authority, authority bindings, privilege budget, action classes, target classes, blast radius, scan quality, and action path evidence.
- Add GitLab platform refs to Control Path Graph nodes/edges, workflow chains, Agent Action BOM items, control backlog rows, evidence packets, and report summaries.
- Ensure GitLab manual gates are rendered as approval evidence only when the pipeline semantics support that claim; unresolved/dynamic rules must remain unknown or report-only.
- Add GitLab-specific reason codes for deploy/write/release/package publish/database/IaC actions while reusing platform-neutral action classes.

Repo paths:
- `core/detect/workflowcap/analyze.go`
- `core/aggregate/inventory/privileges.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/risk/action_paths.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/aggregate/scanquality/scanquality.go`
- `schemas/v1`

Run commands:
- `go test ./core/detect/workflowcap ./core/aggregate/inventory ./core/aggregate/privilegebudget ./core/risk ./core/report ./core/aggregate/controlbacklog ./core/aggregate/scanquality -count=1`
- `make test-contracts`
- `make test-scenarios`

Test requirements:
- Unit tests for GitLab capability projection into repo write, deploy write, release write, package publish, secret access, manual approval, and unresolved include quality signals.
- Contract tests for Agent Action BOM, risk report, report summary, control graph, and evidence bundle fields that include GitLab platform refs.
- Scenario tests proving GitLab deploy authority ranks and renders beside equivalent GitHub workflow authority.

Matrix wiring:
- Fast lane: focused workflowcap, inventory, risk, BOM, and scan quality tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixture comparing GitHub and GitLab authority parity.
- Cross-platform lane: stable GitLab path refs and include refs across OS path separators.
- Risk lane: hardening tests for unresolved includes, ambiguous manual gates, and secret refs.

Acceptance criteria:
- GitLab CI authority contributes to action paths, privilege budget, BOM, control backlog, graph, and scan quality.
- GitLab approval/manual gate evidence is not overstated when rules/includes are dynamic or unresolved.
- GitLab action paths have stable IDs, reason codes, target classes, and evidence refs.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added GitLab CI/CD workflow authority to action paths, privilege budget, Agent Action BOM, control backlog, graph, evidence packets, and scan quality summaries.
Semver marker override: [semver:minor]
Contract/API impact: Additive platform-neutral and GitLab-specific CI authority fields in public report and schema outputs.
Versioning/migration impact: Existing outputs remain valid; regenerated outputs may include new GitLab-backed paths.
Architecture constraints: Aggregation owns privilege rollups; risk owns action-path classification; report layers render only projected fields.
ADR required: no
TDD first failing test(s): Add failing parity fixtures that assert GitLab deploy/write authority appears in BOM and risk output before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Ambiguous GitLab authority cannot be rendered as verified approval or enforcement; it remains unknown/report-only with closure guidance.

### Story 1.3: Add Azure DevOps Pipeline Parser, Template Resolver, And Detector Findings

Priority: P0
Recommendation coverage: 38

Tasks:
- Add an Azure DevOps parser for `azure-pipelines.yml`, `azure-pipelines.yaml`, `.azure/pipelines/*.yml`, and safe local templates referenced from pipeline YAML.
- Model top-level `trigger`, `pr`, `resources`, `variables`, `variableGroups`, `stages`, `jobs`, `deployment` jobs, `steps`, `pool`, `environment`, `strategy`, templates, task refs, script/bash/pwsh/cmd steps, and package/release/deploy operations.
- Resolve local templates only when they stay inside the scan root, are regular files, and do not require repository/resource/provider access. Mark remote repository templates and dynamic expressions as unresolved local evidence gaps.
- Extract service connection hints from task inputs and environment variables, variable group names, agent pools, protected environment names, approval/check hints, deployment jobs, secret refs by name only, AI agent invocations, MCP/tool invocation, and cloud/deploy/package operations.
- Emit CI agent findings with `ci_platform=azure_devops`, parser confidence, template resolution status, stage/job/deployment evidence, and no raw secret values.

Repo paths:
- `core/detect/ciagent/detector.go`
- `core/detect/ciagent/detector_test.go`
- `core/detect/workflowcap/analyze.go`
- new package under `core/detect` for Azure pipeline parsing if needed
- `testinfra/contracts`
- `scenarios/wrkr`

Run commands:
- `go test ./core/detect/ciagent ./core/detect/workflowcap -count=1`
- `make test-contracts`
- `scripts/validate_scenarios.sh`

Test requirements:
- Unit tests for basic pipeline, multi-stage pipeline, variable groups, service connections, deployment jobs, protected environments, agent pools, local templates, remote templates, task inputs, script AI agent execution, MCP invocation, malformed YAML, and unsafe template paths.
- Golden finding tests proving stable platform evidence and no raw secret value serialization.
- Scenario fixture for Azure DevOps pipeline with service connection deploy authority, variable group secret refs, environment approval hint, headless agent execution, and template usage.

Matrix wiring:
- Fast lane: focused Azure parser and ciagent detector tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario validation plus Azure pipeline fixture coverage.
- Cross-platform lane: Windows path normalization, CRLF YAML, and local template path safety.
- Risk lane: `make test-hardening` for unsafe templates, malformed YAML, secret-looking payloads, remote template refs, and ambiguous approval checks.

Acceptance criteria:
- Azure pipeline YAML produces deterministic CI agent findings when AI/headless/tool/deploy authority is present.
- Service connections, variable groups, deployment jobs, environments, and agent pools appear as structured evidence.
- Local templates are resolved safely and unresolved remote/dynamic templates are explicit evidence gaps.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added first-class Azure DevOps pipeline detection for local pipelines, safe local templates, stages, jobs, service connections, variable groups, environments, approvals/check hints, agent pools, deployment jobs, secrets by reference, AI agent execution, and MCP/tool invocation.
Semver marker override: [semver:minor]
Contract/API impact: Additive detector evidence, workflow capability fields, scenario fixtures, and schemas for `azure_devops` platform output.
Versioning/migration impact: Existing GitHub/Jenkins findings remain unchanged; downstream consumers should tolerate the new CI platform enum.
Architecture constraints: Detection owns Azure YAML parsing; workflow capability projection consumes normalized parser facts; no remote template resolution.
ADR required: no
TDD first failing test(s): Add failing Azure parser fixtures for service connections, variable groups, deployment jobs, and unsafe templates before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Missing, dynamic, or remote templates produce deterministic unresolved evidence states instead of silently dropping deployment authority.

### Story 1.4: Wire Azure Authority Into Workflow Capabilities, Risk, Privilege Budget, BOM, And Scan Quality

Priority: P0
Recommendation coverage: 38

Tasks:
- Extend workflow capability projection with Azure DevOps stage/job/deployment, environment, service connection, variable group, agent pool, approval/check hint, template resolution, secret ref, AI agent execution, MCP/tool invocation, and release/deploy/package fields.
- Map Azure service connections and variable groups into credential provenance, credential authority, authority bindings, privilege budget, action classes, target classes, and standing/JIT provenance where evidence supports the classification.
- Add Azure platform refs to Control Path Graph nodes/edges, workflow chains, Agent Action BOM items, control backlog rows, evidence packets, and report summaries.
- Treat Azure approvals/checks as control evidence only when local/exported evidence supports that claim. Environment names or comments alone should not become verified approval evidence.
- Add Azure-specific reason codes while preserving platform-neutral action classes and report wording.

Repo paths:
- `core/detect/workflowcap/analyze.go`
- `core/aggregate/inventory/privileges.go`
- `core/aggregate/privilegebudget/budget.go`
- `core/risk/action_paths.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/aggregate/scanquality/scanquality.go`
- `schemas/v1`

Run commands:
- `go test ./core/detect/workflowcap ./core/aggregate/inventory ./core/aggregate/privilegebudget ./core/risk ./core/report ./core/aggregate/controlbacklog ./core/aggregate/scanquality -count=1`
- `make test-contracts`
- `make test-scenarios`

Test requirements:
- Unit tests for Azure service connection authority, variable group secret refs, deployment environment target class, agent pool evidence, package/release/deploy actions, and unresolved template quality signals.
- Contract tests for Agent Action BOM, risk report, report summary, control graph, privilege budget, and evidence bundle fields that include Azure platform refs.
- Scenario tests proving Azure deploy authority ranks and renders beside equivalent GitHub/GitLab workflow authority.

Matrix wiring:
- Fast lane: focused workflowcap, inventory, privilege budget, risk, BOM, and scan quality tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixture comparing Azure authority to GitHub/GitLab authority.
- Cross-platform lane: stable Azure template refs and path IDs across OS path separators.
- Risk lane: hardening tests for unresolved templates, ambiguous approval hints, secret refs, and service connection overclaiming.

Acceptance criteria:
- Azure pipeline authority contributes to action paths, privilege budget, BOM, control backlog, graph, and scan quality.
- Azure service connections and variable groups are visible without exposing raw values.
- Azure approvals/checks are labeled by evidence strength and do not imply enforcement without supporting evidence.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added Azure DevOps pipeline authority to action paths, privilege budget, Agent Action BOM, control backlog, graph, evidence packets, and scan quality summaries.
Semver marker override: [semver:minor]
Contract/API impact: Additive platform-neutral and Azure-specific CI authority fields in public report and schema outputs.
Versioning/migration impact: Existing outputs remain valid; regenerated outputs may include new Azure-backed paths.
Architecture constraints: Aggregation owns privilege rollups; risk owns action-path classification; report layers render only projected fields.
ADR required: no
TDD first failing test(s): Add failing Azure authority fixtures that assert service connections and deployment jobs appear in BOM and risk output before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Azure approval/check hints without corroborating evidence remain declared/unknown and cannot become enforcement-capable claims.

## Epic 2: Runtime Proof, Redaction, And Portable Artifacts

Objective: turn local coding-agent sessions and evidence artifacts into safe, shareable, proof-linked runtime context.
Traceability: Recommendations 39, 41, 42, 43, and 44.

### Story 2.1: Add Coding-Agent Session Ingest Providers And Normalized Session Model

Priority: P0
Recommendation coverage: 39

Tasks:
- Add a normalized session model for provider, session ID, run ID, repo, workflow, PR/MR refs, author/reviewer refs, tool, prompt/ref, response/ref, changed files, commands/actions, file writes, approvals, policy decisions, proof refs, graph refs, outcome, timestamps, redaction hints, and source artifact refs.
- Add provider-specific readers behind the ingest boundary for local Codex-style artifacts, Claude Code sessions, Cursor sessions, Copilot coding-agent/session exports, Gait traces, and an `unknown` future-runtime adapter.
- Keep provider readers isolated under `core/ingest` or new subpackages under `core` so risk/report layers consume only normalized session records.
- Add deterministic session IDs from stable provider/repo/run/session keys, with collision handling that does not expose raw prompt content.
- Add schema validation, no-secret serialization checks, and redaction hint propagation for prompt, transcript, command, changed-file, author, reviewer, provider URL, credential subject, proof ref, and graph ref fields.

Repo paths:
- `core/ingest/ingest.go`
- `core/cli/ingest.go`
- `core/evidence/evidence.go`
- `core/report/redaction.go`
- `schemas/v1/evidence`
- new packages under `core` for session readers if needed
- `testinfra/contracts`

Run commands:
- `go test ./core/ingest ./core/cli ./core/evidence ./core/report -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- Unit tests for each provider reader using fake local artifacts and for normalized ID stability, timestamp parsing, missing optional fields, malformed inputs, provider autodetect, unknown provider fallback, and redaction hint propagation.
- Negative tests rejecting raw-secret-looking payloads, unsupported schema versions, unsafe file paths, binary payloads, and provider artifacts that try to escape the scan/output root.
- Contract tests for normalized session schema and CLI ingest JSON envelope.

Matrix wiring:
- Fast lane: focused session reader and ingest CLI tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixture with at least one Codex-style session and one Gait trace.
- Cross-platform lane: path normalization and timestamp stability for provider artifacts.
- Risk lane: `make test-hardening` and `make test-chaos` for malformed, partial, conflicting, or secret-bearing session artifacts.

Acceptance criteria:
- `wrkr ingest` can load local session artifacts without network access and write normalized managed artifacts.
- Provider-specific fields are normalized before risk/report/evidence code consumes them.
- Prompt/transcript content is never required for deterministic joins; refs/digests/redacted snippets are enough.
- Invalid or unsafe input fails with stable error class and exit code.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added deterministic local coding-agent session ingest for Codex-style agents, Claude Code, Cursor, Copilot, Gait traces, and future runtime exports.
Semver marker override: [semver:minor]
Contract/API impact: Additive ingest CLI behavior, session schemas, normalized runtime evidence fields, and redaction selectors.
Versioning/migration impact: Existing runtime evidence and evidence-packet input formats remain compatible.
Architecture constraints: Ingest owns provider readers and normalization; risk/report consume normalized records only.
ADR required: yes
TDD first failing test(s): Add failing provider-reader fixtures and normalized session schema tests before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Partial or malformed session artifacts produce explicit invalid/unmatched/unknown states and never become proof of safe execution.

### Story 2.2: Correlate Session Evidence Into Runtime Evidence, Graph, Evidence Packets, And BOM Coverage

Priority: P0
Recommendation coverage: 39

Tasks:
- Convert normalized session records into runtime evidence records and evidence packet refs with stable correlation keys for path ID, agent ID, repo, workflow, PR/MR, changed files, action class, target, proof refs, graph refs, and outcome evidence.
- Add graph/session nodes and refs where existing Control Path Graph and workflow chain contracts can represent runtime execution without breaking v1 consumers.
- Extend Agent Action BOM coverage to show static authority, observed session actions, proof status, missing outcome evidence, changed files, runtime evidence state, and evidence packet status together.
- Add Gait coverage/report joins for session evidence so control-capable or approval-capable boundaries are visible only when evidence supports them.
- Add deterministic summary counts for session records matched/unmatched/stale/conflicting, runtime-proven action paths, missing outcome evidence, and session evidence gaps.

Repo paths:
- `core/ingest/ingest.go`
- `core/ingest/evidence_packets.go`
- `core/report/gait_coverage.go`
- `core/report/agent_action_bom.go`
- `core/report/render_markdown.go`
- `core/evidence/evidence.go`
- `core/cli/report_artifacts.go`
- `core/aggregate/attackpath/graph.go`
- `schemas/v1`

Run commands:
- `go test ./core/ingest ./core/report ./core/evidence ./core/cli ./core/aggregate/attackpath -count=1`
- `make test-contracts`
- `make test-scenarios`

Test requirements:
- Unit tests for session-to-runtime conversion, session-to-evidence-packet refs, graph refs, BOM coverage, stale/conflict handling, changed-file joins, and missing outcome evidence.
- Contract/golden tests for report JSON, markdown, evidence bundle, Agent Action BOM, and graph outputs with session evidence.
- Scenario tests with static CI authority plus a matching session artifact and a conflicting/unmatched session artifact.

Matrix wiring:
- Fast lane: focused ingest correlation, graph, report, and evidence tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixture for matched/unmatched/conflicting session evidence.
- Cross-platform lane: stable session refs, changed-file refs, and graph IDs across path separators.
- Risk lane: hardening/chaos tests for stale session evidence, conflicting session outcomes, corrupt proof refs, and redaction misses.

Acceptance criteria:
- Agent Action BOM items can distinguish "could happen" from "observed happened" without hiding missing proof/outcome evidence.
- Session evidence refs are stable and available in graph, BOM, evidence packet, report, and bundle outputs.
- Unmatched or conflicting session records are visible and do not silently improve readiness.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added runtime session evidence correlation into graph refs, evidence packets, Agent Action BOM coverage, Gait coverage, reports, and evidence bundles.
Semver marker override: [semver:minor]
Contract/API impact: Additive runtime evidence, graph, evidence-packet, BOM, and report fields.
Versioning/migration impact: Existing artifacts remain valid when session evidence is absent.
Architecture constraints: Correlation belongs in ingest/evidence/report boundaries; risk semantics cannot parse raw provider artifacts.
ADR required: no
TDD first failing test(s): Add failing matched/unmatched session correlation fixture before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Stale or conflicting session evidence cannot mark an action path runtime-proven or control-ready.

### Story 2.3: Generate Paired Internal And External Artifacts With A Local-Only Join Map

Priority: P0
Recommendation coverage: 41, 42

Tasks:
- Add report/evidence artifact pairing that writes internal and customer-redacted variants from the same built summary, with deterministic artifact IDs and shared stable redacted joins.
- Define a private join map format that maps internal IDs/labels to redacted IDs/labels for remediation handoff, stores it locally with restrictive permissions, and excludes it from shareable bundles and public manifests.
- Add artifact metadata fields for pair ID, variant kind, share profile, redaction version, selected fields, source artifact refs, private join-map path, and shareability status.
- Ensure `wrkr report`, `wrkr evidence`, `wrkr export`, and any `wrkr assess` workflow use one redaction engine so paired artifacts do not drift.
- Add safety checks that block writing private join maps into shareable output directories or including them in external bundles.

Repo paths:
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `core/report/redaction.go`
- `core/report/redaction_summary.go`
- `core/report/artifacts.go`
- `core/evidence/evidence.go`
- `schemas/v1/evidence`

Run commands:
- `go test ./core/report ./core/evidence ./core/cli -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- Unit tests for paired artifact generation, deterministic pair IDs, join-map content, join-map exclusion, permissions, redaction stability, and artifact metadata.
- Hardening tests for unsafe join-map paths, shareable bundle leaks, duplicate pair IDs, and conflicting redaction profiles.
- Contract tests for internal/external variant metadata and redaction summary fields.

Matrix wiring:
- Fast lane: focused report/evidence artifact pairing tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixture producing paired internal/external reports from one scan.
- Cross-platform lane: artifact path normalization and permissions fallback behavior.
- Risk lane: `make test-hardening` and `make test-chaos` for join-map leakage, unsafe paths, and partial writes.

Acceptance criteria:
- One scan/report can produce internal and external artifacts with matching stable joins.
- The private join map is local-only, permission-restricted where supported, and excluded from shareable bundles.
- External artifacts remain useful for customer sharing while internal artifacts retain remediation detail.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added paired internal and customer-redacted report artifacts with deterministic joins and a local-only private join map.
Semver marker override: [semver:minor]
Contract/API impact: Additive report/evidence artifact metadata and redaction summary fields.
Versioning/migration impact: Existing single-artifact report generation remains available.
Architecture constraints: Report/evidence packaging owns variants; redaction engine owns pseudonyms; no detector or risk logic depends on redacted labels.
ADR required: no
TDD first failing test(s): Add failing paired artifact fixture that asserts join-map exclusion from external bundles before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: A failed external artifact write cannot leave a partial shareable bundle containing the private join map.

### Story 2.4: Extend Customer-Safe Evidence, Prompt, And Provider Redaction Controls

Priority: P0
Recommendation coverage: 42

Tasks:
- Extend redaction field selectors to cover sessions, prompts/transcripts, reviewers, changed files, provider URLs, declarations, evidence packet fields, boundary refs, session IDs, run IDs, PR/MR refs, and action outcome refs.
- Add deterministic pseudonyms that preserve joins across one artifact set while preventing recovery of internal names, URLs, paths, proof refs, graph refs, and credential subjects from external variants.
- Apply redaction consistently to Agent Action BOM, report summary, evidence packets, runtime/session evidence, portable bundle manifests, markdown, CSV, and export pack outputs.
- Add redaction summaries that list selected fields, default fields, pseudonym scope, join-map availability, shareability status, and known unredacted technical fields.
- Add fail-closed tests that reject external/shareable artifacts containing raw prompt text, raw secret-looking values, filesystem roots, private provider URLs, internal repo paths, or unredacted credential subjects.

Repo paths:
- `core/report/redaction.go`
- `core/report/redaction_summary.go`
- `core/report/build.go`
- `core/report/render_markdown.go`
- `core/report/agent_action_bom.go`
- `core/evidence/evidence.go`
- `schemas/v1`
- `testinfra/contracts`

Run commands:
- `go test ./core/report ./core/evidence -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- Unit tests for each new redaction selector, deterministic pseudonym stability, cross-artifact joins, share-profile defaults, and markdown/CSV/report JSON coverage.
- Negative tests for raw prompts, provider URLs, filesystem paths, changed files, credential subjects, proof refs, graph refs, and declaration fields in external artifacts.
- Contract tests for redaction summary schema and share profile metadata.

Matrix wiring:
- Fast lane: focused redaction and report/evidence tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: redacted evidence bundle scenario.
- Cross-platform lane: filesystem path redaction for POSIX and Windows paths.
- Risk lane: `make test-hardening` for redaction misses and secret-looking payload rejection.

Acceptance criteria:
- External/customer-redacted artifacts contain no raw sensitive session, prompt, provider, path, owner, reviewer, credential, proof, graph, or declaration values covered by selected profile fields.
- Joins remain deterministic within an artifact set and are explainable in redaction summaries.
- Internal artifacts remain unredacted unless a share profile requests redaction.

Changelog impact: required
Changelog section: Security
Draft changelog entry: Extended customer-safe redaction to session metadata, prompts, reviewers, changed files, provider URLs, declarations, evidence packet fields, proof refs, graph refs, and credential subjects.
Semver marker override: [semver:minor]
Contract/API impact: Additive redaction selectors, share-profile metadata, and schema fields.
Versioning/migration impact: Existing selectors remain valid; stricter defaults may redact more fields for external profiles.
Architecture constraints: Redaction is a report/evidence/export concern and must not alter source inventory or risk semantics.
ADR required: no
TDD first failing test(s): Add failing external artifact redaction leak tests before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Unknown sensitive field classes in shareable artifacts default to redacted/blocked rather than leaking raw values.

### Story 2.5: Add Portable Evidence Bundle Manifest And Boundary Labels

Priority: P0
Recommendation coverage: 43, 44

Tasks:
- Add a portable artifact manifest that enumerates stable file names, artifact kind, variant kind, schema version, redaction profile, boundary label, proof-chain refs, source privacy metadata, evidence-state summary, generator version, and digest for each included artifact.
- Include meaningful outputs in one exportable bundle: BOM, evidence packets, runtime/session summaries, proof refs, executive summary, control recommendations, backlog CSV, graph refs, workflow chains, internal/external variants, and evidence-state metadata.
- Add `boundary_label` to Agent Action BOM items, graph nodes/edges where useful, evidence packets, runtime/session evidence summaries, report artifacts, export manifests, and markdown sections.
- Derive boundary labels conservatively: detector-only facts default to `discovery_only`, rendered recommendations default to `report_only`, locally ingested approval evidence can be `approval_capable`, and `enforcement_capable` requires explicit Gait/control evidence showing Wrkr observed or owns the execution boundary.
- Add bundle validation that prevents private join maps, raw source payloads, unsafe paths, or unredacted sensitive fields from entering shareable bundles.

Repo paths:
- `core/evidence/evidence.go`
- `core/report/artifacts.go`
- `core/cli/report_artifacts.go`
- `core/cli/export.go`
- `core/report/agent_action_bom.go`
- `core/report/gait_coverage.go`
- `core/report/render_markdown.go`
- `schemas/v1/evidence`
- `schemas/v1`

Run commands:
- `go test ./core/evidence ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-hardening`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- Unit tests for manifest generation, stable file names, artifact digests, schema versions, redaction profile metadata, boundary label derivation, proof refs, source privacy metadata, and shareable bundle validation.
- Contract tests for evidence bundle manifest schema and additive boundary fields in BOM/report/graph/evidence packet outputs.
- Hardening tests for join-map exclusion, unsafe artifact paths, raw source payloads, and boundary overclaiming.

Matrix wiring:
- Fast lane: focused evidence/report/export manifest tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: portable evidence bundle scenario with internal/external variants.
- Cross-platform lane: stable relative bundle paths and digests.
- Risk lane: `make test-hardening` and `make test-chaos` for partial bundles, missing proof chain, corrupt manifest refs, and boundary overclaims.

Acceptance criteria:
- Every bundle has a stable manifest that explains what each artifact is, how it was redacted, which boundary it supports, and which proof/source privacy refs apply.
- Shareable bundles exclude private join maps and unsafe raw payloads.
- Markdown and JSON clearly distinguish discovery, report, approval, and enforcement boundaries.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added portable evidence bundle manifests with stable artifact metadata, redaction profiles, proof-chain refs, source privacy metadata, evidence-state summaries, and boundary labels.
Semver marker override: [semver:minor]
Contract/API impact: Additive evidence bundle, export, BOM, graph, evidence packet, and markdown fields.
Versioning/migration impact: Existing evidence build outputs remain available while new manifests provide richer bundle metadata.
Architecture constraints: Evidence/report/export own packaging and boundary labels; risk can supply evidence states but not overclaim enforcement.
ADR required: yes
TDD first failing test(s): Add failing bundle manifest and boundary-label schema fixtures before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Missing or contradictory boundary evidence defaults to `discovery_only` or `report_only`, never `approval_capable` or `enforcement_capable`.

## Epic 3: Product Workflow And Buyer Reporting

Objective: make Wrkr feel like a repeatable product workflow with low-click buyer jobs and workflow-first reports.
Traceability: Recommendations 40, 45, and 46.

### Story 3.1: Refine Buyer-Facing Agentic SDLC Control Report Around Workflow Chains

Priority: P0
Recommendation coverage: 40

Tasks:
- Reorder report templates so the primary buyer section leads with top workflow chains/action paths, not raw findings.
- Render for each top workflow chain: path type, target class, autonomy tier, authority, blast radius, evidence states, approval path, proof status, runtime/session evidence, recommendation, boundary label, and plain-language explanation.
- Add concise recommendation language that distinguishes missing owner, missing approval, missing proof, standing credential, evidence contradiction, runtime observed, and ready-for-control states.
- Keep raw findings, parser diagnostics, graph refs, proof details, scan quality, and detector details in appendices with stable anchors.
- Add schema and markdown golden coverage for CISO, platform, customer-draft, design-partner, and agent-action-bom templates.

Repo paths:
- `core/report/templates/templates.go`
- `core/report/render_markdown.go`
- `core/report/agent_action_bom.go`
- `core/report/build.go`
- `core/cli/report.go`
- `docs/commands/report.md`
- `schemas/v1/report/report-summary.schema.json`

Run commands:
- `go test ./core/report ./core/cli -count=1`
- `make test-contracts`
- `make test-focused-docs`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- Markdown golden tests for workflow-first report ordering and appendix split.
- JSON contract tests for workflow chain summary, recommendation, evidence states, proof/runtime status, and boundary labels.
- CLI tests for report template selection and focus interactions.

Matrix wiring:
- Fast lane: focused report rendering and CLI tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: buyer report scenario with top workflow chains and evidence gaps.
- Cross-platform lane: stable markdown anchors and artifact paths.
- Risk lane: hardening tests for overclaiming approval/enforcement and missing evidence wording.

Acceptance criteria:
- Buyer-facing report first page answers what workflow can act, what authority it has, what proof exists, what is unresolved, and what to do next.
- Raw findings no longer dominate the primary buyer flow.
- JSON and markdown present the same recommendation and evidence semantics.

Changelog impact: required
Changelog section: Changed
Draft changelog entry: Refined buyer-facing reports to lead with agentic SDLC workflow chains, authority, evidence state, proof status, runtime evidence, boundary labels, and recommendations before raw findings.
Semver marker override: [semver:minor]
Contract/API impact: Additive and reordered report JSON/markdown presentation fields; existing raw findings remain available.
Versioning/migration impact: Report consumers should rely on field names rather than markdown ordering.
Architecture constraints: Report templates present projected facts and must not recompute detector/risk semantics.
ADR required: no
TDD first failing test(s): Add workflow-first markdown golden and report summary schema tests before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Missing workflow-chain evidence renders a clear unknown/gap state and does not fall back to misleading raw-finding claims.

### Story 3.2: Add Repeatable Assessment Workflow Command Or Contracted Sequence

Priority: P0
Recommendation coverage: 45

Tasks:
- Add `wrkr assess` or an explicitly documented equivalent sequence that runs import/connect target resolution, scan, Agent Action BOM/report generation, optional runtime/evidence ingest, portable pack export, optional action assignment payloads, and optional drift review.
- Produce one deterministic output directory with a manifest that lists state, proof chain, report artifacts, evidence bundle, export pack, backlog CSV, private join map if generated, redacted variants, drift summary, and command metadata.
- Support stable defaults for `--json`, `--quiet`, `--explain`, `--state`, `--output-dir`, `--share-profile`, `--focus`, `--baseline`, `--runtime-input`, and `--frameworks` or an equivalent that matches existing CLI patterns.
- Reuse existing command internals instead of duplicating scan/report/evidence/export/regress logic. Ensure partial failure behavior and exit codes match the failing stage.
- Add docs that show a complete local-first assessment workflow and a re-run for drift using fake data.

Repo paths:
- `core/cli/scan.go`
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `core/cli/export.go`
- `core/cli/root.go`
- `core/evidence/evidence.go`
- `core/report/artifacts.go`
- `core/regress`
- `docs/commands`
- `schemas/v1`

Run commands:
- `go test ./core/cli ./core/evidence ./core/report ./core/regress -count=1`
- `make test-contracts`
- `make test-focused-docs`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- CLI contract tests for assess success, missing target, invalid output dir, optional runtime input, optional baseline, redacted bundle, quiet/json/explain modes, and stage-specific failures.
- Determinism tests proving two runs with fixed input and generated-at control produce stable manifest and artifact names.
- Docs parity tests for the command or documented sequence.

Matrix wiring:
- Fast lane: focused CLI orchestration and manifest tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: end-to-end assessment scenario.
- Cross-platform lane: output directory paths, artifact names, and manifest refs.
- Risk lane: hardening tests for unsafe output dirs, partial writes, private join-map leaks, and exit-code mapping.

Acceptance criteria:
- A user can run one documented workflow to get scan state, BOM/report, evidence pack, recommendations/backlog, export bundle, and optional drift summary.
- The workflow writes one output directory manifest with stable relative refs.
- Existing commands remain usable and behavior-compatible.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added a repeatable assessment workflow that connects scan, report, optional evidence ingest, export pack, action assignment payloads, and drift review into one deterministic output directory and manifest.
Semver marker override: [semver:minor]
Contract/API impact: New CLI command or contracted documented workflow plus additive assessment manifest schema.
Versioning/migration impact: Existing `scan`, `ingest`, `report`, `evidence`, `export`, and `regress` commands remain compatible.
Architecture constraints: CLI orchestrates existing boundaries; it must not fork detector, risk, evidence, export, or regress semantics.
ADR required: no
TDD first failing test(s): Add failing assess CLI contract tests and manifest golden before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: A stage failure returns that stage's stable exit code and leaves either no manifest or an explicit partial manifest marked non-shareable.

### Story 3.3: Add Low-Click Review Workflow Presets And Filters

Priority: P1
Recommendation coverage: 46

Tasks:
- Add named focus presets for common buyer jobs: `bom`, `release`, `write-deploy`, `approval-evidence-unknown`, `owner-evidence-unknown`, `evidence-gaps`, `contradictions`, `drift-review`, and `recommendations`.
- Wire presets into `wrkr report` and/or `wrkr assess` using additive `--focus <preset>` behavior while preserving existing `--focus-path` semantics for exact Agent Action BOM paths.
- Define each preset as deterministic filters over existing fields: path type, target class, authority, action class, evidence state, proof status, owner state, approval state, contradiction state, drift state, and recommendation.
- Add preset-specific template titles, summary counts, empty states, and recommended next actions without hiding appendix evidence.
- Update control backlog and govern-first sorting so presets return stable, actionable top items.

Repo paths:
- `core/cli/report.go`
- `core/report/templates/templates.go`
- `core/report/render_markdown.go`
- `core/report/agent_action_bom.go`
- `core/aggregate/controlbacklog/controlbacklog.go`
- `core/risk/govern_first.go`
- `docs/commands/report.md`
- `docs/commands`
- `schemas/v1`

Run commands:
- `go test ./core/cli ./core/report ./core/aggregate/controlbacklog ./core/risk -count=1`
- `make test-contracts`
- `make test-focused-docs`

Test requirements:
- Unit tests for each preset filter, sorting, empty state, summary count, and appendix retention.
- CLI tests for valid preset, unknown preset, preset plus focus path, preset plus share profile, and preset plus baseline.
- Markdown golden tests for low-click buyer outputs.

Matrix wiring:
- Fast lane: focused preset filter and report tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixture covering every preset at least once.
- Cross-platform lane: stable preset output ordering and artifact paths.
- Risk lane: hardening tests for unknown presets, context-only paths, and evidence-gap overclaiming.

Acceptance criteria:
- Users can generate common buyer views without knowing detector internals.
- Presets are deterministic, documented, schema-backed where public, and preserve appendix traceability.
- Empty states explain absence versus unknown evidence without implying safety.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added low-click report focus presets for BOM generation, release-adjacent AI paths, write/deploy reach, owner and approval evidence gaps, evidence gaps, contradictions, drift review, and recommendations.
Semver marker override: [semver:minor]
Contract/API impact: Additive CLI/report preset enum, report summary fields, and docs.
Versioning/migration impact: Existing report templates and `--focus-path` behavior remain available.
Architecture constraints: Presets filter projected report/risk fields; they must not bypass risk or evidence semantics.
ADR required: no
TDD first failing test(s): Add failing preset filter tests and CLI unknown-preset test before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: A preset with incomplete evidence renders evidence gaps and unknown states instead of excluding uncertain paths.

## Epic 4: Drift Review Infrastructure

Objective: make re-runs and comparisons first-class so Wrkr becomes recurring infrastructure.
Traceability: Recommendation 47.

### Story 4.1: Add First-Class Drift Category Model And Regress Output

Priority: P0
Recommendation coverage: 47

Tasks:
- Add drift categories for `new_write_paths`, `new_deploy_paths`, `new_credentials`, `new_unknown_approval_evidence`, `resolved_gaps`, `worsened_paths`, `new_contradictions`, `paths_ready_for_control`, removed paths, changed authority, changed evidence, and changed target class.
- Compare current and baseline action paths using stable path IDs and fallback normalized keys for platform, repo, workflow, job/stage, action class, credential subject, target class, evidence state, boundary label, and proof/session refs.
- Add severity/priority rules for each drift category, including fail-closed handling when baseline/current schemas differ or key fields are missing.
- Extend regress JSON and schemas with category summaries, examples, affected path refs, evidence refs, and recommended next actions.
- Preserve existing regress behavior for inventory drift, approval drift, secret-bearing workflow drift, critical attack path drift, and control path drift.

Repo paths:
- `core/regress`
- `core/state/state.go`
- `core/risk/action_paths.go`
- `core/aggregate/inventory/privileges.go`
- `schemas/v1/regress`
- `testinfra/contracts`

Run commands:
- `go test ./core/regress ./core/state ./core/risk ./core/aggregate/inventory -count=1`
- `make test-contracts`
- `make test-hardening`

Test requirements:
- Unit tests for every drift category, stable key matching, added/removed/changed path classification, schema version mismatch, missing baseline fields, and deterministic sorting.
- Golden regress fixtures for new write path, new deploy path, credential expansion, approval evidence becoming unknown, resolved gap, worsened path, contradiction, and ready-for-control path.
- Contract tests for regress result schema additions.

Matrix wiring:
- Fast lane: focused regress drift category tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario fixture with baseline/current state pairs.
- Cross-platform lane: path ID and normalized key stability across path separators.
- Risk lane: hardening tests for malformed baselines, schema mismatches, duplicate path IDs, and missing evidence fields.

Acceptance criteria:
- Regress output names new/removed/changed authority and evidence movement in buyer-understandable categories.
- Existing drift outputs remain compatible and are not silently removed.
- Missing or incompatible drift inputs fail closed with actionable errors or explicit unknown states.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added first-class drift review categories for new write/deploy paths, credentials, approval evidence gaps, resolved gaps, worsened paths, contradictions, and paths ready for control.
Semver marker override: [semver:minor]
Contract/API impact: Additive regress JSON/schema fields and drift reason codes.
Versioning/migration impact: Existing regress consumers remain valid; new drift categories are optional/additive.
Architecture constraints: Regress owns comparison; risk supplies stable action-path fields and evidence states.
ADR required: no
TDD first failing test(s): Add failing baseline/current drift category fixtures before implementation.
Cost/perf impact: medium
Chaos/failure hypothesis: Schema mismatch or missing comparison keys cannot produce a clean no-drift result; it yields explicit unknown/fail-closed drift evidence.

### Story 4.2: Add Drift Review Report, Preset, And Paths-Ready-For-Control Workflow

Priority: P0
Recommendation coverage: 47, 45, 46

Tasks:
- Render drift category summaries in report markdown/JSON, Agent Action BOM primary view, evidence bundles, assessment manifests, and low-click `drift-review` focus preset.
- Add `paths_ready_for_control` output that identifies paths whose evidence moved from unknown/missing to verified/approval-capable/control-ready without implying Gait enforcement unless boundary labels support it.
- Add recommendations for new write/deploy paths, new credentials, unknown approval evidence, worsened evidence, contradictions, and resolved gaps.
- Allow `wrkr report --baseline <baseline-path>` and/or `wrkr assess --baseline <baseline-path>` to surface drift review summaries from existing regress comparison.
- Ensure drift summaries include stable refs back to current path, baseline path when available, proof/session/evidence refs, and artifact boundary labels.

Repo paths:
- `core/cli/report.go`
- `core/cli/report_artifacts.go`
- `core/report/build.go`
- `core/report/render_markdown.go`
- `core/report/agent_action_bom.go`
- `core/report/artifacts.go`
- `core/regress`
- `schemas/v1`
- `docs/commands/report.md`
- `docs/commands/regress.md`

Run commands:
- `go test ./core/cli ./core/report ./core/regress -count=1`
- `make test-contracts`
- `make test-focused-docs`
- `scripts/run_v1_acceptance.sh --mode=local`

Test requirements:
- Report/CLI tests for baseline supplied, missing baseline, malformed baseline, drift-review preset, paths-ready-for-control view, and markdown/JSON consistency.
- Golden markdown tests for drift summary ordering and recommendations.
- Contract tests for assessment/report manifest drift metadata.

Matrix wiring:
- Fast lane: focused report/regress CLI tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: assessment re-run scenario with baseline/current drift artifacts.
- Cross-platform lane: stable baseline/current artifact refs.
- Risk lane: hardening tests for invalid baselines, missing current paths, and boundary overclaiming for ready-for-control paths.

Acceptance criteria:
- Reports and assessment outputs make drift categories visible without requiring users to inspect raw regress JSON.
- Paths ready for control are labeled as report/approval/enforcement capable only when evidence supports the boundary.
- New/worsened/resolved drift items include actionable next steps and refs.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Added drift review reporting, a low-click drift preset, and paths-ready-for-control summaries across report, assessment, evidence, and Agent Action BOM outputs.
Semver marker override: [semver:minor]
Contract/API impact: Additive report/evidence/assessment fields and CLI behavior for baseline-backed drift summaries.
Versioning/migration impact: Existing report baseline behavior remains compatible; new drift sections appear when baseline data is supplied.
Architecture constraints: Report renders regress output; it must not perform independent drift classification.
ADR required: no
TDD first failing test(s): Add failing drift-review report golden and CLI baseline tests before implementation.
Cost/perf impact: low
Chaos/failure hypothesis: Missing or malformed baselines cannot produce misleading "no drift"; they fail or render explicit unavailable drift status.

## Epic 5: Contracts, Scenarios, Docs, And Release Readiness

Objective: lock Sprint 4 behavior into public schemas, executable scenarios, docs, changelog, and release validation lanes.
Traceability: All Sprint 4 recommendations.

### Story 5.1: Update Schemas, Scenarios, Docs, Changelog, And Acceptance Coverage

Priority: P0
Recommendation coverage: 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47

Tasks:
- Update all touched v1 schemas with GitLab CI, Azure DevOps, platform-neutral CI authority, session ingest, runtime/session evidence, artifact pairing, join-map metadata, redaction fields, portable bundle manifest, boundary labels, assessment manifests, focus presets, and drift review categories.
- Add deterministic schema fixtures and contract tests for old and new report/evidence/export/regress shapes.
- Add scenarios for GitLab CI deploy/release authority, Azure service connection deployment, coding-agent session ingest, internal/external redacted artifact pair, portable bundle, boundary labels, buyer workflow-first report, assess workflow, low-click presets, and drift review.
- Update docs and examples for scan, ingest, report, export, evidence, regress, action, assess, contracts/schemas, and detection coverage.
- Update changelog with operator-facing entries and semver marker guidance.
- Add docs parity checks for new flags, examples, report behavior, evidence bundle manifest, redaction selector docs, and drift review examples.

Repo paths:
- `schemas/v1`
- `testinfra/contracts`
- `internal/acceptance`
- `internal/scenarios/coverage_map.json`
- `scenarios/wrkr`
- `README.md`
- `docs/commands/scan.md`
- `docs/commands/ingest.md`
- `docs/commands/report.md`
- `docs/commands/export.md`
- `docs/commands/evidence.md`
- `docs/commands/regress.md`
- `docs/commands/action.md`
- `docs/commands`
- `docs/trust/contracts-and-schemas.md`
- `docs/trust/detection-coverage-matrix.md`
- `schemas/v1/README.md`
- `CHANGELOG.md`

Run commands:
- `make lint-fast`
- `make test-fast`
- `make test-contracts`
- `scripts/validate_scenarios.sh`
- `make test-scenarios`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- `scripts/run_v1_acceptance.sh --mode=local`
- `make test-focused-docs`
- `make prepush-full`

Test requirements:
- Contract tests for every new/changed schema and backwards-compatible fixture.
- Scenario tests mapped in `internal/scenarios/coverage_map.json`.
- Docs-vs-CLI parity tests for new flags, examples, templates, focus presets, redaction fields, and assessment sequence.
- Release acceptance run before advertising Sprint 4 behavior.

Matrix wiring:
- Fast lane: schema/docs focused tests and targeted unit tests.
- Core CI lane: `make lint-fast`, `make test-fast`, `make test-contracts`.
- Acceptance lane: scenario validation, scenario tests, and local v1 acceptance.
- Cross-platform lane: Windows smoke for schemas, fixtures, CI pipeline parsing, session artifacts, report artifacts, bundle paths, and drift baselines.
- Risk lane: `make test-hardening`, `make test-chaos`, and `make test-perf` when implementation touches parser safety, artifact safety, redaction, boundary labels, or drift scale.
- Release/UAT lane: `make test-release-smoke` and `scripts/run_v1_acceptance.sh --mode=release`.

Acceptance criteria:
- Every Sprint 4 public contract has a schema and deterministic fixture.
- Every recommendation maps to at least one scenario or contract test.
- Docs explain GitLab/Azure coverage, session ingest, paired artifacts, redaction, portable bundle manifests, boundary labels, assess workflow, low-click presets, and drift review with fake data only.
- Changelog entries are present before release.

Changelog impact: required
Changelog section: Added
Draft changelog entry: Documented Sprint 4 GitLab/Azure CI coverage, coding-agent session ingest, paired redacted artifacts, portable evidence bundles, boundary labels, repeatable assessment workflows, low-click presets, and drift review contracts with schema and scenario coverage.
Semver marker override: [semver:minor]
Contract/API impact: Broad additive v1 schema, scenario, docs, CLI/report/export/evidence/regress contract updates.
Versioning/migration impact: No field removals; additive fields require schema consumers to tolerate new enums and objects.
Architecture constraints: Docs and schemas must match executable behavior in the same PRs.
ADR required: no
TDD first failing test(s): Add schema/fixture/docs parity failures before implementation PRs update behavior.
Cost/perf impact: low
Chaos/failure hypothesis: Contract drift is caught by docs, schema, scenario, and acceptance lanes before release.

## Definition of Done

- All Sprint 4 recommendation rows in the traceability table map to shipped stories, tests, schemas, docs, and changelog entries.
- GitLab CI/CD and Azure DevOps coverage use structured YAML parsing, safe local include/template resolution, stable reason codes, deterministic sorting, and no raw secret extraction.
- CI platform authority feeds workflow capabilities, inventory privileges, privilege budget, action paths, Control Path Graph, Agent Action BOM, control backlog, scan quality, evidence packets, reports, and drift summaries.
- Coding-agent session ingest is local-file based, provider-specific only at the ingest boundary, normalized into Wrkr runtime/session evidence, redaction-aware, proof-linked, and deterministic.
- Internal/external paired artifacts are generated from the same scan/report graph, with a local-only private join map excluded from shareable bundles.
- Redaction profiles cover session, prompt, evidence packet, author, reviewer, repo path, changed file, proof ref, graph ref, credential subject, provider URL, declaration, and boundary fields.
- Portable evidence bundles include a stable manifest with artifact kinds, file names, schema versions, redaction profile, proof-chain refs, source privacy metadata, boundary labels, evidence-state summaries, and digests.
- Every meaningful path/artifact claim carries a boundary label and does not imply enforcement unless supporting evidence exists.
- Buyer-facing reports lead with workflow chains, authority, evidence states, proof/runtime status, recommendations, and plain-language explanations.
- `wrkr assess` or an equivalent documented assessment workflow produces one deterministic output directory and manifest across scan, report, optional ingest, export pack, recommendations, and drift review.
- Low-click focus presets are deterministic, documented, schema-backed where public, and preserve appendix traceability.
- Drift review exposes new/removed/changed authority, changed evidence, changed target class, new credentials, new unknown approval evidence, resolved gaps, worsened paths, new contradictions, and paths ready for control.
- No scan/risk/proof/report/ingest path calls an LLM or defaults to network access.
- No raw secret values are extracted, logged, serialized, or committed in fixtures.
- Required implementation gates are green: `make lint-fast`, `make test-fast`, `make test-contracts`, scenario validation, local v1 acceptance, and focused docs checks.
- Risk-bearing implementation PRs also run hardening, chaos, performance, or `make prepush-full` lanes as specified by story matrix wiring.

# PLAN NEXT: Govern-First Control-Path Governance

Date: 2026-04-22

Source of truth:
- User-provided PM change list after the large-scale organization scan.
- `AGENTS.md` repository instructions.
- `product/wrkr.md`.
- `product/dev_guides.md`.
- `product/architecture_guides.md`.

Scope:
- Wrkr only.
- Planning only. No implementation is included in this plan.
- Convert Wrkr from broad scanner posture toward AI and automation control-path governance for engineering environments.
- Preserve deterministic, offline-first, file-based evidence behavior and existing CLI/exit-code contracts.

## Global Decisions (Locked)

- Product position: Wrkr is "governance and proof for unknown AI and automation control paths across engineering environments."
- Default customer outcome: answer "What should security review first?" through a short prioritized control backlog.
- Product umbrella term: `control_surface`.
- Control surface subtypes: `ai_agent`, `coding_assistant_config`, `mcp_server_tool`, `ci_automation`, `release_automation`, `dependency_agent_surface`, `secret_bearing_workflow`, `non_human_identity`.
- Primary Wrkr signal is separate from supporting security signal in all new governance outputs.
- Raw findings remain available as machine-readable evidence but are not the default human/operator decision surface.
- Default scan mode becomes governance-oriented while keeping existing stable JSON keys additive and backward compatible.
- Secret semantics classify references, value evidence, scope gaps, owner gaps, rotation evidence gaps, and write-capable usage separately.
- No scan/risk/proof path may call an LLM or exfiltrate scan data by default.
- Structured parsing remains mandatory for structured configs; regex-only parsing is allowed only for unstructured text or a narrowly bounded reference detector.
- Enterprise integrations such as Jira, ServiceNow, GitHub Issues, Slack, or Teams must default to local dry-run/export artifacts unless explicit opt-in network execution is provided.
- Contract/runtime waves must land before docs/report/ticket polish waves.

## Current Baseline (Observed)

- `core/model/finding.go` is the canonical detector/policy finding contract. It has severity, remediation, permissions, evidence, and parse error metadata, but no native control backlog fields, action taxonomy, evidence quality, signal class, confidence level, control-path type, SLA, or explicit secret-reference subtype.
- `core/cli/scan.go` emits `findings`, `ranked_findings`, `top_findings`, `action_paths`, `inventory`, `privilege_budget`, profile, posture score, and compliance summary. It does not expose `--mode quick|governance|deep`.
- `core/aggregate/inventory` already models tools, agents, owner metadata, approval summary, security visibility summary, privilege budget, and agent privilege map. Security visibility currently has `approved`, `known_unapproved`, and `unknown_to_security`.
- `core/owners` supports CODEOWNERS and deterministic repo fallback ownership. It does not yet support service catalog, Backstage, GitHub teams, repo topics, explicit custom owner mappings, or conflicting owner resolution.
- `core/detect/workflowcap` already parses GitHub workflow YAML and derives write/deploy/db/IaC capabilities, headless execution, secret access, and gate/proof hints.
- `core/detect/secrets` redacts values and detects env files plus workflow/Jenkins secret references, but current finding type is still generic `secret_presence`.
- `core/regress` already supports deterministic baselines, drift exit code `5`, permission expansion, revoked-tool reappearance, and critical attack-path drift. Drift reasons do not yet map to governance-first categories like new secret-bearing workflow or approval expired.
- `core/report` supports `exec`, `operator`, `audit`, and `public` templates with deterministic Markdown/PDF generation. It does not yet provide native CISO/AppSec/platform/customer-draft bundles led by a control backlog.
- `core/export` supports inventory and appendix export. It does not yet export tickets.
- Scenario, e2e, acceptance, contract, hardening, chaos, and perf gates already exist and must be wired into implementation stories.
- `PLAN_NEXT.md` did not exist before this planning run.

## Exit Criteria

- `wrkr scan --json` includes a deterministic `control_backlog` led by unique Wrkr signals and keeps existing raw finding surfaces available for compatibility.
- `wrkr scan` defaults to governance mode, with explicit `--mode quick`, `--mode governance`, and `--mode deep`.
- Generated, vendored, package-manager, minified, and build-output noise is suppressed or moved to a scan-quality appendix by default.
- Every control backlog item includes repo, path, control-path type, capability, owner, evidence source, approval status, security visibility, recommended action, confidence, evidence gaps, confidence-raising guidance, SLA, and closure criteria.
- Every finding/control item has a fixed action taxonomy value or deterministic equivalent accepted by the schema.
- Secret-bearing workflows distinguish secret references from leaked values and explain owner/scope/rotation/proof evidence gaps.
- Inventory workflows can approve, attach evidence, accept risk, deprecate, exclude, and expire/renew approvals with deterministic proof records.
- Drift views answer what new or changed AI/automation control paths appeared since the last approved baseline.
- Ownership resolution distinguishes explicit, inferred, conflicting, and missing owners with confidence.
- Large-org scans keep JSON stdout clean, progress on stderr, phase timing visible, partial results explicit, and status inspectable after interruptions.
- Native reports and ticket exports lead with the control backlog and keep raw findings in appendices.

## Public API and Contract Map

Stable existing public surfaces:
- CLI commands in `core/cli/root.go`: `scan`, `inventory`, `regress`, `report`, `export`, `evidence`, `verify`, `identity`, `lifecycle`, `manifest`, `score`, `fix`, `campaign`, `mcp-list`, `action`, `version`.
- Exit codes in `core/cli/root.go`: `0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, `8` unsafe operation blocked.
- Existing `wrkr scan --json` keys must remain present unless explicitly deprecated by a future major version: `findings`, `ranked_findings`, `top_findings`, `inventory`, `profile`, `posture_score`, `compliance_summary`.
- Existing proof chain, lifecycle manifest, state snapshot, report, appendix, SARIF, and regress baseline artifacts remain portable and verifiable.

New public surfaces to add:
- `wrkr scan --mode quick|governance|deep`.
- `control_backlog` object in scan state and scan JSON, versioned as `control_backlog_version`.
- `scan_quality` appendix containing suppressed generated/package noise, parser errors, detector errors, and completeness warnings.
- Finding/control item enums: `signal_class`, `control_surface_type`, `control_path_type`, `recommended_action`, `confidence`, `evidence_basis`, `security_visibility_state`, `write_path_class`, `secret_signal_type`.
- Inventory lifecycle commands: `wrkr inventory approve`, `wrkr inventory attach-evidence`, `wrkr inventory accept-risk`, `wrkr inventory deprecate`, `wrkr inventory exclude`.
- Drift categories for control-path changes in `wrkr regress run --json` and `wrkr inventory --diff --json`.
- Report templates: `ciso`, `appsec`, `platform`, `audit`, `customer-draft`, with compatibility alias for current `exec|operator|audit|public`.
- Ticket export command surface under `wrkr export tickets`.

Internal surfaces:
- New aggregation packages may live under `core/aggregate/controlbacklog`, `core/aggregate/scanquality`, and focused helper packages for classification. Keep orchestration thin in `core/cli`.
- Detector logic remains under `core/detect/*`; risk logic remains under `core/risk/*`; ownership logic remains under `core/owners`; evidence/proof stays under `core/evidence`, `core/proofemit`, and `core/proofmap`.

Shim and deprecation path:
- Keep existing finding JSON fields and report templates. Add new fields additively.
- Map existing security visibility value `approved` to new display value `known_approved` only in new governance surfaces; do not mutate old inventory fields without a schema/version note.
- Keep current `top_findings` while adding `control_backlog.items`. Do not remove `top_findings` during this plan.
- Existing `secret_presence` findings may continue for compatibility, but governance outputs must derive and expose new secret signal semantics.

Schema/versioning policy:
- Add explicit version fields for new artifacts: `control_backlog_version`, `scan_quality_version`, `approval_inventory_version`, `ticket_export_version`.
- Enum additions are minor-version compatible when old fields remain. Enum renames or removals require shim logic, docs, and compatibility tests.
- New artifacts must be byte-stable across repeated runs except explicit timestamp/version fields.

Machine-readable error expectations:
- Invalid scan mode, report template, ticket format, or inventory action arguments: exit `6`, JSON error code `invalid_input`.
- Invalid governance policy/config schema: exit `3`, JSON error code `policy_schema_violation`.
- Approval-required enforcement paths: exit `4`, JSON error code `approval_required`.
- Drift found by regress/inventory diff: exit `5`, JSON status `drift`.
- Missing optional network adapter configuration: exit `7`, JSON error code `dependency_missing`.
- Unsafe output path, symlink marker abuse, or unmanaged destructive write: exit `8`, JSON error code `unsafe_operation_blocked`.

## Docs and OSS Readiness Baseline

- README first screen must say what Wrkr does, who it is for, how to get first value, and why it is governance/proof for control paths rather than generic AppSec scanning.
- Docs must introduce the lifecycle path model: discover -> classify -> attach evidence -> approve -> monitor drift -> prove control.
- Integration-first docs flow must lead with `wrkr scan --mode governance --json`, `wrkr inventory approve`, `wrkr regress init/run --json`, `wrkr report --template ciso`, and `wrkr export tickets --dry-run --json`.
- Docs source of truth: command docs in `docs/commands/*.md`, product positioning in `docs/positioning.md`, trust/security docs in `docs/trust/*.md`, examples in `docs/examples/*.md`, decisions in `docs/decisions/*.md`.
- OSS trust baseline must remain aligned: `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `SECURITY.md`, `.github/CODEOWNERS`, `.github/ISSUE_TEMPLATE/*`, `.github/pull_request_template.md`, and release/trust docs.
- Any CLI/help/JSON/schema/exit-code change must update docs and pass docs parity gates in the same implementation story.

## Recommendation Traceability

| Rec | Normalized recommendation | Epic/story coverage |
|---|---|---|
| R1 | Reposition Wrkr around AI and automation control-path governance | W1-S1, W5-S1 |
| R2 | Make govern-first control backlog the default output | W1-S1, W2-S1 |
| R3 | Split unique Wrkr signals from supporting security signals | W1-S1, W2-S1, W5-S1 |
| R4 | Add fixed finding action taxonomy | W1-S2, W3-S1 |
| R5 | Add evidence quality and confidence | W1-S2, W4-S1 |
| R6 | Add approval inventory workflow | W3-S1, W3-S2 |
| R7 | Make drift recurring value | W3-S3 |
| R8 | Add scan modes quick/governance/deep | W1-S4, W2-S1 |
| R9 | Suppress generated/package noise by default | W1-S4 |
| R10 | Improve secret reference semantics | W1-S3, W2-S2 |
| R11 | Add control mapping | W2-S2, W3-S2 |
| R12 | Add native customer reports | W5-S1 |
| R13 | Add ticket export | W5-S2 |
| R14 | Add enterprise ownership resolution | W4-S1 |
| R15 | Add security visibility state | W2-S3 |
| R16 | Add write-path classification | W2-S2 |
| R17 | Add large-org operator UX | W4-S2 |
| R18 | Add baseline and approval expiration | W3-S1, W3-S3 |
| R19 | Tighten agent vs automation model around control surfaces | W1-S1, W2-S2 |
| R20 | Productize proof | W3-S2, W5-S1 |

## Test Matrix Wiring

Fast lane:
- `make lint-fast`
- `make test-fast`
- Targeted `go test` commands named by each story.
- Docs parity checks for touched command docs: `scripts/check_docs_cli_parity.sh`.

Core CI lane:
- `make prepush`
- `go test ./internal/e2e -count=1`
- `go test ./internal/integration -count=1`
- `.github/required-checks.json` and branch-protection contract validation remain aligned.

Acceptance lane:
- `scripts/run_v1_acceptance.sh --mode=local`
- `go test ./internal/acceptance -count=1`
- `go test ./internal/scenarios -count=1 -tags=scenario`
- New scenario fixtures under `scenarios/wrkr/**` for each governance behavior.

Cross-platform lane:
- Required PR checks remain `fast-lane` and `windows-smoke`.
- Windows/macOS smoke must cover path filtering, JSON stdout cleanliness, and report/ticket artifact path behavior when touched.

Risk lane:
- `make prepush-full` for architecture, risk, adapter, or failure-semantics changes.
- `make test-contracts` for schema/artifact/CLI JSON changes.
- `make test-scenarios` for outside-in behavior changes.
- `make test-hardening` and `make test-chaos` for approval persistence, baseline/drift, long-running scan status, and unsafe output behavior.
- `make test-perf` for generated-path filtering, scan modes, control backlog construction, large-org progress/status, and report/ticket export scaling.

Merge/release gating rule:
- No implementation wave may merge with failing fast/core/contract/scenario gates.
- Stories touching proof, evidence, regress drift, approval state, or failure handling require risk lane green before merge.
- Report/ticket/docs waves may not merge before Wave 1 through Wave 3 contracts are green.

## Epic Wave 1: Control-Surface Contract And Signal Quality

Objective:
- Establish the contract vocabulary that lets Wrkr speak in control surfaces, signal classes, actions, confidence, secret semantics, scan modes, and noise policy without collapsing detector/risk/inventory boundaries.

### Story W1-S1: Add Control Surface And Backlog Contract

Priority: P0

Tasks:
- Add a focused control backlog model with deterministic item sorting and a stable version field.
- Define fields for repo, path, control surface type, control-path type, capability, owner, owner source, ownership status, evidence source, approval status, security visibility, signal class, recommended action, confidence, evidence gaps, SLA, closure criteria, and linked raw finding IDs.
- Add enum validation helpers for `unique_wrkr_signal` vs `supporting_security_signal`.
- Keep raw detector findings unchanged and derive backlog items in aggregation.
- Add fixture/golden output for a mixed org scan with CI workflow, MCP config, coding assistant config, dependency surface, and supporting secret reference.

Repo paths:
- `core/model/finding.go`
- `core/aggregate/controlbacklog/`
- `core/aggregate/inventory/`
- `core/risk/`
- `core/state/`
- `internal/scenarios/`
- `scenarios/wrkr/control-backlog-governance/`

Run commands:
- `go test ./core/aggregate/controlbacklog ./core/aggregate/inventory ./core/model -count=1`
- `go test ./internal/scenarios -run 'TestControlBacklogGovernance' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`

Test requirements:
- Schema validation tests for the new backlog artifact.
- Golden JSON repeat-run byte stability tests.
- Compatibility tests proving existing `findings`, `top_findings`, and `inventory` JSON remain available.
- Scenario fixture proving primary Wrkr signals rank before supporting security signals.

Matrix wiring:
- Fast lane: targeted package tests.
- Core CI lane: `make prepush`.
- Acceptance lane: new scenario fixture.
- Risk lane: `make test-contracts`, `make prepush-full`.

Acceptance criteria:
- `wrkr scan --path scenarios/wrkr/control-backlog-governance/repos --json` emits `control_backlog.control_backlog_version`.
- Backlog item order is deterministic across two runs with distinct state paths.
- Each backlog item has a valid signal class and links back to raw finding evidence.
- Existing scan JSON consumers can still read `findings`, `top_findings`, and `inventory`.

Changelog impact: required

Changelog section: Added

Draft changelog entry: Added the versioned control backlog contract for governance-first scan output while preserving existing raw finding JSON surfaces.

Semver marker override: none

Contract/API impact:
- Adds stable scan JSON fields and artifact schema. Existing fields remain stable.

Versioning/migration impact:
- Add `control_backlog_version: "1"`. No migration required for old state files; old snapshots produce an empty or derived backlog when read.

Architecture constraints:
- Keep detector output as raw evidence and backlog aggregation as a separate package.
- Thin CLI orchestration only; no risk logic embedded in `core/cli`.
- Explicit side-effect-free API naming for backlog build functions.
- Deterministic sort order by priority, confidence, repo, path, control type, and linked finding ID.

ADR required: yes

TDD first failing test(s):
- `TestBuildControlBacklogSplitsSignalClassesAndSortsDeterministically`.
- `TestScanJSONRetainsLegacyFindingSurfacesWithControlBacklog`.

Cost/perf impact: medium

Chaos/failure hypothesis:
- If a raw finding has incomplete owner/evidence metadata, backlog construction emits a low-confidence item with explicit gaps instead of dropping it or panicking.

### Story W1-S2: Add Action Taxonomy, Evidence Quality, And Confidence

Priority: P0

Tasks:
- Define fixed recommended actions: `attach_evidence`, `approve`, `remediate`, `downgrade`, `deprecate`, `exclude`, `monitor`, `inventory_review`, `suppress`, `debug_only`.
- Add evidence quality fields: confidence, evidence basis, evidence gaps, and what would raise confidence.
- Map existing finding classes into default actions without changing detector semantics.
- Add deterministic SLA assignment rules by action, capability, write-path class, security visibility, and confidence.
- Add contract tests for every taxonomy value and reason-code stability.

Repo paths:
- `core/model/finding.go`
- `core/aggregate/controlbacklog/`
- `core/risk/`
- `core/report/`
- `docs/trust/contracts-and-schemas.md`

Run commands:
- `go test ./core/aggregate/controlbacklog ./core/risk ./core/report -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `make test-contracts`
- `make prepush-full`

Test requirements:
- Enum validation tests.
- Golden JSON tests for each action.
- CLI `--json` stability tests for error envelopes and valid/invalid action filters when filters are introduced.
- Deterministic SLA rule tests.

Matrix wiring:
- Fast lane: targeted package tests.
- Core CI lane: e2e CLI contract.
- Risk lane: `make test-contracts`, `make prepush-full`.

Acceptance criteria:
- Every backlog item has exactly one allowed recommended action.
- Secret-bearing workflows with only references default to `attach_evidence` or `approve`, not automatic `remediate`, unless unsafe value evidence exists.
- Generated parse errors can be marked `suppress` or `debug_only` in scan quality surfaces.
- Confidence basis and confidence-raising guidance are deterministic and non-empty for medium/low confidence items.

Changelog impact: required

Changelog section: Added

Draft changelog entry: Added deterministic recommended-action, evidence-quality, confidence, and SLA fields to governance backlog items.

Semver marker override: none

Contract/API impact:
- Adds stable enum values and backlog JSON fields.

Versioning/migration impact:
- Backlog schema remains version `1` if added before release; otherwise bump minor artifact version and preserve old readers.

Architecture constraints:
- Taxonomy mapping must live in aggregation/risk packages, not detectors.
- Reason codes and action values must be stable and documented.
- Fail closed on unknown configured taxonomy values.

ADR required: yes

TDD first failing test(s):
- `TestRecommendedActionTaxonomyCoversKnownFindingFamilies`.
- `TestEvidenceQualityExplainsOwnerFallbackConfidence`.

Cost/perf impact: low

Chaos/failure hypothesis:
- If evidence basis is missing or contradictory, item confidence falls to low and the evidence gap is surfaced instead of silently treating the item as controlled.

### Story W1-S3: Split Secret Reference Semantics From Secret Value Risk

Priority: P0

Tasks:
- Introduce secret signal types: `secret_reference_detected`, `secret_value_detected`, `secret_scope_unknown`, `secret_rotation_evidence_missing`, `secret_owner_missing`, `secret_used_by_write_capable_workflow`.
- Update secret detector and workflow capability aggregation so workflow references remain redacted and classified as references.
- Add control backlog language that says rotation/owner/scope/proof evidence is missing rather than implying a leaked secret.
- Add tests proving raw values are never emitted and workflow secret reference names are handled deterministically.

Repo paths:
- `core/detect/secrets/`
- `core/detect/workflowcap/`
- `core/aggregate/controlbacklog/`
- `core/risk/`
- `core/report/`
- `scenarios/wrkr/secret-reference-semantics/`

Run commands:
- `go test ./core/detect/secrets ./core/detect/workflowcap ./core/aggregate/controlbacklog ./core/risk -count=1`
- `go test ./internal/scenarios -run 'TestSecretReferenceSemantics' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`

Test requirements:
- Unit tests for secret signal classification.
- Redaction tests proving secret values are absent from JSON, Markdown, PDF, CSV, and ticket exports.
- Scenario tests for rotation evidence attached vs missing.
- Contract tests for secret signal enum stability.

Matrix wiring:
- Fast lane: detector and backlog tests.
- Acceptance lane: new secret-reference scenario.
- Risk lane: `make test-contracts`, `make prepush-full`.

Acceptance criteria:
- A GitHub workflow with `secrets.MY_TOKEN` produces `secret_reference_detected`, not `secret_value_detected`.
- If the same workflow is write-capable, backlog item includes `secret_used_by_write_capable_workflow`.
- If control evidence is attached, the item can close as controlled without remediation language.
- No output contains raw secret values.

Changelog impact: required

Changelog section: Security

Draft changelog entry: Refined secret-bearing automation semantics so Wrkr distinguishes secret references, leaked values, ownership/scope gaps, and rotation evidence gaps without exposing secret values.

Semver marker override: none

Contract/API impact:
- Adds secret signal enum values and changes governance wording for secret findings. Legacy raw finding compatibility remains.

Versioning/migration impact:
- Existing `secret_presence` findings are still accepted and mapped to the new secret signal types in governance outputs.

Architecture constraints:
- Secret detectors may flag presence and references only; no raw value extraction.
- Workflow-derived secret context must be merged in aggregation, not duplicated across detectors.
- Default behavior remains offline and deterministic.

ADR required: yes

TDD first failing test(s):
- `TestWorkflowSecretReferenceDoesNotClaimLeakedSecret`.
- `TestSecretValueNeverAppearsInGovernanceOutputs`.

Cost/perf impact: low

Chaos/failure hypothesis:
- If a workflow file cannot be parsed, Wrkr moves the parse failure to scan quality and does not invent secret risk from unreadable content.

### Story W1-S4: Add Scan Modes And Generated-Path Noise Policy

Priority: P0

Tasks:
- Add `--mode quick|governance|deep` to `wrkr scan`.
- Make `governance` the default mode.
- Define mode-specific detector/path scope: quick scans high-signal repo/CI/agent/MCP files, governance scans control backlog evidence surfaces, deep runs exhaustive detector/debug scope.
- Add default generated/package suppression for `dist/`, `build/`, nested `target/`, `.yarn/sdks/`, `node_modules/`, generated SDK folders, vendored dependency trees, minified JS, and package-manager internals.
- Move parse errors from suppressed/generated paths into `scan_quality` instead of top-level governance backlog.
- Preserve deterministic ordering and explicit inclusion behavior for deep mode.

Repo paths:
- `core/cli/scan.go`
- `core/detect/`
- `core/source/local/`
- `core/source/github/`
- `core/aggregate/scanquality/`
- `internal/e2e/source/`
- `scenarios/wrkr/first-offer-noise-pack/`
- `docs/commands/scan.md`

Run commands:
- `go test ./core/detect/... ./core/source/local ./core/source/github ./core/aggregate/scanquality -count=1`
- `go test ./internal/e2e/source -count=1`
- `go test ./internal/acceptance -run 'TestV1Acceptance/AC06_scan_diff_no_noise' -count=1`
- `make test-perf`
- `make prepush-full`

Test requirements:
- CLI help/usage tests for `--mode`.
- Invalid mode exit-code and JSON error envelope tests.
- Fixture/golden tests for quick/governance/deep output differences.
- Generated path suppression tests including symlink and nested-root safety.
- Perf regression tests for large path sets.

Matrix wiring:
- Fast lane: source/detect/scanquality package tests.
- Core CI lane: e2e source tests.
- Acceptance lane: noise scenario and acceptance no-noise check.
- Cross-platform lane: Windows path separator smoke.
- Risk lane: `make test-perf`, `make prepush-full`.

Acceptance criteria:
- `wrkr scan --path <repos> --json` behaves as governance mode.
- `wrkr scan --mode deep --json` can include debug/raw parse errors that governance mode suppresses from the backlog.
- Suppressed paths are represented in `scan_quality` with counts and rationale, sorted deterministically.
- Invalid `--mode` exits `6` with JSON error code `invalid_input`.

Changelog impact: required

Changelog section: Changed

Draft changelog entry: Made governance scan mode the default, added quick/deep scan modes, and moved generated/package noise into a deterministic scan-quality appendix.

Semver marker override: none

Contract/API impact:
- Adds CLI flag and scan JSON fields. Changes default prioritization and human output, but keeps legacy raw JSON fields.

Versioning/migration impact:
- No state migration required. New state snapshots include mode and scan-quality metadata.

Architecture constraints:
- Path filtering must be a reusable deterministic source/detector scope layer.
- Mode selection must not be hidden global state.
- Long-running scan loops must propagate context cancellation.

ADR required: yes

TDD first failing test(s):
- `TestScanModeGovernanceSuppressesGeneratedPathNoise`.
- `TestScanModeDeepKeepsDebugParseErrorsInScanQuality`.
- `TestInvalidScanModeJSONErrorEnvelope`.

Cost/perf impact: medium

Chaos/failure hypothesis:
- If suppression encounters unreadable paths or unsafe symlinks, scan quality records deterministic warnings and high-risk unreadable control paths fail closed when applicable.

## Epic Wave 2: Govern-First Runtime Output

Objective:
- Make the new contracts visible in operator output, write-path classification, control mapping, and security visibility without removing existing scanner evidence.

### Story W2-S1: Make Control Backlog The Default Scan Decision Surface

Priority: P0

Tasks:
- Emit `control_backlog` in scan JSON and persist it in scan state.
- Update human `wrkr scan --explain` to lead with top backlog items and rationale.
- Keep stdout clean JSON when `--json` is set; send progress and warnings to stderr only.
- Put raw findings, parse errors, detector errors, and generated-path issues in appendix-style JSON surfaces.
- Add `--top` or reuse existing report top behavior only if needed for backlog count; otherwise default to top 10 backlog items.

Repo paths:
- `core/cli/scan.go`
- `core/state/`
- `core/report/activation.go`
- `core/report/render_markdown.go`
- `docs/commands/scan.md`
- `internal/e2e/cli_contract/`
- `internal/acceptance/`

Run commands:
- `go test ./core/cli ./core/state ./core/report -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `go test ./internal/acceptance -run 'TestV1Acceptance' -count=1`
- `scripts/check_docs_cli_parity.sh`
- `make test-contracts`

Test requirements:
- CLI `--json` stdout-only stability tests.
- Help/usage tests for new mode/default wording.
- Golden scan JSON tests for backlog and raw appendix.
- Exit-code invariants for unchanged success/failure paths.

Matrix wiring:
- Fast lane: CLI/report package tests.
- Core CI lane: e2e CLI contract.
- Acceptance lane: V1 acceptance with new governance assertions.
- Risk lane: `make test-contracts`.

Acceptance criteria:
- `wrkr scan --json` has valid `control_backlog.items` and no non-JSON stdout.
- `wrkr scan --explain` answers which items security should review first.
- Raw findings are still emitted in JSON for downstream compatibility.
- Warnings, progress, and scan-quality notes do not corrupt JSON stdout.

Changelog impact: required

Changelog section: Changed

Draft changelog entry: Changed scan output to lead with a prioritized control backlog while keeping raw findings available for compatibility.

Semver marker override: none

Contract/API impact:
- Adds new default JSON and human output surfaces. Existing JSON fields remain.

Versioning/migration impact:
- Existing state files remain readable. New state files include backlog and scan quality.

Architecture constraints:
- CLI should call aggregation/report builders, not rank backlog inline.
- Output writers must keep stdout/stderr separation explicit.
- Context cancellation must flush partial progress safely.

ADR required: yes

TDD first failing test(s):
- `TestScanJSONStdoutContainsOnlyJSONWithControlBacklog`.
- `TestScanExplainLeadsWithTopControlBacklogItems`.

Cost/perf impact: medium

Chaos/failure hypothesis:
- If report/backlog artifact writing fails after state save begins, managed artifact rollback preserves previous state and emits deterministic runtime error.

### Story W2-S2: Add Write-Path Classification And Control Mapping

Priority: P0

Tasks:
- Define write-path classes: `read`, `write`, `pr_write`, `repo_write`, `release_write`, `package_publish`, `deploy_write`, `infra_write`, `secret_bearing_execution`, `production_adjacent_write`.
- Derive write-path class from workflow permissions, workflow steps, MCP/tool config, non-human identities, and dependency agent surfaces.
- Map backlog items to controls: owner assigned, approval recorded, least privilege verified, rotation evidence attached, deployment gate present, production access classified, proof artifact generated, review cadence set.
- Ensure write-path classification is visible in scan JSON, inventory, reports, regress drift, and ticket exports.

Repo paths:
- `core/detect/workflowcap/`
- `core/aggregate/inventory/privileges.go`
- `core/aggregate/controlbacklog/`
- `core/risk/attackpath/`
- `core/risk/classify/`
- `core/compliance/`
- `core/proofmap/`
- `internal/scenarios/workflow_capabilities_scenario_test.go`
- `scenarios/wrkr/write-path-classification/`

Run commands:
- `go test ./core/detect/workflowcap ./core/aggregate/inventory ./core/aggregate/controlbacklog ./core/risk/... ./core/compliance ./core/proofmap -count=1`
- `go test ./internal/scenarios -run 'TestWorkflowCapabilities|TestWritePathClassification' -count=1 -tags=scenario`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Unit tests for each write-path class.
- Scenario fixtures for PR write plus secret reference, deploy workflow with environment gate, package publish, and infra write.
- Contract tests proving enum names remain stable.
- Compliance/proof mapping tests for each governance control.

Matrix wiring:
- Fast lane: detector/risk/compliance targeted tests.
- Acceptance lane: workflow capability and new write-path scenario.
- Risk lane: `make test-contracts`, `make test-scenarios`, `make prepush-full`.

Acceptance criteria:
- A workflow with `pull-requests: write` and `secrets.*` produces `pr_write` plus `secret_bearing_execution`.
- A release workflow with publish/deploy steps produces release/deploy/package classes as applicable.
- Control mappings are deterministic and explain which evidence is present or missing.
- Existing attack/action path output includes write-path class references without breaking prior fields.

Changelog impact: required

Changelog section: Added

Draft changelog entry: Added explicit engineering write-path classification and governance control mappings across scan, inventory, risk, and proof outputs.

Semver marker override: none

Contract/API impact:
- Adds enum fields to scan, inventory, backlog, and report JSON.

Versioning/migration impact:
- Additive schema changes only. Old snapshots derive write-path classes when possible.

Architecture constraints:
- Detection extracts evidence; classification and control mapping happen in risk/aggregation/compliance layers.
- No workflow execution or remote lookup is introduced.
- Structured YAML parser behavior remains `gopkg.in/yaml.v3` compatible.

ADR required: yes

TDD first failing test(s):
- `TestWritePathClassifiesPRWriteSecretBearingWorkflow`.
- `TestControlMappingRequiresLeastPrivilegeAndProofEvidence`.

Cost/perf impact: medium

Chaos/failure hypothesis:
- If workflow permissions are ambiguous or inherited, classify confidence as medium/low and surface evidence gaps rather than assuming least privilege.

### Story W2-S3: Expand Security Visibility States

Priority: P1

Tasks:
- Add governance-native states: `known_approved`, `known_unapproved`, `unknown_to_security`, `accepted_risk`, `deprecated`, `revoked`, `needs_review`.
- Preserve old inventory status compatibility with shim mapping.
- Update rollups for tools, agents, write-capable agents, and backlog items.
- Add drift behavior for expired approvals and revoked/deprecated reappearance.
- Update docs and schema contract references.

Repo paths:
- `core/aggregate/inventory/`
- `core/lifecycle/`
- `core/manifest/`
- `core/regress/`
- `core/aggregate/controlbacklog/`
- `docs/state_lifecycle.md`
- `docs/commands/inventory.md`
- `docs/trust/contracts-and-schemas.md`

Run commands:
- `go test ./core/aggregate/inventory ./core/lifecycle ./core/manifest ./core/regress ./core/aggregate/controlbacklog -count=1`
- `go test ./internal/e2e/regress -count=1`
- `scripts/check_docs_cli_parity.sh`
- `make test-contracts`
- `make prepush-full`

Test requirements:
- Compatibility tests for old `approved` state.
- Lifecycle transition tests for accepted risk, deprecated, revoked, and needs review.
- Drift tests for approval expiry and deprecated reappearance.
- Schema/golden updates for visibility rollups.

Matrix wiring:
- Fast lane: inventory/lifecycle/regress package tests.
- Core CI lane: e2e regress.
- Risk lane: `make test-contracts`, `make prepush-full`.

Acceptance criteria:
- New governance backlog uses `known_approved` for approved controls.
- Existing inventory readers still accept current `approved` status where emitted historically.
- Expired approvals move affected items to `needs_review`.
- Revoked or deprecated paths that reappear produce deterministic drift reasons.

Changelog impact: required

Changelog section: Changed

Draft changelog entry: Expanded security visibility into governance-native states for approved, unapproved, accepted-risk, deprecated, revoked, and needs-review control paths.

Semver marker override: none

Contract/API impact:
- Adds/changes visibility enum in new governance surfaces and shims old values.

Versioning/migration impact:
- Old manifests and state snapshots are migrated in-memory through compatibility mapping.

Architecture constraints:
- Lifecycle state transitions remain deterministic and proof-record-backed.
- Visibility rollups must not borrow approval across orgs or repos.
- Fail closed on invalid manually supplied visibility state.

ADR required: yes

TDD first failing test(s):
- `TestSecurityVisibilityMapsApprovedToKnownApprovedInBacklog`.
- `TestExpiredApprovalMovesBacklogItemToNeedsReview`.

Cost/perf impact: low

Chaos/failure hypothesis:
- If lifecycle manifest has invalid approval metadata, state becomes `needs_review` or `revoked` according to deterministic rules rather than silently staying approved.

## Epic Wave 3: Approval Inventory, Evidence, And Drift

Objective:
- Turn discovery into lifecycle governance: attach evidence, approve, accept risk, deprecate, exclude, expire approvals, and monitor drift from approved baselines.

### Story W3-S1: Add Approval Inventory Workflow Commands

Priority: P1

Tasks:
- Add `wrkr inventory approve <id> --owner <team> --evidence <ticket-or-url> --expires <date> --json`.
- Add `wrkr inventory attach-evidence <id> --control <control-id> --url <url> --json`.
- Add `wrkr inventory accept-risk <id> --expires <duration-or-date> --json`.
- Add `wrkr inventory deprecate <id> --reason <reason> --json`.
- Add `wrkr inventory exclude <id> --reason <reason> --json`.
- Store approval owner, evidence URL, control ID, approval expiry, review cadence, last reviewed date, exclusion reason, and renewal state in deterministic state/manifest artifacts.
- Require regular-file markers and safe managed output paths for state mutations.

Repo paths:
- `core/cli/inventory.go`
- `core/lifecycle/`
- `core/manifest/`
- `core/state/`
- `core/evidence/`
- `core/proofemit/`
- `internal/atomicwrite/`
- `internal/e2e/cli_contract/`
- `docs/commands/inventory.md`

Run commands:
- `go test ./core/cli ./core/lifecycle ./core/manifest ./core/state ./core/evidence ./core/proofemit ./internal/atomicwrite -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `make test-contracts`
- `make test-hardening`
- `make test-chaos`
- `make prepush-full`

Test requirements:
- CLI help/usage tests.
- `--json` stability tests.
- Exit-code tests for missing id, invalid expiry, invalid evidence URL/path, unknown action, and unsafe output path.
- Crash-safe atomic write and rollback tests.
- Marker trust tests: marker must be regular file; reject symlink/directory.
- Approval expiry and renewal lifecycle tests.

Matrix wiring:
- Fast lane: targeted CLI/lifecycle/state tests.
- Core CI lane: e2e CLI contract.
- Risk lane: `make test-contracts`, `make test-hardening`, `make test-chaos`, `make prepush-full`.

Acceptance criteria:
- Each inventory mutation emits a deterministic JSON response and proof/lifecycle transition record.
- Invalid or unsafe state mutation exits with the correct machine-readable error envelope.
- Approval expiry is enforced in subsequent scan/regress output.
- Excluded items remain in evidence appendices but leave the active governance backlog with explicit rationale.

Changelog impact: required

Changelog section: Added

Draft changelog entry: Added inventory governance commands for approvals, evidence attachments, accepted risk, deprecation, exclusion, and time-bound review state.

Semver marker override: none

Contract/API impact:
- Adds inventory subcommands and state/proof artifact fields.

Versioning/migration impact:
- Add `approval_inventory_version`. Old manifests read with missing approvals as `missing` or `needs_review`.

Architecture constraints:
- Use plan/apply style APIs for mutating lifecycle state.
- Mutations must be atomic and rollback-safe.
- Proof emission remains file-based and verifiable.
- No network validation of evidence URLs by default.

ADR required: yes

TDD first failing test(s):
- `TestInventoryApproveWritesApprovalProofRecordAtomically`.
- `TestInventoryAcceptRiskRequiresExpiry`.
- `TestInventoryMutationRejectsUnsafeManagedMarker`.

Cost/perf impact: medium

Chaos/failure hypothesis:
- If the process crashes during approval write, previous state remains readable and no partial proof chain is treated as valid.

### Story W3-S2: Productize Proof And Evidence Lifecycle

Priority: P1

Tasks:
- Define evidence/control proof records for owner assigned, approval recorded, least privilege verified, rotation evidence attached, deployment gate present, production access classified, proof artifact generated, and review cadence set.
- Map backlog closure criteria to proof requirements.
- Ensure `wrkr evidence --json`, `wrkr verify --chain --json`, and reports can show whether proof exists for each control.
- Keep `Clyra-AI/proof` primitives authoritative for proof record creation and verification.
- Add compatibility assertions for proof chain integrity and mixed scan/evidence records.

Repo paths:
- `core/evidence/`
- `core/proofemit/`
- `core/proofmap/`
- `core/compliance/`
- `core/verify/`
- `core/cli/evidence.go`
- `core/cli/verify.go`
- `scenarios/cross-product/proof-record-interop/`
- `docs/trust/proof-chain-verification.md`
- `docs/evidence_templates.md`

Run commands:
- `go test ./core/evidence ./core/proofemit ./core/proofmap ./core/compliance ./core/verify ./core/cli -count=1`
- `go test ./internal/integration/interop -count=1`
- `go test ./internal/scenarios -run 'TestPolicyComplianceMapping|TestWave3Compliance' -count=1 -tags=scenario`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Proof record schema validation tests.
- Chain integrity tests with mixed scan/evidence records.
- Golden tests for evidence bundle closure criteria.
- CLI JSON tests for evidence and verify output.

Matrix wiring:
- Fast lane: proof/evidence/compliance package tests.
- Core CI lane: interop integration.
- Acceptance lane: compliance/proof scenarios.
- Risk lane: `make test-contracts`, `make test-scenarios`, `make prepush-full`.

Acceptance criteria:
- Every control backlog item can explain which proof artifacts exist and which are missing.
- Attached evidence creates verifiable proof records with stable record types.
- `wrkr verify --chain --json` validates the resulting proof chain.
- Compliance mapping can consume the same evidence without product-specific hacks.

Changelog impact: required

Changelog section: Added

Draft changelog entry: Added proof and evidence lifecycle mapping so governance controls can show verifiable approval, least-privilege, rotation, deployment-gate, and review evidence.

Semver marker override: none

Contract/API impact:
- Adds proof/evidence record fields and evidence JSON surfaces.

Versioning/migration impact:
- Existing proof chains remain valid; new records append with stable types.

Architecture constraints:
- Do not duplicate proof primitive semantics outside `Clyra-AI/proof`.
- Compliance mapping consumes evidence abstractions, not raw detector internals.
- Verification failure remains exit `2`.

ADR required: yes

TDD first failing test(s):
- `TestControlEvidenceRecordVerifiesInProofChain`.
- `TestBacklogClosureCriteriaMapsToProofRequirements`.

Cost/perf impact: low

Chaos/failure hypothesis:
- If proof append fails after state mutation planning, mutation apply is blocked or rolled back and verification remains fail-closed.

### Story W3-S3: Add Drift-First Approved Baseline Monitoring

Priority: P1

Tasks:
- Extend regress baselines with approved control-path state, security visibility, owner, evidence expiry, write-path class, secret-bearing status, and confidence.
- Add drift categories: `new_unknown_automation`, `new_repo_write_path`, `new_secret_bearing_workflow`, `new_mcp_tool_config`, `approval_expired`, `owner_changed`, `approved_path_risk_increased`, `deprecated_path_reappeared`.
- Update `wrkr regress init --baseline <state> --json`, `wrkr regress run --baseline <baseline> --state <state> --json`, and `wrkr inventory --diff --json` outputs.
- Keep drift exit code `5`.
- Add summary markdown/report integration for drift categories.

Repo paths:
- `core/regress/`
- `core/diff/`
- `core/cli/regress.go`
- `core/cli/inventory.go`
- `core/report/`
- `core/aggregate/controlbacklog/`
- `internal/e2e/regress/`
- `scenarios/wrkr/drift-first-baseline/`
- `docs/commands/regress.md`

Run commands:
- `go test ./core/regress ./core/diff ./core/cli ./core/report ./core/aggregate/controlbacklog -count=1`
- `go test ./internal/e2e/regress -count=1`
- `go test ./internal/scenarios -run 'TestDriftFirstBaseline' -count=1 -tags=scenario`
- `make test-contracts`
- `make test-scenarios`
- `make prepush-full`

Test requirements:
- Baseline schema compatibility tests.
- Drift reason-code stability tests.
- Exit-code `5` contract tests.
- Golden JSON for every new drift category.
- Scenario tests for approved path becoming higher risk and deprecated path reappearing.

Matrix wiring:
- Fast lane: regress/diff/report package tests.
- Core CI lane: e2e regress.
- Acceptance lane: new drift scenario.
- Risk lane: `make test-contracts`, `make test-scenarios`, `make prepush-full`.

Acceptance criteria:
- Regress output leads with new/changed unknown control paths since approved baseline.
- Approval expiry creates `approval_expired` drift and moves visibility to `needs_review`.
- Owner changes are reported with old/new owner and source.
- Drift output remains sorted and byte-stable.

Changelog impact: required

Changelog section: Changed

Draft changelog entry: Changed regress and inventory drift to focus on new or changed AI/automation control paths, approval expiry, owner changes, and risk increases from approved baselines.

Semver marker override: none

Contract/API impact:
- Extends regress baseline schema and drift JSON reasons while preserving exit code `5`.

Versioning/migration impact:
- Add baseline compatibility reader for prior `BaselineVersion`. Bump baseline version only with migration tests.

Architecture constraints:
- Regress compares persisted state and backlog summaries; it must not rescan or call detectors.
- Drift reason codes are stable public contract.
- Ambiguous baseline reads fail closed with machine-readable errors.

ADR required: yes

TDD first failing test(s):
- `TestRegressDetectsNewSecretBearingWriteWorkflow`.
- `TestRegressDetectsApprovalExpiredAndOwnerChanged`.

Cost/perf impact: medium

Chaos/failure hypothesis:
- If baseline is partially written or schema-invalid, regress exits fail-closed with deterministic error and does not produce misleading no-drift output.

## Epic Wave 4: Ownership And Large-Org Operator UX

Objective:
- Make governance scalable for hundreds of repos by resolving owners better and making long-running scans observable without violating offline-first defaults.

### Story W4-S1: Add Enterprise Ownership Resolution

Priority: P1

Tasks:
- Extend `core/owners` to support CODEOWNERS, custom owner mapping files, service catalog exports, Backstage catalog files, GitHub teams/repo topics when available from source metadata, and fallback owner rules.
- Add owner source states: `explicit_owner`, `inferred_owner`, `conflicting_owner`, `missing_owner`.
- Add ownership confidence and evidence basis.
- Keep all network ownership lookups tied to already configured source acquisition; no standalone network calls by default.
- Surface owner quality in backlog, inventory, reports, and ticket exports.

Repo paths:
- `core/owners/`
- `core/source/github/`
- `core/source/org/`
- `core/aggregate/inventory/`
- `core/aggregate/controlbacklog/`
- `docs/examples/`
- `scenarios/wrkr/ownership-quality/`
- `internal/scenarios/ownership_quality_scenario_test.go`

Run commands:
- `go test ./core/owners ./core/source/github ./core/source/org ./core/aggregate/inventory ./core/aggregate/controlbacklog -count=1`
- `go test ./internal/scenarios -run 'TestOwnershipQuality' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`

Test requirements:
- Parser tests for CODEOWNERS, custom mappings, Backstage/service catalog fixtures.
- Conflict resolution tests with deterministic tie-breaking.
- Source adapter parity tests for available GitHub ownership metadata.
- Scenario tests for explicit, inferred, conflicting, and missing owners.

Matrix wiring:
- Fast lane: owners/source/inventory tests.
- Acceptance lane: ownership quality scenario.
- Risk lane: `make test-contracts`, `make prepush-full`.

Acceptance criteria:
- Backlog items distinguish explicit, inferred, conflicting, and missing owners.
- Ownership confidence drives backlog evidence gaps and SLA.
- Local/offline scans work without GitHub owner metadata.
- Conflicting owner data is surfaced as a governance gap, not silently resolved.

Changelog impact: required

Changelog section: Added

Draft changelog entry: Added enterprise ownership resolution with explicit, inferred, conflicting, and missing owner states plus ownership confidence in governance outputs.

Semver marker override: none

Contract/API impact:
- Adds ownership fields and optional owner mapping config surfaces.

Versioning/migration impact:
- Existing owner fields remain; new owner quality metadata is additive.

Architecture constraints:
- Vendor/source schemas must be isolated behind owner/source adapter boundaries.
- Fallback owner rules must be deterministic and documented.
- Optional network-derived metadata must not alter offline default behavior.

ADR required: yes

TDD first failing test(s):
- `TestResolveOwnershipFromCustomMappingBeforeFallback`.
- `TestConflictingOwnersLowerConfidenceAndCreateEvidenceGap`.

Cost/perf impact: medium

Chaos/failure hypothesis:
- If external ownership metadata is unavailable or stale, Wrkr falls back deterministically and marks confidence/evidence gaps rather than failing the entire scan.

### Story W4-S2: Improve Large-Org Operator UX And Scan Status

Priority: P1

Tasks:
- Add phase timing and current phase/repo count to scan progress on stderr.
- Persist last successful phase and partial result marker for interrupted org scans.
- Add `wrkr scan status --state <path> --json` or equivalent subcommand with deterministic status output.
- Document `nohup`/background pattern if `--background` is not implemented; avoid hidden daemons.
- Ensure `--quiet`, `--json`, and `--explain` interactions remain contract-tested.
- Add failure footer with last successful phase and artifact paths.

Repo paths:
- `core/cli/scan.go`
- `core/cli/scan_progress_test.go`
- `core/state/`
- `core/source/org/`
- `internal/e2e/source/`
- `docs/commands/scan.md`
- `docs/examples/operator-playbooks.md`

Run commands:
- `go test ./core/cli ./core/state ./core/source/org -count=1`
- `go test ./internal/e2e/source -count=1`
- `make test-hardening`
- `make test-chaos`
- `make test-perf`
- `make prepush-full`

Test requirements:
- CLI stdout/stderr separation tests.
- Lifecycle/status tests for completed, running, interrupted, partial, and failed scans.
- Crash-safe/atomic status update tests.
- Contention/concurrency tests for status reads during scan writes.
- Perf tests on large synthetic org manifests.

Matrix wiring:
- Fast lane: CLI/state/source tests.
- Core CI lane: e2e source tests.
- Cross-platform lane: Windows status-path smoke.
- Risk lane: `make test-hardening`, `make test-chaos`, `make test-perf`, `make prepush-full`.

Acceptance criteria:
- JSON stdout remains clean for `wrkr scan --json`.
- Progress, phase timing, warnings, and failure footer go to stderr.
- Interrupted scans preserve a deterministic partial state marker and last successful phase.
- `wrkr scan status --json` can describe the last scan without rescanning.

Changelog impact: required

Changelog section: Added

Draft changelog entry: Added large-org scan progress, phase timing, partial-result status, and scan status inspection without changing JSON stdout contracts.

Semver marker override: none

Contract/API impact:
- Adds scan status command/subcommand and status JSON fields.

Versioning/migration impact:
- Existing state files report status as unknown or completed based on available snapshot fields.

Architecture constraints:
- No hidden background daemon by default.
- Status writes must be atomic and readable under contention.
- Cancellation/timeouts must propagate through source acquisition and detector execution.

ADR required: yes

TDD first failing test(s):
- `TestScanJSONProgressOnlyOnStderr`.
- `TestScanStatusReportsInterruptedPartialPhase`.

Cost/perf impact: medium

Chaos/failure hypothesis:
- If an org scan is interrupted while writing state, the next status read returns partial/interrupted metadata and does not corrupt the prior completed snapshot.

## Epic Wave 5: Reports And Work Export

Objective:
- Turn governance outputs into customer-ready artifacts and work items after the core contract/runtime behavior is stable.

### Story W5-S1: Add Native Customer Report Templates Led By Control Backlog

Priority: P2

Tasks:
- Add report templates: `ciso`, `appsec`, `platform`, `audit`, `customer-draft`.
- Generate PDF, Markdown, JSON evidence bundle, and CSV backlog from a single report command.
- Lead every report with the control backlog and move raw findings to an appendix.
- Add redaction/public share-profile handling for customer-draft reports.
- Update report docs, examples, and acceptance fixtures.

Repo paths:
- `core/cli/report.go`
- `core/report/`
- `core/report/templates/`
- `core/export/appendix/`
- `core/export/inventory/`
- `internal/acceptance/report_pdf_acceptance_test.go`
- `internal/scenarios/epic9_scenario_test.go`
- `docs/commands/report.md`
- `docs/examples/security-team.md`

Run commands:
- `go test ./core/report ./core/export/appendix ./core/export/inventory ./core/cli -count=1`
- `go test ./internal/acceptance -run 'TestReportPDFAcceptance|TestV1Acceptance/AC21' -count=1`
- `go test ./internal/scenarios -run 'TestEpic9' -count=1 -tags=scenario`
- `scripts/check_docs_cli_parity.sh`
- `make test-perf`
- `make prepush-full`

Test requirements:
- Template parsing tests.
- Deterministic PDF/Markdown repeat-run tests.
- CSV backlog golden tests.
- Redaction tests for public/customer-draft share profile.
- Docs consistency checks.

Matrix wiring:
- Fast lane: report/export/CLI package tests.
- Acceptance lane: PDF and report scenarios.
- Cross-platform lane: artifact path smoke.
- Risk lane: `make test-perf`, `make prepush-full`.

Acceptance criteria:
- `wrkr report --template ciso --pdf --md --json` returns artifact paths and deterministic summary payload.
- Report starts with control backlog, not raw findings.
- CSV backlog includes owner, evidence, recommended action, SLA, and closure criteria.
- Public/customer-draft reports do not leak secret values or sensitive local paths.

Changelog impact: required

Changelog section: Added

Draft changelog entry: Added customer-ready CISO, AppSec, platform, audit, and customer-draft report templates led by the governance control backlog.

Semver marker override: none

Contract/API impact:
- Adds report template enum values and artifact bundle JSON fields.

Versioning/migration impact:
- Existing report templates continue to work as compatibility aliases.

Architecture constraints:
- Report rendering consumes state/backlog summaries and does not call detectors.
- Artifact writes use managed path safety and deterministic rendering.
- Raw findings must stay appendix-only for these templates.

ADR required: no

TDD first failing test(s):
- `TestReportTemplateCISOLeadsWithControlBacklog`.
- `TestCustomerDraftReportRedactsSensitiveEvidence`.

Cost/perf impact: medium

Chaos/failure hypothesis:
- If one artifact in a report bundle fails to write, the command returns a deterministic error and does not claim the bundle is complete.

### Story W5-S2: Add Ticket Export With Offline Dry-Run First

Priority: P2

Tasks:
- Add `wrkr export tickets --top <n> --format jira|github|servicenow --dry-run --json`.
- Export ticket payloads with owner, repo, path, control-path type, capability, evidence, recommended action, SLA, closure criteria, confidence, and proof requirements.
- Add explicit opt-in adapter execution later or behind separate flags; default is local JSON/CSV/Markdown payload generation.
- Add deterministic grouping/deduping by owner/repo/control path.
- Add simulated adapter fixtures only if network execution is included in implementation scope.

Repo paths:
- `core/cli/export.go`
- `core/export/tickets/`
- `core/aggregate/controlbacklog/`
- `internal/e2e/cli_contract/`
- `docs/commands/export.md`
- `docs/examples/operator-playbooks.md`
- `scenarios/wrkr/ticket-export/`

Run commands:
- `go test ./core/export/tickets ./core/aggregate/controlbacklog ./core/cli -count=1`
- `go test ./internal/e2e/cli_contract -count=1`
- `go test ./internal/scenarios -run 'TestTicketExport' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`

Test requirements:
- CLI help/usage tests.
- JSON schema/golden tests for Jira/GitHub/ServiceNow payload formats.
- Deterministic grouping/deduping tests.
- Invalid format and missing backlog error-envelope tests.
- Dry-run no-network tests.

Matrix wiring:
- Fast lane: export/CLI package tests.
- Core CI lane: e2e CLI contract.
- Acceptance lane: ticket export scenario.
- Risk lane: `make test-contracts`, `make prepush-full`.

Acceptance criteria:
- `wrkr export tickets --top 10 --format jira --dry-run --json` emits deterministic local ticket payloads and makes no network calls.
- Each ticket includes owner, evidence, recommended action, SLA, and closure criteria.
- Unsupported formats exit `6` with `invalid_input`.
- Ticket exports can be generated from saved state without rescanning.

Changelog impact: required

Changelog section: Added

Draft changelog entry: Added offline-first ticket export payloads for Jira, GitHub Issues, and ServiceNow from top governance backlog items.

Semver marker override: none

Contract/API impact:
- Adds export subcommand/format and ticket export JSON schema.

Versioning/migration impact:
- Add `ticket_export_version: "1"` to exported payloads.

Architecture constraints:
- Exporters consume control backlog state and never run detectors.
- Network adapters must be explicit opt-in and fail closed on missing credentials.
- Default dry-run path is deterministic and offline.

ADR required: yes

TDD first failing test(s):
- `TestExportTicketsDryRunDoesNotUseNetwork`.
- `TestTicketPayloadIncludesClosureCriteriaAndSLA`.

Cost/perf impact: low

Chaos/failure hypothesis:
- If adapter configuration is missing or unavailable, dry-run remains usable and opt-in send mode fails closed with a machine-readable dependency error.

## Minimum-Now Sequence

Wave 1:
- Implement W1-S1, W1-S2, W1-S3, and W1-S4.
- This wave creates the public vocabulary and suppresses large-scale-organization scan noise before changing downstream reports or workflows.
- Required gates: targeted tests, `make test-contracts`, scenario fixtures, `make prepush-full`, and `make test-perf` for scan modes/noise.

Wave 2:
- Implement W2-S1, W2-S2, and W2-S3.
- This wave makes governance backlog visible by default and adds write-path/control/visibility semantics.
- Required gates: CLI contract, acceptance, scenarios, contract tests, and risk lane.

Wave 3:
- Implement W3-S1, W3-S2, and W3-S3.
- This wave turns backlog items into lifecycle-managed controls with proof and drift.
- Required gates: hardening, chaos, contract, scenario, interop, and prepush-full.

Wave 4:
- Implement W4-S1 and W4-S2.
- This wave improves enterprise accuracy and scan operability for large orgs.
- Required gates: source/owner scenarios, hardening, chaos, perf, and cross-platform smoke.

Wave 5:
- Implement W5-S1 and W5-S2.
- This wave packages governance output into customer reports and work exports after the underlying contracts are stable.
- Required gates: report acceptance, ticket export scenarios, docs parity, perf, and contract tests.

## Explicit Non-Goals

- No dashboard-first scope in this backlog.
- No Axym or Gait product feature implementation in this repository.
- No LLM calls in scan, risk, proof, reporting, or ticket export paths.
- No default network ticket creation or notification sending.
- No secret value extraction or secret value output.
- No replacement of SAST, SCA, or secret scanning as Wrkr's product lane.
- No removal of existing raw finding JSON fields during this plan.
- No broad refactor that collapses source, detection, aggregation, identity, risk, proof, and compliance boundaries.
- No generated binary, transient scan report, or customer data commit.

## Definition of Done

- Every recommendation R1-R20 maps to at least one merged story.
- Every new CLI surface has help text, command docs, JSON tests, and exit-code tests.
- Every schema/artifact change has versioning, compatibility, and golden tests.
- Every governance output is deterministic across repeated runs except explicit timestamp/version fields.
- Every risk-bearing story has failure-mode tests and runs `make prepush-full`.
- Approval and evidence mutations are atomic, rollback-safe, and proof-verifiable.
- Raw findings remain accessible while default operator/customer views lead with the control backlog.
- Secret-bearing automation language distinguishes references from leaked values and never emits secret values.
- Generated/package noise is suppressed by default or moved to scan quality.
- Reports and ticket exports are offline-first and backlog-led.
- Docs, README positioning, trust docs, and command references match implemented behavior.
- `CHANGELOG.md` `## [Unreleased]` can be updated from the story-level changelog fields without re-deciding semver intent.

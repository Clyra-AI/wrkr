# wrkr report

## Synopsis

```bash
wrkr report [--json] [--explain] [--md] [--md-path <path>] [--pdf] [--pdf-path <path>] [--evidence-json] [--evidence-json-path <path>] [--csv-backlog] [--csv-backlog-path <path>] [--template exec|operator|audit|public|ciso|appsec|platform|customer-draft|agent-action-bom|design-partner-summary] [--share-profile internal|public|customer-redacted|design-partner|external-redacted|investor-safe] [--redact <fields>] [--baseline <path>] [--previous-state <path>] [--top <n>] [--state <path>]
```

## Flags

- `--json`
- `--explain`
- `--md`
- `--md-path`
- `--pdf`
- `--pdf-path`
- `--evidence-json`
- `--evidence-json-path`
- `--csv-backlog`
- `--csv-backlog-path`
- `--template`
- `--share-profile`
- `--redact`
- `--baseline`
- `--previous-state`
- `--top`
- `--state`

## Example

```bash
wrkr report --md --md-path ./.tmp/wrkr-summary.md --template operator --share-profile internal --json
wrkr report --pdf --pdf-path ./.tmp/wrkr-summary.pdf --template exec --json
wrkr report --md --md-path ./.tmp/wrkr-summary-public.md --template public --share-profile public --json
wrkr report --template agent-action-bom --share-profile customer-redacted --md --md-path ./.tmp/customer-bom.md --evidence-json --evidence-json-path ./.tmp/customer-bom.json --json
wrkr report --template design-partner-summary --share-profile design-partner --md --md-path ./.tmp/design-partner.md --evidence-json --evidence-json-path ./.tmp/design-partner-evidence.json --json
wrkr report --template agent-action-bom --share-profile internal --redact owners,repos,paths --json
wrkr report --template ciso --md --md-path ./.tmp/ciso.md --pdf --pdf-path ./.tmp/ciso.pdf --evidence-json --evidence-json-path ./.tmp/evidence.json --csv-backlog --csv-backlog-path ./.tmp/backlog.csv --json
wrkr report --template agent-action-bom --json --evidence-json --evidence-json-path ./.tmp/agent-action-bom-evidence.json
```

## Behavior contract

wrkr report renders deterministic summaries from saved scan state without changing JSON or exit-code contracts.
wrkr report --pdf writes a deterministic PDF artifact with wrapped, paginated executive-summary output; the board-ready claim is acceptance-backed by explicit executive report fixtures.

Expected JSON keys: `status`, `generated_at`, additive `next_steps`, `top_findings`, `attack_paths`, `top_attack_paths`, additive `action_paths`, additive `agent_action_bom`, additive `action_path_to_control_first`, additive `action_surface_registry`, additive `control_path_graph`, additive `runtime_evidence`, additive `assessment_summary`, additive `exposure_groups`, `total_tools`, `tool_type_breakdown`, `compliance_gap_count`, `compliance_summary`, `summary`, `md_path`, `pdf_path`, additive `evidence_json_path`, additive `backlog_csv_path`, and additive `artifact_paths`.
`summary.share_profile_metadata` is additive metadata describing whether deterministic redaction was applied, which redaction version produced the artifact, the high-level policy summary for that share profile, and the selected/profile-default redaction fields that shaped the artifact.
`summary.scan_scope` is additive buyer-facing scope metadata for the saved target mode, scope label, source boundary, repo count, and target count.
`summary.operational_exposure` and `summary.governance_readiness` are additive split readiness axes. They separate what a path can operationally do from how complete its ownership/approval/policy/proof posture is.
`assessment_summary` is additive at the top level and under `summary` when govern-first action paths are present; it leads with governable-path counts, the top path to control first, the strongest identity-backed path, additive `ownerless_exposure` counts, additive `identity_exposure_summary`, additive `identity_to_review_first` / `identity_to_revoke_first`, and the saved proof-chain path.
`summary.attack_paths` provides deterministic attack-path section metadata (`total`, `top_path_ids`) used in report templates and external appendix joins.
`compliance_summary.frameworks[*].controls[*]` exposes additive framework/control/article rollups with deterministic `finding_count`, `mapped_rule_ids`, and coverage status.
`summary.compliance_summary` mirrors the same machine-readable contract used by report markdown/PDF generation.
When the saved scan target is `my_setup`, `summary.activation` exposes the same additive concrete-first activation view used by the local-machine scan flow.
When the saved scan target is `org` or `path`, `summary.activation` exposes the additive govern-first candidate path view used by the scan flow.
`summary.action_paths` and top-level `action_paths` expose the ranked govern-first path objects, including additive delivery-chain fields such as `pull_request_write`, `merge_execute`, `deploy_write`, `delivery_chain_status`, and `production_target_status`, ownership/governance fields such as `operational_owner`, `owner_source`, `ownership_status`, and `approval_gap_reasons`, additive canonical evidence-state fields `control_resolution_state`, `control_resolution_reasons`, `control_evidence_refs`, `approval_evidence_state`, `owner_evidence_state`, `proof_evidence_state`, `runtime_evidence_state`, `target_evidence_state`, and `credential_evidence_state`, additive execution-identity fields such as `execution_identity`, `execution_identity_type`, `execution_identity_source`, `execution_identity_status`, and `execution_identity_rationale`, additive path-semantics fields such as `business_state_surface`, `shared_execution_identity`, `path_context`, `standing_privilege`, `standing_privilege_reasons`, `action_classes`, `action_reasons`, and additive `mutable_endpoint_semantics[]`, additive buyer-facing fields `control_state`, `control_state_reasons`, `risk_zone`, `risk_zone_reasons`, `review_burden`, `review_burden_reasons`, and additive `confidence_lane` / `confidence_lane_reasons`, additive tool identity fields `tool_family_id` and `tool_instance_id`, additive normalized `credential_authority`, additive purpose/version/config metadata (`purpose`, `purpose_source`, `purpose_confidence`, `version`, `version_source`, `config_fingerprint`, `config_source`), additive `action_lineage.segments[]`, additive join refs `attack_path_refs` and `source_finding_keys`, additive `gait_coverage` per path, and additive `credential_provenance` compatibility rollup plus `credentials[]` entries (`type`, `subject`, `scope`, `confidence`, `evidence_basis`, `credential_kind`, `access_type`, `standing_access`, `likely_jit`, `evidence_location`, `classification_reasons`, `risk_multiplier`). Purpose metadata uses explicit `wrkr:purpose` annotations as the highest-confidence source when available, then falls back to deterministic workflow, MCP, script, symbol, and location evidence. `attack_path_score` is now path-linked: high attack-path scores attach only to matching govern-first paths instead of being smeared across every path in the same repo. `summary.action_path_to_control_first` / top-level `action_path_to_control_first` expose one prioritized path plus additive summary counters for credential-bearing, standing-privilege, control-first, lane, and evidence-state counts, along with additive `empty_state_status` / `empty_state_reasons` metadata. Legacy counters such as `missing_approval_paths`, `missing_policy_paths`, and `missing_proof_paths` remain compatibility aliases derived from the canonical evidence-state projection.
`summary.scan_quality` carries the saved scan-quality contract into report output so buyers can distinguish clean negative results from partial, reduced, or blocked detector coverage without opening raw scan state. `summary.scan_quality.detectors[*]` exposes attempted/parsed/partial/suppressed/failure counts and deterministic `coverage_reasons`.
`summary.agent_action_bom` and top-level `agent_action_bom` expose the canonical Agent Action BOM artifact for operator and demo workflows. Use `wrkr report --template agent-action-bom --json` when you want one joined artifact that leads with risky agent actions, graph refs, proof refs, runtime evidence correlation, and next-action priority. Raw scan JSON remains the discovery surface; graph-shaped BOM output is canonical in `report`.
Agent Action BOM `proof_coverage`, canonical evidence-state fields, and compatibility aliases such as `summary.missing_proof_items` reflect path-linked proof sufficiency from control-backlog requirements. A valid proof chain or visible top-level `proof_refs` does not by itself mean every risky path has satisfied approval, review, least-privilege, or attached-evidence proof. `agent_action_bom.proof_refs` remains the global chain/finding reference set; each item’s `proof_refs` is path-specific and may include `path:*`, `finding:*`, and linked proof-record refs only for that exact path context.
Agent Action BOM items and additive `action_paths` now carry deterministic policy-coverage context (`none`, `declared`, `matched`, `runtime_proven`, `stale`, `conflict`), canonical evidence-state fields, buyer-facing `control_state` (`safe_by_default`, `approval_required`, `block_recommended`, `evidence_required`, `inventory_only`), explicit `risk_zone`, explicit `review_burden`, additive confidence lanes (`confirmed_action_path`, `likely_action_path`, `semantic_review_candidate`, `context_only`), additive normalized `credential_authority`, additive purpose/version/config metadata, additive `mutable_endpoint_semantics[]`, additive `action_lineage.segments[]` from repo/workflow through credential/target/approval/proof joins, path-level `gait_coverage` for `policy_decision`, `approval`, `jit_credential`, `freeze_window`, `kill_switch`, `action_outcome`, and `proof_verification`, and optional `introduced_by` provenance metadata. When local provenance sidecars such as `.wrkr/provenance/source-metadata.json`, `.wrkr/provenance/github-event.json`, `.wrkr/provenance/gitlab-event.json`, or `.wrkr/provenance/control-metadata.json` are present, Wrkr prefers those deterministic repo-local records before falling back to local git attribution for metadata that came from provided sidecars. Buyer-facing markdown uses evidence-scoped language such as `approval evidence not found`, `owner evidence is unknown`, and `path-specific proof not found` instead of claiming enterprise controls are absent outside the scanned or provided evidence. Wrkr reports coverage and evidence only; Gait remains the enforcement layer.
`agent_action_bom.summary.empty_state_status` and `empty_state_reasons` are additive buyer-facing guardrails. They replace the old “no control-first items means positive empty state” shortcut with explicit reason-coded eligibility that also considers standing credentials, proof/policy gaps, unresolved ownership, confidence lanes, and reduced scan coverage.
Workflow-backed credential rollups now distinguish built-in `github_workflow_token` posture from durable PAT-style references when deterministic workflow metadata is available.
When deterministic MCP/A2A joins exist, BOM items expose both compatibility `reachability[]` entries and buyer-facing `reachable_servers[]`, `reachable_tools[]`, additive `reachable_endpoints[]`, additive `reachable_targets[]`, `reachable_apis[]`, and `reachable_agents[]` projections with trust-depth metadata and evidence refs. These fields describe static declaration reachability, not live endpoint observation.
Buyer-facing BOM items now also carry additive `confidence` and `evidence_strength` labels so dependency-only, constructor-only, tool-binding, credential-bearing, and workflow-backed paths read differently in customer handoff output.
Agent Action BOM items also carry buyer-facing `queue`, `finding_visibility`, and `remediation` fields, plus additive `inventory_risk`, `risk_tier`, `credentials[]`, `path_context`, `tool_family_id`, `tool_instance_id`, `attack_path_refs`, `source_finding_keys`, and optional `exclusion_reason`. When a top attack path does not map to any govern-first action path, Wrkr emits a deterministic exclusion item instead of silently dropping the path from the BOM.
`agent_action_bom.scan_quality` mirrors the same detector-health summary when the BOM artifact is present, which keeps MCP/WebMCP “nothing found” claims auditable in customer-ready exports.
`summary.action_paths[*].path_id` and `summary.action_path_to_control_first.path.path_id` remain opaque deterministic identifiers currently emitted in `apc-<hex>` form. Use them as stable join keys only; consumers must not parse business meaning from the string.
`summary.action_surface_registry` and top-level `action_surface_registry` group ranked paths by workflow, MCP server, agent config, API schema, or route surface. Each entry carries stable `registry_id`, grouped `path_ids`, owner, purpose, version/config metadata, merged credential authority, reachable actions, additive `mutable_endpoint_semantics[]`, proof status, confidence lane, remediation, and graph refs for buyer-ready drill-down without re-running detectors.
`summary.control_path_graph` and top-level `control_path_graph` expose the versioned governance graph Wrkr derives from action-path identity, credential, tool, workflow, repo, governance-control, target, and action-capability facts. Nodes and edges now also carry additive `attack_path_refs`, `source_finding_keys`, node-level `lineage_segment`, additive purpose/version/config metadata, additive `credential_authority` on credential nodes when Wrkr can deterministically join them, and additive `mutable_endpoint_semantics[]` on path-linked nodes when static endpoint classification is available. Use `nodes[*].path_id` / `edges[*].path_id` plus `action_paths[*].path_id`, `attack_path_refs`, and `source_finding_keys` as stable join keys only; consumers must not parse business meaning from node or edge identifiers.
When `wrkr ingest` has written a managed runtime evidence sidecar next to the selected state file, `summary.runtime_evidence` and top-level `runtime_evidence` expose deterministic path/agent/runtime correlation metadata without mutating saved scan findings. Both fields are omitted when runtime evidence is unavailable. Correlations can join by `path_id`, `agent_id`, repo/workflow location, policy ref, and graph refs, and normalized runtime evidence classes include `policy_decision`, `approval`, `jit_credential`, `freeze_window`, `kill_switch`, `action_outcome`, and `proof_verification`.
`summary.exposure_groups` and top-level `exposure_groups` provide additive grouped exposure clusters on top of raw `action_paths`; they preserve `path_ids` for drill-down while summarizing repeated paths by repo, tool, execution identity, delivery-chain status, and business-state surface.
`summary.top_risks` becomes path-first when govern-first `action_paths` exist, but the raw `top_findings` payload remains unchanged for operators and automation.
Customer-ready templates `ciso`, `appsec`, `platform`, `audit`, and `customer-draft` lead with `summary.control_backlog` and render the control backlog before raw risk/finding sections in Markdown/PDF. `agent-action-bom` now leads with scanned scope, source privacy, split readiness axes, coverage confidence, and then the highest-value governable paths. `design-partner-summary` renders a concise top-validated-path narrative with plain-language problem, explanation, threat, remediation, confidence, proof-gap, credential-authority, mutable-endpoint, owner, purpose, and lineage fields while explicitly preserving Wrkr's static-only boundary language. `customer-draft` remains compatible with the public share profile, and operators can now opt into `--share-profile customer-redacted`, `design-partner`, `external-redacted`, or `investor-safe` when they need stable pseudonyms while preserving joins inside one artifact set. `--redact owners,repos,paths,...` adds deterministic pseudonymization on top of the selected share profile. `--csv-backlog` writes a deterministic CSV with owner, evidence, recommended action, SLA, and closure criteria columns. `--evidence-json` writes a deterministic JSON evidence bundle led by the control backlog, additive `action_surface_registry`, additive `agent_action_bom`, and additive `control_path_graph`.
`summary.control_backlog.items[*]` now carry queue and visibility semantics intended for buyer-facing triage: `queue` is one of `control_first`, `review_queue`, `inventory_hygiene`, or `debug_only`; `finding_visibility` is one of `primary`, `appendix`, or `debug`; and `remediation` names the concrete next action Wrkr expects for that path.
`summary.control_backlog.items[*].security_test_recipes` provides deterministic validation recipes for risky control paths, including prompt injection, MCP endpoint swap, egress attempt, destructive action dry-run, untrusted repo content, and secret-scope validation classes where applicable.
`summary.security_visibility` exposes additive reference-basis and `unknown_to_security` counts sourced from the saved scan state.
When the saved scan state does not carry a usable `reference_basis`, report output suppresses `unknown_to_security` claims and surfaces `reference_basis unavailable` wording instead.
`wrkr report` renders from saved scan state only. It summarizes static posture, risky write paths, and proof artifacts; it does not claim live runtime observation or control-layer enforcement.
Manual `identity` and `inventory` approvals refresh the saved backlog, action-path posture, and posture score in place, so `wrkr report --state <path> --json` reflects those decisions without a rescanning step.
`next_steps[]` is additive machine-readable handoff guidance for the operator-to-auditor path. It points to current report artifact fields, the follow-on `wrkr evidence --json` flow, and the explicit proof-verification step.

Public template behavior (`--template public --share-profile public`):

- `summary.section_order` starts with headline then methodology.
- `summary.methodology` includes machine-readable reproducibility metadata (`wrkr_version`, scan window, repo/file counts, command set, and exclusion criteria).
- built-in production-target packs classify common deploy, Terraform/IaC, Kubernetes, package publishing, release automation, database migration, and customer-impacting workflows by default; custom scan-time production-target policy files remain authoritative when supplied.
- when saved-state security visibility lacks a usable reference basis, public/report wording suppresses `unknown_to_security` counts instead of fabricating them.
- share-profile redaction is applied to public-facing risk/proof fields.

`--explain` emits short deterministic compliance mapping lines sourced from the same `compliance_summary` payload.
When current findings do not yet map to bundled controls, the explain/report summary says bundled framework mappings are available and that current coverage still reflects only evidence present in the saved scan state.

## Coverage semantics

Report compliance/posture values are derived from evidence present in the current scan state.

- Low compliance/coverage in report output indicates control evidence gaps in the scanned snapshot.
- Low compliance/coverage does not imply Wrkr lacks framework support.
- Use report findings as remediation priorities, then remediate gaps, rerun deterministic scan/evidence/report commands, and confirm improvement from the updated evidence state.

---
title: "Contracts and Schemas"
description: "Reference index for Wrkr command contracts, schema assets, and proof interoperability surfaces."
---

# Contracts and Schemas

## Scan Governance Additions

`wrkr scan --json` includes additive governance-first artifacts while preserving existing raw finding and inventory surfaces.

- `control_backlog.control_backlog_version = "1"` identifies the backlog schema.
- `control_backlog.items[*].signal_class` is one of `unique_wrkr_signal` or `supporting_security_signal`.
- `control_backlog.items[*].recommended_action` is one of `attach_evidence`, `approve`, `remediate`, `downgrade`, `deprecate`, `exclude`, `monitor`, `inventory_review`, `suppress`, or `debug_only`.
- `control_backlog.items[*].confidence` is one of `high`, `medium`, or `low`.
- `control_backlog.items[*].linked_control_path_node_ids` / `linked_control_path_edge_ids` are additive graph join keys tied to the versioned `control_path_graph`.
- `agent_privilege_map[*].credential_provenance` and `action_paths[*].credential_provenance` use stable enums: `static_secret`, `workload_identity`, `inherited_human`, `oauth_delegation`, `jit`, and `unknown`.
- `control_path_graph.version = "1"` identifies the additive governance graph schema in saved state, report JSON, and evidence bundles.
- `control_backlog.items[*].write_path_classes` may include `read`, `write`, `pr_write`, `repo_write`, `release_write`, `package_publish`, `deploy_write`, `infra_write`, `secret_bearing_execution`, and `production_adjacent_write`.
- `control_backlog.items[*].governance_controls[*].control` is one of `owner_assigned`, `approval_recorded`, `least_privilege_verified`, `rotation_evidence_attached`, `deployment_gate_present`, `production_access_classified`, `proof_artifact_generated`, or `review_cadence_set`; `status` is `satisfied`, `gap`, or `not_applicable`.
- Governance backlog visibility may use `known_approved`, `known_unapproved`, `unknown_to_security`, `accepted_risk`, `deprecated`, `revoked`, or `needs_review`. Legacy inventory surfaces still accept the historic `approved` compatibility value.
- `scan_quality.scan_quality_version = "1"` identifies the scan-quality appendix schema.
- `scan_quality.mode` is one of `quick`, `governance`, or `deep`.
- `scan_quality.parse_errors[*].recommended_action` is `suppress` for generated/package-manager noise and `debug_only` for parser diagnostics that should stay outside the active governance backlog.

These fields are additive. Consumers that depend on `findings`, `ranked_findings`, `top_findings`, `inventory`, `profile`, `posture_score`, and `compliance_summary` can continue to read those fields unchanged.

Secret-bearing workflow semantics are also additive. Workflow references such as `${{ secrets.NAME }}` are classified as `secret_reference_detected` and may combine with `secret_used_by_write_capable_workflow`; they must not be treated as `secret_value_detected` unless a detector explicitly proves a value was exposed.

## Evidence-state contract model

Wrkr's public report, backlog, risk, and evidence contracts now lead with evidence-scoped control posture.

- `control_resolution_state` is one of `detected_control`, `declared_control`, `external_control_reference`, `no_visible_control`, `not_applicable`, or `contradictory_control`.
- Canonical `approval_evidence_state`, `owner_evidence_state`, `proof_evidence_state`, `runtime_evidence_state`, `target_evidence_state`, and `credential_evidence_state` are one of `verified`, `declared`, `inferred`, `unknown`, or `contradictory`.
- `target_class` is one of `production_impacting`, `release_adjacent`, `customer_data_adjacent`, `internal_tooling`, `developer_productivity`, `test_demo_sandbox`, or `unknown`.
- `action_path_type` is one of `ai_assisted_workflow`, `agent_framework`, `automation_bot`, `ci_cd_workflow`, `legacy_script`, `plain_source_code`, or `unknown_executable_path`.
- Coverage-qualified absence surfaces use `not_found_with_complete_coverage`, `not_found_with_reduced_coverage`, `not_scanned`, `unsupported_surface`, or `candidate_parse_failed`.
- Runtime absence surfaces use `not_collected`, `not_applicable`, `missing_required`, or `missing_for_control_claim`.

Compatibility aliases such as `missing_approval_paths`, `missing_policy_paths`, `missing_proof_paths`, and older `approval_gap` surfaces remain additive compatibility shims in v1, but they are derived from the canonical evidence-state projection rather than serving as independent truth.

## Enterprise Evidence Contracts

Wrkr's Sprint 2 enterprise-evidence surface stays local-file based and deterministic.

- `schemas/v1/evidence/external-control-evidence.schema.json` is the public v1 sidecar contract for imported ownership, approval, branch protection, deployment approvals, required checks, freeze windows, kill switches, and other external control evidence.
- `wrkr-control-declarations.yaml` and `.wrkr/control-declarations.yaml` are versioned declaration inputs for owner mappings, target classes, non-production declarations, and declared control links.
- `action_paths[*].evidence_decisions[]` and `agent_action_bom.items[*].evidence_decisions[]` preserve source precedence, freshness, selected evidence, and rejected lower-precedence candidates instead of flattening imported evidence to one opaque winner.
- `action_paths[*].contradictions[]`, `closure_requirements`, `lifecycle_queue`, and `evidence_completeness` keep enterprise conflicts, required closure evidence, lifecycle ownership gaps, and sufficiency scoring explicit across report, BOM, and risk surfaces.
- Accepted governance dispositions stay auditable: `accepted_risk` and suppression metadata remain visible in JSON/report artifacts instead of deleting evidence.
- Evidence completeness is not risk scoring. Low `evidence_completeness` means Wrkr needs more evidence for the current conclusion, not that the path is safe.
- Canonical source precedence is documented and deterministic: provider export, signed declaration, repo-local policy/config, app catalog ownership, git/review inference, then naming-convention or repo fallback.
- `agent_action_bom.summary.primary_view` is the focused workflow-BOM contract for Sprint 3 buyer output. It carries the selected `path_id`, selection reason, path map, evidence/control posture, additive `risk_tier`, additive concise `recommended_next_actions[]`, additive `coverage_status` (`complete`, `reduced`, `not_scanned`, or `unsupported_surface`), and appendix refs without removing the full `agent_action_bom.items[*]` detail surface.
- `summary.repeat_usage_signals` and `agent_action_bom.summary.repeat_usage_signals` are additive privacy-safe local-repeatability counters for baselines, assess reruns, regress artifacts, evidence exports, ticket exports, and action-contract exports.

## Canonical references

- `mutable_endpoint_semantic_refs`, `credential_authority_ref`, and `authority_binding_refs` are the stable join contract for repeated risk, backlog, graph, and report projections.
- `inventory.canonical_stores` is the authoritative per-scan store for full mutable-endpoint, credential-authority, and authority-binding detail.
- Shareable/default report and BOM projections keep the canonical ref fields and omit embedded `mutable_endpoint_semantics`, `credential_authority`, and `authority_bindings` payloads; explicit `--share-profile internal` output may resolve those fields from the canonical store for non-shareable detail views.
- Report-style workflows now default to a redacted share profile (`customer-redacted`, `public`, or `design-partner` depending on template). Explicit internal output is marked `artifact_metadata.shareability_status=internal_only`.

- Root exit codes and flags: `docs/commands/root.md`
- Command contract index: `docs/commands/index.md`
- Manifest open specification: `docs/specs/wrkr-manifest.md`
- JSON schemas: `schemas/v1/`
  - `schemas/v1/control-path-graph.schema.json`

## Command anchors

```bash
wrkr manifest generate --json
wrkr export --format inventory --json
wrkr verify --chain --json
```

## Compatibility posture

Within the same major contract line, additive fields are expected to remain backward compatible for consumers that ignore unknown optional fields.
Command-specific validators may still reject inputs that never matched the documented contract, for example non-scan JSON passed to `wrkr campaign aggregate`.

## Drift-review contract model

Wrkr's recurring drift-review surface is baseline-backed and fail-closed by design.

- `schemas/v1/regress/regress-baseline.schema.json` now carries additive `action_paths_captured` and normalized `action_paths[]` state so `wrkr regress` can compare stable workflow/action-path posture across reruns.
- `schemas/v1/regress/regress-result.schema.json` now carries additive `comparison_status`, `comparison_issues[]`, `drift_category_count`, and `drift_categories[]` with stable categories such as `new_write_paths`, `new_deploy_paths`, `new_credentials`, `new_unknown_approval_evidence`, `resolved_gaps`, `worsened_paths`, `new_contradictions`, `paths_ready_for_control`, `removed_paths`, `changed_authority`, `changed_evidence`, and `changed_target_class`.
- `summary.regress_drift` mirrors the same additive drift-category model inside `wrkr report --json` and report evidence artifacts.
- `agent_action_bom.summary.drift_review` mirrors the same additive drift-category model inside buyer-facing workflow-first report output.
- `assessment-manifest.json` stage metadata now carries additive `comparison_status` and `drift_category_count` on `stages.regress` so repeatable assessment workflows can distinguish clean drift review from unavailable baseline comparison data.

## Q&A

### Where are Wrkr JSON schemas and contracts defined?

Schemas live in `schemas/v1/`, while command and flag contracts are documented under `docs/commands/`.

### Which spec defines the Wrkr manifest contract?

`docs/specs/wrkr-manifest.md` is the canonical manifest specification reference.

### How should I design consumers to remain compatible over time?

Treat additive optional fields as non-breaking, validate required fields strictly, and pin expected schema/manifest versions in CI checks.

### Which JSON artifacts are valid inputs to `wrkr campaign aggregate`?

Only complete `wrkr scan --json` artifacts. Other `status=ok` envelopes from commands such as `wrkr version` or `wrkr report` are not valid campaign inputs.

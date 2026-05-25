# Wrkr Schemas v1

This directory contains versioned JSON/YAML schemas for Wrkr runtime and artifact contracts.

- `cli/`: shared CLI success/error envelope contracts.
- `agent-action-bom.schema.json`: canonical Agent Action BOM artifact contract for report and evidence outputs.
- `evidence/external-control-evidence.schema.json`: canonical local sidecar contract for imported ownership, approval, branch, deployment, and policy control evidence.
- Agent Action BOM, report summary, and risk-report schemas now also carry additive policy-coverage, buyer-facing action-path posture (`control_state`, `risk_zone`, `review_burden`), normalized runtime-evidence/Gait coverage projection, additive imported control-evidence correlation metadata (`constraint_evidence_classes`, `constraint_evidence_refs`, external-control record counts, repo/service/workflow/environment correlation keys), optional `introduced_by` attribution fields, and the additive `github_workflow_token` credential kind used by the demo-readiness control-loop workflows.
- `findings/`: finding and extension-detector descriptor contracts.
- `inventory/` and `risk/`: deterministic privilege, credential-provenance, action-path, and govern-first contracts.
- `manifest/`: open `wrkr-manifest.yaml` interoperability specification.
- `regress/`: posture regression baseline and drift-result contracts.
- `report/`: deterministic shareable report-summary contracts, including additive design-partner summary mode, expanded share-profile metadata, action-surface registry remediation, and field-selection redaction metadata.

Canonical enum additions in the v1 schema line include:

- `control_resolution_state`: `detected_control`, `declared_control`, `external_control_reference`, `no_visible_control`, `not_applicable`, `contradictory_control`
- canonical evidence states: `verified`, `declared`, `inferred`, `unknown`, `contradictory`
- `target_class`: `production_impacting`, `release_adjacent`, `customer_data_adjacent`, `internal_tooling`, `developer_productivity`, `test_demo_sandbox`, `unknown`
- `action_path_type`: `ai_assisted_workflow`, `agent_framework`, `automation_bot`, `ci_cd_workflow`, `legacy_script`, `plain_source_code`, `unknown_executable_path`
- coverage-qualified absence states: `not_found_with_complete_coverage`, `not_found_with_reduced_coverage`, `not_scanned`, `unsupported_surface`, `candidate_parse_failed`
- runtime absence states: `not_collected`, `not_applicable`, `missing_required`, `missing_for_control_claim`

Compatibility aliases can remain present in v1 where existing consumers still expect them, but schema examples and user-facing docs should lead with the canonical evidence-state fields instead of unsupported blanket `missing_*` wording.

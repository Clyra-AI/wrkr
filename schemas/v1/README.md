# Wrkr Schemas v1

This directory contains versioned JSON/YAML schemas for Wrkr runtime and artifact contracts.

- `cli/`: shared CLI success/error envelope contracts.
- `agent-action-bom.schema.json`: canonical Agent Action BOM artifact contract for report and evidence outputs.
- Agent Action BOM, report summary, and risk-report schemas now also carry additive policy-coverage, buyer-facing action-path posture (`control_state`, `risk_zone`, `review_burden`), normalized runtime-evidence/Gait coverage projection, optional `introduced_by` attribution fields, and the additive `github_workflow_token` credential kind used by the demo-readiness control-loop workflows.
- `findings/`: finding and extension-detector descriptor contracts.
- `inventory/` and `risk/`: deterministic privilege, credential-provenance, action-path, and govern-first contracts.
- `manifest/`: open `wrkr-manifest.yaml` interoperability specification.
- `regress/`: posture regression baseline and drift-result contracts.
- `report/`: deterministic shareable report-summary contracts.

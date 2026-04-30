# Wrkr Schemas v1

This directory contains versioned JSON/YAML schemas for Wrkr runtime and artifact contracts.

- `cli/`: shared CLI success/error envelope contracts.
- `agent-action-bom.schema.json`: canonical Agent Action BOM artifact contract for report and evidence outputs.
- Agent Action BOM, report summary, and risk-report schemas now also carry additive policy-coverage, normalized runtime-evidence correlation, and optional `introduced_by` attribution fields used by Wave 3/4 control-loop workflows.
- `findings/`: finding and extension-detector descriptor contracts.
- `inventory/` and `risk/`: deterministic privilege, credential-provenance, action-path, and govern-first contracts.
- `manifest/`: open `wrkr-manifest.yaml` interoperability specification.
- `regress/`: posture regression baseline and drift-result contracts.
- `report/`: deterministic shareable report-summary contracts.

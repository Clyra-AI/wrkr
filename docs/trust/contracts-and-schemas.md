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
- `control_backlog.items[*].write_path_classes` may include `read`, `write`, `pr_write`, `repo_write`, `release_write`, `package_publish`, `deploy_write`, `infra_write`, `secret_bearing_execution`, and `production_adjacent_write`.
- `control_backlog.items[*].governance_controls[*].control` is one of `owner_assigned`, `approval_recorded`, `least_privilege_verified`, `rotation_evidence_attached`, `deployment_gate_present`, `production_access_classified`, `proof_artifact_generated`, or `review_cadence_set`; `status` is `satisfied`, `gap`, or `not_applicable`.
- Governance backlog visibility may use `known_approved`, `known_unapproved`, `unknown_to_security`, `accepted_risk`, `deprecated`, `revoked`, or `needs_review`. Legacy inventory surfaces still accept the historic `approved` compatibility value.
- `scan_quality.scan_quality_version = "1"` identifies the scan-quality appendix schema.
- `scan_quality.mode` is one of `quick`, `governance`, or `deep`.
- `scan_quality.parse_errors[*].recommended_action` is `suppress` for generated/package-manager noise and `debug_only` for parser diagnostics that should stay outside the active governance backlog.

These fields are additive. Consumers that depend on `findings`, `ranked_findings`, `top_findings`, `inventory`, `profile`, `posture_score`, and `compliance_summary` can continue to read those fields unchanged.

Secret-bearing workflow semantics are also additive. Workflow references such as `${{ secrets.NAME }}` are classified as `secret_reference_detected` and may combine with `secret_used_by_write_capable_workflow`; they must not be treated as `secret_value_detected` unless a detector explicitly proves a value was exposed.

## Canonical references

- Root exit codes and flags: `docs/commands/root.md`
- Command contract index: `docs/commands/index.md`
- Manifest open specification: `docs/specs/wrkr-manifest.md`
- JSON schemas: `schemas/v1/`

## Command anchors

```bash
wrkr manifest generate --json
wrkr export --format inventory --json
wrkr verify --chain --json
```

## Compatibility posture

Within the same major contract line, additive fields are expected to remain backward compatible for consumers that ignore unknown optional fields.
Command-specific validators may still reject inputs that never matched the documented contract, for example non-scan JSON passed to `wrkr campaign aggregate`.

## Q&A

### Where are Wrkr JSON schemas and contracts defined?

Schemas live in `schemas/v1/`, while command and flag contracts are documented under `docs/commands/`.

### Which spec defines the Wrkr manifest contract?

`docs/specs/wrkr-manifest.md` is the canonical manifest specification reference.

### How should I design consumers to remain compatible over time?

Treat additive optional fields as non-breaking, validate required fields strictly, and pin expected schema/manifest versions in CI checks.

### Which JSON artifacts are valid inputs to `wrkr campaign aggregate`?

Only complete `wrkr scan --json` artifacts. Other `status=ok` envelopes from commands such as `wrkr version` or `wrkr report` are not valid campaign inputs.

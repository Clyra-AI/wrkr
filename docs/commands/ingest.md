# wrkr ingest

## Synopsis

```bash
wrkr ingest --state ./.wrkr/last-scan.json --input runtime-evidence.json --json
```

`ingest` stores deterministic local evidence beside the saved scan state without mutating scan truth.

## Flags

- `--json`
- `--state`
- `--input`

## Contract

Expected JSON keys: `status`, `artifact_path`, `record_count`, `matched_records`, `unmatched_records`, and additive `runtime_evidence`.

The managed runtime evidence artifact is written next to the selected state file as `runtime-evidence.json`.

Runtime and external-control records are normalized and sorted deterministically. Each record must provide:

- `source`
- `observed_at` in RFC3339 format
- `evidence_class`

External-control sidecars should validate against `schemas/v1/evidence/external-control-evidence.schema.json` and use `record_kind=external_control` plus a deterministic `source_type` such as `provider_export`, `repo_policy`, `app_catalog`, `ticket_export`, or `customer_owner_map`.

Each record must also provide at least one deterministic correlation key: `path_id`, `agent_id`, `repo` + `location`, `repo` + `workflow`, `repo` + `environment`, `service`, `policy_ref`, `proof_ref`, `target`, or graph refs.

Normalized evidence classes:

- `policy_decision`
- `approval`
- `jit_credential`
- `freeze_window`
- `kill_switch`
- `action_outcome`
- `proof_verification`
- `owner_assignment`
- `policy_record`
- `branch_protection`
- `protected_environment`
- `deployment_approval`
- `required_check`
- `security_gate`
- `other` for explicit legacy/unknown carry-through

Additional additive keys may include `tool`, `repo`, `service`, `workflow`, `environment`, `path`, `target`, `action_classes`, `policy_ref`, `proof_ref`, `graph_node_refs`, `graph_edge_refs`, `status`, `issuer`, `valid_until`, `max_age`, `confidence`, `redaction_hints`, `owner`, `required_checks`, `branch`, and `evidence_refs`.

## Safety and failure modes

- Malformed JSON input returns exit `6`.
- Schema or contract violations return exit `3`.
- Unsafe managed output paths return exit `8`.
- Static scan findings remain unchanged; report and evidence commands consume runtime evidence only as corroborating metadata.
- Runtime evidence can promote BOM/report policy coverage to `runtime_proven` without rewriting saved scan findings.
- External control evidence can attach deterministic ownership, approval, branch-protection, protected-environment, required-check, security-gate, freeze-window, and kill-switch refs to govern-first paths without live provider calls.
- Report and Agent Action BOM rendering also project path-level `gait_coverage` status for `policy_decision`, `approval`, `jit_credential`, `freeze_window`, `kill_switch`, `action_outcome`, and `proof_verification`, using `present`, `missing`, `stale`, `conflict`, or `not_applicable` without implying Wrkr enforced the action.
- Buyer-facing runtime absence framing is derived after correlation: static-only paths render `not_collected`, out-of-scope runtime controls render `not_applicable`, matched-path gaps render `missing_required`, and unsupported runtime-backed control claims render `missing_for_control_claim`.
- Ingest can corroborate a control claim with runtime evidence, but it does not convert static lack of runtime evidence into proof that an enterprise control is absent.

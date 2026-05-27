# wrkr ingest

## Synopsis

```bash
wrkr ingest --state ./.wrkr/last-scan.json --input runtime-evidence.json --json
wrkr ingest --state ./.wrkr/last-scan.json --input agentic-evidence-packets.json --json
wrkr ingest --state ./.wrkr/last-scan.json --input codex-session.json --json
```

`ingest` stores deterministic local evidence beside the saved scan state without mutating scan truth.

## Flags

- `--json`
- `--state`
- `--input`

## Contract

Expected JSON keys: `status`, `artifact_path`, plus either runtime-evidence keys (`record_count`, `matched_records`, `unmatched_records`, additive `runtime_evidence`) or evidence-packet keys (`artifact_kind=evidence_packets`, `packet_count`, `matched_packets`, `unmatched_packets`, additive `evidence_packets`).

The managed runtime evidence artifact is written next to the selected state file as `runtime-evidence.json`. Managed Agentic SDLC evidence packets are written next to the selected state file as `agentic-evidence-packets.json`.
Managed normalized coding-agent session artifacts are written next to the selected state file as `runtime-sessions.json`.

Runtime and external-control records are normalized and sorted deterministically. Each record must provide:

- `source`
- `observed_at` in RFC3339 format
- `evidence_class`

External-control sidecars should validate against `schemas/v1/evidence/external-control-evidence.schema.json` and use `record_kind=external_control` plus a deterministic `source_type` such as `provider_export`, `signed_declaration`, `repo_policy`, `app_catalog`, `ticket_export`, or `customer_owner_map`.

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

Additional additive keys may include `tool`, `repo`, `service`, `workflow`, `environment`, `path`, `target`, `action_classes`, `policy_ref`, `proof_ref`, `graph_node_refs`, `graph_edge_refs`, `status`, `issuer`, `valid_until`, `max_age`, `confidence`, `freshness_state`, `redaction_hints`, `owner`, `required_checks`, `branch`, and `evidence_refs`.

Wrkr normalizes external-control records with deterministic source precedence and freshness metadata. Correlation summaries now preserve additive `freshness_state` / `freshness_states` so stale or expired evidence is visible without silently verifying a control.
These imports stay local-file based and deterministic; Wrkr correlates them without live provider calls.
Agentic evidence-packet sidecars should validate against `schemas/v1/evidence/agentic-evidence-packets.schema.json`. They are typed local audit packets for consequential AI-assisted or automation-assisted SDLC changes and can correlate by `path_id`, `agent_id`, `repo` + `workflow`, `pull_request_ref`, `files_touched`, `proof_refs`, or graph refs. Packet output stays summary-level: refs, digests, result, and missing-evidence state are serialized, but raw secret values and raw diff payloads are not.
Coding-agent session artifacts can be either normalized `schemas/v1/evidence/runtime-sessions.schema.json` bundles or provider-shaped local JSON exports that Wrkr normalizes at ingest time. Supported providers are `codex`, `claude_code`, `cursor`, `copilot`, `gait`, and `unknown`. Raw prompt or response text is never persisted directly; Wrkr stores deterministic refs/digests plus redaction hints instead.

## Safety and failure modes

- Malformed JSON input returns exit `6`.
- Schema or contract violations return exit `3`.
- Unsafe managed output paths return exit `8`.
- Static scan findings remain unchanged; report and evidence commands consume runtime evidence only as corroborating metadata.
- Runtime evidence can promote BOM/report policy coverage to `runtime_proven` without rewriting saved scan findings.
- External control evidence can attach deterministic ownership, approval, branch-protection, protected-environment, required-check, security-gate, freeze-window, and kill-switch refs to govern-first paths without live provider calls.
- Session ingest projects the same normalized session records into runtime-evidence and evidence-packet views during report/evidence generation, so static authority and observed session behavior stay joined without keeping raw provider payloads in report layers.
- Report and Agent Action BOM rendering also project path-level `gait_coverage` status for `policy_decision`, `approval`, `jit_credential`, `freeze_window`, `kill_switch`, `action_outcome`, and `proof_verification`, using `present`, `missing`, `stale`, `conflict`, or `not_applicable` without implying Wrkr enforced the action.
- Buyer-facing runtime absence framing is derived after correlation: static-only paths render `not_collected`, out-of-scope runtime controls render `not_applicable`, matched-path gaps render `missing_required`, and unsupported runtime-backed control claims render `missing_for_control_claim`.
- Ingest can corroborate a control claim with runtime evidence, but it does not convert static lack of runtime evidence into proof that an enterprise control is absent.

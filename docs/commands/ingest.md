# wrkr ingest

## Synopsis

```bash
wrkr ingest --state ./.wrkr/last-scan.json --input runtime-evidence.json --json
```

`ingest` stores deterministic runtime evidence beside the saved scan state without mutating scan truth.

## Flags

- `--json`
- `--state`
- `--input`

## Contract

Expected JSON keys: `status`, `artifact_path`, `record_count`, `matched_records`, `unmatched_records`, and additive `runtime_evidence`.

The managed runtime evidence artifact is written next to the selected state file as `runtime-evidence.json`.

Runtime evidence records are normalized and sorted deterministically. Each record must provide:

- `source`
- `observed_at` in RFC3339 format
- `evidence_class`

Each record must also provide at least one deterministic correlation key: `path_id`, `agent_id`, `repo` + `location`, `policy_ref`, `proof_ref`, `target`, or graph refs.

Normalized evidence classes:

- `policy_decision`
- `approval`
- `jit_credential`
- `freeze_window`
- `kill_switch`
- `action_outcome`
- `proof_verification`
- `other` for explicit legacy/unknown carry-through

Additional additive keys may include `tool`, `repo`, `location`, `target`, `action_classes`, `policy_ref`, `proof_ref`, `graph_node_refs`, `graph_edge_refs`, `status`, and `evidence_refs`.

## Safety and failure modes

- Malformed JSON input returns exit `6`.
- Schema or contract violations return exit `3`.
- Unsafe managed output paths return exit `8`.
- Static scan findings remain unchanged; report and evidence commands consume runtime evidence only as corroborating metadata.
- Runtime evidence can promote BOM/report policy coverage to `runtime_proven` without rewriting saved scan findings.

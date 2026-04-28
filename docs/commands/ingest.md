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

- `path_id`
- `source`
- `observed_at` in RFC3339 format
- `evidence_class`

Additional additive keys may include `agent_id`, `tool`, `repo`, `policy_ref`, `proof_ref`, `status`, and `evidence_refs`.

## Safety and failure modes

- Malformed JSON input returns exit `6`.
- Schema or contract violations return exit `3`.
- Unsafe managed output paths return exit `8`.
- Static scan findings remain unchanged; report and evidence commands consume runtime evidence only as corroborating metadata.

# ADR: Wave 24 Runtime Session Ingest

Date: 2026-05-27
Status: accepted

## Context

Wrkr already accepted deterministic runtime evidence bundles and typed evidence packets, but it did not have a first-class way to ingest local coding-agent session artifacts from Codex-style agents, Claude Code, Cursor, Copilot, Gait traces, or future provider exports.

## Decision

1. Add a first-class managed `runtime-sessions.json` sidecar under `schemas/v1/evidence/runtime-sessions.schema.json`.
2. Normalize provider-shaped local JSON artifacts at the ingest boundary into Wrkr-owned session records before report, risk, evidence, or proof layers consume them.
3. Persist only deterministic refs, digests, redaction hints, and normalized metadata for prompt/response material; raw prompt or transcript text is never required for joins.
4. Project normalized sessions into runtime-evidence and evidence-packet views during report and evidence generation instead of letting downstream layers parse provider-specific payloads directly.

## Consequences

- `wrkr ingest` can accept provider-shaped session artifacts and writes a deterministic managed session sidecar beside the selected state file.
- Report, BOM, and evidence outputs can distinguish static authority from observed session behavior without network calls or non-deterministic joins.
- Customer-safe redaction can be applied consistently to session identifiers, provider refs, changed files, approvals, proof refs, and graph refs from one normalized surface.

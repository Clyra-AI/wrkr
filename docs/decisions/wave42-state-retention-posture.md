---
title: "Wave 4.2 State-Retention Posture"
description: "Why Wrkr records retained-state posture as refs and digests only."
---

# Decision

Wrkr records agent state-retention posture through additive sidecar/report fields:

- `state_retention_status`
- `retained_state_types`
- `state_location_refs`
- `state_digest_refs`

Those fields are refs-and-digests only. Raw prompt, response, tool-result, checkpoint, log, sandbox-file, and memory-content payloads are rejected during ingest.

# Why

- Retained state is a real privacy and governance risk surface for agentic delivery systems.
- The product still has to honor Wrkr's deterministic, no-exfiltration, file-based evidence boundary.
- Refs and digests preserve audit usefulness without turning Wrkr into a storage layer for sensitive agent memory.

# Consequences

- Unknown retention posture stays explicit unknown; it is never treated as safe by omission.
- Shared share profiles redact host/model/state details by default.
- Operators can prove that state may persist without committing or exporting raw retained contents.

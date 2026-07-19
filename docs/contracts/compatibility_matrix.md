---
title: "Compatibility Matrix"
description: "Compatibility expectations for Wrkr command contracts, schema surfaces, and deterministic behavior across v1 lines."
---

# Compatibility Matrix

## Contract Stability

| Surface | Stability Expectation |
|---|---|
| Exit codes | Stable and versioned as API |
| `--json` envelope | Stable keys for major line |
| Schema assets in `schemas/v1` | Backward-compatible additive changes |
| `composed_action_paths` and proposed Action Contracts | Additive v1 surfaces; IDs are stable join keys and contracts remain report-only |
| Proposed Action Contract v2 | Frozen reader-compatible schema; never silently rewritten to v3 |
| Proposed Action Contract v3 | Typed authority, precondition, confirmation, approval, compensation, revision, and imported-lifecycle contract |
| Action Contract artifact v1 | Opt-in JCS-digested portable envelope from `wrkr export action-contracts` |
| `decision_trace` proof records | Additive within the v1 proof-output line; reference by `record_id`, not by chain position |
| Manifest spec | Managed by `spec_version` |

## Consumer Guidance

- Validate schema before processing exported artifacts.
- Treat unknown required fields as blocking.
- Treat regress drift exit `5` as a stable CI failure signal.
- Treat `composed_action_paths[*].claim_state` as a conservative evidence claim. Static or declared compositions are not runtime enforcement proof, and `proposed_action_contract.report_only=true` means Wrkr is proposing a downstream control shape, not enforcing it.
- Read version `2` artifacts with their frozen schema. New scans emit version `3`; migration is an explicit re-scan/export path, never an in-place upgrade of a v2 contract ID.
- A v3 authority or precondition requirement has separate required constraint, observed value, evidence state, and freshness state. `declared`, `inferred`, `unknown`, stale, or contradictory evidence is not an authority grant or a satisfied condition.
- A v3 successor requires a matching explicit predecessor, exactly one higher revision, and `supersedes_ref`. Gait/Axym activation, rejection, execution, effect, and verification observations are imported evidence only; they do not represent Wrkr state transitions.
- Validate a portable envelope against `proposed-action-contract-artifact.schema.json`; recompute its RFC 8785 JCS digest using its documented canonical content projection. Presentation timestamps are excluded, while a redacted share profile produces a distinct artifact identity.
- Treat `decision_trace_refs`, decision-trace `composition_ids[]` / `proposed_action_contract_refs[]`, evidence-bundle `composition_refs[]`, and `proof-records/decision-traces.jsonl` as additive traceability surfaces; existing consumers should ignore them if unused.
- Treat `agent_action_bom.summary.primary_view.composition_id` and its bounded `composition_stage_map[]` as the buyer lead when present. If absent, existing path-first primary-view behavior remains compatible.

## Command Anchors

```bash
wrkr export --format inventory --json
wrkr export action-contracts --state ./.wrkr/last-scan.json --json
wrkr manifest generate --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
```

## Q&A

### Which Wrkr surfaces are stable across the v1 contract line?

Exit codes, primary `--json` envelopes, and schemas in `schemas/v1` are treated as stable API surfaces for consumers.

### How should consumers handle unknown fields in JSON outputs?

Ignore unknown optional fields, but fail on missing required fields and schema violations.

### How do I pin compatibility in CI pipelines?

Validate exported artifacts against the intended schema version and assert expected exit-code behavior for contract-critical commands.

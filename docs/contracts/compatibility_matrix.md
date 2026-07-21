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
| `composed_action_paths` and proposed Action Contracts | Additive v1 surfaces; pairwise IDs remain supported, bounded multi-stage pattern IDs/fields are additive, stable IDs exclude volatile path IDs, and contracts remain report-only |
| Proposed Action Contract v2 | Frozen reader-compatible schema; never silently rewritten to v3 |
| Proposed Action Contract v3 | Typed authority, precondition, confirmation, approval, compensation, revision, and imported-lifecycle contract |
| Action Contract artifact v1 | Opt-in JCS-digested portable envelope from `wrkr export action-contracts` |
| Action Contract packet v1 | Opt-in single-contract JSON/Markdown buyer projection from the normalized portable artifact; excluded from default reports |
| Action Contract conformance fixture v1 | Exact production-generated artifact and packet bytes pinned by producer/schema versions and SHA-256 digests; deliberate updates only |
| `decision_trace` proof records | Additive within the v1 proof-output line; reference by `record_id`, not by chain position |
| Manifest spec | Managed by `spec_version` |

## Consumer Guidance

- Validate schema before processing exported artifacts.
- Treat unknown required fields as blocking.
- Treat regress drift exit `5` as a stable CI failure signal.
- Treat `composed_action_paths[*].claim_state` as a conservative evidence claim. Static or declared compositions are not runtime enforcement proof, and `proposed_action_contract.report_only=true` means Wrkr is proposing a downstream control shape, not enforcing it.
- For bounded multi-stage paths, preserve stage array order and the explicit `system_class`, `trust_boundary`, `correlation_refs`, `reachability_state`, `observed_execution`, alternate-route, and truncation fields. Do not infer a missing transition. `possible` is static correlation; only all-stage imported runtime outcome evidence can produce `observed`.
- Read version `2` artifacts with their frozen schema. New scans emit version `3`; migration is an explicit re-scan/export path, never an in-place upgrade of a v2 contract ID.
- A v3 authority or precondition requirement has separate required constraint, observed value, evidence state, and freshness state. `declared`, `inferred`, `unknown`, stale, or contradictory evidence is not an authority grant or a satisfied condition.
- A v3 successor requires a matching explicit predecessor, exactly one higher revision, and `supersedes_ref`. Gait/Axym activation, rejection, execution, effect, and verification observations are imported evidence only; they do not represent Wrkr state transitions.
- Validate a portable envelope against `proposed-action-contract-artifact.schema.json`; recompute its RFC 8785 JCS digest using its documented canonical content projection. Presentation timestamps are excluded, while a redacted share profile produces a distinct artifact identity.
- Validate an Action Contract packet against `report/action-contract-packet.schema.json`. Require an explicit contract selector, preserve the artifact/contract/family/revision/digest tuple, treat every non-verified or non-fresh requirement as a visible gap, and never treat the packet as activation authority. JSON and Markdown are two projections of the same bounded packet model.
- Consume cross-product fixtures only from `scenarios/cross-product/action-contract-interop/expected/fixture-manifest.json`. Wrkr owns and regenerates these exact bytes through `scripts/generate_action_contract_conformance.sh`; Gait and Axym own the configured consumers. Hand-authored Gait/Axym projections are not compatibility evidence. A release receipt must name fixture version `1`, the fixture-manifest digest, producer/schema versions, the external consumer version, each unchanged artifact digest, and `status: pass`.
- Treat `decision_trace_refs`, decision-trace `composition_ids[]` / `proposed_action_contract_refs[]`, evidence-bundle `composition_refs[]`, and `proof-records/decision-traces.jsonl` as additive traceability surfaces; existing consumers should ignore them if unused.
- Treat `agent_action_bom.summary.primary_view.composition_id` and its bounded `composition_stage_map[]` as the buyer lead when present. If absent, existing path-first primary-view behavior remains compatible.

## Command Anchors

```bash
wrkr export --format inventory --json
wrkr export action-contracts --state ./.wrkr/last-scan.json --json
wrkr report --template action-contract-packet --contract-id pac-0123456789abcdef --state ./.wrkr/last-scan.json --json
wrkr manifest generate --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
```

## Q&A

### Which Wrkr surfaces are stable across the v1 contract line?

Exit codes, primary `--json` envelopes, and schemas in `schemas/v1` are treated as stable API surfaces for consumers.

### How should consumers handle unknown fields in JSON outputs?

Ignore unknown optional fields, but fail on missing required fields and schema violations.

### How do I pin compatibility in CI pipelines?

Validate exported artifacts against the intended schema version and assert expected exit-code behavior for contract-critical commands. For Action Contract interoperability, run `scripts/generate_action_contract_conformance.sh --check`, then configure the external Gait/Axym consumer entrypoints and run `scripts/test_action_contract_interop.sh`. Missing consumers return dependency-missing exit `7`; a Wrkr-local stub is not a passing release receipt.

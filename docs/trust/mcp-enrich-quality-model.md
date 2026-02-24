---
title: "MCP Enrich Quality Model"
description: "Quality states and fail-safe semantics for optional MCP enrich lookups."
---

# MCP Enrich Quality Model

Wrkr `scan --enrich` can attach optional MCP advisory/registry metadata to findings. This page defines how quality is reported and how fail-safe behavior works.

## Scope

- Applies only when `--enrich` is enabled.
- Does not change offline deterministic defaults when enrich is not enabled.
- Reports metadata quality without failing the base static scan path.

## Quality states

Wrkr emits these values under the evidence key `enrich_quality`.

| Quality | Meaning | Typical condition |
|---|---|---|
| `ok` | Advisory and registry lookups succeeded with fresh schemas. | Both providers returned parseable current responses. |
| `partial` | At least one provider succeeded, at least one failed. | One network/provider error occurred while the other returned data. |
| `stale` | Returned data is parseable but schema compatibility/freshness is degraded. | Legacy/compat schema paths or mixed stale+error conditions. |
| `unavailable` | No provider data could be trusted. | Both providers failed or returned unusable responses. |

## Fallback semantics

- Fail-safe defaults: `advisory_count=0`, `registry_status=unknown`, `enrich_quality=unavailable`.
- Errors are captured as stable adapter classes in `enrich_errors` (for example `advisory_error`, `registry_error`).
- Schema metadata is explicit (`advisory_schema`, `registry_schema`) so upstream drift is visible in output.
- `as_of` always records lookup time to bound operator interpretation.

## Deterministic expectations

- With enrich disabled, scan/risk/proof behavior remains deterministic and offline-safe.
- With enrich enabled, adapter behavior is deterministic for a fixed provider response set, but provider volatility is expected and surfaced through `enrich_quality` and schema fields.
- Risk logic consumes `enrich_quality` explicitly, so low-quality enrich states do not silently overstate trust.

## Operator guidance

1. Treat `ok` as normal enrich evidence quality.
2. Treat `partial`/`stale` as advisory quality degradation and verify with another run before policy action.
3. Treat `unavailable` as no enrich confidence; rely on deterministic static findings and attack-path posture until providers recover.

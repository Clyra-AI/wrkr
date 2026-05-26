# ADR: Wave 21 Control Declarations And Evidence Governance

Date: 2026-05-25
Status: accepted

## Context

Wave 2 of the enterprise-evidence rollout needs Wrkr to accept customer-supplied control context without turning local declarations into invisible assumptions. Before this change, Wrkr could ingest repo-local control sidecars and Gait deployment constraints, but it still merged path-level control signals with first-non-empty behavior, did not model freshness on imported evidence, and had no versioned declaration artifact for owner mappings, non-production declarations, target classes, or declared control links.

## Decision

1. Add versioned local declaration loading for `wrkr-control-declarations.yaml` and `.wrkr/control-declarations.yaml`.
2. Validate declarations deterministically at scan time and fail closed on invalid schema, unsafe paths, duplicate scopes, or unsupported evidence refs.
3. Normalize imported and declared control evidence through one shared evidence-decision model that preserves source precedence, freshness, rejected candidates, and contradiction payloads.
4. Treat customer declarations as declared evidence only. They can influence owners, targets, and control posture, but they cannot bypass freshness checks or contradiction detection.
5. Surface additive `evidence_decisions[]` and `contradictions[]` in action-path, backlog, BOM, and report JSON so higher-precedence wins remain explainable and auditable.

## Rationale

- Customer context is useful only when Wrkr can prove where it came from, when it expires, and why it beat or lost to other sources.
- Fail-closed declaration validation preserves deterministic behavior and avoids silently weakening the control model.
- A shared evidence-decision layer keeps precedence rules aligned across ingest, ownership, attribution, risk projection, and reporting.
- Contradictions such as “declared non-production but production-bearing in practice” are high-value governance findings and should stay visible.

## Consequences

- `wrkr scan` can now load versioned customer declarations from the repo root without live provider calls.
- Imported and declared evidence now carries freshness semantics (`fresh`, `stale`, `expired`, `unknown`) instead of only raw timestamps.
- Higher-precedence source wins no longer erase lower-precedence disagreements; they remain visible in additive decision payloads and can still escalate to contradictions when ambiguity or production-bearing conflicts exist.

# Wave 2 Govern-First Runtime Output

Date: 2026-04-22

## Status

Accepted.

## Context

Wave 1 added the control backlog, scan modes, signal classes, and scan-quality appendix. Wave 2 makes those contracts useful in normal runtime output without removing existing scanner evidence surfaces.

## Decision

- `wrkr scan --json` continues to emit raw findings, ranked findings, inventory, risk, profile, posture score, and compliance summary.
- The additive `control_backlog` is the governance decision surface and is also persisted in scan state.
- `wrkr scan --explain` leads with control backlog review items before secondary compliance/report details.
- Write-path classes are explicit additive fields on governance backlog items, inventory privilege-map entries, and action paths.
- Governance control mappings are additive fields. They describe whether owner, approval, least-privilege, rotation, deployment-gate, production-classification, proof, and review-cadence evidence is satisfied, missing, or not applicable.
- Governance backlog visibility maps legacy `approved` to `known_approved` while inventory compatibility fields continue to accept the historic `approved` value.

## Consequences

- Existing JSON consumers that ignore unknown fields remain compatible.
- Operators can answer which AI or automation control path needs review first from `control_backlog` or `scan --explain`.
- Proof records can carry action-path governance evidence without introducing network calls or runtime execution.

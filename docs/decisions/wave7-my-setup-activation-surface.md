# ADR: Wave 7 Additive `my_setup` Activation Surface

Date: 2026-03-15
Status: accepted

## Context

The audit found that `wrkr scan --my-setup --json` often surfaced policy-only findings first, even when concrete local tool or secret signals existed. The launch-alignment plan allowed two paths:

- narrow public positioning and avoid a broad developer-first promise
- add a safer first-value surface for `my_setup`

For this implementation, the broader runtime path was selected as an additive improvement while preserving the raw risk contract.

## Decision

1. Keep existing `findings`, `ranked_findings`, `top_findings`, and report risk arrays unchanged.
2. Add a new `activation` projection for `my_setup` in scan/report outputs.
3. Suppress policy-only items from the activation projection when concrete local tool, MCP, secret, or parse-error signals exist.
4. Return a deterministic empty/reasoned activation result when no qualifying concrete signals exist.

## Rationale

- Additive projection improves first-run clarity without breaking automation that depends on raw ranking fields.
- Targeting `my_setup` only avoids surprising org/path consumers with onboarding-specific shaping logic.
- Deterministic empty-state behavior is safer than fabricating or mutating the underlying risk ordering.

## Consequences

- Docs and examples can point users at `activation` for the concrete first-value path.
- Automation consumers can ignore the new field and continue using the legacy ranking surfaces.
- Public/share-profile sanitization must cover the new activation payload where applicable.


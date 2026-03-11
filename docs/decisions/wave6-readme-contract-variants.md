# ADR: Wave 6 README Contract Variants

Date: 2026-03-11  
Status: accepted

## Context

Wrkr is moving from the classic shared README contract to a landing-page-first README that is intentionally lighter on install/trust footer content and heavier on developer/security workflows.

Proof and Gait are not changing in this implementation wave.

Hard-coded validation in:

- `docs/contracts/readme_contract.md`
- `scripts/check_docs_consistency.sh`
- `testinfra/hygiene/wave2_docs_contracts_test.go`

currently assumes one shared README section model for all repositories.

## Decision

Wrkr will support two documented README contract variants:

1. Variant A: classic shared README model used by Proof/Gait and historical Wrkr.
2. Variant B: Wrkr landing-page model with `Start Here`, workflow-first sections, and canonical install/trust details moved to docs surfaces outside the README footer.

Validation will accept either variant during the transition.

## Consequences

- Wrkr can land the locked README body without silently weakening docs enforcement.
- Proof and Gait can remain on the classic model until their tracked follow-ups complete.
- Docs/install/trust discoverability must remain explicit in canonical docs/docs-site surfaces when Variant B is used.

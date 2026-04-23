# Wave 3 Approval, Evidence, And Drift

## Status

Accepted.

## Context

Wave 3 turns governance backlog items into lifecycle-managed controls. The implementation must remain deterministic, offline-first, file-based, and compatible with existing state, manifest, proof, evidence, and regress contracts.

## Decision

- Inventory governance mutations are CLI-local state transitions over saved Wrkr artifacts.
- Mutations update the saved state snapshot and `wrkr-manifest.yaml`, append lifecycle/proof records, and roll back managed artifacts on write failure.
- Approval inventory fields are additive and versioned with `approval_inventory_version`.
- Proof and evidence lifecycle status is derived from the existing proof chain and active control backlog items.
- Regress drift remains a persisted-state comparison. It does not rescan and does not call detectors.

## Consequences

- `wrkr inventory approve|attach-evidence|accept-risk|deprecate|exclude` can be used in CI or operator workflows without network execution.
- `wrkr evidence --json` and `wrkr verify --chain --json` can show which control proof exists and what is still missing.
- `wrkr regress run --json` and `wrkr inventory --diff --json` can prioritize approved-baseline drift categories such as expired approvals, owner changes, new write paths, and new secret-bearing workflows.
- Existing raw findings, inventory export fields, proof chains, and legacy regress reasons remain available for compatibility.

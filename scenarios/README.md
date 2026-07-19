# Wrkr Scenarios

Wrkr scenarios are deterministic repo-local fixtures for scan, report, evidence, regress, and cross-product compatibility behavior.

Composition fixtures live under `scenarios/wrkr/composed-action-paths/` and define the canonical Wrkr-side outputs for composed action paths, proposed Action Contracts, decision trace refs, evidence refs, Agent Action BOM primary-view refs, and regress snapshot refs.

Exact-byte cross-product Action Contract fixtures live under `scenarios/cross-product/action-contract-interop/`. They are generated through the production Wrkr scan, saved-state, export, and packet paths; the manifest pins their schemas and digests. Wrkr passes those unchanged bytes to separately configured Gait and Axym consumers and never substitutes local downstream behavior. The former `scenarios/cross-product/composed-action-contracts/` directory is only a legacy pointer and contains no authoritative hand-authored projections.

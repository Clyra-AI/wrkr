# ADR: Wave 48 Grouped Endpoint Projections And Analysis Progress

Date: 2026-06-14

## Context

Wave 2 of the stdout-scale and buyer-BOM hardening plan found a remaining scale
gap after canonical ref-only serialization landed: endpoint-dense repos still
copied large mutable-endpoint fanout into govern-first action paths, control
path graph nodes, Agent Action BOM items, and action-surface registry output.
That kept buyer/shareable artifacts noisy and could still amplify heap during
analysis. Operators also lacked deterministic visibility into which analysis
subphase was actually slow or memory-heavy once detector execution finished.

## Decision

1. Preserve the authoritative per-scan mutable-endpoint canonical store, but add
   grouped endpoint receipts to downstream report-facing projections.
2. Emit additive grouped endpoint fields on action/report/graph surfaces:
   `endpoint_ref_group_id`, `endpoint_ref_count`, `endpoint_route_groups`,
   `endpoint_operation_counts`, and bounded `endpoint_ref_samples`.
3. Keep compatibility `mutable_endpoint_semantic_refs` fields, but bound them to
   small deterministic samples on repeated graph/BOM/registry projections
   instead of cloning the full ref set everywhere.
4. Let saved-state canonical stores retain enough grouped information to hydrate
   full endpoint refs back for local/internal rebuild paths when needed.
5. Extend scan progress with deterministic `phase_substep` events for:
   inventory, action paths, control graph, workflow chains, backlog, state
   finalization, and artifact write.
6. Make heap receipts opt-in through `--progress-heap`, emitted only on
   machine-readable progress events so standard stdout JSON contracts remain
   unchanged.

## Consequences

- Endpoint-dense report surfaces stay bounded while still explaining how many
  endpoints and route families are implicated.
- Local/state-backed rebuild flows can recover the full endpoint group through
  canonical stores instead of depending on repeated projection clones.
- Operator diagnostics improve because a long scan can identify the exact
  analysis subphase rather than only saying `analysis`.
- Consumers that previously assumed repeated endpoint-ref arrays would always
  carry every ref now need to respect the grouped receipt fields and the saved
  canonical store for full detail.

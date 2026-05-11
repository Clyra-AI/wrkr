# Wave 20: Mutable Endpoint Semantics And Action Surface Registry

## Context

Wave 3 of buyer action registry hardening needs Wrkr to explain not only that a govern-first path exists, but what static business mutation surface it exposes and how related paths roll up into a buyer-readable registry. Before this change, govern-first ranking understood credentials, delivery-chain writes, proof gaps, and ownership, but it did not carry first-class static endpoint semantics or a grouped registry view across OpenAPI specs, route files, and MCP declaration hints.

## Decision

1. Add additive `mutable_endpoint_semantics[]` across inventory tool/privilege surfaces, govern-first action paths, control-path graph nodes, Agent Action BOM items, and report/evidence artifacts.
2. Keep endpoint classification static-only. Wrkr parses declared OpenAPI operations, common route files, and MCP declaration hints; it does not probe live endpoints or claim runtime reachability by default.
3. Represent endpoint semantics as deterministic objects with `semantic`, `confidence`, `surface`, `operation`, and `evidence_refs` so buyer-facing projections can explain why a path was classified.
4. Add a deterministic `action_surface_registry` projection to report/evidence artifacts that groups ranked paths by workflow, server, route/API surface, or agent config using stable grouping keys and path/graph join refs.
5. Upgrade govern-first ranking and buyer projections so high-impact mutable endpoint semantics such as `payment`, `refund`, `user_admin`, `delete`, `deploy`, and `production_mutation` elevate control priority, risk-zone selection, review burden, and top-path ordering ahead of generic write inventory when static evidence supports it.

## Consequences

- Buyers can distinguish low-context write capability from higher-consequence business mutation surfaces without live traffic or runtime inference.
- Report and evidence JSON now include grouped registry rows that summarize owner, purpose, version/config metadata, credential authority, reachable actions, endpoint semantics, proof status, and graph joins in one place.
- Static endpoint findings remain bounded claims: they improve prioritization and explainability, but they do not imply live production access, live reachability, or enforcement by Gait.

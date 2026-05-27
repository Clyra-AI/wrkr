# ADR: Wave 23 High-Stakes Authority Correlation

Date: 2026-05-26
Status: accepted

## Context

Wave 4 of the Sprint 3 Agentic SDLC plan needs Wrkr to treat production, cloud, SaaS, mutable-endpoint, and release authority as first-class path facts instead of leaving them as loose permission hints. Before this change, Wrkr could identify mutable endpoints, workflow capabilities, credential provenance, and buyer-facing action paths, but it did not have one additive contract for structured authority bindings, could not surface high-stakes presets directly in path JSON, and could over-promote route/OpenAPI evidence into governed paths without explicit authority correlation.

## Decision

1. Add a shared additive `authority_bindings[]` contract across inventory privilege entries, action paths, Agent Action BOM items, and control-path graph nodes.
2. Allow authority bindings to represent `cloud_role`, `kubernetes_rbac`, `service_connection`, `workload_identity`, `deployment_path`, and `saas_token` evidence without exposing raw secret values.
3. Extend normalized credential provenance and credential authority with additive `target_system`, `likely_scope`, and `scope_confidence` fields so SaaS and cloud authority stay explainable in existing surfaces.
4. Add deterministic `high_stakes_presets[]` and `production_context` projection on action paths and buyer-facing report items.
5. Fail closed for route/OpenAPI production-data findings that lack direct authority correlation by rendering them as appendix-only context instead of govern-first paths.
6. Prefer workflow-local structured evidence first, then merge repo-wide authority signals additively for deterministic correlation when the same repo carries cloud, SaaS, or mutable-endpoint evidence in multiple files.

## Rationale

- Buyers need to see what kind of authority a path carries, not just that some credential exists.
- High-stakes sorting is easier to explain and safer to govern when the classification is explicit and schema-backed.
- A shared authority-binding contract keeps inventory, risk, report, and graph artifacts aligned.
- Appendix-only handling for uncorrelated route/OpenAPI signals avoids overclaiming governed control coverage.

## Consequences

- Inventory, risk, report, and graph schemas now carry additive authority and high-stakes fields.
- Workflow capability and privilege-budget correlation own the primary authority-binding flow; downstream reports consume it rather than recomputing new heuristics.
- Scenario and contract coverage must treat appendix-only production context as a valid fail-closed outcome, not a regression.

## Validation Plan

- `go test ./core/detect/workflowcap ./core/aggregate/privilegebudget ./core/risk ./core/report ./testinfra/contracts -count=1`
- `make test-contracts`
- `make test-scenarios`
- Acceptance criteria:
  - Workflow and repo evidence can project authority bindings without raw secret values.
  - High-stakes presets appear in buyer-facing JSON and markdown with deterministic ordering.
  - Uncorrelated route/OpenAPI production-data surfaces remain appendix-only instead of claiming governed execution authority.

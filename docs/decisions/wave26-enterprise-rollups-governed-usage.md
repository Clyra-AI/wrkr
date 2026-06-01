# ADR: Wave 26 Enterprise Rollups and Governed Usage Metrics

Date: 2026-05-31
Status: accepted

## Context

Wave 1 of the GTM, packaging, and scale-gates plan needs Wrkr to summarize large-org action-path posture into executive-readable groups without rescanning, weakening determinism, or leaking private repo details in shareable artifacts. The same wave also needs non-sensitive governed-usage counters that product, GTM, and buyer-facing workflows can reuse without turning report output into billing enforcement.

## Decision

1. Add one additive executive-rollup model that groups existing govern-first action paths by action class, target class, risk zone, credential authority, production-target posture, evidence state, owner state, repo cluster, detector confidence, contradiction state, and closure action.
2. Derive rollups only from already-projected report facts (`action_paths`, `control_backlog`, exposure groups, and evidence-state projections) instead of introducing a second scan or separate aggregation pipeline.
3. Reuse that same rollup structure across report summaries, Agent Action BOM summaries, control-backlog exports, markdown rendering, and report-evidence bundles.
4. Add one additive governed-usage metric set for monitored paths, governed paths, evidence packs, audit-export families, approval decisions, connected runtimes, governed surfaces, verified controls, unknown controls, and contradictions.
5. Keep both contracts redaction-safe by exposing only stable ids, counts, grouped dimension labels, and non-sensitive counters, while leaving repo, owner, proof, and graph detail in the existing deeper artifacts.

## Rationale

- One shared rollup keeps executive, operator, BOM, and evidence outputs aligned instead of letting each surface invent different grouping rules.
- Deriving from existing govern-first facts preserves the source -> detection -> aggregation -> risk -> report/evidence boundary and keeps the implementation deterministic.
- Group ids and counter names are stable enough for GTM automation while remaining safe to ignore for older consumers.
- Non-sensitive counters give Wrkr a packaging/value language that reflects governed work rather than seats or private scan volume.

## Consequences

- `summary.executive_rollup` and `summary.governed_usage_metrics` are now additive report-summary contracts, and Agent Action BOM summaries mirror both.
- Markdown report output now leads with executive rollups before verbose backlog and appendix detail.
- Evidence command JSON and report-evidence bundles now expose governed-usage metrics for downstream audit and GTM workflows.
- Future waves that add deployment modes, public-surface evidence, or website samples must reuse these shared summary contracts instead of forking parallel rollup logic.

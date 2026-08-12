# ADR: Wave 61 Workflow Catalog And Execution Topology

Date: 2026-08-12
Status: accepted

## Context

Overlapping detectors independently walked and parsed CI files, Jenkinsfiles could reach a YAML parser, and inherited workflow facts lacked one bounded relationship model. Some enterprise aliases, such as Jenkins global shared libraries, are not resolvable from repository source alone.

## Decision

1. Build one immutable workflow catalog per scan scope and let detector projections consume its parser result.
2. Dispatch GitHub, GitLab, Azure, Jenkins, composite-action, and shared-source files explicitly.
3. Normalize reusable execution relationships with caller, callee, origin, resolution state, confidence, evidence refs, and truncation reasons.
4. Bound traversal to depth 8 and fanout 64; cycles, dynamic references, and remote sources remain explicit unresolved receipts.
5. Analyze Jenkins statically. Never execute Groovy, contact a controller, load plugins, or require Java.
6. Accept optional local `--execution-topology` mappings for external registrations. Store only the canonical digest and sanitized metadata. A mapping proves a declared relationship, not execution or control effectiveness.

## Consequences

One malformed source produces one canonical parser outcome, inherited facts remain attributable to callers, and unsupported dynamic behavior is visible rather than guessed. Hosted sparse acquisition must include the source classes used by these adapters.

## Validation

- Platform parser and relationship resolver unit tests
- Local include non-downgrade, cycle, depth, fanout, and topology safety tests
- Identical-path multi-repository attribution checks
- Customer execution-truth scenarios and hosted sparse-selection tests

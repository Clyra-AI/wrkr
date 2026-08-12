# ADR: Wave 60 Canonical Evidence Authority

Date: 2026-08-12
Status: accepted

## Context

Repository scans observe credential references but cannot normally prove that a credential exists, is active, is usable by the observed path, or has a standing lifetime. Legacy booleans and provenance fallbacks could promote an unresolved reference into standing authority.

## Decision

1. Use `observation -> reference -> binding -> effective authority -> control -> proof` as the canonical evidence ladder.
2. Add typed existence, binding, and lifetime evidence states to normalized credential authority. Keep lifetime kind separate.
3. Make the normalized authority predicate the only source for confirmed standing authority, scoring, action-path eligibility, composition ranking, and buyer totals.
4. Preserve legacy fields for v1 readability, but normalize absent typed evidence to unresolved `legacy_untyped_authority`; legacy booleans cannot promote claims.
5. Treat source secret/environment references as references only. Unknown lifetime remains unknown and never defaults to durable or standing.

## Consequences

Confirmed standing totals may decrease, while candidate/reference counts remain visible. Consumers can explain exactly which predecessor is missing. Old state remains readable but is conservative until rescanned or supplemented with typed imported evidence.

## Validation

- Credential-authority truth-table and state-migration tests
- Structured-document false-identity tests
- Customer execution-truth scenarios at 96, 384, and 674 repositories
- Contract, proof, report, hardening, and regression lanes

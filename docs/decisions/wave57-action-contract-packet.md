# ADR: Opt-in Action Contract buyer packet

Date: 2026-07-19
Status: accepted

## Decision

`wrkr report --template action-contract-packet --contract-id <id>` renders one
explicitly selected proposed Action Contract as packet-schema version `1` JSON
or bounded Markdown. The packet builder consumes the exact normalized portable
artifact and redacted composition selected by `wrkr export action-contracts`;
report code does not rescore the path, infer an authority grant, or construct a
parallel contract truth.

The packet model fixes deterministic section order and item order, caps
authority requirements, readiness checks, references, lifecycle observations,
gaps, stages, values, and Markdown lines, and records every truncation. Missing,
inferred, unknown, stale, expired, or contradictory evidence stays visible as
a gap. Static reachability is labeled possible and distinct from imported
observed-execution evidence. The JSON and Markdown renderers consume the same
normalized model.

The packet remains opt-in and does not add fields, findings, or bytes to the
default scan or report. A saved-state contract ID is mandatory; collections
are never resolved by silently selecting their first member. Non-internal
share profiles run recursive redaction before artifact and packet identity are
assigned, so a redacted packet has a distinct deterministic identity.

## Boundary

The packet is a buyer-readable proposal. Wrkr does not activate the contract,
approve an action, issue credentials, execute effects, or enforce policy. Gait
owns activation and runtime enforcement. Axym owns downstream evidence
verification. Imported observations describe those systems; they are not Wrkr
state transitions.

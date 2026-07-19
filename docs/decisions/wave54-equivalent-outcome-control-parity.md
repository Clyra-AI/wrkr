# ADR: Equivalent-Outcome Control Parity

Date: 2026-07-18
Status: accepted

## Decision

Wrkr applies equivalent-outcome control parity in the risk/composition layer
after bounded outcomes are grouped and before the proposed Action Contract is
rebuilt. It snapshots each eligible route's canonical recommendation and peer
identity, then makes one deterministic pass. A weaker route can only be raised
to the most restrictive snapshot peer; it can never lower a recommendation.

Raised routes carry the exact reason
`composition:equivalent_outcome_control_parity` and a stable
`peer:<composition_id>` escalation source. The rebuilt report-only contract
includes that reason. Duplicate peers and input order cannot change the result.

An unknown recommendation is not assigned an invented rank. It is converted to
the fail-closed `block` recommendation with an explicit unknown-control reason.
Wrkr still only proposes this control: Gait remains responsible for runtime
enforcement and approval execution.

## Consequences

- Equivalent routes cannot retain a less restrictive recommendation simply
  because they were constructed before a restrictive peer.
- Reciprocal peer groups do not feedback-loop because all comparisons use the
  pre-parity snapshot.
- The parity projection remains bounded to the existing stable-target outcome
  groups and does not expand discovery or default report finding counts.

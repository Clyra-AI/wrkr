# ADR: Proposed Action Contract v3 and lifecycle evidence

Date: 2026-07-18
Status: accepted

## Decision

Wrkr keeps the version `2` Proposed Action Contract schema immutable and emits
version `3` for new composed proposals. Version 3 represents authority,
preconditions, confirmation, approval, compensation, and their evidence/freshness
separately from any downstream grant or execution. A requirement is not
satisfied merely because it is declared or inferred.

The v2 family-ID derivation remains the family identity for v3. A new contract
without explicit predecessor evidence is revision `1`. A successor requires a
validated same-family predecessor, the next numeric revision, and
`supersedes_ref`; timestamps, scan order, and filenames never infer history.

Imported Gait and Axym lifecycle observations are typed, contradiction-preserving
evidence. They are outside the immutable contract-content and approval-scope
digests, so a later receipt can create a new artifact variant without mutating a
contract revision. Wrkr neither activates/rejects a contract nor executes an
effect or verification.

## Consequences

- Embedding schemas accept explicit v2 and v3 alternatives during migration.
- Unknown, stale, inferred-only, or contradictory required evidence fails the
  report-only readiness projection closed.
- Approval scope uses the shared proof RFC 8785 JCS domain over immutable
  contract material; observations and presentation time are excluded.

# ADR: Wave 10 Manual Identity Transition Rollback

Date: 2026-03-26
Status: accepted

## Context

`wrkr identity approve|review|deprecate|revoke` previously wrote `wrkr-manifest.yaml` before updating the lifecycle chain and proof chain.

That created a correctness gap:

- a downstream lifecycle or proof failure could return `runtime_failure`
- the manifest could still show the new approval or lifecycle state
- proof-backed history and manifest posture could diverge after a failed command

Wrkr treats lifecycle posture as a contract artifact, not a best-effort convenience view, so manual transitions must fail closed.

## Decision

1. Preflight lifecycle-chain and proof-chain reads before any managed write.
2. Snapshot the managed artifacts touched by the transition:
   - manifest
   - lifecycle chain
   - proof chain
   - proof-chain attestation
   - proof signing key
3. Write the lifecycle and proof artifacts first.
4. Save the manifest last.
5. If any downstream write or proof-emission step fails, restore the snapped artifacts and return `runtime_failure`.
6. Preserve the existing public CLI surface:
   - same subcommands
   - same success payload shape
   - same `runtime_failure` classification on downstream persistence or proof errors

## Rationale

- Preflighting removes read and parse failures before any state mutation begins.
- Snapshot-and-restore gives Wrkr a deterministic rollback path without inventing a new public transaction API.
- Saving the manifest last reduces the chance that user-visible lifecycle posture advances ahead of recorded history.
- Including the proof signing key in the rollback set avoids leaving a newly initialized key behind after a failed transition.

## Consequences

- Manual lifecycle transitions now have explicit rollback semantics across the managed artifact set.
- Failure-path tests must cover:
  - malformed proof chain before transition
  - interrupted proof-chain write during transition
  - unchanged manifest, lifecycle, and proof artifacts after failure
- `wrkr verify --chain` remains the explicit proof integrity gate; this ADR only hardens commit ordering for manual transitions.

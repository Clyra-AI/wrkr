# ADR: Wave 9 Hosted Org Resume Checkpoints

Date: 2026-03-25
Status: accepted

## Context

Large-org hosted scans could take long enough that an interrupted run forced operators to restart from scratch, even when most repositories had already been materialized safely under the scan-state directory.

The GTM-critical plan required:

1. bounded concurrency for hosted org materialization
2. explicit `--resume` behavior for interrupted scans
3. checkpoint state that stayed internal, deterministic, and ownership-gated

## Decision

1. Keep checkpoint files internal and store them under the scan-state directory in `org-checkpoints/`.
2. Reuse the existing managed-directory safety pattern: non-empty unmanaged checkpoint roots fail closed.
3. Persist completed repository materialization with atomic checkpoint writes after each durable repo completion.
4. Allow `--resume` only for hosted org scans, and fail closed when checkpoint target, repo set, or materialized-root metadata no longer matches the requested run.
5. Preserve deterministic final ordering by sorting final repo/failure output independently of worker completion order.

## Rationale

- Internal checkpoint files avoid creating a new public compatibility surface while still giving operators a real recovery path.
- Atomic per-repo checkpoint commits make interruption handling auditable and crash-safe.
- Metadata validation is safer than silently mixing stale checkpoint state with a different org or repo set.
- Bounded concurrency improves large-org throughput without allowing unbounded worker fan-out.

## Consequences

- Hosted org runs can resume safely after interruption without re-materializing completed repositories.
- `--resume` becomes a user-visible CLI contract, but checkpoint file format remains an internal implementation detail.
- Docs must describe checkpoint location and mismatch behavior without presenting checkpoint files as proof artifacts.

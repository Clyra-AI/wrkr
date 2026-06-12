# ADR: Wave 34 Bounded State and Grouped Policy Signal

Date: 2026-06-12
Status: accepted

## Context

Wave 3 of the Sprint 0 subtractive-fixes plan moves Wrkr from "bounded first
screen" to "bounded persisted posture." Wave 30 already made `wrkr scan --json`
smaller and safer to share, but three follow-on gaps remained:

1. saved state, report JSON, and evidence JSON could still carry large derived
   collections that grew with repo fanout
2. several hot-path JSON artifact writers still assembled full blobs in memory
   before writing them to disk
3. posture score and scan finding counts still treated repeated per-repo policy
   outcomes as raw fanout instead of one logical governance outcome

## Decision

1. Persist grouped `policy_outcomes` in saved scan state and backfill them from
   raw policy findings when older snapshots are loaded.
2. Treat grouped policy outcomes as the scoring basis for policy pass-rate
   calculations and as the logical signal basis for severity/finding summaries
   when raw repo fanout would otherwise dominate the result.
3. Cap large saved-state derived collections such as ranked findings,
   attack/action paths, control backlog rows, graph nodes/edges, workflow
   chains, and repo exposure summaries before serialization, and publish the
   omitted-row counts through explicit `suppressed_counts`.
4. Stream large JSON artifacts to disk through atomic temp-file writers instead
   of building full marshal blobs on hot paths for state, report evidence,
   evidence bundles, and assessment artifacts.
5. Keep bounded stdout surfaces honest by pairing previews with `suppressed_counts`
   and artifact handoff paths instead of pretending omitted rows disappeared.

## Consequences

- Saved-state posture remains deterministic and portable without letting large
  derived projections grow without limit.
- Report, evidence, and assess file sinks keep the same atomic publish semantics
  while avoiding avoidable whole-blob JSON assembly on the write path.
- Score and grouped finding summaries now reflect logical policy failures rather
  than the number of repos that happened to repeat the same failing rule.

# ADR: Wave 33 Decision Trace Proof Records

Date: 2026-06-10
Status: accepted

## Context

Wave 3 also requires one compact audit record for high-impact agentic actions.
Wrkr already had action paths, workflow chains, proof refs, control evidence,
and provenance, but those details were spread across several report and evidence
surfaces. Operators needed a bounded way to answer:

1. what changed
2. which authority the change could reach
3. which policy or approval context was checked
4. which proof and evidence refs support the decision

## Decision

1. Introduce a new proof record type, `decision_trace`, for bounded high-impact
   action traces.
2. Emit `decision_trace` only for high-stakes or control-first action paths so
   the proof chain does not grow unbounded on low-signal inventory.
3. Keep the proof record canonical and let report and evidence surfaces
   reference it through `decision_trace_refs` instead of duplicating the full
   trace payload in every buyer-facing artifact.
4. Export the proof-chain subset as `proof-records/decision-traces.jsonl` inside
   evidence bundles so offline auditors can review trace records directly.

## Consequences

- High-impact delivery-system changes and workflow actions now have one compact,
  verifiable trace record in the proof chain.
- Buyer-facing BOM and report output can point to proof-backed trace refs
  without reopening raw scan state or repeating large context blocks.
- Future precedent or enterprise evidence work can extend the same
  `decision_trace` record type instead of inventing another audit artifact.

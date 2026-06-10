# ADR: Wave 31 Focused Buyer Workflow and Canonical Projection

Date: 2026-06-10
Status: accepted

## Context

Wave 2 of the scan-output-signal-hardening plan moves Wrkr from "the focused BOM
exists" to "the focused BOM is the default buyer workflow." The repo already had
the primary-view BOM contract, design-partner summary, and shared buyer-facing
projection code, but two gaps remained:

1. first-screen workflows could still drift back toward broader report surfaces
   instead of leading with the one workflow/action path that matters most
2. multiple downstream surfaces could accidentally re-derive control or evidence
   semantics and disagree even when they all started from the same action path

That combination would reduce trust exactly where the plan is trying to improve
it: the top workflow BOM, the control backlog, the graph, the evidence bundle,
and the buyer-facing markdown.

## Decision

1. Treat the focused Agent Action BOM as the buyer-default workflow surface for
   repo-first reviews. The selected `agent_action_bom.summary.primary_view`
   remains the first joined workflow path and all broader detail stays available
   in appendices or evidence JSON instead of being removed.
2. Keep Risk as the owner of buyer-facing path semantics. Control/evidence/
   recommendation posture is projected once from canonical action-path facts and
   then consumed by report, backlog, graph, registry, and evidence surfaces.
3. Enforce cross-consumer parity with acceptance coverage. If a downstream
   surface re-derives conflicting control/evidence/recommendation state, the
   parity tests fail instead of letting the divergence ship quietly.

## Consequences

- The first workflow a new operator sees is "scan repo, render focused BOM,
  inspect the top path," with the rest of the audit trail still preserved.
- Buyer-facing markdown and evidence output stay trustworthy because they no
  longer get to invent their own path posture.
- Future Wave 3 and Wave 4 surfaces must either consume the same projection or
  explicitly justify why a new contract is needed.

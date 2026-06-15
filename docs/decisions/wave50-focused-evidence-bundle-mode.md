# ADR: Wave 50 Focused Evidence Bundle Mode

Date: 2026-06-15
Status: accepted

## Context

Wrkr already had a focused Agent Action BOM primary view and `--focus-path`
selection, but `--evidence-json` still wrote the broader evidence bundle even
when the operator was intentionally drilling into one workflow or one bounded
focus preset. That created two problems:

1. design-partner and buyer-safe follow-up artifacts stayed much larger than
   the workflow under review
2. users had to choose between a readable focused report and a much noisier
   evidence handoff for the same path

Wave 4 of the stdout/scale/BOM hardening plan requires the focused report path
and the evidence handoff path to stay aligned.

## Decision

1. Treat `wrkr report --focus-path ... --evidence-json` as a focused evidence
   bundle request for the selected path.
2. Treat focus-preset report workflows such as `--focus bom --evidence-json`
   as bounded top-path evidence bundles capped to a small deterministic set.
3. Keep the shared output finalizer, redaction, suppression metadata, and
   canonical refs unchanged; only trim the exported evidence surfaces that are
   not needed for the focused review handoff.
4. Keep full graph and workflow exports opt-in outside this focused evidence
   mode.

## Consequences

- Focused report drilldown now produces a comparably focused evidence artifact.
- Shareable handoff bundles stay smaller without inventing a separate evidence
  schema or bypassing the shared finalizer.
- Operators can still export the broader graph and workflow context when they
  intentionally need it.

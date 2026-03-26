# ADR: Wave 11 Fix Apply Mode and Deterministic Multi-PR Publication

Date: 2026-03-26
Status: accepted

## Context

Wrkr already shipped deterministic remediation planning and preview PR publication, but later launch waves required two additive capabilities:

- an explicit apply surface that writes real repo files for supported templates
- deterministic grouping across more than one remediation PR without creating duplicate PR spam on reruns

The plan also required preview mode semantics to remain stable for existing consumers.

## Decision

1. `wrkr fix` keeps preview mode as the default contract.
2. `--apply` is the explicit repo-mutation flag and requires `--open-pr`.
3. Apply mode only works for deterministic, supported templates and fails closed when no apply-capable remediations are available.
4. `--max-prs` deterministically groups publication into contiguous remediation chunks and reuses stable branch names and PR identities on reruns.

## Rationale

- Explicit side-effect naming preserves operator trust and keeps preview/apply symmetric.
- Fail-closed apply support prevents ambiguous patch targets from turning into silent best-effort edits.
- Deterministic grouping avoids duplicate PR churn and keeps cadence suitable for CI-driven automation.
- Keeping grouping additive to preview mode avoids a breaking contract change for current users.

## Consequences

- Existing `wrkr fix --top N --json` consumers continue to receive preview-only output by default.
- Apply mode currently supports deterministic manifest generation and can be extended template-by-template later.
- Multi-PR publication adds additive machine-readable fields (`mode`, `pull_requests`, `apply_supported_count`) without removing existing output keys.

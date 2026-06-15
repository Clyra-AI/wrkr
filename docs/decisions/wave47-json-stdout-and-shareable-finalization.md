# ADR: Wave 47 JSON Stdout And Shareable Finalization

## Context

Wrkr already had deterministic scan, report, evidence, and assessment artifacts,
but Wave 1 of the stdout-scale/BOM hardening plan still left three gaps:

1. interactive `--json` on large-output commands could still dump heavyweight
   payloads directly into a terminal
2. shareable report-style artifacts relied mainly on typed field sanitizers, so
   newly added nested free-form evidence strings could leak owner/repo/path-like
   tokens before a test caught them
3. report/evidence serialization exposed suppression metadata unevenly, which
   made it harder for downstream consumers to tell which caps and handoff paths
   shaped a given artifact

## Decision

1. Add a shared `--json-stdout` policy for `scan`, `report`, `evidence`, and
   `assess`:
   - `auto` keeps full machine-readable JSON for pipes and redirects
   - interactive TTY stdout emits compact JSON summaries by default
   - `full` restores full interactive stdout JSON explicitly
2. Keep `--state` and `.wrkr/last-scan.json` as the canonical scan artifacts,
   and keep `--json-path` as the full command-response JSON sink even when
   interactive stdout is compacted.
3. Run shareable/default report-style outputs through one finalization path that
   attaches artifact-budget metadata, strips repeated canonical payload clones,
   and applies a residual token replacement pass derived from the authoritative
   saved snapshot before serialization.
4. Fail closed when residual shareable validation still finds owner, repo,
   provider/ref, review URL, or filesystem-path tokens after the recursive pass.

## Consequences

- Interactive operators get safer terminal behavior without breaking CI, pipes,
  redirects, or existing file-based automation.
- Shareable/default outputs are now protected by both typed sanitizers and a
  snapshot-derived residual-token gate, which is more robust against future
  nested field additions.
- Report/evidence consumers can see the cap budgets and the intended appendix or
  focused-detail handoff path directly in machine-readable metadata instead of
  inferring it from omitted rows alone.

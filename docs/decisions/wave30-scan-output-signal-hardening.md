# ADR: Wave 30 Scan Output Signal Hardening

## Context

Wrkr already had deterministic scan, report, and buyer-facing workflow artifacts, but
large scans still risked three kinds of operator pain:

1. repeated endpoint, authority, and workflow detail fanning out across multiple
   report surfaces
2. raw per-occurrence policy and parse noise making first-screen JSON harder to trust
3. stdout JSON and progress UX competing for the same surface during local scans

The scan-output-signal-hardening plan requires Wrkr to keep full deterministic
artifacts on disk while making the default JSON/report surfaces smaller, more
grouped, and safer to share.

## Decision

1. Add additive canonical reference ids for mutable endpoint semantics,
   credential authority, and authority bindings, plus a per-scan canonical store
   under `inventory.canonical_stores`.
2. Preserve backward-compatible expanded fields for existing consumers, but add
   reference fields on privilege-map entries, govern-first action paths, Agent
   Action BOM items, action-surface registry entries, graph nodes, and backlog
   rows so downstream consumers can join to one store instead of re-deriving.
3. Prefer bounded scan stdout summaries for `wrkr scan --json`, with the full
   scan artifact continuing to live at `--state`.
4. Expose grouped `policy_outcomes`, explicit `suppressed_counts`, and scan
   summary counts so large scans can omit heavyweight arrays without pretending
   those facts disappeared.
5. Keep low-signal parse failures in `scan_quality` while preserving actionable
   config-bound parse failures in the compatibility findings surface.
6. Allow `--progress auto` to use the interactive stderr bar for `--json`
   scans when the terminal can safely render it, while keeping event-mode
   liveness for non-interactive stderr targets.

## Consequences

- Buyer-facing reports gain deterministic grouped policy summaries and explicit
  suppression metadata without needing live services or LLM calls.
- Existing consumers can continue reading expanded path/report fields during the
  compatibility window, but new consumers should prefer the canonical refs and
  bounded summary contract.
- Shared report artifacts must redact newly introduced grouped-path refs and any
  repo-derived occurrence refs to remain safe for `customer-redacted`,
  `design-partner`, `external-redacted`, `investor-safe`, and `public` outputs.

# ADR: Wave 29 Enterprise Pressure Gates

Date: 2026-06-01
Status: accepted

## Context

Wave 4 of the GTM, packaging, and scale-gates plan needs a repeatable
enterprise-scale release signal. Wrkr already has large-org executive rollups,
governed-usage metrics, deployment-mode metadata, and public/redacted report
surfaces, but without a recurring 300+ repo synthetic fixture the team still has
to trust those qualities by spot-checking ad hoc scans.

## Decision

1. Generate the enterprise fixture from one deterministic source of truth in
   `internal/enterprisepressure` instead of checking in hundreds of fake repos.
2. Materialize two variants:
   - `baseline` for compactness, proof, and redaction checks
   - `current` for deterministic drift-category pressure
3. Gate the fixture through three scenario lanes:
   - contract/scorecard
   - hardening/redaction
   - chaos/fail-closed drift handling
4. Let `make test-perf` emit
   `.tmp/release/enterprise-pressure-scorecard.{json,md}` when the pressure
   gate runs with release/perf enforcement enabled.
5. Keep timing budgets in scenario contract data so threshold changes are
   explicit review events, not silent test edits.

## Rationale

- A generated fixture keeps the repo maintainable while still guaranteeing 300+
  repo coverage.
- Separate baseline/current variants make drift categories intentional and easy
  to review.
- Scorecard artifacts give release/UAT reviewers something auditable instead of
  relying on raw test logs.
- Contract-backed thresholds make performance and readability expectations
  visible and easy to reason about.

## Consequences

- `scenarios/wrkr/enterprise-pressure/expected/contract.json` becomes the
  authoritative threshold file for enterprise pressure gates.
- `scripts/test_perf_budgets.sh`, `scripts/test_hardening_core.sh`,
  `scripts/test_chaos_source.sh`, and release acceptance flows can call focused
  scenario tests without re-encoding fixture logic.
- Intentional changes to large-org compactness, redaction, drift categories, or
  timing budgets now require a contract update plus changelog rationale.

# Enterprise Pressure Fixture

This fixture is generated in tests from `internal/enterprisepressure`.

Why generated instead of checked in:

- The product requirement is 300+ repos, but hand-maintaining that many fake
  repos would create noisy churn.
- The generator keeps baseline and drift variants aligned from one source of
  truth.
- Release gates can mutate a few deterministic repos to exercise drift
  categories without customer data.

Safe update flow:

1. Change `internal/enterprisepressure/fixture.go`.
2. Re-run the enterprise scenario tests and inspect the emitted scorecard.
3. Update `expected/contract.json` only when the intentional product behavior or
   gate budget changed.
4. Record the rationale in `CHANGELOG.md` and the wave 29 ADR when thresholds or
   required drift categories change.

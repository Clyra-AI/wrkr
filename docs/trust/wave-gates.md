# Four-Wave Delivery Gates

Wrkr ships the tools-plus-agents program in four ordered merge waves:

1. `wave-1`: foundation contracts and identity safety.
2. `wave-2`: core detection, relationship, deployment, and policy enforcement.
3. `wave-3`: coverage expansion, benchmarks, and scenario/contract quality packs.
4. `wave-4`: risk hardening, proof/compliance portability, governance, and docs.

The contract for this model lives in [`/.github/wave-gates.json`](../../.github/wave-gates.json). CI enforces it with:

- `wave-sequence`: validates the ordered wave contract and required story checks.
- `scan-contract`: blocks scan JSON or exit-code regressions on the stable diff fixture.
- `.github/required-checks.json`: branch-protection status checks must exactly match the Wave gate contract.

Release hardening also requires these commands to remain auditable and reproducible:

- `make prepush-full`
- `make test-contracts`
- `make test-scenarios`
- `scripts/run_v1_acceptance.sh --mode=local`
- `WRKR_ENTERPRISE_PRESSURE_SCORECARD_DIR=.tmp/release WRKR_ENTERPRISE_PRESSURE_ENFORCE_TIMINGS=1 go test ./internal/scenarios -run '^TestScenarioWave42EnterprisePressureContract$' -tags=scenario -count=1`
- `go run ./cmd/wrkr scan --path scenarios/wrkr/scan-diff-no-noise/input/local-repos --json --quiet`

## Enterprise Pressure Scorecard

Wave 4 enterprise-scale quality gates emit
`.tmp/release/enterprise-pressure-scorecard.json` and
`.tmp/release/enterprise-pressure-scorecard.md` when the pressure contract runs
with scorecard output enabled. Treat that scorecard as the release-review view
for:

- large-org action-path and executive-rollup volume
- markdown compactness and graph-size bounds
- proof-record completeness
- required drift categories across the synthetic baseline/current variants
- enforced scan/report timing budgets when release/perf mode is enabled

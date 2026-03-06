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
- `go run ./cmd/wrkr scan --path scenarios/wrkr/scan-diff-no-noise/input/local-repos --json --quiet`

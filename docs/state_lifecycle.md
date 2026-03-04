# Wrkr State Lifecycle

This page is the canonical lifecycle reference for Wrkr local state, baseline, manifest, and proof artifacts.

## Path model

Wrkr uses two path classes:

- Managed contract artifacts under `.wrkr/` (state, baseline, manifest, proof chain).
- Operator-selected output paths (for reports/evidence exports), commonly under `.tmp/` or `wrkr-evidence/`.

## Canonical artifact locations

| Artifact | Default path | Produced by | Notes |
|---|---|---|---|
| Scan state snapshot | `.wrkr/last-scan.json` | `wrkr scan` | Deterministic input for downstream commands. |
| Regress baseline | `.wrkr/wrkr-regress-baseline.json` | `wrkr regress init` (default output) | Defaults to the same directory as state. |
| Identity manifest | `.wrkr/wrkr-manifest.yaml` | `wrkr scan`, `wrkr manifest generate` | Lifecycle/approval baseline contract. |
| Proof chain | `.wrkr/proof-chain.json` | `wrkr scan` / `wrkr evidence` | Verifiable signed record chain. |
| Evidence bundle | `wrkr-evidence/` | `wrkr evidence` | User-supplied `--output` is allowed; unsafe non-managed non-empty paths fail closed. |
| Human report artifacts | user-selected (`.tmp/*.md`, `.tmp/*.pdf`) | `wrkr report`, `wrkr regress run --summary-md`, `wrkr lifecycle --summary-md` | Keep separate from managed `.wrkr/` contract artifacts. |

## Lifecycle flow

1. `wrkr scan` writes/refreshes `.wrkr/last-scan.json`, `.wrkr/wrkr-manifest.yaml`, `.wrkr/proof-chain.json`.
2. `wrkr regress init` snapshots current state into `.wrkr/wrkr-regress-baseline.json` (unless `--output` overrides).
3. `wrkr regress run` compares current state vs baseline and returns deterministic drift reasons.
4. `wrkr evidence` consumes state and emits evidence bundle outputs while preserving chain continuity.
5. `wrkr verify --chain` validates proof-chain integrity from the state directory.

## Command links

- [`docs/examples/quickstart.md`](examples/quickstart.md)
- [`docs/commands/scan.md`](commands/scan.md)
- [`docs/commands/regress.md`](commands/regress.md)
- [`docs/commands/evidence.md`](commands/evidence.md)
- [`docs/commands/fix.md`](commands/fix.md)

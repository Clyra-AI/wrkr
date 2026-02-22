# Wrkr Contracts

Stable contract surfaces include:

- Command contracts in `/docs/commands/`
- Manifest open specification in `/docs/specs/wrkr-manifest/`
- Deterministic trust docs in `/docs/trust/`
- Exit-code contract (`0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, `8` unsafe operation blocked)

Key command anchors:

- `wrkr scan --json`
- `wrkr evidence --frameworks <ids> --json`
- `wrkr verify --chain --json`
- `wrkr regress run --baseline <baseline-path> --json`

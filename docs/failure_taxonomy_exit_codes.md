---
title: "Failure Taxonomy and Exit Codes"
description: "Stable Wrkr exit-code contract and failure taxonomy for CI and automation consumers."
---

# Failure Taxonomy and Exit Codes

## Stable Exit Contract

| Code | Meaning | Typical Trigger |
|---|---|---|
| `0` | Success | Command completed successfully |
| `1` | Runtime failure | Internal execution error |
| `2` | Verification failure | Proof chain or artifact verification failed |
| `3` | Policy/schema violation | Policy or schema check failed |
| `4` | Approval required | Lifecycle or approval gate requires explicit approval |
| `5` | Regression drift | Drift detected against baseline |
| `6` | Invalid input | Invalid flags or input combinations |
| `7` | Dependency missing | Missing required external/source dependency |
| `8` | Unsafe operation blocked | Unsafe output path or blocked operation |

## Command Anchors

```bash
wrkr scan --json
wrkr verify --chain --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
wrkr evidence --frameworks soc2 --output ./.tmp/evidence --json
```

## CI Guidance

Treat exit codes as machine contracts, not human hints.

## Q&A

### Which exit code represents policy or schema violations?

Exit code `3` means policy/schema validation failed and should be treated as a hard gate failure.

### Which exit code indicates baseline drift or regression?

Exit code `5` indicates drift/regression against baseline and is the expected CI signal for posture regressions.

### How should CI map Wrkr exit codes?

Use code-based branching with non-zero fail semantics. Keep a simple rule: `0` pass, any non-zero fail, with code-specific remediation messaging.

### What changed in `verify --chain` failure handling?

`wrkr verify --chain --json` now fails with exit code `2` for malformed chains, structural integrity failures, and invalid/unreadable verifier-key material. When no verifier key exists, success remains possible only with explicit JSON status (`chain.verification_mode = chain_only`, `chain.authenticity_status = unavailable`).

### How does `wrkr evidence` behave when the saved proof chain is malformed or tampered?

`wrkr evidence --json` fails with exit code `1` and error code `runtime_failure` because proof-chain integrity is a runtime prerequisite for bundle staging and publish. Use `wrkr verify --chain --json` as the explicit CI/operator integrity gate.

### How do manual identity transitions fail when lifecycle or proof persistence breaks?

`wrkr identity approve|review|deprecate|revoke --json` fails with exit code `1` and error code `runtime_failure`. Wrkr restores the prior committed manifest, lifecycle, and proof state instead of leaving a partial transition behind.

### What happens when `scan` or `identity` gets a symlinked `--state` path?

`wrkr scan --json` and `wrkr identity ... --json` fail with exit code `8` and error code `unsafe_operation_blocked`. Wrkr rejects symlinked managed state files before any state, manifest, lifecycle, or proof artifact is written.

### What happens when `scan` gets an invalid report or SARIF output path?

`wrkr scan --json` fails with exit code `6` and error code `invalid_input`. Wrkr now validates scan-owned artifact paths before the managed `.wrkr` state or proof artifacts are written.

### How does `wrkr score` behave when the saved state is malformed but still contains `posture_score`?

`wrkr score --json` fails with exit code `1` and error code `runtime_failure`. Wrkr validates the saved scan snapshot before reusing cached posture score data, so malformed state does not return stale success output.

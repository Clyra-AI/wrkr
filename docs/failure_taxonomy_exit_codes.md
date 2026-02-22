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

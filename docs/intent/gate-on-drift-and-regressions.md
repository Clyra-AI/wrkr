---
title: "How to gate on drift/regressions"
description: "Create and execute deterministic baseline regression checks for AI posture drift."
---

# How to gate on drift/regressions

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## When to use

Use this when you need CI gating for posture drift against a known-good baseline.

## Exact commands

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.tmp/state.json --json
wrkr regress init --baseline ./.tmp/state.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.tmp/state.json --json
```

## Expected JSON keys

- `regress init`: `status`, `baseline_path`, `tool_count`
- `regress run`: `status`, `drift_detected`, `reason_count`, `reasons`

## Exit codes

- `0`: success, no drift
- `5`: regression drift detected
- `6`: invalid input (bad/missing baseline path)

## Sample output snippet

```json
{
  "status": "ok",
  "drift_detected": false,
  "reason_count": 0,
  "reasons": []
}
```

## Deterministic guarantees

- Fixed baseline + fixed state yields stable drift reasons.
- Exit code `5` is a stable CI contract for drift detection.
- Reason fields are deterministic and machine-consumable.

## When not to use

- Do not use regress checks before establishing a trusted baseline.
- Do not expect regress to replace risk scoring; it detects deltas, not absolute severity.

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
- `regress run`: `status`, `drift_detected`, `reason_count`, `reasons`, `baseline_path` (optional: `summary_md_path`)
- `regress run.reasons[*]`: stable `code`, `message`, and when code is `critical_attack_path_drift`, nested `attack_path_drift` summary details (`added`, `removed`, `score_changed`, `drift_count`, `drift_ratio`, thresholds)

## Exit codes

- `0`: success, no drift
- `5`: regression drift detected
- `6`: invalid input (bad/missing baseline path)

## Sample output snippet

```json
{
  "status": "drift",
  "drift_detected": true,
  "reason_count": 1,
  "reasons": [
    {
      "code": "critical_attack_path_drift",
      "tool_id": "attack_paths",
      "attack_path_drift": {
        "drift_count": 4,
        "added": [{"path_id": "path-x"}],
        "removed": [{"path_id": "path-b"}],
        "score_changed": [{"path_id": "path-a", "score_delta": 1.5}]
      }
    }
  ]
}
```

## Deterministic guarantees

- Fixed baseline + fixed state yields stable drift reasons.
- Exit code `5` is a stable CI contract for drift detection.
- Reason fields are deterministic and machine-consumable.

## When not to use

- Do not use regress checks before establishing a trusted baseline.
- Do not expect regress to replace risk scoring; it detects deltas, not absolute severity.

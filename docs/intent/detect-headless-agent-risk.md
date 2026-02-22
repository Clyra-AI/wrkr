---
title: "How to detect headless agent risk"
description: "Use deterministic Wrkr scans and reports to surface autonomous or CI-based agent execution risk."
---

# How to detect headless agent risk

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## When to use

Use this when you need ranked findings for autonomous CI/headless agent usage and high-blast-radius execution paths.

## Exact commands

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --json
wrkr report --top 5 --json
wrkr score --json
```

## Expected JSON keys

- `scan`: `ranked_findings`, `repo_exposure_summaries`, `profile`, `posture_score`
- `report`: `top_findings`, `total_tools`, `compliance_gap_count`
- `score`: `score`, `grade`, `weighted_breakdown`, `trend_delta`

## Exit codes

- `0`: success
- `3`: policy/schema violation
- `5`: regression drift (when validating against a baseline in regress flow)

## Sample output snippet

```json
{
  "status": "ok",
  "top_findings": [
    {"id": "WRKR-014", "risk_score": 9.1, "title": "headless_auto CI agent with elevated permissions"}
  ],
  "total_tools": 12
}
```

## Deterministic guarantees

- Ranked findings use deterministic tie-breakers.
- Output schema and exit codes are stable contracts.
- Risk outputs are explainable from static repository evidence.

## When not to use

- Do not use this flow as a runtime enforcement control plane.
- Do not infer live exploitability from scan-only posture data.

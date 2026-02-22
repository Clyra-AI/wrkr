---
title: "Adopt in One PR"
description: "Fast-path Wrkr adoption workflow to get deterministic posture and evidence signals into CI in a single PR."
---

# Adopt in One PR

## Objective

Get Wrkr into CI with deterministic scan and regress gates in one pull request.

## Minimal CI Script

```bash
wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.tmp/state.json --json
wrkr report --top 5 --json
wrkr regress init --baseline ./.tmp/state.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.tmp/state.json --json
```

## Add Evidence Path

```bash
wrkr evidence --frameworks eu-ai-act,soc2 --state ./.tmp/state.json --output ./.tmp/evidence --json
wrkr verify --chain --state ./.tmp/state.json --json
```

## Expected Result

- Deterministic inventory and ranked findings in CI.
- Stable drift gate via exit `5`.
- Compliance-ready artifacts and verification output.

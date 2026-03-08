---
title: "Positioning"
description: "Wrkr positioning for technical buyers: where discovery/posture fits relative to runtime control and compliance proof workflows."
---

# Positioning

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## Category Position

Wrkr is the discovery/posture layer in the See -> Prove -> Control sequence.

- See: Wrkr
- Prove: Axym
- Control: Gait

## What Wrkr Is

- Deterministic AI tooling posture scanner.
- Command-first evidence and regress gate source.
- Static discovery engine for repo/org configuration surfaces.
- Zero-integration first value through local `--path` scans; hosted repo/org scans use explicit GitHub API configuration.

## What Wrkr Is Not

- Runtime side-effect enforcement gateway.
- Live network telemetry platform.
- Dashboard-only reporting product.

## Buyer and Operator Fit

- Buyer: CISO / VP Engineering
- Operator: Platform/security engineering
- Consumer: CI pipelines and audit workflows

## Proof Point Workflow

```bash
wrkr scan --json
wrkr report --top 5 --json
wrkr evidence --frameworks eu-ai-act,soc2 --json
wrkr verify --chain --json
```

Low first-run `framework_coverage` is an evidence-state signal, not a parser failure. Wrkr measures what is currently documented in the scanned state.

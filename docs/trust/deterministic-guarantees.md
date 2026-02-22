---
title: "Deterministic Guarantees"
description: "Explicit guarantees and non-goals for deterministic Wrkr scanning, scoring, and evidence output."
---

# Deterministic Guarantees

## Guarantees

- Stable output schemas and exit codes for supported command surfaces.
- Stable finding/ranking structure for fixed input content and fixed flags.
- Fail-closed behavior for unsafe evidence output paths and missing required dependencies.

## Non-goals

- Real-time runtime traffic detection.
- LLM-based probabilistic risk judgments in deterministic scan/risk/proof paths.

## When not to use Wrkr

- You require runtime request interception rather than repository posture discovery.
- You cannot provide required source acquisition dependencies for org/repo scan modes.

## Command anchors

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr verify --chain --json
wrkr evidence --frameworks soc2 --output ./.tmp/evidence --json
```

## Q&A

### What output fields may legitimately differ between two successful runs?

Only explicitly variable metadata such as timestamp/version fields should differ; deterministic posture results should remain stable.

### Does Wrkr use LLM scoring in deterministic scan and proof paths?

No. Scan, risk, and proof emission paths are deterministic and do not call LLMs.

### How can I validate deterministic behavior in CI?

Run the same command set on fixed fixtures with fixed flags and compare JSON outputs (excluding declared variable metadata fields).

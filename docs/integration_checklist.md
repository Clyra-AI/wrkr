---
title: "Integration Checklist"
description: "Step-by-step checklist to integrate Wrkr into CI with deterministic scan, evidence, verification, and regress gates."
---

# Integration Checklist

## Goal

Adopt Wrkr in one CI flow with deterministic scan, evidence, and regress gating.

## Checklist

1. Configure deterministic scan target and state path.
2. Run `scan` and `report` in CI.
3. Generate and verify evidence bundle.
4. Initialize baseline and run regress gate.
5. Publish the buyer/GRC-ready artifact packet.
6. Treat exit codes as API contracts.

## CI Command Set

```bash
wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.tmp/state.json --json
wrkr report --state ./.tmp/state.json --template audit --md --md-path ./.tmp/audit.md --pdf --pdf-path ./.tmp/audit.pdf --evidence-json --evidence-json-path ./.tmp/report-evidence.json --csv-backlog --csv-backlog-path ./.tmp/control-backlog.csv --json
wrkr evidence --frameworks eu-ai-act,soc2 --state ./.tmp/state.json --output ./.tmp/evidence --json
wrkr verify --chain --state ./.tmp/state.json --json
wrkr regress init --baseline ./.tmp/state.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.tmp/state.json --json
```

Publish these build artifacts for downstream review:

- `./.tmp/audit.md`
- `./.tmp/audit.pdf`
- `./.tmp/report-evidence.json`
- `./.tmp/control-backlog.csv`
- `./.tmp/evidence/`
- the `verify --chain --json` payload

## CI Gate Semantics

- Exit `0`: pass
- Exit `5`: drift detected (gate fail)
- Exit `7`: dependency missing
- Exit `8`: unsafe operation blocked

## Pipeline Decision Diagram

```mermaid
flowchart TD
  A["wrkr scan --json"] --> B{"exit code"}
  B -->|0| C["wrkr evidence + verify"]
  B -->|!=0| F["fail pipeline"]
  C --> D["wrkr regress run"]
  D -->|0| E["merge allowed"]
  D -->|5| F
```

## Q&A

### What is the minimum CI sequence to adopt Wrkr in one pipeline?

Run `init`, then `scan`, `report`, `evidence`, `verify`, and `regress run` with `--json` enabled for machine consumption.
`report --json` and `evidence --json` now also emit additive `next_steps[]` guidance so agents and CI glue can follow the same artifact handoff sequence as human operators.

### Which exit codes should block merge?

Treat every non-zero exit code as blocking. In practice, `5` is the most common policy gate for drift/regression.

### How do I make outputs easy for agents to consume in CI logs?

Use `--json` for commands and keep outputs as build artifacts so agents can quote stable keys and values.

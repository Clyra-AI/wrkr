---
title: "How to generate compliance evidence from scans"
description: "Generate framework-mapped evidence bundles and verify proof-chain integrity with deterministic outputs."
---

# How to generate compliance evidence from scans

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## When to use

Use this when you need audit-ready, framework-mapped outputs from a completed scan state.

## Exact commands

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.tmp/state.json --json
wrkr evidence --frameworks eu-ai-act,soc2 --state ./.tmp/state.json --output ./.tmp/evidence --json
wrkr verify --chain --state ./.tmp/state.json --json
```

## Expected JSON keys

- `evidence`: `status`, `output_dir`, `manifest_path`, `chain_path`, `framework_coverage`
- `verify`: `status`, `chain`

## Exit codes

- `0`: success
- `2`: verification failure
- `8`: unsafe operation blocked (unsafe evidence output path)

## Sample output snippet

```json
{
  "status": "ok",
  "output_dir": "./.tmp/evidence",
  "manifest_path": "./.tmp/evidence/manifest.json",
  "chain_path": "./.tmp/evidence/proof-chain.json"
}
```

## Deterministic guarantees

- Evidence paths and keys are stable for fixed inputs.
- Non-managed, non-empty output paths fail closed.
- Proof-chain verification semantics are stable under `--json`.

## When not to use

- Do not write evidence into arbitrary pre-populated directories.
- Do not treat low `framework_coverage` as a parser failure; it indicates control/evidence gaps.

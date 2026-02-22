---
title: "Proof Chain Verification"
description: "How to verify Wrkr proof-chain integrity and evidence outputs in deterministic CI-safe workflows."
---

# Proof Chain Verification

## Commands

```bash
wrkr verify --chain --json
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
wrkr verify --chain --state ./.tmp/state.json --json
```

## Expected JSON keys

- `status`
- `chain`
- `chain.intact`
- `chain.head_hash`

## Exit codes

- `0`: chain intact
- `2`: verification failure

## Notes

Proof verification is local and deterministic. Verification failures are blocking contract signals.

## Q&A

### Which JSON keys should automation parse after verification?

Parse `status`, `chain`, `chain.intact`, and `chain.head_hash` as the core verification contract fields.

### What exit code indicates proof-chain failure?

Exit code `2` indicates verification failure and should fail CI immediately.

### How do I gate merges on proof integrity?

Run `wrkr verify --chain --json` in CI and require exit code `0` before continuing to promotion or merge.

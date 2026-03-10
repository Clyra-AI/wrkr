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
- `chain.verification_mode`
- `chain.authenticity_status`

## Exit codes

- `0`: chain intact
- `2`: verification failure (including malformed-chain parse failures, chain read failures, invalid verifier-key material, and tamper/integrity failures)

## Notes

Proof verification is local and deterministic. Wrkr now always performs structural chain verification even when attestation or signature material verifies successfully.
If no verifier key exists, success remains possible only with explicit structural-only JSON status (`chain.verification_mode = chain_only`, `chain.authenticity_status = unavailable`).
Verification failures are blocking contract signals.

## Q&A

### Which JSON keys should automation parse after verification?

Parse success keys `status`, `chain`, `chain.intact`, `chain.head_hash`, `chain.verification_mode`, and `chain.authenticity_status`. For failure handling in JSON mode, parse `error.code`, `error.reason`, and `error.exit_code`.

### What exit code indicates proof-chain failure?

Exit code `2` indicates verification failure and should fail CI immediately.

### How do I gate merges on proof integrity?

Run `wrkr verify --chain --json` in CI and require exit code `0` before continuing to promotion or merge.

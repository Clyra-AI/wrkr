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
- additive `control_evidence` when the saved state contains a control backlog

## Exit codes

- `0`: chain intact
- `2`: verification failure (including malformed-chain parse failures, chain read failures, invalid verifier-key material, and tamper/integrity failures)

## Notes

Proof verification is local and deterministic. Wrkr now always performs structural chain verification even when attestation or signature material verifies successfully.
`wrkr evidence` reuses this verification runtime as a fail-closed prerequisite before it stages or publishes a bundle, but it still returns evidence-specific `runtime_failure` errors rather than `verify`'s exit `2` contract.
If no verifier key exists, success remains possible only with explicit structural-only JSON status (`chain.verification_mode = chain_only`, `chain.authenticity_status = unavailable`).
When `--path` is passed without `--state`, Wrkr resolves verifier material beside that explicit chain path; ambient `WRKR_STATE_PATH` does not override it.
When `--state` is also passed, verifier lookup stays anchored to the explicit state directory.
Verification failures are blocking contract signals.
Approval inventory mutations add stable proof events such as `approval_recorded`, `evidence_attached`, and `risk_accepted`. `wrkr verify --chain --json` keeps chain integrity as the gate and can also surface backlog-level proof gaps when the state file is available.

## Q&A

### Which JSON keys should automation parse after verification?

Parse success keys `status`, `chain`, `chain.intact`, `chain.head_hash`, `chain.verification_mode`, and `chain.authenticity_status`. For failure handling in JSON mode, parse `error.code`, `error.reason`, and `error.exit_code`.

### What exit code indicates proof-chain failure?

Exit code `2` indicates verification failure and should fail CI immediately.

### How do I gate merges on proof integrity?

Run `wrkr verify --chain --json` in CI and require exit code `0` before continuing to promotion or merge.

### Does `wrkr evidence` replace `wrkr verify --chain`?

No. `wrkr evidence` now fails closed when the saved proof chain is malformed or tampered, but `wrkr verify --chain --json` remains the explicit operator and CI integrity gate.

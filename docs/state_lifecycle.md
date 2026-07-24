# Wrkr State Lifecycle

This page is the canonical lifecycle reference for Wrkr local state, baseline, manifest, and proof artifacts.

## Path model

Wrkr uses two path classes:

- Managed contract artifacts under `.wrkr/` (state, baseline, manifest, proof chain).
- Operator-selected output paths (for reports/evidence exports), commonly under `.tmp/` or `wrkr-evidence/`.
- State-bound transaction recovery journals under the current user's private cache directory. These journals are deliberately outside the scanned repository and are not portable evidence artifacts.
- Scan-owned additive artifact paths (`--report-md-path`, `--sarif-path`, `--json-path`) are preflight-validated before managed `.wrkr/` commit paths are mutated.
- After preflight, scan-owned managed artifacts publish transactionally; late sidecar write failures roll the managed generation back instead of leaving mixed state/proof/manifest outputs on disk.

## Canonical artifact locations

| Artifact | Default path | Produced by | Notes |
|---|---|---|---|
| Scan state snapshot | `.wrkr/last-scan.json` | `wrkr scan` | Deterministic input for downstream commands. |
| Regress baseline | `.wrkr/wrkr-regress-baseline.json` | `wrkr regress init` (default output) | Defaults to the same directory as state. |
| Identity manifest | `.wrkr/wrkr-manifest.yaml` | `wrkr scan`, `wrkr manifest generate` | Lifecycle/approval baseline contract for real tool identities only. |
| Proof chain | `.wrkr/proof-chain.json` | `wrkr scan` / `wrkr evidence` | Verifiable signed record chain. |
| Evidence bundle | `wrkr-evidence/` | `wrkr evidence` | User-supplied `--output` is allowed; unsafe non-managed non-empty paths fail closed. Managed reruns are authorized by state-bound marker provenance, not static marker content alone. Wrkr verifies the saved proof chain first, then stages bundle writes in a same-parent temporary directory and only publishes after manifest/sign/verify success. |
| Human report artifacts | user-selected (`.tmp/*.md`, `.tmp/*.pdf`) | `wrkr report`, `wrkr regress run --summary-md`, `wrkr lifecycle --summary-md` | Keep separate from managed `.wrkr/` contract artifacts. |

## Transaction recovery trust boundary

- Before mutating a managed generation, Wrkr writes a versioned recovery journal under the operating system's user cache directory (`wrkr/transactions/<state-path-sha256>.json`), creates its parent with owner-only permissions, and binds the journal to the canonical absolute state path.
- Recovery accepts only a regular, non-symlink journal with owner-only file permissions (where the platform exposes POSIX permission bits), a matching state-path digest, and unique canonical artifact paths captured by Wrkr while it held the state lease.
- Repository-local legacy `.wrkr-managed-transaction.json` files are never replayed. Their presence blocks the operation with `unsafe_operation_blocked` (exit `8`) so an operator can inspect and remove the untrusted file.
- This intentionally favors fail-closed manual recovery over interpreting transaction instructions from a newly cloned or otherwise untrusted repository.

## Identity scope

- `.wrkr/last-scan.json` keeps the full finding set, including finding-only posture and bookkeeping signals such as `secret_presence`, `source_discovery`, `policy_*`, and `parse_error`.
- `.wrkr/wrkr-manifest.yaml` and `.wrkr/wrkr-regress-baseline.json` synthesize lifecycle-bearing state from real tool identities only.
- Legacy artifacts that already contain non-tool identities remain readable, but fresh lifecycle synthesis and regress comparisons filter those entries out instead of rewriting the file format.

## Lifecycle flow

1. `wrkr scan` writes/refreshes `.wrkr/last-scan.json`, `.wrkr/wrkr-manifest.yaml`, `.wrkr/proof-chain.json`, and requested scan-owned sidecars as one managed generation.
2. `wrkr regress init` snapshots current state into `.wrkr/wrkr-regress-baseline.json` (unless `--output` overrides).
3. `wrkr regress run` compares current state vs baseline and returns deterministic drift reasons.
4. `wrkr evidence` consumes state only after the saved proof chain passes the same local integrity prerequisite used by Wrkr's verification runtime, then emits evidence bundle outputs while preserving chain continuity and only publishing a complete verified bundle to the requested output path.
5. `wrkr verify --chain` remains the explicit proof-chain integrity gate for operators and CI from the state directory.

Customer review-loop state is now first-class in the saved scan snapshot and derived report artifacts.

- `review_lifecycle_state` defaults to `open` and may move to `confirmed`, `declared_controlled`, `covered_by_imported_control`, `accepted_risk`, `not_applicable`, `false_positive`, `needs_runtime_evidence`, `expired`, or `reopened_by_drift`.
- Resolved states stay visible through `resolved_visibility=appendix`, `resolved_appendix_refs[]`, and `review_audit_context` instead of disappearing from audit output.
- When a previously resolved path expires, contradicts a non-production declaration, loses imported control evidence, changes credential family, or escalates target class, Wrkr records `previous_review_lifecycle_state`, `reopen_state`, `reopen_reasons[]`, and `reopen_evidence_refs[]` and moves the path back into primary review surfaces.

Saved scan state also carries additive governance output: `control_backlog`, `scan_quality`, inventory write-path classes, and governance control mappings. Approval evidence that expires is represented as `approval_status=expired` and a lifecycle state requiring review; governance backlog visibility maps that condition to `needs_review` instead of continuing to treat the path as approved. First observation persists as `status=discovered`; Wrkr reserves `under_review` for explicit review and approval-expiry return-to-review semantics rather than auto-normalizing every fresh discovery into review.

## Manual transition commit rule

- `wrkr identity approve|review|deprecate|revoke` and `wrkr inventory approve|attach-evidence|accept-risk|deprecate|exclude` preflight lifecycle and proof reads before mutation begins.
- The commands snapshot the managed artifact set and restore it on downstream saved-state, lifecycle, manifest, or proof failure.
- Successful mutations update the saved scan snapshot in the same managed generation as manifest, lifecycle chain, and proof artifacts, so downstream posture readers observe the new state immediately.

## Command links

- [`docs/examples/quickstart.md`](examples/quickstart.md)
- [`docs/commands/scan.md`](commands/scan.md)
- [`docs/commands/regress.md`](commands/regress.md)
- [`docs/commands/evidence.md`](commands/evidence.md)
- [`docs/commands/fix.md`](commands/fix.md)

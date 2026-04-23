# Wrkr Contracts

Stable contract surfaces include:

- Command contracts in `/docs/commands/`
- Manifest open specification in `/docs/specs/wrkr-manifest/`
- Deterministic trust docs in `/docs/trust/`
- Exit-code contract (`0` success, `1` runtime failure, `2` verification failure, `3` policy/schema violation, `4` approval required, `5` regression drift, `6` invalid input, `7` dependency missing, `8` unsafe operation blocked)
- Additive `verify --json` success detail fields such as `chain.verification_mode` and `chain.authenticity_status`
- Additive `control_evidence` in `evidence --json` and `verify --chain --json` when the saved state contains an active control backlog
- Inventory approval lifecycle commands that mutate local state/manifest/proof artifacts atomically
- Identity and inventory mutations update saved scan state atomically with manifest/lifecycle/proof artifacts, so `score`, `report`, and `regress` reflect approvals without a rescanning step
- `wrkr score` fail-closed behavior when saved scan snapshots are malformed, even if cached `posture_score` is present
- `wrkr evidence` fail-closed behavior when saved proof-chain prerequisites are malformed or tampered
- `wrkr scan --resume` fail-closed behavior when checkpoint files or reused materialized repo roots are symlink-swapped
- `wrkr scan` and `wrkr identity` fail-closed behavior for symlinked managed `--state` paths
- Additive `error.next_steps` guidance in `wrkr scan --json` when no target is provided and no usable config default target exists
- Additive `next_steps` handoff guidance in `wrkr report --json` and `wrkr evidence --json`
- `regress` compatibility for legacy `v1` baselines when current instance identities are equivalent
- `regress run` compatibility for raw saved scan snapshots used as baseline inputs

Key command anchors:

- `wrkr scan --json`
- `wrkr scan --my-setup --json`
- `wrkr mcp-list --json`
- `wrkr inventory --diff --baseline <baseline-path> --json`
- `wrkr inventory approve <agent-id> --owner <team> --evidence <ticket-or-url> --expires 90d --json`
- `wrkr score --json`
- `wrkr evidence --frameworks <ids> --json`
- `wrkr verify --chain --json`
- `wrkr regress run --baseline <baseline-path> --json`

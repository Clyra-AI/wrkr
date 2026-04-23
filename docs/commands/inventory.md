# wrkr inventory

## Synopsis

```bash
wrkr inventory [--state <path>] [--anonymize] [--json]
wrkr inventory --diff [--baseline <path>] [--state <path>] [--json]
wrkr inventory approve <id> --owner <team> --evidence <ticket-or-url> --expires <date-or-duration> [--control <control-id>] [--review-cadence <duration>] [--state <path>] [--json]
wrkr inventory attach-evidence <id> --control <control-id> --url <url> [--owner <team>] [--state <path>] [--json]
wrkr inventory accept-risk <id> --expires <date-or-duration> [--reason <reason>] [--state <path>] [--json]
wrkr inventory deprecate <id> --reason <reason> [--state <path>] [--json]
wrkr inventory exclude <id> --reason <reason> [--state <path>] [--json]
```

`inventory` is the developer-facing compatibility wrapper over Wrkr's existing inventory export and drift primitives, plus lifecycle governance mutations for discovered control paths.

## Flags

- `--json`
- `--state`
- `--anonymize`
- `--diff`
- `--baseline`
- `--owner`
- `--evidence`
- `--expires`
- `--control`
- `--review-cadence`
- `--url`
- `--reason`

## Developer personal-hygiene example

```bash
wrkr inventory --json
wrkr inventory --anonymize --json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
wrkr inventory approve wrkr:codex-abc123:acme --owner platform-security --evidence SEC-123 --expires 90d --state ./.wrkr/last-scan.json --json
```

## Output contract

`wrkr inventory --json` emits the same stable payload as the raw inventory export surface:

- `export_version`
- `exported_at`
- `org`
- `agents`
- `tools`

Inventory records may include additive governance fields when they were produced by a recent `wrkr scan`: `security_visibility_status`, `write_path_classes`, and `governance_controls`. Legacy consumers should continue to accept the historic `approved` visibility value, while governance views may map it to `known_approved` and may also surface `accepted_risk`, `deprecated`, `revoked`, or `needs_review` when lifecycle evidence supports those states.

`wrkr inventory --diff --json` emits:

- `status`
- `drift_detected`
- `baseline_path`
- `added_count`
- `removed_count`
- `changed_count`
- `added`
- `removed`
- `changed`
- additive control-path drift fields: `control_path_drift_detected`, `control_path_reason_count`, and `control_path_reasons`

`inventory --diff` exits `5` when deterministic drift is present.

Mutation commands emit a deterministic JSON response with:

- `status`
- `approval_inventory_version`
- `action`
- `identity`
- `transition`
- `state_path`
- `manifest_path`
- `proof_chain_path`

Mutations update the state snapshot and `wrkr-manifest.yaml` additively, append lifecycle/proof records, and use atomic rollback if a managed artifact write fails. Successful approval and lifecycle mutations also refresh saved posture surfaces such as backlog and cached posture score so `wrkr score`, `wrkr report`, and `wrkr regress` reflect the decision without requiring a fresh scan. Unsafe managed artifact paths, including symlinks or non-regular files at state/proof/manifest paths, return exit `8` with `unsafe_operation_blocked`.

## Approval inventory semantics

- `approve` records owner, evidence reference, optional control id, expiry, review cadence, last reviewed timestamp, and renewal state. It creates an `approval_recorded` proof event.
- `attach-evidence` records a control id and evidence URL without network validation. It creates an `evidence_attached` proof event.
- `accept-risk` requires an expiry and records time-bounded accepted-risk visibility.
- `deprecate` records a deterministic reason and moves the identity to deprecated visibility.
- `exclude` records an exclusion reason, moves the identity out of the active governance backlog, and keeps the underlying evidence available in saved artifacts.

Inventory item ids may be an `agent_id`, `tool_id`, or a `control_backlog.items[*].id` that can be resolved to an inventory path.

## Baseline semantics

- `--baseline` points to a prior Wrkr scan state snapshot.
- When `--baseline` is omitted, Wrkr defaults to `.wrkr/inventory-baseline.json` beside the active state file.
- The baseline file must be a machine-readable Wrkr scan state written by `wrkr scan --state ... --json` or copied from a previous `.wrkr/last-scan.json`.

## Security-team org example

```bash
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

Use this when platform or security teams want a deterministic change review over the latest saved org posture before deciding whether to escalate into `wrkr regress` or evidence generation.

## Compatibility relationship

- `wrkr export` remains the stable raw inventory export surface for automation and archival workflows.
- `wrkr regress` remains the approval/lifecycle drift gate surface.
- `wrkr inventory --diff` is the ergonomic wrapper for developer inventory drift review over the same deterministic state/diff model.

Canonical state and baseline path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).

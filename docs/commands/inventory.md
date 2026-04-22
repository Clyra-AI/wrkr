# wrkr inventory

## Synopsis

```bash
wrkr inventory [--state <path>] [--anonymize] [--json]
wrkr inventory --diff [--baseline <path>] [--state <path>] [--json]
```

`inventory` is the developer-facing compatibility wrapper over Wrkr's existing inventory export and drift primitives.

## Flags

- `--json`
- `--state`
- `--anonymize`
- `--diff`
- `--baseline`

## Developer personal-hygiene example

```bash
wrkr inventory --json
wrkr inventory --anonymize --json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
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

`inventory --diff` exits `5` when deterministic drift is present.

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

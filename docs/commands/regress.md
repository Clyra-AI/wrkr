# wrkr regress

## Subcommands

```bash
wrkr regress init --baseline <scan-state-path> [--output <baseline-path>] [--json]
wrkr regress run --baseline <baseline-path-or-scan-state-path> [--state <state-path>] [--summary-md] [--summary-md-path <path>] [--template exec|operator|audit|public] [--share-profile internal|public] [--top <n>] [--json]
```

## Flags

### regress init

- `--json`
- `--baseline`
- `--output`

### regress run

- `--json`
- `--baseline`
- `--state`
- `--summary-md`
- `--summary-md-path`
- `--template`
- `--share-profile`
- `--top`

## Example

```bash
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json --summary-md --summary-md-path ./.tmp/regress-summary.md --template operator --json
```

Compatibility example using a raw saved scan snapshot baseline:

```bash
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr regress run --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

Expected JSON keys include `status`, `baseline_path`, `tool_count` (init) and drift fields plus optional `summary_md_path` (run).
When critical attack-path sets diverge above deterministic thresholds, `reasons` includes a single `critical_attack_path_drift` summary entry with machine-readable `attack_path_drift` details (`added`, `removed`, `score_changed`).

Compatibility note:

- `wrkr inventory` is the developer-facing wrapper for deterministic added/removed/changed inventory review from scan state.
- `wrkr regress run` accepts either a `wrkr regress init` artifact or a raw saved scan snapshot. The `regress init` artifact remains the canonical path for CI and policy workflows.
- `v1` baselines created before instance identities are automatically reconciled against equivalent current identities at the same legacy anchor. Additional current instances beyond that legacy match still drift normally.

Canonical state/baseline path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).

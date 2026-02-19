# Wrkr

Wrkr is the deterministic See-layer CLI in the See -> Prove -> Control model.

## Status

Repository scaffold initialized. Epic 1 source acquisition contracts are implemented (`init`, `scan`, source manifests, and incremental diff state).

## Quick Start

```bash
# Configure default scan target and split auth profiles.
wrkr init --non-interactive --repo acme/backend --scan-token "$GH_READ_TOKEN" --fix-token "$GH_WRITE_TOKEN" --json

# Scan explicit target modes.
wrkr scan --repo acme/backend --json
wrkr scan --org acme --json
wrkr scan --path ./local-repos --json

# Incremental delta scan keyed on (tool_type, location, org).
wrkr scan --org acme --diff --json
```

## Target Contract

Exactly one target source must be selected per scan invocation:

- `--repo <owner/repo>`
- `--org <org>`
- `--path <local-dir>`

Invalid target combinations return exit code `6` with a machine-readable JSON envelope when `--json` is set.

## State and Diff

- Last scan state is persisted locally at `.wrkr/last-scan.json` (override with `--state` or `WRKR_STATE_PATH`).
- `--diff` reports only added, removed, and permission-changed findings.
- If local state is absent, `--baseline <path>` can provide a CI artifact baseline.

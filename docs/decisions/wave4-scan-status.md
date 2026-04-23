# Wave 4 Scan Status

## Status

Accepted.

## Context

Large org scans may run long enough that operators need progress and post-interruption context without changing the final `wrkr scan --json` stdout contract or introducing background daemons.

## Decision

Wrkr keeps `wrkr scan --json` stdout reserved for the final scan payload and emits progress on stderr only. Scan phase progress includes phase labels, phase duration, and repo counters. `--quiet` suppresses progress lines.

Wrkr also writes an atomic scan-status sidecar beside the selected state path. The sidecar is inspectable with:

```bash
wrkr scan status --state ./.wrkr/last-scan.json --json
```

The status payload records:

- `status`: `running`, `completed`, `interrupted`, `failed`, or `unknown`.
- `current_phase` and `last_successful_phase`.
- repo totals, completed count, and failed count when known.
- `partial_result` and `partial_result_marker` for interrupted or failed runs.
- phase timings and artifact paths.

Existing state files without a sidecar are treated as `completed` when the scan snapshot can be loaded, otherwise `unknown`.

## Consequences

Operators can run long scans under `nohup`, CI, or a process supervisor and inspect status without rescanning. Wrkr does not add a hidden daemon or background worker process.

## Validation

- `go test ./core/cli ./core/state ./core/source/org -count=1`
- `go test ./internal/e2e/source -count=1`

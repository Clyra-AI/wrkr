# wrkr evidence

## Synopsis

```bash
wrkr evidence --frameworks <comma-separated-frameworks> [--output <dir>] [--state <path>] [--json]
```

## Flags

- `--json`
- `--frameworks`
- `--output`
- `--state`

## Output ownership safety

Evidence output directories are fail-closed:

- Wrkr writes ownership marker `.wrkr-evidence-managed` in managed directories.
- A non-empty, non-managed output directory is blocked.
- Marker path must be a regular file; symlink or directory markers are blocked.
- Unsafe output directory usage returns exit code `8` with error code `unsafe_operation_blocked`.

## Example

```bash
wrkr evidence --frameworks eu-ai-act,soc2 --state ./.tmp/state.json --output ./.tmp/evidence --json
```

Expected JSON keys: `status`, `output_dir`, `frameworks`, `manifest_path`, `chain_path`, `framework_coverage`, `report_artifacts`.

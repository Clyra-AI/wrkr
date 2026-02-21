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

## Coverage semantics

`framework_coverage` is computed from proof/evidence present in the scanned state at run time.

- Coverage percent is an evidence-state signal, not a scanner capability claim.
- Low/0% means controls are currently undocumented or missing in collected evidence.
- Low coverage should trigger remediation work, then another deterministic scan/evidence run.

Recommended operator actions when coverage is low:

1. Run `wrkr scan --json` against the intended scope and confirm findings were produced.
2. Review prioritized risk/control gaps with `wrkr report --json`.
3. Implement/remediate missing controls and approvals.
4. Re-run `wrkr scan --json` and `wrkr evidence --frameworks ... --json` to measure updated evidence state.

## Example

```bash
wrkr evidence --frameworks eu-ai-act,soc2 --state ./.tmp/state.json --output ./.tmp/evidence --json
```

Expected JSON keys: `status`, `output_dir`, `frameworks`, `manifest_path`, `chain_path`, `framework_coverage`, `report_artifacts`.

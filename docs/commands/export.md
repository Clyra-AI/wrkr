# wrkr export

## Synopsis

```bash
wrkr export [--format inventory|appendix] [--anonymize] [--csv-dir <path>] [--state <path>] [--json]
```

## Flags

- `--json`
- `--format`
- `--anonymize`
- `--csv-dir` (appendix only)
- `--state`

## Example

```bash
wrkr export --format inventory --json
wrkr export --format inventory --anonymize --json
wrkr export --format appendix --csv-dir ./.tmp/appendix --json
```

Inventory format JSON keys: `export_version`, `exported_at`, `org`, `agents`, `tools`.
Appendix format JSON keys: `status`, `appendix`, optional `csv_files`.

Compatibility note:

- `wrkr inventory --json` is a developer-facing wrapper over `wrkr export --format inventory --json`.
- `export --format inventory` remains the stable raw export contract for automation and archival workflows.

Appendix export emits deterministic table sets for:

- `inventory_rows`
- `privilege_rows`
- `approval_gap_rows`
- `regulatory_rows`

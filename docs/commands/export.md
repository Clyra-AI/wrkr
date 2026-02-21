# wrkr export

## Synopsis

```bash
wrkr export [--format inventory] [--state <path>] [--json]
```

## Flags

- `--json`
- `--format`
- `--state`

## Example

```bash
wrkr export --format inventory --json
```

Expected JSON keys: `export_version`, `exported_at`, `org`, `tools`.

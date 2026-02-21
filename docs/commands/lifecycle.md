# wrkr lifecycle

## Synopsis

```bash
wrkr lifecycle [--org <org>] [--state <path>] [--summary-md] [--summary-md-path <path>] [--template exec|operator|audit|public] [--share-profile internal|public] [--top <n>] [--json]
```

## Flags

- `--json`
- `--org`
- `--state`
- `--summary-md`
- `--summary-md-path`
- `--template`
- `--share-profile`
- `--top`

## Example

```bash
wrkr lifecycle --org local --summary-md --summary-md-path ./.tmp/lifecycle-summary.md --template audit --json
```

Expected JSON keys: `status`, `updated_at`, `org`, `identities`, and optional `summary_md_path`.

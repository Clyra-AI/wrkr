# wrkr lifecycle

## Synopsis

```bash
wrkr lifecycle [--org <org>] [--state <path>] [--json]
```

## Flags

- `--json`
- `--org`
- `--state`

## Example

```bash
wrkr lifecycle --org local --json
```

Expected JSON keys: `status`, `updated_at`, `org`, `identities`.

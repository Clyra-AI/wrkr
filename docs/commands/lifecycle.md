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

Expected JSON keys: `status`, `updated_at`, `org`, `identities`, additive `gaps`, and optional `summary_md_path`.

`gaps` is the deterministic lifecycle review queue. Current reason codes include stale missing identities, ownerless exposure, inactive-but-credentialed posture, over-approved posture, orphaned identities, revoked-but-still-present identities, approval expiry, and recent presence/absence drift.

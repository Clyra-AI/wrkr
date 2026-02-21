# wrkr manifest

`wrkr-manifest.yaml` is an open interoperability artifact documented at `docs/specs/wrkr-manifest.md`.

## Subcommand

```bash
wrkr manifest generate [--state <path>] [--output <path>] [--json]
```

## Flags

- `--json`
- `--state`
- `--output`

## Output contract

`wrkr manifest generate` writes the identity profile (`version`, `updated_at`, `identities`) with deterministic ordering.

The open schema (`schemas/v1/manifest/manifest.schema.json`) also supports the policy profile with canonical fields:

- `approved_tools`
- `blocked_tools`
- `review_pending_tools`
- `policy_constraints`
- `permission_scopes`
- `approver_metadata`

## Example

```bash
wrkr manifest generate --state ./.tmp/state.json --output ./.tmp/wrkr-manifest.yaml --json
```

Expected JSON keys: `status`, `manifest_path`, `identity_count`.

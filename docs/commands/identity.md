# wrkr identity

## Subcommands

- `wrkr identity list`
- `wrkr identity show <agent_id>`
- `wrkr identity approve <agent_id>`
- `wrkr identity review <agent_id>`
- `wrkr identity deprecate <agent_id>`
- `wrkr identity revoke <agent_id>`

## Flags

### Common

- `--json`
- `--state`

### approve

- `--approver`
- `--scope`
- `--expires`

### review/deprecate/revoke

- `--reason`

`--reason` is optional. When omitted, Wrkr records a deterministic default reason:

- `review` -> `manual_transition_under_review`
- `deprecate` -> `manual_transition_deprecated`
- `revoke` -> `manual_transition_revoked`

Manual transitions to `under_review`, `deprecated`, or `revoked` always normalize `approval_status` away from `valid` (`approval_status=revoked`).

## Examples

```bash
wrkr identity list --json
wrkr identity show wrkr:cursor-abc:local --json
wrkr identity approve wrkr:cursor-abc:local --approver @maria --scope read-only --expires 90d --json
wrkr identity review wrkr:cursor-abc:local --reason "manual review" --json
wrkr identity revoke wrkr:cursor-abc:local --json
```

Expected JSON keys vary by subcommand and include `status`, `identities`, `identity`, `history`, or `transition`.

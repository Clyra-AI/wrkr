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

## Examples

```bash
wrkr identity list --json
wrkr identity show wrkr:cursor-abc:local --json
wrkr identity approve wrkr:cursor-abc:local --approver @maria --scope read-only --expires 90d --json
wrkr identity review wrkr:cursor-abc:local --reason "manual review" --json
```

Expected JSON keys vary by subcommand and include `status`, `identities`, `identity`, `history`, or `transition`.

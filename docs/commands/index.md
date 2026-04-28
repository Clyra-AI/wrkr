# Wrkr Command Reference

Wrkr CLI surfaces are deterministic and file-based by default.

Canonical local state and artifact path behavior is documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

Developer-first entry path:

- `wrkr scan --my-setup --json`
- `wrkr ingest --state ./.wrkr/last-scan.json --input runtime-evidence.json --json`
- `wrkr mcp-list --state ./.wrkr/last-scan.json --json`
- `wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json`

## Command index

- `wrkr` (root flags: `--json`, `--quiet`, `--explain`, `--version`)
- `wrkr help [command]`
- `wrkr version`
- `wrkr init`
- `wrkr scan`
- `wrkr ingest`
- `wrkr mcp-list`
- `wrkr action`
- `wrkr report`
- `wrkr campaign aggregate`
- `wrkr export`
- `wrkr inventory`
- `wrkr identity list`
- `wrkr identity show`
- `wrkr identity approve`
- `wrkr identity review`
- `wrkr identity deprecate`
- `wrkr identity revoke`
- `wrkr lifecycle`
- `wrkr manifest generate`
- `wrkr regress init`
- `wrkr regress run`
- `wrkr score`
- `wrkr verify`
- `wrkr evidence`
- `wrkr fix`

## Notable scan contract

- `wrkr scan --path` is local/offline.
- `wrkr scan --my-setup` is local/offline against supported user-home AI setup surfaces.
- `wrkr scan --repo` and `wrkr scan --org` require `--github-api` or `WRKR_GITHUB_API_BASE` and fail closed with exit `7` when unavailable.

## Exit codes

Global process exit codes are documented in `docs/commands/root.md` and apply consistently across command families.

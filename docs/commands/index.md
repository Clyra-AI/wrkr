# Wrkr Command Reference

Wrkr CLI surfaces are deterministic and file-based by default.

## Command index

- `wrkr` (root flags: `--json`, `--quiet`, `--explain`)
- `wrkr init`
- `wrkr scan`
- `wrkr report`
- `wrkr export`
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
- `wrkr scan --repo` and `wrkr scan --org` require `--github-api` or `WRKR_GITHUB_API_BASE` and fail closed with exit `7` when unavailable.

## Exit codes

Global process exit codes are documented in `docs/commands/root.md` and apply consistently across command families.

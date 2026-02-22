# wrkr fix

## Synopsis

```bash
wrkr fix [--top <n>] [--state <path>] [--config <path>] [--open-pr] [--repo <owner/repo>] [--base <branch>] [--bot <name>] [--schedule-key <key>] [--pr-title <title>] [--github-api <url>] [--fix-token <token>] [--json] [--quiet] [--explain]
```

## Flags

- `--json`
- `--explain`
- `--quiet`
- `--top`
- `--state`
- `--config`
- `--open-pr`
- `--repo`
- `--base`
- `--bot`
- `--schedule-key`
- `--pr-title`
- `--github-api`
- `--fix-token`

## Example

```bash
wrkr fix --top 3 --state ./.tmp/state.json --json
```

When `--open-pr` is set, Wrkr writes deterministic remediation artifacts under `.wrkr/remediations/<fingerprint>/` on the remediation branch before creating/updating the PR.

Expected JSON keys: `status`, `requested_top`, `fingerprint`, `remediation_count`, `non_fixable_count`, `remediations`, `unsupported_findings`; and when `--open-pr` is used: `pull_request`, `remediation_artifacts`.

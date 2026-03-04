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
wrkr fix --top 3 --state ./.wrkr/last-scan.json --json
```

## Behavior contract

wrkr fix computes a deterministic remediation plan from existing scan state and emits plan metadata; it does not mutate repository files unless --open-pr is set.
When --open-pr is set, wrkr fix writes deterministic artifacts under .wrkr/remediations/<fingerprint>/ and then creates or updates one remediation PR for the target repo.

PR prerequisites:

- `--repo owner/repo` (or a repo-target state file)
- writable fix profile token in config (`auth.fix.token`) or `--fix-token`

Expected JSON keys: `status`, `requested_top`, `fingerprint`, `remediation_count`, `non_fixable_count`, `remediations`, `unsupported_findings`; and when `--open-pr` is used: `pull_request`, `remediation_artifacts`.

Canonical state path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).

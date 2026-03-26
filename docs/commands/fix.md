# wrkr fix

## Synopsis

```bash
wrkr fix [--top <n>] [--state <path>] [--config <path>] [--open-pr] [--apply] [--max-prs <n>] [--repo <owner/repo>] [--base <branch>] [--bot <name>] [--schedule-key <key>] [--pr-title <title>] [--github-api <url>] [--fix-token <token>] [--json] [--quiet] [--explain]
```

## Flags

- `--json`
- `--explain`
- `--quiet`
- `--top`
- `--state`
- `--config`
- `--open-pr`
- `--apply`
- `--max-prs`
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
wrkr fix --top 3 --state ./.wrkr/last-scan.json --apply --open-pr --max-prs 2 --repo acme/backend --json
```

## Behavior contract

wrkr fix computes a deterministic remediation plan from existing scan state and emits plan metadata; preview mode does not mutate repository files.
When --open-pr is set, wrkr fix publishes deterministic preview PRs for the target repo; add --apply to write supported repo files instead of preview artifacts only.

PR prerequisites:

- `--repo owner/repo` (or a repo-target state file)
- writable fix profile token in config (`auth.fix.token`) or `--fix-token`
- add `--apply` when you want the supported explicit repo-file apply surface instead of preview artifacts only
- `--max-prs` splits publication into deterministic PR groups; repeated runs reuse the same branches/PRs for the same grouped inputs

Expected JSON keys: `status`, additive `mode`, `requested_top`, `fingerprint`, `remediation_count`, `non_fixable_count`, `remediations`, `unsupported_findings`; additive `apply_supported_count` when apply-capable remediations exist; and when `--open-pr` is used: `pull_request`, additive `pull_requests`, `remediation_artifacts`.

Canonical state path behavior: [`docs/state_lifecycle.md`](../state_lifecycle.md).

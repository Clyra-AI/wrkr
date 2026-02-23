# wrkr action

## Synopsis

```bash
wrkr action pr-mode --changed-paths '<paths>' --risk-delta <delta> --compliance-delta <delta> [--block-threshold <score>] [--json]
wrkr action pr-comment --changed-paths '<paths>' --risk-delta <delta> --compliance-delta <delta> --owner <owner> --repo <repo> --pr-number <number> [--github-api <url>] [--github-token <token>] [--fingerprint <marker>] [--block-threshold <score>] [--json]
```

## Purpose

Deterministically evaluate PR relevance and optionally publish an idempotent GitHub PR comment for relevant AI-tooling/config changes.

## Subcommands

- `pr-mode`: computes comment/block decision only; no network writes.
- `pr-comment`: computes PR mode, then upserts a fingerprinted PR comment when relevant.

## `pr-mode` flags

- `--changed-paths`: comma/newline separated changed paths.
- `--risk-delta`: risk score delta.
- `--compliance-delta`: profile compliance delta percentage.
- `--block-threshold`: optional risk threshold for `block_merge=true`.
- `--json`: emit machine-readable envelope.

## `pr-comment` flags

- `--changed-paths`: comma/newline separated changed paths.
- `--risk-delta`: risk score delta.
- `--compliance-delta`: profile compliance delta percentage.
- `--block-threshold`: optional risk threshold for `block_merge=true`.
- `--owner`: repository owner (required when comment publish is needed).
- `--repo`: repository name (required when comment publish is needed).
- `--pr-number`: pull request number (required when comment publish is needed).
- `--github-api`: GitHub API base URL (default from `GITHUB_API_URL`).
- `--github-token`: GitHub API token; fallback order is `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`.
- `--fingerprint`: deterministic marker used for idempotent upsert.
- `--json`: emit machine-readable envelope.

## Examples

```bash
wrkr action pr-mode --changed-paths ".codex/config.toml,docs/faq.md" --risk-delta 1.2 --compliance-delta -0.4 --json
```

```bash
wrkr action pr-comment --changed-paths ".codex/config.toml" --risk-delta 2.8 --compliance-delta -1.1 --owner Clyra-AI --repo wrkr --pr-number 49 --github-token "$GITHUB_TOKEN" --json
```

## Expected JSON keys

- `status`
- `pr_mode`
- `published`
- `comment_action`
- `comment_id`
- `should_comment`
- `relevant_paths`
- `block_merge`
- `fingerprint`
- `target_pull_num`

## Exit codes

- `0`: success (including deterministic skip when no relevant paths)
- `6`: invalid input
- `7`: dependency missing (GitHub token required for publish path)
- `1`: runtime failure (GitHub API upsert errors)

## Deterministic guarantees

- Relevant-path filtering uses deterministic path-prefix rules.
- Comment upsert is idempotent by fingerprint marker.
- Repeated runs with the same inputs produce the same PR mode decision and comment body.

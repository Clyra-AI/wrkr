---
title: "How to scan org repos for AI agents/configs"
description: "Command-first workflow to scan GitHub org or repo sources for AI tool configurations with deterministic JSON outputs."
---

# How to scan org repos for AI agents/configs

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## When to use

Use this when you need a deterministic inventory of AI tool configurations across a repo, org, or local path.

## Exact commands

```bash
# Org scan (requires GitHub acquisition endpoint)
wrkr scan --org acme --github-api https://api.github.com --json

# Repo scan
wrkr scan --repo acme/backend --github-api https://api.github.com --json

# Offline/local scan
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json
```

## Expected JSON keys

- `status`
- `target`
- `findings`
- `ranked_findings`
- `inventory`
- `repo_exposure_summaries`
- `profile`
- `posture_score`

## Exit codes

- `0`: success
- `6`: invalid input (for example invalid target combinations)
- `7`: dependency missing (for example org/repo acquisition unavailable)

## Sample output snippet

```json
{
  "status": "ok",
  "target": {"mode": "path", "value": "./scenarios/wrkr/scan-mixed-org/repos"},
  "inventory": {"tools": []},
  "profile": {"name": "baseline"},
  "posture_score": {"score": 0}
}
```

## Deterministic guarantees

- Same repository content and same flags produce stable findings ordering and stable key structure.
- Discovery is static by default (`discovery_method: static`).
- No live probing is performed in default deterministic mode.

## When not to use

- Do not use org/repo mode without `--github-api` (or `WRKR_GITHUB_API_BASE`).
- Do not use Wrkr if you need dynamic runtime traffic inspection; Wrkr is config/posture discovery.

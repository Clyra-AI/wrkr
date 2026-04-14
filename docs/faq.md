---
title: "FAQ"
description: "Frequently asked technical and buyer-facing questions about Wrkr discovery, determinism, and evidence workflows."
---

# FAQ

## Frequently Asked Questions

### What is Wrkr in one sentence?

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

### Is Wrkr deterministic?

Yes. Wrkr scan/risk/proof paths are deterministic by default for fixed inputs.

### Does Wrkr need a hosted control plane?

No. Core operation is local and file-based by default.

### Does Wrkr require setup for repo or org scans?

`--path` is the zero-integration first-value path. Hosted `--repo` and `--org` scans require explicit GitHub API configuration via `--github-api`, config `github_api_base`, or `WRKR_GITHUB_API_BASE`, and they usually also need a GitHub token for private repos or to avoid public API rate limits. Token resolution order is `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`.

`wrkr init` can now persist both the default hosted target and the hosted GitHub API base, so org-first onboarding can be:

```bash
wrkr init --non-interactive --org acme --github-api https://api.github.com --json
wrkr scan --config ~/.wrkr/config.json --json
```

For hosted org runs, the least-privilege fine-grained PAT recipe is: select only the target repositories, grant read-only repository metadata, and grant read-only repository contents. That matches the exact endpoints Wrkr calls: `GET /orgs/{org}/repos`, `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1`, and `GET /repos/{owner}/{repo}/git/blobs/{sha}`.

### Does Wrkr replace runtime enforcement?

No. Wrkr is discovery/posture. Runtime enforcement is a separate control layer.

### Do I need Axym or Gait to run Wrkr?

No. Wrkr runs standalone for discovery, posture scoring, regress gates, and evidence generation.
Axym and Gait are optional companion projects that interoperate through shared `Clyra-AI/proof` contracts.

### Does `wrkr mcp-list` do vulnerability scanning?

No. `mcp-list` inventories saved MCP posture, transport, privilege surface, and optional local trust overlay state.
Wrkr does not perform live MCP probing or package vulnerability assessment in this path. Use dedicated scanners such as Snyk for vulnerability workflows.

### Should I start with `wrkr scan --my-setup` or `wrkr scan --github-org`?

For the current public launch, start with `wrkr init --org ... --github-api ... --json`, then run `wrkr scan --config ... --json` when the goal is org posture, shared inventory review, or compliance handoff.
If hosted prerequisites are not ready yet, use `wrkr scan --path ./your-repo --json` as the zero-integration repo-local fallback or `wrkr scan --my-setup --json` for developer-machine hygiene. `--path` scans the selected directory itself when that directory is the repo root with signals such as `.git`, `go.mod`, `AGENTS.md`, or `.codex/`; it scans immediate child repos instead when you point it at a bundle root such as `./scenarios/wrkr/scan-mixed-org/repos`.
Developers doing only local checks can still start with `wrkr scan --my-setup --json`.

For larger orgs, prefer the opinionated path:

```bash
wrkr init --non-interactive --org acme --github-api https://api.github.com --json
wrkr scan --config ~/.wrkr/config.json --state ./.wrkr/last-scan.json --timeout 30m --json --json-path ./.wrkr/scan.json --report-md --report-md-path ./.wrkr/scan-summary.md --sarif --sarif-path ./.wrkr/wrkr.sarif
```

If the run is interrupted, rerun the same target with `--resume`. If `partial_result`, `source_errors`, or `source_degraded` is present, treat the result as incomplete until the hosted scan finishes cleanly.

### Do I need Gait to use `wrkr mcp-list`?

No. Gait trust overlay data is optional. When no local trust registry is available, `mcp-list` degrades explicitly to `trust_status=unavailable` instead of failing.

### How do I fail CI on posture drift?

Use `wrkr regress init` to establish a baseline and `wrkr regress run` in CI. Exit `5` indicates drift.

### How do I produce compliance evidence?

Use `wrkr evidence --frameworks ... --json` and verify chain integrity with `wrkr verify --chain --json`.

### Why can framework coverage be low on the first run?

`framework_coverage` reflects the controls and approvals currently evidenced in the scanned state. Low or zero coverage means more evidence work is needed; it does not mean Wrkr lacks support for that framework. `wrkr evidence --json` now emits additive `coverage_note` guidance with the same interpretation for automation and operator handoffs.

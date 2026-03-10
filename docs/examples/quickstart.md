# Wrkr Quickstart (Offline-safe)

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## Positioning

Wrkr is the AI-DSPM discovery layer in the See -> Prove -> Control sequence:

- See: Wrkr discovers tools, permissions, autonomy context, and risk.
- Prove: Axym consumes proof records and maps controls.
- Control: Gait enforces policy decisions.

Wrkr is useful standalone and interoperates with Axym/Gait through shared proof contracts.

The fastest zero-integration first value is `wrkr scan --my-setup --json` against the local machine setup, followed by `wrkr mcp-list` from the saved state snapshot.

For hosted source modes, `scan --repo` and `scan --org` require `--github-api` (or `WRKR_GITHUB_API_BASE`) and typically also need a GitHub token for private repos or to avoid public API rate limits.
Token resolution order is: `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`.

Canonical local artifact paths are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

## Developer-machine hygiene first

```bash
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
```

Expected outputs:

- `scan --my-setup`: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `inventory`, `profile`, `posture_score`
- `mcp-list`: `status`, `generated_at`, `rows`, optional `warnings`

Common first surprises:

- MCP servers requesting write or shell permissions from user-home config.
- Environment key presence (`location=process:env`) without exposing raw values.
- Local `AGENTS.md` or `.agents/` project markers under common workspace roots.
- `warnings` on `scan` or `mcp-list` explaining that known MCP declaration files failed to parse, so posture may be incomplete even when the command itself succeeded.

## Org handoff when you need team-wide posture

```bash
wrkr scan --github-org acme --github-api https://api.github.com --json
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --json
```

Expected outputs:

- `scan --github-org`: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `inventory`, `repo_exposure_summaries`, `profile`, `posture_score`
- `inventory --diff`: `status`, `drift_detected`, `baseline_path`, `added_count`, `removed_count`, `changed_count`, `added`, `removed`, `changed`

Optional enrich-mode note:

- `scan --enrich` adds MCP evidence metadata (`source`, `as_of`, `advisory_count`, `registry_status`, `enrich_quality`, schema IDs, and adapter error classes).

## Evidence + verification

```bash
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
wrkr verify --chain --json
```

Expected outputs:

- `evidence`: `output_dir`, `manifest_path`, `chain_path`, `framework_coverage`
- `verify`: `chain.intact=true`

Low or zero `framework_coverage` on a first run is expected when the scanned state lacks documented approvals or controls. Treat it as an evidence gap and rerun after remediation.

## Regression baseline

```bash
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --json
```

Expected outputs:

- `regress init`: `baseline_path`, `tool_count`
- `regress run`: `status`, `drift_detected`, `reason_count`, `reasons`, `baseline_path` (when attack-path drift is critical, reasons include one `critical_attack_path_drift` summary with `attack_path_drift` details)

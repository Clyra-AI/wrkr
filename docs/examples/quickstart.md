# Wrkr Quickstart (Offline-safe)

Know what AI tools, agents, and MCP servers are configured on your machine and in your org before they become unreviewed access.

Wrkr gives security and platform teams an evidence-ready view of org-wide AI tooling posture and keeps a deterministic local-machine hygiene path for developers who want a secondary self-serve check. This quickstart leads with the minimum-now org posture path, then shows the local-machine flow.

## Positioning

Wrkr is an AI-DSPM discovery and posture tool in the See -> Prove -> Control sequence.

- See: Wrkr inventories tools, permissions, autonomy context, and posture.
- Prove: proof-ready artifacts can flow into downstream evidence consumers.
- Control: Gait is the optional runtime enforcement counterpart.

The fastest minimum-now public value is `wrkr scan --github-org ... --json` followed by `wrkr evidence ... --json`. The zero-integration local-machine path remains available through `wrkr scan --my-setup --json`.

For hosted source modes, `scan --repo` and `scan --org` require `--github-api` (or `WRKR_GITHUB_API_BASE`) and typically also need a GitHub token for private repos or to avoid public API rate limits.
Token resolution order is: `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`.

Canonical local artifact paths are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

## Security/platform posture first

```bash
wrkr scan --github-org acme --github-api https://api.github.com --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --output ./.tmp/evidence --json
wrkr verify --chain --json
```

Expected outputs:

- `scan --github-org`: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `inventory`, `repo_exposure_summaries`, `profile`, `posture_score`
- `evidence`: `output_dir`, `manifest_path`, `chain_path`, `framework_coverage`
- `verify`: `chain.intact=true`

Hosted source modes require `--github-api` (or `WRKR_GITHUB_API_BASE`) and usually need a GitHub token for private repos or to avoid public rate limits.

## Developer-machine hygiene (secondary path)

```bash
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
```

Expected outputs:

- `scan --my-setup`: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, additive `activation`, `inventory`, `profile`, `posture_score`
- `mcp-list`: `status`, `generated_at`, `rows`, optional `warnings`

Common first surprises:

- `activation.items` calling out concrete local tool, MCP, or secret signals before policy-only findings.
- MCP servers requesting write or shell permissions from user-home config.
- Environment key presence (`location=process:env`) without exposing raw values or turning that signal into an approvable identity.
- Local `AGENTS.md` or `.agents/` project markers under common workspace roots.
- `warnings` on `scan` or `mcp-list` explaining that known MCP declaration files failed to parse, so posture may be incomplete even when the command itself succeeded.

Optional enrich-mode note:

- `scan --enrich` adds MCP evidence metadata (`source`, `as_of`, `advisory_count`, `registry_status`, `enrich_quality`, schema IDs, and adapter error classes).

## Evidence + verification

```bash
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --output ./.tmp/evidence --json
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

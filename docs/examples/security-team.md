# Security Team Org Inventory and Compliance Handoff

Use this workflow when platform or security teams need to widen from developer hygiene into deterministic org posture, then package the result into compliance-ready evidence that can be verified offline.

## Exact commands

```bash
wrkr scan --github-org acme --github-api https://api.github.com --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./wrkr-evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
```

Hosted repo/org scans typically need GitHub authentication for private repos or to avoid public API rate limits.
Token resolution order is: `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`.

Optional deeper triage after the saved state exists:

```bash
wrkr mcp-list --state ./.wrkr/last-scan.json --gait-trust ~/.gait/trust-registry.yaml --json
wrkr report --top 5 --json
```

## Expected JSON keys

- `scan --github-org`: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `inventory`, `repo_exposure_summaries`, `profile`, `posture_score`
  - `inventory.security_visibility_summary` gives you the additive `unknown_to_security` counts and reference basis for that run
  - `agent_privilege_map[*]` is instance-scoped and includes `agent_instance_id`, `write_capable`, and `security_visibility_status`
- `evidence`: `status`, `output_dir`, `frameworks`, `manifest_path`, `chain_path`, `framework_coverage`
- `verify`: `status`, `chain`
- `mcp-list`: `status`, `generated_at`, `rows`, optional `warnings`
- `report`: `status`, `generated_at`, `top_findings`, `total_tools`, `summary`

## How to frame the results

- `scan` and `mcp-list` answer inventory, privilege, and trust-overlay questions.
- `scan` is the place to count unknown-to-security write-capable paths; use `inventory.security_visibility_summary.unknown_to_security_write_capable_agents` for that machine-readable number.
- `report` gives the ranked operator summary for triage.
- `evidence` and `verify` package the saved posture into portable proof artifacts for audit/compliance workflows.

## Scope boundary

Wrkr does not perform live MCP probing or package/server vulnerability assessment in this workflow. Use dedicated scanners such as Snyk for those surfaces. Gait interoperability is optional and provides control-layer context rather than a requirement to run Wrkr.

Canonical state, baseline, manifest, and proof-chain paths are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

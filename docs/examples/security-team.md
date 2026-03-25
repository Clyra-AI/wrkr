# Security Team Org Inventory and Compliance Handoff

Use this workflow when platform or security teams need the recommended minimum-now Wrkr path: deterministic org posture first, then compliance-ready evidence that can be verified offline.

## Exact commands

Hosted prerequisites for this path:

- pass `--github-api https://api.github.com` (or set `WRKR_GITHUB_API_BASE`)
- provide a GitHub token for private repos or to avoid public API rate limits
- token resolution order is `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`
- fine-grained PAT guidance: select only the target repositories and grant read-only repository metadata plus read-only repository contents
- connector endpoints: `GET /orgs/{org}/repos`, `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1`, `GET /repos/{owner}/{repo}/git/blobs/{sha}`
- if hosted prerequisites are not ready yet, start with `wrkr scan --path ./your-repo --json` or `wrkr scan --my-setup --json` first and return to this flow when GitHub access is configured

```bash
wrkr scan --github-org acme --github-api https://api.github.com --state ./.wrkr/last-scan.json --timeout 30m --json --json-path ./.wrkr/scan.json --report-md --report-md-path ./.wrkr/scan-summary.md --sarif --sarif-path ./.wrkr/wrkr.sarif
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./wrkr-evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
```

If a hosted org scan is interrupted, rerun the same target with `--resume` to reuse checkpointed materialization state under the scan-state directory:

```bash
wrkr scan --github-org acme --github-api https://api.github.com --state ./.wrkr/last-scan.json --resume --json --json-path ./.wrkr/scan.json
```

Interpretation notes:

- retry, cooldown, resume, and completion progress lines are additive stderr-only operator UX in `--json` mode
- `partial_result`, `source_errors`, or `source_degraded` means the org posture is incomplete and should be rerun before downstream campaign-style aggregation
- `org-checkpoints/` is resumability metadata beside the scan state, not a proof artifact

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
- `scan` is the place to count unknown-to-security write-capable paths; use `inventory.security_visibility_summary.unknown_to_security_write_capable_agents` only when `inventory.security_visibility_summary.reference_basis` is present for that run.
- `report` gives the ranked operator summary for triage.
- `evidence` and `verify` package the saved posture into portable proof artifacts for audit/compliance workflows.

## Scope boundary

Wrkr does not perform live MCP probing or package/server vulnerability assessment in this workflow. Use dedicated scanners such as Snyk for those surfaces. Gait interoperability is optional and provides control-layer context rather than a requirement to run Wrkr.

Canonical state, baseline, manifest, and proof-chain paths are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

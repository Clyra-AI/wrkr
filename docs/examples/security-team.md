# Security Team Org Inventory and Compliance Handoff

Use this workflow when platform or security teams need the recommended minimum-now Wrkr path: deterministic org posture first, then compliance-ready evidence that can be verified offline.

## Exact commands

Hosted prerequisites for this path:

- pass `--github-api https://api.github.com` (or set `WRKR_GITHUB_API_BASE`)
- provide a GitHub token for private repos or to avoid public API rate limits
- token resolution order is `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`
- fine-grained PAT guidance: select only the target repositories and grant read-only repository metadata plus read-only repository contents
- connector endpoints: `GET /orgs/{org}/repos`, `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1`, `GET /repos/{owner}/{repo}/git/blobs/{sha}`
- if hosted prerequisites are not ready yet, start with `wrkr scan --path ./your-repo --json` or `wrkr scan --my-setup --json` first and return to this flow when GitHub access is configured; `--path` scans the selected directory itself when it is the repo root and uses bundle roots like `./scenarios/wrkr/scan-mixed-org/repos` when you want a deterministic repo-set

```bash
wrkr init --non-interactive --org acme --github-api https://api.github.com --json
wrkr scan --config ~/.wrkr/config.json --state ./.wrkr/last-scan.json --timeout 30m --profile assessment --json --json-path ./.wrkr/scan.json --report-md --report-md-path ./.wrkr/scan-summary.md --sarif --sarif-path ./.wrkr/wrkr.sarif
wrkr report --state ./.wrkr/last-scan.json --template ciso --md --md-path ./.wrkr/ciso.md --pdf --pdf-path ./.wrkr/ciso.pdf --evidence-json --evidence-json-path ./.wrkr/report-evidence.json --csv-backlog --csv-backlog-path ./.wrkr/control-backlog.csv --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./wrkr-evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
```

`wrkr evidence` now requires the saved proof chain to be intact before it stages or publishes a bundle, and `wrkr verify --chain --json` remains the explicit operator/CI integrity gate.
`wrkr init` can now persist the hosted GitHub API base together with the default org target, so the follow-on `wrkr scan --config ...` path stays copy-pasteable without repeating `--github-api` on every run.

If a hosted org scan is interrupted, rerun the same target with `--resume` to reuse checkpointed materialization state under the scan-state directory:

```bash
wrkr scan --config ~/.wrkr/config.json --state ./.wrkr/last-scan.json --resume --json --json-path ./.wrkr/scan.json
```

Interpretation notes:

- retry, cooldown, resume, per-repo materialization completion, local repo discovery, scan phase, and completion progress lines are additive stderr-only operator UX in `--json` mode
- `partial_result`, `source_errors`, or `source_degraded` means the org posture is incomplete and should be rerun before downstream campaign-style aggregation
- `org-checkpoints/` is resumability metadata beside the scan state, not a proof artifact
- `--resume` revalidates checkpoint files and reused materialized repo roots before detector execution, so symlink-swapped resume state is blocked as unsafe

Optional deeper triage after the saved state exists:

```bash
wrkr mcp-list --state ./.wrkr/last-scan.json --gait-trust ~/.gait/trust-registry.yaml --json
wrkr report --top 5 --template appsec --json
```

## Expected JSON keys

- `scan` (hosted org mode): `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `inventory`, `repo_exposure_summaries`, `profile`, `posture_score`
  - `inventory.security_visibility_summary` gives you the additive `unknown_to_security` counts and reference basis for that run
  - `agent_privilege_map[*]` is instance-scoped and includes `agent_instance_id`, `write_capable`, and `security_visibility_status`
- `evidence`: `status`, `output_dir`, `frameworks`, `manifest_path`, `chain_path`, `framework_coverage`
- `evidence.coverage_note`: additive interpretation for low/zero first-run coverage; treat it as an evidence-gap signal, not unsupported framework parsing
- `evidence.next_steps`: additive machine-readable handoff guidance for verify/report sequencing and generated artifact-field review
- `verify`: `status`, `chain`
- `mcp-list`: `status`, `generated_at`, `rows`, optional `warnings`
- `report`: `status`, `generated_at`, additive `next_steps`, `top_findings`, `total_tools`, `summary`, optional `artifact_paths`

## How to frame the results

- `scan` and `mcp-list` answer inventory, privilege, and trust-overlay questions.
- `scan --profile assessment` gives the bounded customer-readout view of risky write paths first while leaving raw findings and proof artifacts intact.
- `scan` is the place to count unknown-to-security write-capable paths; use `inventory.security_visibility_summary.unknown_to_security_write_capable_agents` only when `inventory.security_visibility_summary.reference_basis` is present for that run.
- `report` gives the ranked operator summary for triage and can emit customer-ready CISO/AppSec/platform/audit/customer-draft artifacts led by the control backlog.
- `report` is a saved-state renderer for static posture and offline proof artifacts; it is not a live observation surface.
- `report.next_steps` and `evidence.next_steps` are additive machine-readable sequencing hints for the operator-to-auditor handoff path; use them when you want automation or agents to follow the same artifact workflow the docs describe, using the referenced artifact fields in the same payload.
- `evidence` packages the saved posture into portable proof artifacts only when the saved proof chain is intact, and `verify` remains the explicit machine gate for proof integrity.
- `coverage_note` is the machine-readable companion to `framework_coverage`; use it when handing results to operators or downstream automation so sparse first-run evidence is framed as a remediation queue instead of a parser failure.

## Operator-to-auditor handoff packet

Operator runs:

- `wrkr scan --config ~/.wrkr/config.json --state ./.wrkr/last-scan.json ... --json`
- `wrkr report --state ./.wrkr/last-scan.json --template ciso --md --md-path ./.wrkr/ciso.md --pdf --pdf-path ./.wrkr/ciso.pdf --evidence-json --evidence-json-path ./.wrkr/report-evidence.json --csv-backlog --csv-backlog-path ./.wrkr/control-backlog.csv --json`
- `wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./wrkr-evidence --json`
- `wrkr verify --chain --state ./.wrkr/last-scan.json --json`

Buyer, GRC, or audit consumer reads:

- `./.wrkr/ciso.md` or `./.wrkr/ciso.pdf` for the narrative summary
- `./.wrkr/report-evidence.json` for machine-readable report evidence
- `./.wrkr/control-backlog.csv` for owner/SLA/closure tracking
- `./wrkr-evidence/` for the portable bundle, manifest, framework mappings, and proof artifacts
- the `verify --chain --json` result for explicit integrity confirmation

Use `report.next_steps` and `evidence.next_steps` when you want automation to follow this same packet flow without reconstructing the sequence from docs.

## Scope boundary

Wrkr does not perform live MCP probing or package/server vulnerability assessment in this workflow. Use dedicated scanners such as Snyk for those surfaces. Gait interoperability is optional and provides control-layer context rather than a requirement to run Wrkr.

Canonical state, baseline, manifest, and proof-chain paths are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

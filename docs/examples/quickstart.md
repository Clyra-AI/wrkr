# Wrkr Quickstart (Offline-safe)

Know what AI tools, agents, and MCP servers are configured on your machine and in your org before they become unreviewed access.

Wrkr gives security and platform teams an evidence-ready view of org-wide AI tooling posture and keeps deterministic zero-integration fallback paths available when hosted prerequisites are not ready yet. This quickstart leads with the evaluator-safe scenario flow, then widens to the org posture path and local fallback flows.

## Positioning

Wrkr is an AI-DSPM discovery and posture tool in the See -> Prove -> Control sequence.

- See: Wrkr inventories tools, permissions, autonomy context, and posture.
- Prove: proof-ready artifacts can flow into downstream evidence consumers.
- Control: Gait is the optional runtime enforcement counterpart.

The fastest minimum-now public value is the curated scenario path below. If hosted prerequisites are not ready yet after that, use the repo-local or local-machine fallback section later in this guide.

Canonical local artifact paths are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

## Evaluator-safe scenario first

Use the curated scenario bundle when you want a clean first pass through discovery, evidence, verify, and regress without the repo-root fixture noise in the Wrkr repository itself.

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.tmp/wrkr-scenario-evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json --json
```

Use this flow first when you want the evaluator-safe path. It avoids repo-root fixture noise from Wrkr's own scenarios, docs, and tests while still exercising the shipped wedge.
This is the canonical `repo_set` path example: Wrkr scans the immediate child repos under `./scenarios/wrkr/scan-mixed-org/repos` in deterministic order instead of treating that bundle root as one repo.

## Security/platform posture first

Hosted prerequisites for this path:

- pass `--github-api https://api.github.com` (or set `WRKR_GITHUB_API_BASE`)
- provide a GitHub token for private repos or to avoid public API rate limits
- token resolution order is `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`
- fine-grained PAT guidance: select only the target repositories and grant read-only repository metadata plus read-only repository contents
- connector endpoints: `GET /orgs/{org}/repos`, `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1`, `GET /repos/{owner}/{repo}/git/blobs/{sha}`

```bash
wrkr scan --github-org acme --github-api https://api.github.com --state ./.wrkr/last-scan.json --timeout 30m --json --json-path ./.wrkr/scan.json --report-md --report-md-path ./.wrkr/scan-summary.md --sarif --sarif-path ./.wrkr/wrkr.sarif
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --output ./.tmp/evidence --json
wrkr verify --chain --json
```

`wrkr evidence` now fails closed when the saved proof chain is malformed or tampered, and `wrkr verify --chain --json` remains the explicit integrity gate for CI and operator workflows.

If a hosted run is interrupted, rerun the same target with `--resume`. Retry/cooldown/resume progress stays on stderr in `--json` mode, and `partial_result` / `source_errors` means the posture output is incomplete until the run is repeated successfully.
Resumed hosted scans also revalidate checkpoint files and reused materialized repo roots before detector execution, so symlink-swapped resume state is blocked as unsafe.

If you scan the Wrkr repo root during evaluation, expect repo-root fixture noise because the repo includes intentionally noisy scenario and test fixtures. Use the curated scenario path above first, then move to your own repo or org target.

Expected outputs:

- `scan --github-org`: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `inventory`, `repo_exposure_summaries`, `profile`, `posture_score`
- `evidence`: `output_dir`, `manifest_path`, `chain_path`, `framework_coverage`
- `verify`: `chain.intact=true`

## If hosted prerequisites are not ready yet

```bash
wrkr scan --path ./your-repo --json
wrkr scan --my-setup --json
```

Use `--path` when you want repo-local discovery with no hosted setup. When `./your-repo` itself is the repo root and carries repo-root signals such as `.git`, `go.mod`, `AGENTS.md`, or `.codex/`, Wrkr scans that directory as one repo. Use a bundle root like `./scenarios/wrkr/scan-mixed-org/repos` when you want Wrkr to scan immediate child repos as a repo-set. Use `--my-setup` when you want developer-machine hygiene for local configs, MCP posture, and secret-presence signals.

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

`wrkr evidence` does not replace `wrkr verify --chain --json`; it now reuses the same proof-chain prerequisite and aborts before publish when saved proof state is malformed or tampered.

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

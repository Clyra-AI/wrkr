# Wrkr Quickstart (Offline-safe)

Know what AI tools, agents, and MCP servers are configured on your machine and in your org before they become unreviewed access.

Wrkr gives security and platform teams an evidence-ready view of org-wide AI tooling posture and keeps deterministic zero-integration fallback paths available when hosted prerequisites are not ready yet. This quickstart starts with the shortest repo-to-focused-BOM path, then shows the hosted org posture, evaluator-safe scenario, and local fallback flows for broader rollout or audit handoff.

## Focused repo review first

Use this first when you want the shortest path from scan to one workflow BOM:

```bash
wrkr scan --path ./your-repo --profile assessment --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scan-summary.md
wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --md --md-path ./.tmp/focused-agent-action-bom.md
wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --evidence-json --evidence-json-path ./.tmp/focused-agent-action-bom-evidence.json
```

The report leads with `agent_action_bom.summary.primary_view`, which answers the
top buyer/operator questions first: what the workflow can change, what authority
it uses, what proof exists, and what should change next. When you want a bounded
before/after validation loop instead of a one-time review, initialize a
baseline and use `assess`:

```bash
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json
wrkr assess --path ./your-repo --output-dir ./.wrkr/design-partner-assessment --baseline ./.wrkr/wrkr-regress-baseline.json --template design-partner-summary --share-profile design-partner --ticket-format jira
```

`summary.repeat_usage_signals` and `agent_action_bom.summary.repeat_usage_signals`
stay privacy-safe and only count local artifact families such as baselines,
evidence exports, ticket exports, and assess reruns. Delete those local artifacts
when you want the repeat-use counters to reset.

Choose one explicit first-value path:

- Focused repo review when you want the fastest path to the top workflow BOM.
- Hosted org posture when GitHub access is ready. This is the primary public-launch path.
- Evaluator-safe scenario when you are evaluating Wrkr itself or hosted setup is not ready yet. This sample is intentionally risky by design.
- Developer-machine hygiene when you want local MCP and tool posture first.

## Positioning

Wrkr is an AI-DSPM discovery and posture tool in the See -> Prove -> Control sequence.

- See: Wrkr inventories tools, permissions, autonomy context, and posture.
- Prove: proof-ready artifacts can flow into downstream evidence consumers.
- Control: Gait is the optional runtime enforcement counterpart.

The fastest minimum-now public value for the current launch is the hosted org posture path below when prerequisites are ready. If they are not, use the evaluator-safe scenario fallback and then return to the org posture workflow once GitHub access is configured.

Canonical local artifact paths are documented in [`docs/state_lifecycle.md`](../state_lifecycle.md).

## Security/platform posture first

Hosted prerequisites for this path:

- pass `--github-api https://api.github.com` (or set `WRKR_GITHUB_API_BASE`)
- provide a GitHub token for private repos or to avoid public API rate limits
- token resolution order is `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`
- fine-grained PAT guidance: select only the target repositories and grant read-only repository metadata plus read-only repository contents
- connector endpoints: `GET /orgs/{org}/repos`, `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1`, `GET /repos/{owner}/{repo}/git/blobs/{sha}`

```bash
wrkr init --non-interactive --org acme --github-api https://api.github.com
wrkr scan --config ~/.wrkr/config.json --state ./.wrkr/last-scan.json --timeout 30m --report-md --report-md-path ./.wrkr/scan-summary.md --sarif --sarif-path ./.wrkr/wrkr.sarif
wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --md --md-path ./.wrkr/focused-agent-action-bom.md --evidence-json --evidence-json-path ./.tmp/agent-action-bom-evidence.json
./scripts/run_agent_action_bom_demo.sh after ./.tmp/agent-action-bom-demo
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.tmp/evidence
wrkr verify --chain --state ./.wrkr/last-scan.json
```

`wrkr evidence` now fails closed when the saved proof chain is malformed or tampered, and `wrkr verify --chain --json` remains the explicit integrity gate for CI and operator workflows.
`wrkr init` can now persist the hosted GitHub API base together with the default org target, so follow-on hosted scans can reuse `--config` instead of repeating `--github-api` each time.
Low or zero first-run `framework_coverage` means the current hosted scan state still lacks documented controls or approvals. It is an evidence gap, not a parser failure, and the additive `coverage_note` in `wrkr evidence --json` carries the same interpretation for automation.

If a hosted run is interrupted, rerun the same target with `--resume`. Retry/cooldown/resume progress stays on stderr in `--json` mode, and `partial_result` / `source_errors` means the posture output is incomplete until the run is repeated successfully.
Resumed hosted scans also revalidate checkpoint files and reused materialized repo roots before detector execution, so symlink-swapped resume state is blocked as unsafe.

If you scan the Wrkr repo root during evaluation, expect repo-root fixture noise because the repo includes intentionally noisy scenario and test fixtures. Use the curated scenario fallback below first, then move to your own repo or org target.

Expected outputs:

- `scan` (hosted org mode): `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `inventory`, `repo_exposure_summaries`, `profile`, `posture_score`
- `report --template agent-action-bom`: additive `agent_action_bom`, `summary.agent_action_bom`, `control_path_graph`, and matching top-level plus `summary.runtime_evidence` when a managed runtime evidence sidecar is present
- `scripts/run_agent_action_bom_demo.sh after`: deterministic demo path that scans the fixture repo, ingests runtime sidecars, renders the Agent Action BOM report, and writes an evidence bundle
- `evidence`: `output_dir`, `manifest_path`, `chain_path`, `framework_coverage`
- `verify`: `chain.intact=true`

## Evaluator-safe scenario fallback

Use the curated scenario bundle when hosted prerequisites are not ready yet, or when you want a clean first pass through discovery, evidence, verify, and regress without the repo-root fixture noise in the Wrkr repository itself.
The curated bundle is intentionally risky by design. An `F` posture score or low first-run `framework_coverage` is expected here and shows that Wrkr is surfacing control and evidence gaps in the sample repo-set.

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scenario-summary.md
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.tmp/wrkr-scenario-evidence
wrkr verify --chain --state ./.wrkr/last-scan.json
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json
```

Use this flow when you want the evaluator-safe fallback. It avoids repo-root fixture noise from Wrkr's own scenarios, docs, and tests while still exercising the shipped wedge.
This is the canonical `repo_set` path example: Wrkr scans the immediate child repos under `./scenarios/wrkr/scan-mixed-org/repos` in deterministic order instead of treating that bundle root as one repo.
Low or zero first-run `framework_coverage` in this path is still an evidence-gap signal. It means the current state lacks documented controls or approvals, not that the framework mapping is unsupported.

## If hosted prerequisites are not ready yet

```bash
wrkr scan --path ./your-repo --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scan-summary.md
wrkr scan --my-setup --state ./.wrkr/last-scan.json
```

Use `--path` when you want repo-local discovery with no hosted setup. When `./your-repo` itself is the repo root and carries repo-root signals such as `.git`, `go.mod`, `AGENTS.md`, or `.codex/`, Wrkr scans that directory as one repo. Use a bundle root like `./scenarios/wrkr/scan-mixed-org/repos` when you want Wrkr to scan immediate child repos as a repo-set. Use `--my-setup` when you want developer-machine hygiene for local configs, MCP posture, and secret-presence signals.
If you start with `wrkr scan --json` and no target on a clean machine, the JSON error now points back to these same hosted, evaluator-safe, and `--my-setup` entry paths with additive `error.next_steps[]`.

Automation / CI equivalent:

```bash
wrkr scan --path ./your-repo --profile assessment --state ./.wrkr/last-scan.json --json --json-path ./.wrkr/scan.json
wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
wrkr assess --path ./your-repo --output-dir ./.wrkr/assessment --json
```

## Developer-machine hygiene (secondary path)

```bash
wrkr scan --my-setup --state ./.wrkr/last-scan.json
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
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.tmp/evidence
wrkr verify --chain --state ./.wrkr/last-scan.json
```

`wrkr evidence` does not replace `wrkr verify --chain --json`; it now reuses the same proof-chain prerequisite and aborts before publish when saved proof state is malformed or tampered.
`wrkr evidence --json` also emits additive `coverage_note` guidance so automation and operator UX can explain low or zero first-run coverage as an evidence-state gap rather than a parser failure.

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

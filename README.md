# Wrkr

Find the bounded AI-connected software-delivery paths in your repos and org, rank the riskiest ones first, and emit offline-verifiable proof before they become unreviewed access.

Wrkr gives security and platform teams a deterministic, evidence-ready view of static AI tooling posture and gives developers a local-machine hygiene path when they want to inspect their own setup first. It discovers supported AI dev tools, MCP servers, and agent frameworks, shows what can write, highlights what to review or control first, and emits proof artifacts for audits and CI. Wrkr stays in the static posture boundary: it does not claim runtime observation or control-layer enforcement.

Security/platform-led. Developer hygiene included. Deterministic by default.

Docs: [clyra-ai.github.io/wrkr](https://clyra-ai.github.io/wrkr/) | Command reference: [`docs/commands/`](docs/commands/) | Examples: [`docs/examples/`](docs/examples/)

## Install

### Homebrew

```bash
brew install Clyra-AI/tap/wrkr
```

### Go install (Pinned/reproducible)

```bash
WRKR_VERSION="v1.0.0"
go install github.com/Clyra-AI/wrkr/cmd/wrkr@"${WRKR_VERSION}"
```

### Go install (Secondary convenience latest path)

```bash
go install github.com/Clyra-AI/wrkr/cmd/wrkr@latest
```

### Verify the installed CLI

```bash
wrkr version --json
```

Canonical pinned install and release-parity guidance lives in [`docs/install/minimal-dependencies.md`](docs/install/minimal-dependencies.md).

## Start Here

Start with the curated scenario flow when you want the fastest evaluator-safe demo, then widen to org posture once you are ready for hosted acquisition. If the hosted prerequisites are not ready yet, use the deterministic fallback paths below before returning to the org flow.

### Evaluators (Recommended first path)

Use the curated scenario bundle first when you want copy-pasteable discovery, evidence, verify, and regress output without the repo-root fixture noise that shows up if you scan the Wrkr repository root directly.

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.tmp/wrkr-scenario-evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.wrkr/last-scan.json --json
```

This curated path is the recommended first-value workflow for evaluation because it avoids repo-root fixture noise from Wrkr's own scenario, docs, and test fixtures while still showing the shipped wedge: discovery, posture, evidence, verification, and regression gates.

### Security Teams (Recommended first path)

Hosted prerequisites for this path:

- pass `--github-api https://api.github.com` (or set `WRKR_GITHUB_API_BASE`)
- provide a GitHub token for private repos or to avoid public API rate limits
- token resolution order is `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`
- fine-grained PAT guidance: select only the target repositories and grant read-only repository metadata plus read-only repository contents so Wrkr can call the exact GitHub endpoints it uses (`GET /orgs/{org}/repos`, `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1`, `GET /repos/{owner}/{repo}/git/blobs/{sha}`)
- large-org runbook: [`docs/examples/security-team.md`](docs/examples/security-team.md)

```bash
wrkr scan --github-org acme --github-api https://api.github.com --state ./.wrkr/last-scan.json --timeout 30m --profile assessment --json --json-path ./.wrkr/scan.json --report-md --report-md-path ./.wrkr/scan-summary.md --sarif --sarif-path ./.wrkr/wrkr.sarif
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
```

`--json` keeps stdout reserved for the final machine-readable payload. `--json-path` adds a byte-identical JSON artifact on disk, hosted org scans surface deterministic progress/retry/completion lines on stderr without polluting stdout JSON, and `--resume` reuses durable org-scan checkpoint state under the scan-state directory when an earlier hosted scan was interrupted. `--profile assessment` narrows the govern-first readout for customer-style scans without changing raw findings, proof chains, or exit codes.
If a hosted org scan is interrupted, rerun the same target with `--resume`. Treat `partial_result`, `source_errors`, or `source_degraded` as incomplete posture output and rerun after rate limits, permission issues, or upstream failures are resolved.
`wrkr evidence` now requires the saved proof chain to be intact before it stages or publishes a bundle, and `wrkr verify --chain` remains the explicit operator/CI integrity gate. `--resume` also revalidates checkpoint files and reused materialized repo roots so symlink-swapped entries fail closed instead of being treated as trusted scan roots.
When one run needs both hosted and local scope, use repeatable `--target` flags:

```bash
wrkr scan --target org:acme --target path:./your-repos --github-api https://api.github.com --json
```

Explicit multi-target scans add deterministic `targets[]` arrays to the scan payload, saved state, and source manifest.
`wrkr init` still persists one default target in this wave, so multi-target defaults are intentionally not stored in config yet.

If you are evaluating Wrkr itself, prefer the curated scenario above before scanning the repository root. The Wrkr repo contains scenario and test fixtures, so repo-root fixture noise can overwhelm the posture score and hide the intended first-value path.

If hosted prerequisites are not ready yet, start with one of these deterministic fallback paths:

```bash
wrkr scan --path ./your-repo --json
wrkr scan --my-setup --json
```

### Developers (Secondary local hygiene)

Use this secondary flow when you want local machine hygiene first or when the hosted org posture prerequisites are not ready yet.

```bash
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json

cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

In one flow, Wrkr answers:

- What AI tools, agents, and MCP servers are configured in my local setup?
- Which API-key environments are present without exposing secret values or creating approvable identities?
- Which MCP servers are requesting access, over what transport, and with what trust status?
- What changed since my last known-good snapshot?

Environment-key presence and source-bookkeeping signals stay in findings and risk output. Lifecycle identities and approvals are reserved for real tool, agent, and MCP surfaces.
For `scan --my-setup`, Wrkr also emits additive `activation.items` when concrete local tool, MCP, or secret signals exist so the first-value path stays concrete without mutating the raw `top_findings` ranking.

Abbreviated `scan --my-setup` example:

```json
{
  "status": "ok",
  "target": {
    "mode": "my_setup"
  },
  "top_findings": [
    {
      "risk_score": 9.3,
      "finding": {
        "severity": "high",
        "finding_type": "mcp_server",
        "tool_type": "mcp",
        "location": ".claude/settings.json"
      }
    },
    {
      "risk_score": 7.4,
      "finding": {
        "severity": "high",
        "finding_type": "secret_presence",
        "tool_type": "secret",
        "location": "process:env"
      }
    },
    {
      "risk_score": 6.8,
      "finding": {
        "severity": "medium",
        "finding_type": "tool_config",
        "tool_type": "agent_project",
        "location": "Projects/payments-bot/AGENTS.md"
      }
    }
  ],
  "warnings": [
    "MCP visibility may be incomplete because these declaration files failed to parse: .codex/config.yaml"
  ],
  "activation": {
    "target_mode": "my_setup",
    "message": "Review 3 concrete local AI tool, MCP, or secret signal(s) first. Policy-only items remain in the raw ranking but are suppressed from this activation view.",
    "eligible_count": 3,
    "suppressed_policy_items": true,
    "items": [
      {
        "rank": 1,
        "risk_score": 9.3,
        "finding_type": "mcp_server",
        "tool_type": "mcp",
        "location": ".claude/settings.json"
      }
    ]
  }
}
```

Abbreviated `mcp-list` example:

```json
{
  "status": "ok",
  "rows": [
    {
      "server_name": "postgres-prod",
      "transport": "stdio",
      "requested_permissions": ["db.write"],
      "privilege_surface": ["write"],
      "gateway_coverage": "unprotected",
      "trust_status": "unreviewed",
      "risk_note": "Gateway posture is unprotected; review least-privilege controls."
    },
    {
      "server_name": "slack",
      "transport": "http",
      "requested_permissions": ["network.access"],
      "privilege_surface": ["read"],
      "gateway_coverage": "protected",
      "trust_status": "trusted",
      "risk_note": "Static MCP declaration discovered; verify package pinning and trust."
    }
  ]
}
```

Wrkr is not a vulnerability scanner. It inventories what is configured and what it can touch. Use dedicated tools such as Snyk for package and server vulnerability assessment.

Abbreviated org-scan example:

```json
{
  "status": "ok",
  "target": {
    "mode": "org",
    "value": "acme"
  },
  "top_findings": [
    {
      "risk_score": 9.7,
      "finding": {
        "rule_id": "WRKR-A004",
        "severity": "critical",
        "tool_type": "agent",
        "location": "services/ops/agent.py"
      }
    }
  ],
  "inventory": {
    "tools": 47,
    "agents": 12,
    "security_visibility_summary": {
      "reference_basis": "state_snapshot",
      "unknown_to_security_tools": 6,
      "unknown_to_security_agents": 9,
      "unknown_to_security_write_capable_agents": 3
    }
  },
  "agent_privilege_map": [
    {
      "agent_id": "wrkr:langchain-inst-a1b2c3d4e5:acme",
      "agent_instance_id": "langchain-inst-a1b2c3d4e5",
      "framework": "langchain",
      "symbol": "planner_agent",
      "bound_tools": ["postgres-prod", "slack"],
      "bound_data_sources": ["prod-db"],
      "bound_auth_surfaces": ["OPENAI_API_KEY"],
      "deployment_status": "deployed",
      "write_capable": true,
      "security_visibility_status": "unknown_to_security",
      "production_write": false
    }
  ],
  "compliance_summary": {
    "frameworks": [
      {
        "framework": "soc2",
        "mapped_finding_count": 12
      },
      {
        "framework": "eu-ai-act",
        "mapped_finding_count": 8
      },
      {
        "framework": "pci-dss",
        "mapped_finding_count": 5
      }
    ]
  }
}
```

Your developers are already using AI coding tools, agents, and MCP servers. That is not the problem. The problem is being unable to inventory them, map what they can touch, and prove they are governed.

Wrkr scans your GitHub org, shows supported AI tools and agents with privilege mapping and policy gaps, and emits evidence bundles your team can hand to auditors. Your developers keep moving. You get the posture and the proof.

## Why Wrkr

AI tool usage is already happening across developer machines, repositories, MCP configs, and CI pipelines.

Developers need fast answers:

- What is configured on my machine?
- What can it touch?
- What changed since last scan?

Security teams need organization-wide answers:

- Which AI tools and agents exist across repos?
- Which ones are write-capable right now, and which ones become `production_write` only after production targets are configured?
- Which unknown-to-security paths can already write or touch credentials?
- Which findings map to policy and compliance frameworks?
- Can we hand an auditor a deterministic evidence bundle instead of a spreadsheet?

Wrkr answers both without requiring runtime interception or moving scan data out of your environment.

## What You Get

- Local AI setup inventory for supported user-home config surfaces.
- MCP server catalog with transport, requested permissions, trust overlay, and posture notes.
- Org-wide inventory of AI tools, agent frameworks, CI execution patterns, and MCP declarations.
- Deterministic, instance-scoped identity and privilege mapping for real tool-bearing surfaces.
- Native structured parsing for supported agent frameworks including LangChain, CrewAI, OpenAI Agents SDK, AutoGen, LlamaIndex, MCP-client patterns, and conservative custom-agent scaffolds.
- First-class `security_visibility_status` for `approved`, `known_unapproved`, and `unknown_to_security` agent/tool paths.
- Relationship resolution from agents to tools, data sources, auth surfaces, and deployment artifacts.
- Ranked findings, attack-path context, and posture scoring.
- `inventory --diff` for drift review against a known-good snapshot.
- Policy findings with stable rule IDs and remediation text.
- Explicit `wrkr fix --apply` support for supported repo-file changes, with preview mode preserved for unsupported targets and `--max-prs` for deterministic grouping.
- Packaged GitHub Action support through the repo-root `action.yml`, wrapping the same CLI contracts for scheduled scans, PR comments, SARIF, and repo-targeted remediation dispatch.
- Compliance mappings for EU AI Act, SOC 2, PCI-DSS, and related frameworks.
- Signed evidence bundles for audit and CI workflows.
- Wrapped, paginated PDF executive summaries suitable for board-ready sharing when the acceptance fixtures stay green.
- Native JSON, SARIF, and proof-friendly output contracts.

## What Wrkr Detects

Wrkr is deterministic and file-based by default.

It detects supported signals from:

- Local-machine setup rooted at the current user home directory.
- Repository config and source surfaces.
- GitHub repo and org acquisition targets.
- MCP declarations and gateway posture.
- AI tool configs for Claude, Cursor, Codex, Copilot, skills, and CI agent execution patterns.
- Agent definitions and bindings from supported framework-native sources, conservative custom-agent scaffolds, and explicit `wrkr:custom-agent` custom-source markers.
- Deployment artifacts linking agents to Docker, Kubernetes, serverless, and CI/CD paths.
- Prompt-channel and attack-path risk signals from static artifacts.

## What Wrkr Does Not Do

- It does not probe MCP endpoints live by default.
- It does not replace package or vulnerability scanners.
- It does not enforce runtime tool behavior or block agents.
- It does not monitor live runtime traffic.
- It does not turn environment-key presence or source-bookkeeping findings into approvable lifecycle identities.
- It does not use LLMs in scan, risk, or proof paths.

Wrkr is the inventory and posture layer. Gait is the control layer when runtime enforcement is needed.

## Works With Gait

Wrkr discovers what is configured. Gait enforces what is allowed to execute.

Use Wrkr when you want to answer:

- What tools and agents exist?
- What can they touch?
- What changed?
- Where are the policy and compliance gaps?

Use Gait when you want to answer:

- Should this action be allowed right now?
- Should this tool be blocked, gated, or require approval?

The two products complement each other. Wrkr gives you the inventory and evidence. Gait gives you runtime control.

## Typical Workflows

### Personal AI setup hygiene

```bash
wrkr scan --my-setup --json
wrkr mcp-list --state ./.wrkr/last-scan.json --json
cp ./.wrkr/last-scan.json ./.wrkr/inventory-baseline.json
wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

### Repo or org posture review

```bash
wrkr scan --github-org acme --github-api https://api.github.com --json
wrkr report --top 5 --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state ./.wrkr/last-scan.json --output ./.wrkr/evidence --json
wrkr verify --chain --state ./.wrkr/last-scan.json --json
```

Treat malformed or tampered proof state as a hard blocker: `wrkr evidence` now fails closed before publish, and `wrkr verify --chain --json` remains the explicit machine gate to run in CI or release promotion flows.

### CI distribution

```bash
wrkr scan --path . --sarif --json
wrkr regress run --baseline ./.wrkr/inventory-baseline.json --state ./.wrkr/last-scan.json --json
```

## Command Surface

- `wrkr scan` scans local setup, repos, or GitHub orgs.
- `wrkr mcp-list` projects MCP posture from saved state.
- `wrkr inventory --diff` shows deterministic drift from baseline.
- `wrkr report` renders ranked summaries from saved state.
- `wrkr fix` plans deterministic remediations, supports explicit apply mode for supported repo files, and can split publication across deterministic PR groups.
- `wrkr evidence` builds signed, compliance-ready evidence bundles.
- `wrkr verify` verifies proof-chain integrity.
- `wrkr regress` gates on drift and regressions.
- `action.yml` packages the scheduled/PR/SARIF automation wrapper around the CLI.
- `wrkr version` reports CLI version in human or JSON form.

## Output And Contracts

Wrkr treats machine-readable output and exit codes as product contracts.

- `--json` emits stable machine-readable output.
- `--json-path` writes the same final machine-readable scan payload to disk without changing the `--json` stdout contract.
- `--sarif` emits SARIF `2.1.0` for security tooling and GitHub code scanning workflows.
- Partial-result mode preserves findings when a detector or source path fails non-fatally.
- `--timeout` and signal cancellation are enforced end-to-end.
- Exit codes remain deterministic across success, runtime failure, verification failure, policy/schema violation, approval-required, regress drift, invalid input, dependency missing, and unsafe-operation-blocked paths.

## Security And Privacy

- Read-only by default.
- No raw secret values are emitted in findings.
- Local setup scans keep data in your environment.
- Local path scans stay bounded to the selected repo root; root-escaping symlinked config, env, workflow, and MCP files are rejected with explicit diagnostics instead of being read.
- Evidence is file-based, portable, and verifiable.
- Same input, same output, barring explicit timestamps and version fields.

## Learn More

- Quickstart: [`docs/examples/quickstart.md`](docs/examples/quickstart.md)
- Personal hygiene workflow: [`docs/examples/personal-hygiene.md`](docs/examples/personal-hygiene.md)
- Security-team workflow: [`docs/examples/security-team.md`](docs/examples/security-team.md)
- Scan command: [`docs/commands/scan.md`](docs/commands/scan.md)
- MCP list: [`docs/commands/mcp-list.md`](docs/commands/mcp-list.md)
- Inventory drift: [`docs/commands/inventory.md`](docs/commands/inventory.md)
- Evidence bundles: [`docs/commands/evidence.md`](docs/commands/evidence.md)
- Positioning: [`docs/positioning.md`](docs/positioning.md)

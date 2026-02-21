# Wrkr — PRD v1

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Status | Execution-ready |
| Owner | Product and Engineering |
| Last Updated | 2026-02-21 |

---

## Executive Summary

Wrkr is an open-source Go CLI and AI-DSPM scanner that discovers AI development tools across an organization, tracks their lifecycle, and produces compliance-ready proof records of AI posture. It answers four questions no existing tool can: What AI tools are developers using? What can those tools access? What's their trust status? Can we prove it to an auditor?

**Primary audiences:** The primary user is the **platform engineering lead** responsible for developer tooling standards. The primary buyer is the **CISO or VP of Engineering** who needs to answer "what AI tools are in our environment" for auditors, boards, or regulators. The champion is the **security engineer** who runs the scan and surfaces findings.

**Why this exists:** The average enterprise has 3-7x more AI-assisted development tools in active use than their security team knows about — browser extensions, personal API keys, coding agents with production credentials, MCP servers connected to internal systems. CASBs see network traffic but cannot read `.claude/settings.json`, `.cursor/rules/*.mdc`, or `.vscode/mcp.json` in repos. SAST tools scan code but don't inventory the AI tools that generated it. Wrkr reads the source of truth: code, configs, and CI pipelines.

**Positioning within Clyra AI:** Wrkr is the "See" step in the See (Wrkr) -> Prove (Axym) -> Control (Gait) governance sequence. All three products produce proof records in the shared `Clyra-AI/proof` format. Wrkr findings flow directly into Axym's compliance mapping with zero format translation. Wrkr's structured risk tags map to Gait's policy matching fields, enabling automatic policy rule generation from discovery results. The products are independently useful but form a closed loop together.

---

## Problem Statement

### The pain (stated by the buyer in their own words):

- **CISO**: "The board asked me for an AI inventory last quarter. I had to manually survey 200 engineers. The results were incomplete by the time I compiled them. I need this automated and continuous."
- **VP Engineering**: "I'm not against AI tools. I just need to know what's running, what it can touch, and whether it meets our security bar. Right now I have no idea."
- **Platform Engineer**: "I standardized on Claude Code for our team. Then I found out three other teams are using Cursor with custom rules that bypass our code review policy. I had no way to know."
- **GRC Analyst**: "The auditor asked for evidence of AI governance. I showed them a policy document. They asked for technical controls and an inventory. I had nothing."

### The job to be done (JTBD):

**When** I'm responsible for engineering security and compliance at a company with 50+ developers using AI tools, **I want to** automatically discover every AI development tool, agent, plugin, and configuration across my organization, understand what each can access, and produce evidence that our AI usage meets regulatory requirements, **so that** I can govern AI adoption without slowing it down, and prove compliance when audited.

### Why this wins (mapping to historical pattern):

| Pattern | Cloud/Container Precedent | Wrkr Application |
|---------|--------------------------|-------------------|
| Discovery before enforcement | Wiz: "See risk in 5 mins before changing anything" | `wrkr scan`: see every AI tool in 10 mins, no changes required |
| Neutral third party | AWS didn't build Datadog | Anthropic/OpenAI won't build cross-surface governance |
| Existing budget | CISO's cloud security budget | CISO's AppSec + compliance budget |
| Bottom-up distribution | Trivy, Snyk CLI spread through devs | `brew install Clyra-AI/tap/wrkr`, runs in CI |
| Regulatory forcing function | SOX → cloud audit tools | EU AI Act → AI compliance evidence |
| Open source trust | Falco, OPA became standards | Security tool that scans AI tools must be auditable itself |

---

## Product Overview

### One-liner:

**Wrkr is an open-source Go CLI that discovers AI development tools across your organization and produces compliance-ready proof records of your AI posture.**

### Core loop (the "10-minute time-to-value"):

```
Install → Connect → Scan → See → Fix → Prove
  brew     GitHub    auto    inventory   PRs    proof
  install  OAuth     detect  + risks     to     records
  Clyra-AI/tap/  token             ranked     fix    + bundle
  wrkr
```

### What Wrkr scans (the "sensor surface"):

**Layer 1: Code & Config (primary — this is the moat)**

| What | Where | What Wrkr Extracts |
|------|-------|--------------------|
| Claude Code config | `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json` (project root), `CLAUDE.md` (root, `.claude/`, parent dirs), `.claudeignore`, `.claude/commands/`, hooks | Skills, hooks, MCP server declarations (in settings.json and .mcp.json), permissions, allowed tools, custom commands, ignore patterns |
| Cursor config | `.cursor/rules/*.mdc` (frontmatter rules — globs, alwaysApply, description), `.cursorrules` (deprecated, still scanned), `.cursor/mcp.json` | Custom rules with applicability metadata, context sources, allowed actions, MCP servers |
| Codex config | `.codex/config.toml`, `.codex/config.yaml`, `AGENTS.md`, `AGENTS.override.md` | Task definitions, automations, permissions, agent configuration overrides, sandbox mode, MCP servers (in config.toml) |
| GitHub Copilot config | `.github/copilot-instructions.md`, `.github/copilot-setup-steps.yml` (coding agent), `AGENTS.md` (shared standard), `.vscode/mcp.json`, `.vscode/settings.json` (copilot keys), org-level policy controls | Org policies, coding agent environment setup, allowed/blocked suggestions, workspace MCP servers |
| MCP server declarations | `.claude/settings.json`, `.mcp.json` (project root), `.cursor/mcp.json`, `.vscode/mcp.json`, `.codex/config.toml`, standalone `mcp.json`, `managed-mcp.json` (enterprise IT-deployed) | Server endpoints, transport type (stdio/SSE/streamable HTTP), credentials references, data access patterns, `ToolAnnotations` (readOnlyHint, destructiveHint, idempotentHint, openWorldHint) |
| AI-related dependencies | `go.mod`, `package.json`, `requirements.txt`, `pyproject.toml`, etc. | LLM SDKs, agent frameworks, embedding libs |
| API keys & secrets | `.env`, CI secrets (by reference) | AI service credentials (flagged, not extracted) |
| Agent Skills (cross-platform) | `.claude/skills/`, `.agents/skills/` | Skill name, description, `allowed-tools`, implicit invocation policy, MCP dependencies, scripts, supply chain origin |
| CI/CD AI integrations | `.github/workflows/`, Jenkinsfile, etc. | AI tools in pipeline: review bots, code gen, test gen, **headless agent invocations** (Claude Code `-p`, Codex `full-auto`, Copilot coding agent), autonomy level, secret access, human approval gates |

**Layer 2: Platform signals (secondary — enrichment)**

| What | Where | What Wrkr Extracts |
|------|-------|--------------------|
| OAuth/SSO grants | IdP logs (Okta, Azure AD, Google) | Which AI apps have SSO grants, which scopes |
| GitHub App installs | GitHub org settings API | Third-party AI apps installed, their permissions |
| Browser extension inventory | (Pro only, optional endpoint agent) | AI extensions installed across the org |

### What Wrkr produces:

**1. AI Inventory (the posture graph)**

A structured, machine-readable inventory of every AI tool, agent, and configuration in the org:

```yaml
# Example output: wrkr-inventory.yaml
org: acme-corp
scan_date: 2026-09-15T10:30:00Z
scan_version: 1.0.0

tools:
  - id: claude-code-monorepo
    type: claude-code
    location: repos/monorepo/.claude/settings.json
    teams: [platform, payments]
    identity:
      agent_id: "wrkr:claude-code-monorepo:acme-corp"
      status: approved              # discovered | under_review | approved | deprecated | revoked
      first_seen: "2026-06-12T14:20:00Z"
      approved_by: "@maria"
      approved_date: "2026-07-01T10:00:00Z"
      last_scan: "2026-09-15T10:30:00Z"
    permissions:
      mcp_servers:
        - name: postgres-prod
          endpoint: mcp://db.internal:5432
          transport: stdio
          access: read-write
          approved: false
          tool_annotations: { destructiveHint: true, readOnlyHint: false }
      allowed_tools: [bash, file_edit, web_search]
      hooks:
        - name: pre-commit-review
          version: unpinned  # RISK
          source: https://github.com/someone/hook
    risk_score: 8.2
    risk_factors:
      - "MCP server with production database write access, not in approved inventory"
      - "Hook source is unpinned — could change without notice"
      - "No evidence of team security review"

  - id: cursor-frontend-team
    type: cursor
    location: repos/frontend/.cursorrules
    teams: [frontend]
    identity:
      agent_id: "wrkr:cursor-frontend-team:acme-corp"
      status: discovered            # not yet reviewed
      first_seen: "2026-09-15T10:30:00Z"
    permissions:
      context_sources: [codebase, docs/]
      custom_rules: 3
    risk_score: 2.1
    risk_factors: []

summary:
  total_tools: 47
  known_to_security: 16
  unknown_to_security: 31
  high_risk: 5
  medium_risk: 12
  low_risk: 30
```

**2. Risk Report (the "Top 5 that matter")**

Not 200 warnings. Five findings, ranked by blast radius x privilege x trust deficit:

```
┌──────────────────────────────────────────────────────────────────┐
│ WRKR RISK REPORT — acme-corp — 2026-09-15                       │
├────┬───────────────────────────────────────────────────┬────────┤
│ #  │ Finding                                           │ Score  │
├────┼───────────────────────────────────────────────────┼────────┤
│ 1  │ CI: Claude Code -p --dangerouslySkipPermissions   │  9.6   │
│    │   + DEPLOY_KEY, no required reviewers (headless)  │        │
│ 2  │ Claude MCP → prod Postgres (write, unapproved)    │  9.1   │
│ 3  │ payments-svc: 4 AI tools, combined critical       │  8.4   │
│    │   (Bash+DB write+YOLO, aggregate exposure)        │        │
│ 4  │ MCP: unpinned npx -y @acme/db-server (no lockfile)│  7.9   │
│ 5  │ Codex full-auto in CI with org-admin GitHub token │  7.4   │
└────┴───────────────────────────────────────────────────┴────────┘
```

The report output includes deterministic policy outcomes (pass/fail by rule ID), profile compliance status (`baseline`/`standard`/`strict`), and a posture score with grade and trend delta so teams can track posture movement over time, not just point-in-time findings.

**3. Proof Records (the evidence)**

Every scan finding and risk assessment is emitted as a signed proof record via `Clyra-AI/proof`. These records use the same format as Axym's compliance evidence and Gait's enforcement decisions — one format for the entire governance chain.

```go
// Inside wrkr's scan engine
finding := detectAITool(repo, config)
record := proof.NewRecord(proof.RecordOpts{
    Type:      "scan_finding",
    Source:    "wrkr",
    AgentID:   finding.ToolID,
    Event:     finding.ToEventData(),
    Controls:  finding.ToControlEvidence(),
})
signed, _ := proof.Sign(record, signingKey)
proof.AppendToChain(chain, signed)
```

Wrkr emits four proof record types:
- `scan_finding` — an AI tool or risk was discovered (tool type, location, permissions, risk factors)
- `risk_assessment` — a risk was scored (blast radius, privilege level, trust deficit, composite score)
- `approval` — an agent identity was approved or renewed (approver, scope, expiry)
- `lifecycle_transition` — an agent identity changed state: deprecated, revoked, or moved to under_review (actor, reason, previous state, new state)

These records chain into a tamper-evident sequence. Axym can ingest them directly into compliance mapping — no conversion, no adapter. An auditor can verify them with `proof verify`.

**4. Compliance Evidence Bundle**

A portable, versioned, signed directory that an auditor can review. The bundle contains proof records verifiable with the standalone `proof verify` CLI.

```
wrkr/
├── inventory.yaml           # Full AI tool inventory
├── risk-report.yaml         # Scored findings
├── evidence/
│   ├── eu-ai-act/
│   │   ├── article-9-risk-management.yaml    # Mapped controls
│   │   ├── article-13-transparency.yaml
│   │   ├── article-15-accuracy-robustness.yaml
│   │   ├── article-26-deployer-obligations.yaml
│   │   └── gaps.yaml                          # What's missing
│   ├── soc2/
│   │   ├── cc6-logical-access.yaml
│   │   ├── cc7-system-operations.yaml
│   │   └── gaps.yaml
│   └── state/
│       ├── texas-traiga.yaml
│       └── colorado-ai-act.yaml
├── proof-records/
│   ├── scan-findings.jsonl       # All scan_finding proof records
│   ├── risk-assessments.jsonl    # All risk_assessment proof records
│   └── chain.json                # Hash chain metadata
├── scan-metadata.yaml       # When, how, by whom, tool version
└── signatures/
    ├── bundle-signature.sig  # Ed25519 signature of bundle
    └── public-key.pem        # Verification key
```

**5. Remediation PRs (the "Fix it" moment)**

For the top findings, Wrkr opens PRs that fix the issue:

- Pin unpinned hook versions to specific commit SHAs
- Add `wrkr-manifest.yaml` to repos declaring approved AI tool configs
- Remove hardcoded API keys, replace with secret references
- Add CI check that blocks unapproved AI tool configs from merging

---

## User Personas

### Primary User: Platform Engineer / Staff Engineer (the "runner")

**Name archetype:** "Sam, Staff Platform Engineer at a Series C fintech"

Sam owns the internal developer platform. 180 engineers. Sam standardized on Claude Code 6 months ago, but adoption sprawled. Teams added their own MCP servers, copied hooks from public repos, connected agents to internal services without review. Sam's CISO asked for an AI inventory. Sam has no way to produce one.

**Sam's workflow with Wrkr:**

1. `brew install Clyra-AI/tap/wrkr`
2. `wrkr init` (configure GitHub org, scan targets)
3. `wrkr scan` (10 minutes)
4. Reviews inventory and risk report in terminal
5. `wrkr fix --top 3` (opens 3 PRs)
6. `wrkr evidence --frameworks eu-ai-act,soc2` (generates bundle with proof records)
7. Sends evidence bundle to GRC team — or feeds proof records directly into Axym's evidence chain
8. Adds `wrkr scan` to weekly CI cron

### Primary Buyer: CISO or VP Engineering (the "sponsor")

**Name archetype:** "Maria, CISO at a 500-person enterprise"

Maria needs to tell the board: "Here's our AI risk posture." She needs to show the auditor: "Here's evidence of AI governance controls." She does not want to run CLI tools herself. She wants Sam to run Wrkr and hand her the evidence bundle, the risk report, and a dashboard she can show to the board.

**Maria's interaction with Wrkr:**

1. Asks Sam to run Wrkr
2. Reviews the risk report PDF (v1 CLI) or dashboard (Pro)
3. Presents to board: "47 AI tools discovered, 31 were ungoverned, 5 high-risk issues remediated, here's the evidence bundle"
4. Includes Wrkr evidence in next SOC 2 audit package (or feeds into Axym for combined bundle)
5. Approves Wrkr Pro budget for continuous monitoring

### Champion: Security Engineer (the "advocate")

**Name archetype:** "Alex, Senior Security Engineer"

Alex heard about Wrkr on Reddit or at a meetup. Runs `wrkr scan` on a Friday afternoon. Finds 3 things that make their stomach drop. Brings findings to Maria on Monday. Maria funds the team license.

---

## Functional Requirements (LVP v1)

### FR1: Multi-Surface AI Tool Discovery

- Scan GitHub org repos for Claude Code (`.claude/settings.json`, `settings.local.json`, `.mcp.json` at project root, `CLAUDE.md` at root/`.claude/`/parent dirs, `.claudeignore`, `.claude/commands/`, hooks), Cursor (`.cursor/rules/*.mdc` frontmatter rules, `.cursorrules` deprecated, `.cursor/mcp.json`), Codex (`.codex/config.toml`, `.codex/config.yaml`, `AGENTS.md`, `AGENTS.override.md` — the cross-platform agent configuration standard adopted by Codex, Copilot, and Cursor), and Copilot (`.github/copilot-instructions.md`, `.github/copilot-setup-steps.yml`, `AGENTS.md`, `.vscode/mcp.json`, org-level policy controls) configuration files
- Scan Agent Skills across all tools — `.claude/skills/`, `.agents/skills/` (Codex, Copilot), and user/admin paths — using the standardized `SKILL.md` format (agentskills.io spec). Extract `allowed-tools`, implicit invocation policy, MCP dependencies, and script inventory per skill.
- Detect MCP server declarations across all tool-specific config locations (`.claude/settings.json`, `.mcp.json` at project root, `.cursor/mcp.json`, `.vscode/mcp.json`, `.codex/config.toml`, standalone `mcp.json`, enterprise `managed-mcp.json`) and extract endpoints, transport type (stdio/SSE/streamable HTTP), credentials references, access scopes, and `ToolAnnotations` metadata (readOnlyHint, destructiveHint, idempotentHint, openWorldHint)
- Detect AI-related dependencies in package manifests (`go.mod`, `package.json`, `requirements.txt`, `pyproject.toml`)
- Detect AI API keys in `.env` files and CI configuration (flag presence, never extract values)
- Detect GitHub App installations with AI-related scopes
- **Detect autonomous / auto-approve mode configurations:** Cursor YOLO mode (auto-executes commands without confirmation), Claude Code `--allowedTools Bash` and `--dangerouslySkipPermissions` flags, Codex `full-auto` approval mode, Copilot coding agent issue assignment automation. Each detected tool is classified by autonomy level: `interactive` (human approves each action), `copilot` (human triggers with confirmation), `headless_gated` (runs without UI but has approval gates), `headless_auto` (fully autonomous, no human in loop).
- **Detect headless / CI agent execution:** Scan `.github/workflows/*.yml`, Jenkinsfile, and CI configs for AI agent invocations running in pipelines — Claude Code with `-p` flag or SDK usage, Codex in CI with `full-auto`, Copilot coding agent triggers, any AI tool invoked with elevated permissions in automated contexts. Extract: which tool, what permissions granted, whether human approval is required before execution, access to repo secrets.
- **MCP server supply chain analysis:** For each discovered MCP server, extract package origin (npm/PyPI/Go module) and determine whether the package version is pinned or floating (`npx -y` with no lockfile = unpinned). **By default (offline mode), supply chain trust scoring uses only static signals: package pinning, lockfile presence, and transport type.** The optional `--enrich` flag enables live lookups: checking known vulnerabilities via advisory databases and verifying whether the server is listed in the official MCP Registry (`registry.modelcontextprotocol.io`). Offline mode is deterministic (same input = same output). Enriched mode adds non-deterministic signals that may change between runs. Unpinned MCP packages are the exact attack vector used in real-world supply chain compromises (malicious Postmark MCP on npm).
- Support two GitHub scan target modes in v1: repository mode (`wrkr scan --repo <owner/repo>`) for single-repo scans, organization mode (`wrkr scan --org <org>`) for multi-repo org scans. `--repo`, `--org`, and `--path` are mutually exclusive target sources.
- Support scanning: GitHub repos + orgs (required)

### FR2: Inventory Generation

- Produce a structured, machine-readable inventory (YAML and JSON) of all discovered AI tools
- For each tool: type, location, owning team (from CODEOWNERS or heuristic), version info, permissions requested, data access patterns
- Deduplicate tools shared across repos
- Support incremental scan (diff from previous scan)

### FR3: Risk Scoring

- Score each finding on three axes: blast radius (what can it affect), privilege level (what permissions does it have), trust deficit (is it approved, pinned, tested)
- Produce a composite risk score per finding
- Rank and surface only top N findings (default: 5, configurable)
- Suppress low-risk noise by default
- **Autonomy level as risk multiplier:** Tools classified as `headless_auto` (fully autonomous, no human in loop) receive the highest risk multiplier on all three axes. `headless_gated` scores lower but still elevated. `interactive` and `copilot` modes score at baseline. Rationale: an MCP server with DB write access is medium risk when a developer confirms each action; the same server connected to an autonomous agent in CI is critical risk. Autonomy level is the single biggest risk amplifier.
- **Aggregate permission surface per repo:** After scoring individual tools, Wrkr computes a per-repo exposure summary: the deduplicated union of all permissions and data access grants across every AI tool in the repo, the highest autonomy level present, and a combined risk score. A repo with Claude Code (Bash access) + 2 MCP servers (DB write) + Cursor (YOLO mode) has a materially different risk profile than any tool individually. The aggregate view is reported alongside individual findings and emitted as a `risk_assessment` proof record.
- **MCP server supply chain trust:** Each MCP server receives a supply chain trust score (0-10). **Offline (default):** scoring uses static signals only: package pinning (unpinned `npx -y` = 0, pinned with lockfile = high), transport type (stdio = local-only, HTTP = remote exposure). **Enriched (`--enrich`):** adds known vulnerabilities (advisory count) and MCP Registry verification (listed = trust boost, unlisted = unknown). Servers with trust score below threshold (default: 3.0, configurable) are flagged as high-risk findings. This directly addresses the real-world attack vector: malicious MCP server packages published to npm that exfiltrate data through every agent that installs them.
- **Headless / CI execution context as risk signal:** Tools detected running in CI pipelines (`.github/workflows/`, Jenkinsfile) are scored with elevated risk based on: access to repo secrets (`secrets.*` in workflow), deployment permissions, whether human approval gates exist in the workflow (`environment:` with required reviewers), and the autonomy level of the AI tool invocation. A Claude Code `-p --dangerouslySkipPermissions` step with access to `DEPLOY_KEY` in a workflow with no required reviewers is a critical finding.
- **MCP ToolAnnotations as risk input:** When MCP servers declare `ToolAnnotations` (MCP spec 2025-11-25), Wrkr uses them as first-party risk signals: `destructiveHint: true` increases blast radius score, `readOnlyHint: true` reduces privilege score, `idempotentHint: false` increases risk for retry-sensitive operations, `openWorldHint: true` flags external network access. Servers that declare no annotations are scored as unknown-risk (conservative default).
- **Skill-specific risk signals:** Skills are scored on privilege breadth (`allowed-tools` grants — broad grants like `Bash` or `mcp__.*` score high), invocation policy (implicit invocation enabled on side-effect skills scores high), MCP dependency risk (skills declaring MCP tool dependencies inherit the risk profile of those servers), and supply chain trust (unreviewed skills from external sources, missing hashes on supporting scripts, skills installed via `$skill-installer` without pinning).
- **`endpoint_class` derivation:** Wrkr assigns Gait-compatible endpoint classes to each finding based on discovered permissions and access patterns. Derivation rules:
  - `proc.exec` — tool grants shell/exec access: Claude Code `Bash` in `allowed_tools` or `--dangerouslySkipPermissions`, Codex `full-auto` mode, CI steps invoking AI tools with script execution
  - `fs.write` — tool grants file write: Claude Code `file_edit`/`Write` tools, Cursor with auto-apply, MCP servers with `destructiveHint: true` targeting local paths
  - `fs.read` — tool grants file read only: MCP servers with `readOnlyHint: true` targeting local paths, Copilot with read-only repo access
  - `fs.delete` — tool grants file deletion: detected from MCP `destructiveHint: true` + delete operations, CI steps with cleanup permissions
  - `net.http` — tool makes network calls: MCP servers with HTTP/SSE/streamable-HTTP transport, `openWorldHint: true`, AI tools with API access
  - `net.dns` — tool performs DNS resolution: inferred from `openWorldHint: true` on network-capable MCP servers
  - `other` — permissions that don't map to the above (default for unrecognized patterns)
  - When multiple classes apply, emit the highest-privilege class. The full set is included in the `AITool.endpoint_classes` array for aggregate reporting
- **`data_class` derivation:** Wrkr assigns data sensitivity classes based on repo context and tool access patterns:
  - `credentials` — tool has access to secrets: CI workflows with `secrets.*` references, `.env` files with API keys, MCP servers with credential scopes
  - `pii` — repo or tool handles personal data: detected from repo path patterns (`*user*`, `*profile*`, `*customer*`), MCP server access scopes mentioning user data, CODEOWNERS team matching privacy/identity teams
  - `financial` — repo or tool handles financial data: repo path patterns (`*payment*`, `*billing*`, `*transaction*`), MCP servers accessing financial APIs or databases
  - `internal` — default class when no higher sensitivity is detected
  - Multiple classes can apply; the highest sensitivity is used for the primary `data_class` tag, full set in `AITool.data_classes` array
- **Gait policy coverage as risk reduction factor:** tools operating under active Gait policies (detected via `.gait/` config or `gait.yaml` in the repo) receive a risk score reduction, since enforcement controls are in place. Tools with no Gait policy coverage score higher on the trust deficit axis.
- **Gait-compatible risk classification:** each finding emits structured tags that map to Gait's policy matching dimensions, enabling Wrkr risk output to directly inform Gait policy rules:

  | Wrkr Risk Axis | Wrkr Output | Gait Policy Field | Example |
  |---|---|---|---|
  | Blast radius | `risk_class` tag | `match.risk_classes` | `"high"`, `"critical"` |
  | Privilege level | `endpoint_class` tag | `match.endpoint_classes` | `"fs.write"`, `"proc.exec"`, `"net.http"` |
  | Tool type | `tool_type` from AITool | `match.tool_names` | `"claude-code"`, `"cursor"`, `"mcp"` |
  | Data access | `data_class` tag | `match.data_classes` | `"pii"`, `"financial"`, `"credentials"` |
  | Location | repo path | `match.workspace_prefixes` | `"repos/payments-service"` |
  | Trust deficit | `approved` / `pinned` status | (informs policy rule creation) | Unapproved tools → stricter policy rules |
  | Autonomy level | `autonomy_level` from AITool | (informs policy rule creation) | `"headless_auto"`, `"headless_gated"` |
  | Execution context | `execution_context` from AITool | (informs policy rule creation) | `"ci"`, `"scheduled"`, `"issue_assigned"` |
  | Supply chain trust | `mcp_supply_chain.trust_score` | (informs policy rule creation) | Unpinned MCP servers → stricter policy rules |

### FR4: Proof Record Emission

- Every scan finding is emitted as a `scan_finding` proof record via `proof.NewRecord()`
- Every risk assessment is emitted as a `risk_assessment` proof record via `proof.NewRecord()`
- All proof records are signed via `proof.Sign()` and chained via `proof.AppendToChain()`
- Records use the shared `Clyra-AI/proof` format — same format as Axym and Gait
- Proof records can be ingested by Axym without conversion for unified compliance mapping

### FR5: Compliance Evidence Generation

- Generate evidence bundles mapped to: EU AI Act (Articles 9, 13, 15, 26), SOC 2 (CC6, CC7), Texas TRAIGA, Colorado AI Act, ISO 42001, NIST AI 600-1, SOX, PCI-DSS
- Framework definitions loaded from `Clyra-AI/proof/frameworks/*.yaml` (shared across all Clyra AI products)
- Each evidence file: control description, what Wrkr found, gap analysis, recommendation
- Bundle is versioned, timestamped, and cryptographically signed (Ed25519)
- Bundle contains proof records verifiable with standalone `proof verify` CLI

### FR6: Remediation PRs

- For top findings, generate and open GitHub PRs that fix the specific issue
- Supported remediations: version pinning (hooks, MCP servers), MCP server package pinning (replace floating `npx -y @pkg` with pinned version + lockfile, flag known-vulnerable packages), manifest generation (`wrkr-manifest.yaml`), secret removal (replace with reference), CI gate addition, autonomy downgrade (replace YOLO/full-auto configs with gated equivalents, add required reviewers to CI workflows running headless agents), skill hardening (add `disable-model-invocation: true` to side-effect skills, restrict `allowed-tools` to minimum required set, add deny-list hooks for destructive commands)
- PRs include: description of finding, risk score, what the fix does, link to Wrkr docs
- PRs are opened from a `wrkr-bot` GitHub account or configurable identity
- **Scheduled mode auto-opens PRs (Dependabot pattern).** When running on a weekly schedule (via `wrkr-action` or cron), Wrkr opens up to N remediation PRs automatically (default: 3, configurable). Teams merge them like dependency bumps. This creates a recurring weekly cadence — Wrkr produces work that demands response, not just a report that can be ignored.
- **Secondary PR triggers (post-initial-remediation cadence).** After the top findings are remediated (typically weeks 2-4), PR volume doesn't go to zero. Secondary triggers maintain the cadence: (1) newly discovered tools from team changes, new repos, or newly added skills/MCP servers; (2) approval expiry renewals — 90-day default means ~2 renewal PRs/week for a 47-tool org, starting month 3; (3) agent config drift — pinned versions that fall behind upstream, skills with updated `allowed-tools` grants, MCP server endpoint changes; (4) posture baseline violations from `wrkr regress` (new unapproved tools or permission changes). The initial discovery scan is the highest-volume week. After that, the PR cadence normalizes to 1-3 PRs/week from secondary triggers.

### FR7: CI Integration

- Provide GitHub Action: `Clyra-AI/wrkr-action@v1`
- **Scheduled mode (e.g., weekly):** Full org scan → posture delta since last scan → auto-open remediation PRs (FR6). This is the primary engagement loop — Wrkr produces work and a weekly narrative without anyone running a command. The GitHub Action running on a user's own CI cron is free (self-hosted). Slack/webhook notifications, dashboard trending, and managed scheduling are Pro features.
- **PR mode (on pull request):** When a PR modifies AI tool configs (`.claude/`, `.mcp.json`, `CLAUDE.md`, `.cursor/rules/`, `.cursor/mcp.json`, `.codex/`, `.github/copilot-instructions.md`, `.github/copilot-setup-steps.yml`, `.vscode/mcp.json`, `AGENTS.md`, `AGENTS.override.md`, `.claude/skills/`, `.agents/skills/`, `mcp.json`, `.github/workflows/` with AI tool invocations, AI deps), the action comments on the PR with: what changed, risk delta (score before/after), whether the change requires approval, and whether it violates the posture baseline. This puts Wrkr in the developer's workflow on every relevant PR, not just a cron job.
- **Posture score trending:** Each scheduled scan records a composite posture score. The action reports the delta: "AI posture score: 6.2 → 7.8 (+1.6 this month). 3 findings remediated, 1 new skill added (approved)." This gives the CISO a recurring narrative, not a one-time inventory.
- Action optionally blocks merge for high-risk changes (configurable threshold)

### FR8: CLI Experience

- `wrkr init` — interactive setup (GitHub token, default scan target, scan preferences)
- `wrkr scan --repo <owner/repo>` — single-repo scan, produces inventory + risk report + proof records
- `wrkr scan --org <org>` — full org scan across all repositories, produces inventory + risk report + proof records
- `wrkr scan` — scan using configured default target from `wrkr init` (repo or org). Errors if no default is configured and no target flag is provided.
- `wrkr scan --path ./local-repos/` — scan pre-cloned local repos (skips clone phase, enables fully air-gapped operation)
- `wrkr scan --enrich` — enable live advisory/registry lookups for MCP supply chain scoring (non-deterministic, requires network). Combinable with any target mode.
- `wrkr scan --policy <path>` — evaluate custom policy rules in addition to built-in deterministic policy pack
- `wrkr scan --profile [baseline|standard|strict]` — evaluate posture compliance profile and report pass rate + failing rules
- `wrkr scan --diff` — incremental, shows changes since last scan for the selected target. Previous scan state is stored in `.wrkr/last-scan.json` locally. In CI, the previous scan can be loaded from a committed proof chain artifact or a cache key. Comparison is keyed on `(tool_type, location, org)` tuples.
- `wrkr report` — render risk report to terminal (default) or PDF
- `wrkr score` — compute posture score (0-100), grade (`A`-`F`), weighted breakdown, and trend delta from latest scan state
- `wrkr evidence --frameworks [list]` — generate compliance bundle with proof records
- `wrkr fix --top N` — open remediation PRs for top N findings
- `wrkr manifest generate` — create `wrkr-manifest.yaml` for a repo (declaration of approved AI tools)
- `wrkr verify --chain` — verify proof chain integrity (delegates to `Clyra-AI/proof`)
- `wrkr regress init --baseline [scan-path]` — establish approved posture baseline from a known-good scan
- `wrkr regress run --baseline [path]` — check for posture regression (exit 5 on drift)
- `wrkr identity list` — list all tracked agent identities with current lifecycle status
- `wrkr identity show <id>` — show identity details, lifecycle chain, and approval history
- `wrkr identity review <id>` — mark a discovered tool as under review
- `wrkr identity approve <id> --approver <identity> --scope <scope> [--expires <duration>]` — approve a tool with named approver and expiry
- `wrkr identity deprecate <id> --reason <text>` — deprecate a tool with stated reason
- `wrkr identity revoke <id> --reason <text>` — revoke a tool (regression fails if it reappears)
- All commands: `--json` flag for machine-readable output
- All commands: `--quiet` flag for CI usage
- All commands: `--explain` flag for verbose diagnostic output
- All commands use the shared exit code vocabulary defined in `Clyra-AI/proof`: `0` success, `2` verification failure, `5` regression drift, etc.

### FR9: Posture Regression

- `wrkr regress init --baseline [scan-path]` — establish an approved AI tool posture from a known-good scan as a CI baseline
- `wrkr regress run --baseline [path]` — compare current scan results against baseline
- If unapproved tools reappear, new unapproved tools are found, or approved tools gain new unapproved permissions, exit code `5` (regression drift detected)
- Regression checks are deterministic: same repos + same baseline = same result
- Regression fixtures are portable files that can be committed to the repo and run in CI
- **Use case:** After remediating the top 5 findings and establishing an approved posture, run `wrkr regress init` to capture the clean state. Add `wrkr regress run` to weekly CI. If someone adds an unapproved MCP server, copies an unpinned hook, or introduces a new AI tool without review, CI fails before the tool reaches production.
- Maps to the cross-product regression pattern: Gait converts bad runs into enforcement regression fixtures, Axym converts compliance gaps into coverage regression fixtures, Wrkr converts bad scans into posture regression fixtures. Same exit code (`5`), same CI semantics, different governance domain.

### FR10: Agent Identity Lifecycle

Every discovered AI tool receives a persistent identity that tracks its lifecycle from first discovery through approval, deprecation, or revocation. Agent identity is the connective tissue between Wrkr (who discovered it), Gait (who gates its actions), and Axym (who captures its evidence).

- **Identity assignment:** Each discovered tool is assigned a deterministic agent ID on first scan: `wrkr:<tool_id>:<org>`. The ID is stable across scans — the same tool in the same location always produces the same ID.
- **Lifecycle states:** `discovered` → `under_review` → `approved` → `active` → `deprecated` → `revoked`. Transitions are recorded as proof records.
- **Lifecycle transitions:**
  - `discovered`: Wrkr finds the tool for the first time. Emits `scan_finding` proof record.
  - `under_review`: Team acknowledges the finding. Recorded in `wrkr-manifest.yaml` or via `wrkr identity review <id>`.
  - `approved`: Authorized by a named approver with scope and expiry. Emits `approval` proof record with approver identity, scope, timestamp.
  - `active`: Tool is approved and detected in the most recent scan. Automatically derived — not set by CLI command. A tool transitions from `approved` to `active` when `wrkr scan` detects it in a subsequent scan after approval.
  - `deprecated`: Tool is flagged for removal. Emits `lifecycle_transition` proof record with deprecation reason. Grace period configurable.
  - `revoked`: Tool is explicitly blocked. Emits `lifecycle_transition` proof record with revocation reason. Wrkr regression (`wrkr regress run`) fails if a revoked tool reappears.
- **Identity state persistence:** Lifecycle state is persisted in `wrkr-manifest.yaml` per repo (current status, approver, expiry) and in the proof record chain (full history). The manifest is the queryable index; the chain is the audit trail. `wrkr identity list` reads manifests across repos to build the current state view. `wrkr identity show <id>` reads the proof chain for full history.
- **Identity chain:** Each agent's lifecycle is a proof record chain — append-only, tamper-evident. The chain proves the full history: when it was found, who approved it, when approval was renewed, when it was deprecated. An auditor can verify any agent's lifecycle with `proof verify --chain`.
- **Cross-product interop:** Wrkr's agent IDs are the same identifiers that appear in Gait's `IntentContext.Identity` field and Axym's `agent_id` field. When Gait gates an action from `claude-code-monorepo`, the enforcement record links to the same identity Wrkr discovered and tracks. No mapping tables, no translation — one ID across the governance stack.
- **Approval renewal:** Approvals have configurable expiry (default: 90 days). Wrkr scans flag tools with expired approvals as `under_review`. This ensures continuous governance — an approval from six months ago does not mean the tool is still governed today.
- **CLI commands:**
  - `wrkr identity list` — list all tracked agent identities with current status
  - `wrkr identity show <id>` — show identity details and lifecycle chain
  - `wrkr identity review <id>` — mark a discovered tool as under review
  - `wrkr identity approve <id> --approver <identity> --scope <scope> [--expires <duration>]` — approve a tool
  - `wrkr identity deprecate <id> --reason <text>` — deprecate a tool
  - `wrkr identity revoke <id> --reason <text>` — revoke a tool
  - All lifecycle commands emit signed proof records and append to the identity chain

### FR11: Configuration Policy Engine

- Run a deterministic policy evaluator after detection and before final risk aggregation
- Load built-in rules from `Clyra-AI/proof/policies/wrkr/*.yaml` with strict schema validation
- Support custom policy extension via `wrkr scan --policy <path>` and repository-default `wrkr-policy.yaml`
- Emit named pass/fail checks and first-class policy findings (`finding_type: policy_violation`) using stable WRKR rule IDs
- Enforce rule-versioning contract: semantic rule changes require new rule IDs (immutable meaning per ID)
- Include skill-governance built-ins in v1 policy pack:
  - `WRKR-013`: skill privilege ceiling must not combine `proc.exec` with credentialed access
  - `WRKR-014`: skill `allowed-tools` must not conflict with Gait policy constraints
  - `WRKR-015`: skill sprawl concentration threshold exceeded (exec-granting skills dominate repo skill set)
- Fail closed on malformed policy packs or ambiguous high-risk policy evaluation paths

### FR12: Posture Profiles

- Support built-in posture profiles: `baseline`, `standard`, `strict`
- Load profile definitions from `Clyra-AI/proof/policies/wrkr/profiles/*.yaml`
- `wrkr scan --profile [baseline|standard|strict]` emits deterministic compliance percentage, failing rule IDs, and delta from prior scan
- Support profile extension/override from `wrkr-policy.yaml` for org-specific thresholds
- Profile results feed risk report ranking, compliance evidence generation, and proof-record metadata

### FR13: AI Posture Score

- Compute deterministic posture score (`0-100`) with fixed default weighted model:
  - policy pass rate: `40%`
  - approval coverage: `20%`
  - severity distribution: `20%`
  - profile compliance: `10%`
  - drift rate: `10%`
- Map score to grade bands (`A`/`B`/`C`/`D`/`F`) and trend delta against previous scan state
- Expose score via `wrkr score` and in scan/report outputs
- Allow configurable weights in `wrkr-policy.yaml` with strict validation constraints
- Emit score and breakdown as structured outputs consumable by CI gates and `risk_assessment` proof records

---

## Non-Functional Requirements

### NFR1: Data Sovereignty

- **Zero data exfiltration.** Wrkr never sends scan data outside the user's environment. No telemetry on scan contents. No cloud backend required.
- Optional anonymous usage telemetry (command counts only, opt-in) for open-source metrics.

### NFR2: Performance

- Scan 100 repos in under 10 minutes on a standard CI runner (4 vCPU, 8GB RAM)
- Scan 500 repos in under 30 minutes
- Incremental scan completes in under 2 minutes for 100 repos

### NFR3: Reliability

- Deterministic output: same input always produces same inventory and same proof records (no LLM in the scan pipeline — this is pattern matching and static analysis, not generative AI). Note: `--enrich` mode (live advisory/registry lookups) is explicitly non-deterministic and excluded from the determinism guarantee. Default offline mode is fully deterministic.
- Deterministic policy/profile/score outputs in offline mode: identical findings + rule/profile packs + weights produce identical policy results, profile compliance, and posture score
- Scan failures on individual repos don't halt the full scan (graceful degradation)
- All outputs are schema-validated before writing

### NFR4: Security

- Wrkr uses two distinct auth profiles with separate token scopes:
  - **Scan profile (read-only):** Used by `wrkr scan`, `wrkr report`, `wrkr evidence`, `wrkr verify`, `wrkr regress`, `wrkr identity list/show`. GitHub token scopes: `repo` (classic) or `contents: read` + `metadata: read` (fine-grained), `read:org`, `admin:org_hook` (optional, for App installs). This is the minimum-privilege default.
  - **Fix profile (read-write):** Used by `wrkr fix` and `wrkr-action` PR comments. Requires additional scopes: `contents: write` + `pull_requests: write` (fine-grained) or `repo` (classic). Only needed when opening remediation PRs or posting PR comments.
- `wrkr init` configures both profiles separately. Commands that require write access fail with a clear error if only a scan-profile token is configured.
- Scan results are written to local filesystem only
- Evidence bundles and proof records are signed with Ed25519 (default) or cosign (Sigstore) via `Clyra-AI/proof`

### NFR5: Extensibility

- Plugin architecture for adding new AI tool detectors (e.g., when a new AI IDE emerges)
- Two detector interfaces: `Detector.Detect(repoPath string) ([]Finding, error)` for repo-level scanning, `OrgDetector.DetectOrg(orgID string, client OrgClient) ([]Finding, error)` for org-level signals (GitHub App installs, IdP grants)
- Compliance framework mapping is configuration from `Clyra-AI/proof/frameworks/*.yaml`, not code
- Risk scoring weights are configurable

---

## Goals

1. **10-minute time-to-first-value.** From `brew install Clyra-AI/tap/wrkr` to seeing a complete AI inventory of your GitHub org.
2. **Become the system of record for AI tool inventory.** The canonical answer to "what AI tools do we use?" lives in Wrkr output.
3. **Bottom-up adoption through developer trust.** Open source, local-only, no SaaS required. Engineers trust it because they can read it.
4. **Compliance as a forcing function for adoption.** GRC teams pull Wrkr into the org because they need evidence. Platform teams stay because it reduces toil.
5. **Establish the "wrkr-manifest.yaml" as a standard.** Like `package.json` for AI tool declarations — a community convention that becomes the expected file in every repo.
6. **Feed the governance loop.** Wrkr scan findings flow as proof records into Axym's compliance mapping. Wrkr's structured risk tags (`risk_class`, `endpoint_class`, `data_class`) map directly to Gait's policy matching fields, enabling automatic policy rule generation from discovery results. Every Wrkr scan strengthens the full See → Prove → Control sequence.
7. **Never let a remediated risk recur.** The posture regression pattern (`wrkr regress`) converts a clean scan into a permanent CI fixture. Once a team remediates findings and establishes an approved baseline, CI fails if unapproved tools reappear. A scan report is disposable. A CI gate is permanent.
8. **One identity per tool, across the governance stack.** Every discovered AI tool gets a persistent, deterministic identity that follows it from Wrkr (discovery) through Gait (enforcement) to Axym (evidence). No mapping tables, no translation layers — the agent ID is the connective tissue between See, Control, and Prove.
9. **Create work, not reports.** The discovery scan is the hook. The weekly PR cadence is the retention. Wrkr in scheduled mode auto-opens remediation PRs, flags expired approvals, and posts posture deltas — producing recurring work that demands response. A scan report is disposable. A PR that requires merging is an engagement loop. The Dependabot pattern: teams merge Wrkr PRs like dependency bumps, weekly, without thinking about it.

## Non-Goals (v1)

1. **Not a runtime agent.** Wrkr does not sit in the execution path of AI tools. It scans artifacts at rest, not traffic in flight. Gait's `gait scout` observes tools at runtime (what tools are executing, whether they're gated, drift from baseline). Wrkr and scout are complementary: Wrkr discovers the static posture (code, configs, repos), scout observes the dynamic reality (runtime execution, policy coverage). Both feed the governance loop.
2. **Not an enforcement engine.** Wrkr discovers and reports. It does not block or terminate agent actions. Enforcement is Gait's job.
3. **Not a compliance mapper (deep).** Wrkr maps scan findings to framework controls for evidence bundles. Deep compliance mapping, gap detection, and audit bundle assembly are Axym's job. Wrkr's evidence output can be ingested by Axym for richer compliance packages.
4. **Not an LLM observability tool.** Wrkr does not trace LLM calls, measure latency, or evaluate output quality. That's LangSmith/Arize territory.
5. **Not a SaaS product (v1).** The open-source CLI is the product. The GitHub Action running on a user's own CI cron is also free (self-hosted scheduling). Wrkr Pro (dashboard, Slack/webhook notifications, managed scheduling, SIEM export) is the commercial extension, built later. The line is: **self-hosted CLI and CI are free, managed orchestration and notifications are Pro.**
6. **Not cross-platform on day one.** GitHub is the only supported source in v1.
7. **Not a marketplace.** Wrkr does not host, distribute, or recommend AI tools. It inventories what you already have.
8. **Not AI-powered.** The scanner uses deterministic pattern matching, not LLMs. This is deliberate — a governance tool that hallucinates findings is worse than no tool at all.

---

## Acceptance Criteria (LVP v1 "Done" Definition)

### AC1: The "10-Minute Demo"

A new user with a GitHub org of 50+ repos can:

- Install Wrkr (`brew install Clyra-AI/tap/wrkr`)
- Run `wrkr init` with a GitHub token
- Run `wrkr scan --org <org>`
- See a complete AI tool inventory in their terminal
- See a ranked risk report with top 5 findings (configurable via `--top N`)
- Total elapsed time: under 10 minutes

### AC2: The "CISO Slide"

The output of `wrkr report --pdf` produces a one-page summary that a CISO can present to a board, containing: total AI tools discovered, breakdown by type, top 5 risks, and compliance gap count.

### AC3: The "Auditor Package"

The output of `wrkr evidence --frameworks eu-ai-act,soc2` produces a directory that a GRC analyst can hand to an auditor, containing: inventory, risk assessment, control mapping, gap analysis, proof records, and scan metadata — all timestamped and signed. The auditor can independently verify with `proof verify --bundle`.

### AC4: The "Fix It" Loop

`wrkr fix --top 3` opens 3 GitHub PRs that each: describe the finding, explain the risk, and make a specific code change (pin a version, add a manifest, remove a key). PRs pass basic CI checks.

### AC5: The "Detector Test"

For each supported AI tool type (Claude Code, Cursor, Codex, Copilot, MCP, AI dependencies, API keys), a test fixture repo exists with known configurations, and Wrkr correctly detects and inventories 100% of them.

### AC6: The "Diff Scan"

Running `wrkr scan --diff` against a previously scanned target (repo or org) shows only: new tools added, tools removed, tools with changed permissions/configs, and new risk findings. No false positives from unchanged repos.

### AC7: The "Zero Egress" Audit

A network-isolated run (no outbound internet after the clone phase) completes successfully. Wrkr requires GitHub API access to clone repos, but all scanning, detection, risk scoring, and proof record emission happen locally after clone. Scan results are verified to exist only on local filesystem. No DNS lookups to non-GitHub domains during scan. The `--enrich` flag is incompatible with this mode and errors if no network is available. For pre-cloned repos, `wrkr scan --path ./local-repos/` skips the clone phase entirely.

### AC8: The "Proof Record Chain"

All scan findings and risk assessments are emitted as signed proof records in the `Clyra-AI/proof` format. `wrkr verify --chain` and `proof verify --chain` both confirm chain integrity. Axym can ingest the records without conversion and map them to compliance controls.

### AC9: The "Cross-Product Chain"

Proof records from Wrkr (scan_finding, risk_assessment, approval, lifecycle_transition) can be appended to the same chain as Axym records (tool_invocation, decision) and Gait records (policy_enforcement, permission_check, guardrail_activation, approval). `proof verify --chain` validates the mixed-source chain. The chain doesn't care which tool produced which record.

### AC10: The "Posture Regression"

After remediating findings and establishing a clean posture, `wrkr regress init` captures the baseline. Simulating posture drift (adding an unapproved MCP server, introducing an unpinned hook, or adding a new AI tool without manifest approval) causes `wrkr regress run` to exit with code `5` and report exactly which tools or permissions regressed. The regression fixture is a portable file that runs identically in CI and locally. Same repos + same baseline = same pass/fail result, deterministically.

### AC11: The "Identity Lifecycle"

A tool discovered by `wrkr scan` receives a deterministic agent ID (`wrkr:<tool_id>:<org>`) that is stable across scans. Running `wrkr identity approve <id> --approver @maria --scope "read-only" --expires 90d` transitions the tool to `approved`, emits a signed `approval` proof record, and appends it to the identity chain. After 90 days, the next `wrkr scan` flags the tool as `under_review` (expired approval). Running `wrkr identity revoke <id>` transitions the tool to `revoked`, emits a proof record, and causes `wrkr regress run` to fail if the tool reappears. `wrkr identity show <id>` displays the full lifecycle chain, verifiable with `proof verify --chain`.

### AC12: The "Autonomous Agent Alert"

A test fixture repo contains: a `.github/workflows/deploy.yml` with Claude Code invoked via `-p --dangerouslySkipPermissions` and access to `secrets.DEPLOY_KEY` with no `environment:` protection, a `.cursor/` directory with YOLO mode enabled, and a `.codex/config.toml` with `approvalMode = "full-auto"`. `wrkr scan` correctly classifies each as `headless_auto` or equivalent autonomy level, scores them with the autonomy risk multiplier, and the risk report surfaces the CI agent as the #1 finding (highest risk: autonomous + secret access + no human gate).

### AC13: The "Aggregate Exposure"

A test fixture org has `payments-service` with 4 AI tools: Claude Code (Bash + file write), 2 MCP servers (one with DB write to prod Postgres, one read-only), and Cursor with YOLO mode. `wrkr scan` produces individual findings AND a `RepoExposureSummary` for `payments-service` showing: combined permission union (exec + fs.write + db.write + db.read), highest autonomy = `headless_auto` (Cursor YOLO), combined risk score higher than any individual tool, and exposure factors listing the aggregate risk. The aggregate finding appears in the risk report alongside individual findings.

### AC14: The "MCP Supply Chain"

A test fixture repo declares 3 MCP servers: (1) `npx -y @acme/mcp-db` with no lockfile and no pinned version, (2) `npx @verified/mcp-docs@1.2.3` with lockfile present and listed in MCP Registry, (3) `npx -y @malicious/mcp-mail` which has a known npm advisory. `wrkr scan` produces `MCPSupplyChain` data for each: server 1 scores low trust (unpinned, no lockfile), server 2 scores high trust (pinned, lockfile, registry-verified), server 3 is flagged as critical (known vulnerability). The remediation PR for server 1 pins the version and adds a lockfile reference.

### AC15: The "Skill Detection"

A test fixture repo contains: (1) `.claude/skills/deploy/SKILL.md` with `allowed-tools: [Bash, mcp__prod-db]` and implicit invocation enabled, (2) `.agents/skills/review/SKILL.md` with `allowed-tools: [file_read]` and no implicit invocation, (3) `.claude/skills/test/SKILL.md` with a supporting script `run.sh` that has no pinned hash. `wrkr scan` detects all three skills, scores skill 1 as high risk (broad Bash grant + implicit invocation + MCP dependency inheriting the prod-db server's risk), skill 2 as low risk (read-only, explicit invocation), and skill 3 as medium risk (unverified script). The risk report lists skill-specific findings with `allowed-tools` breadth, invocation policy, and supply chain status.

### AC16: The "PR-Mode Comment"

A test fixture PR modifies `.claude/settings.json` to add a new MCP server and changes `.cursor/rules/security.mdc`. `wrkr-action` in PR mode triggers, scans the repo at the PR head commit, and posts a PR comment containing: the specific config files that changed, the risk delta (score before vs. after the PR), whether the new MCP server is pinned and registry-verified, and whether the change requires approval per the `wrkr-manifest.yaml` policy. A second PR that modifies only `README.md` does not trigger the action (no AI config file in the diff).

### AC17: The "Manifest Generation"

Running `wrkr manifest generate` against a repo with Claude Code, Cursor, and 2 MCP servers produces a `wrkr-manifest.yaml` that lists all discovered tools under `review_pending` with status `under_review` and their current configuration (versions, hooks, MCP servers, access scopes), sets `blocked_tools` to empty, and populates the `policy` section with sensible defaults (`require_pinned_versions: true`, `require_mcp_approval: true`). Tools in `under_review` status still carry trust deficit in risk scoring. A human must explicitly move tools to `approved_tools` (via `wrkr identity approve` or manual edit) and commit the manifest for trust deficit to reach zero. This prevents "paper compliance" where auto-generated manifests bypass the review lifecycle. Removing a tool from the manifest and re-scanning flags it as unapproved with elevated risk.

### AC18: The "Policy Check"

A test fixture repo with known rule outcomes (for example WRKR-001 fail, WRKR-002 fail, WRKR-004 pass) produces deterministic policy pass/fail results on repeated runs, with stable rule IDs and remediation hints in JSON output. Running `wrkr scan --policy ./fixtures/wrkr-policy.yaml --json` evaluates custom rules in the same engine and emits violations as first-class findings (`finding_type: policy_violation`) without changing built-in rule semantics.

### AC19: The "Profile Compliance"

For the same fixture input, `wrkr scan --profile baseline|standard|strict --json` returns deterministic profile compliance percentage, explicit failing rule IDs, and compliance delta from previous scan state. Invalid profile references fail closed with a stable error envelope. Profile results are included in risk and evidence outputs.

### AC20: The "Posture Score"

Given a fixed fixture scan state and fixed score weights, `wrkr score --json` emits a deterministic score (`0-100`), grade (`A`-`F`), weighted component breakdown, and trend delta. The score is stable across repeated runs and is emitted in proof-compatible structured form for downstream CI policy gates and evidence chains.

---

## Tech Stack & Architecture

### Design Principles

1. **Boring technology.** Go. Single static binary. Infrastructure standard. No runtime dependencies.
2. **Deterministic pipeline.** Zero LLMs in the scan path. Pattern matching, AST parsing, config parsing. Same input → same output, always.
3. **Evidence as artifact.** Every scan produces signed proof records via `Clyra-AI/proof`. Not a dashboard — files you can `git commit`, chain-verify, and feed into Axym.
4. **Plugin-first extensibility.** New AI tools appear monthly. The detector interface must be trivial to extend.

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│                        wrkr CLI                           │
│                          (Go)                             │
├──────────┬──────────┬───────────┬──────────┬─────────────┤
│  init    │  scan    │  report   │  fix     │  evidence   │
│          │          │           │          │             │
│  config  │  ┌──────┐│  render   │  PR gen  │  compliance │
│  wizard  │  │source││  terminal │  GitHub  │  mapping    │
│          │  │layer ││  + PDF    │  API     │  + signing  │
│          │  └──┬───┘│           │          │             │
│          │     │    │           │          │             │
│          │  ┌──▼───┐│           │          │             │
│          │  │detect││           │          │             │
│          │  │engine││           │          │             │
│          │  └──┬───┘│           │          │             │
│          │     │    │           │          │             │
│          │  ┌──▼──────┐         │          │             │
│          │  │identity ││         │          │             │
│          │  │engine   ││         │          │             │
│          │  └──┬──────┘         │          │             │
│          │     │    │           │          │             │
│          │  ┌──▼───┐│           │          │             │
│          │  │risk  ││           │          │             │
│          │  │score ││           │          │             │
│          │  └──┬───┘│           │          │             │
│          │     │    │           │          │             │
│          │  ┌──▼───┐│           │          │             │
│          │  │proof ││           │          │             │
│          │  │emit  ││           │          │             │
│          │  └──────┘│           │          │             │
├──────────┴──────────┴───────────┴──────────┴─────────────┤
│  imports github.com/Clyra-AI/proof                              │
│                                                          │
│  proof.NewRecord()  · proof.Sign()  · proof.AppendToChain│
│  proof.VerifyChain() · proof.LoadFramework()             │
│                                                          │
│  Clyra-AI/proof — shared across Wrkr, Axym, Gait               │
└──────────────────────────────────────────────────────────┘

Source Layer:
  ├── GitHubSource (clone/API — repos, org metadata, app installs)
 

Detection Engine (plugin architecture):
  ├── ClaudeCodeDetector    → .claude/settings.json, .claude/settings.local.json, .mcp.json (project root), CLAUDE.md (root, .claude/, parent dirs), .claudeignore, .claude/commands/, hooks, autonomy flags (--allowedTools, --dangerouslySkipPermissions, -p)
  ├── CursorDetector        → .cursor/rules/*.mdc (frontmatter), .cursorrules (deprecated), .cursor/mcp.json, YOLO mode detection
  ├── CodexDetector         → .codex/config.toml, .codex/config.yaml, AGENTS.md, AGENTS.override.md, approval mode (suggest/auto-edit/full-auto)
  ├── CopilotDetector       → .github/copilot-instructions.md, .github/copilot-setup-steps.yml, AGENTS.md, .vscode/mcp.json, org policy controls, coding agent assignment config
  ├── MCPDetector           → .claude/settings.json, .mcp.json (project root), .cursor/mcp.json, .vscode/mcp.json, .codex/config.toml, standalone mcp.json, managed-mcp.json, ToolAnnotations extraction, supply chain analysis (package pinning, registry verification, advisory lookup)
  ├── CIAgentDetector       → .github/workflows/*.yml, Jenkinsfile — headless AI tool invocations, autonomy level, secret access (secrets.*), human approval gates (environment: + required_reviewers)
  ├── DependencyDetector    → go.mod, package.json, requirements.txt, pyproject.toml (AI libs)
  ├── SkillDetector         → SKILL.md in .claude/skills/, .agents/skills/ (cross-platform)
  ├── SecretDetector        → .env, CI config (AI API keys)
  └── GitHubAppDetector     → Org-level installed AI apps

Aggregation Engine:
  ├── RepoExposureAggregator   (union of permissions/data access across all tools per repo)
  ├── AutonomyClassifier       (classify each tool: interactive → copilot → headless_gated → headless_auto)
  └── CombinedRiskCalculator   (aggregate risk score per repo, not just per tool)

Policy Engine:
  ├── BuiltInRuleLoader        (`Clyra-AI/proof/policies/wrkr/*.yaml`)
  ├── CustomRuleLoader         (`wrkr scan --policy` + `wrkr-policy.yaml`)
  ├── RuleEvaluator            (deterministic pass/fail checks with stable IDs)
  └── PolicyFindingEmitter     (`finding_type: policy_violation`)

Identity Engine:
  ├── IdentityAssigner         (deterministic agent ID: wrkr:<tool_id>:<org>)
  ├── LifecycleTracker         (state machine: discovered → approved → revoked)
  ├── ApprovalManager          (expiry enforcement, renewal detection)
  └── IdentityChainEmitter     (lifecycle transitions → proof record chain)

Posture Profile Evaluator:
  ├── ProfileLoader            (`baseline` / `standard` / `strict`)
  ├── ThresholdEvaluator       (profile compliance % + failing rules)
  └── DeltaCalculator          (compliance trend vs previous scan)

Risk Scorer:
  ├── BlastRadiusCalculator   (what can this tool affect?)
  ├── PrivilegeCalculator     (what permissions does it have?)
  ├── TrustDeficitCalculator  (is it approved? pinned? tested?)
  ├── PolicySeverityContributor (policy violations influence rank)
  └── CompositeScorer         (weighted combination → single score)

Score Engine:
  ├── ScoreInputAggregator    (policy pass rate, approvals, severity mix, profile compliance, drift rate)
  ├── WeightedScorer          (deterministic 0-100 score)
  ├── GradeMapper             (`A`/`B`/`C`/`D`/`F`)
  └── TrendCalculator         (delta vs prior scan)

Proof Record Emitter:
  ├── Converts Finding → proof.Record (type: scan_finding)
  ├── Converts RiskScore → proof.Record (type: risk_assessment)
  ├── Converts Approval → proof.Record (type: approval)
  ├── Converts LifecycleTransition → proof.Record (type: lifecycle_transition)
  ├── Signs via proof.Sign()
  └── Chains via proof.AppendToChain()

Compliance Mapper:
  reads: Clyra-AI/proof/frameworks/*.yaml (shared definitions)
  ├── ControlMatcher       → Match proof records to controls
  └── EvidenceGenerator    → Proof records + mapping → evidence bundle
```

### Tech Choices

| Component | Choice | Why |
|-----------|--------|-----|
| Language | Go | Same as Gait, Axym, and Clyra-AI/proof. Single static binary. Infrastructure standard. No runtime dependencies. |
| CLI framework | `cobra` + `viper` | Standard for Go CLIs (kubectl, gh, hugo). Consistent with Gait and Axym. |
| Proof records | `github.com/Clyra-AI/proof` (Go module) | Shared primitive. Records, chain, signing, verification, framework definitions. Same format as Axym and Gait. |
| Git operations | `go-git/go-git` + GitHub REST/GraphQL API | Clone for deep scan, API for metadata. Pure Go git implementation, no CGO. |
| Config parsing | `gopkg.in/yaml.v3`, `encoding/json`, `BurntSushi/toml` | Parse AI tool configs as structured data. No regex heroics. |
| Pattern matching | Custom detectors with Go AST parsing where needed (`go/parser` for Go, `smacker/go-tree-sitter` for multi-lang) | Deterministic detection. Each detector is a pure function: `files → findings`. |
| Risk scoring | Weighted formula, configurable via YAML | No ML. No LLM. Auditable math. |
| PDF generation | `jung-kurt/gofpdf` or `pdfcpu` | For the "CISO slide" report output. Pure Go, no external dependencies. |
| Signing | Via `Clyra-AI/proof` (Ed25519 default, cosign for Sigstore alignment) | Evidence bundles and proof records are signed for tamper evidence. |
| CI distribution | GitHub Action (`Clyra-AI/wrkr-action@v1`) | Primary distribution channel. Also Docker image for other CI systems. |
| Testing | Go stdlib `testing` + `testify` | Consistent with Gait, Axym, and Clyra-AI/proof. |
| Distribution | `goreleaser` → Homebrew tap (`Clyra-AI/tap/wrkr`) + GitHub releases + Docker image | Single static binary for every platform. |

### Data Model (core entities)

Wrkr uses `proof.Record` from `Clyra-AI/proof` for evidence emission. The types below are Wrkr-specific — scan and risk logic that lives in the wrkr CLI, not in the shared primitive.

```go
// wrkr-specific types — scan and risk logic

// Inventory is the top-level scan output.
type Inventory struct {
    Org         string      `json:"org"`
    ScanDate    time.Time   `json:"scan_date"`
    ScanVersion string      `json:"scan_version"`
    Tools       []AITool    `json:"tools"`
    Summary     ScanSummary `json:"summary"`
    PolicyChecks      []PolicyCheck      `json:"policy_checks,omitempty"`
    ProfileCompliance *ProfileCompliance `json:"profile_compliance,omitempty"`
    PostureScore      *PostureScore      `json:"posture_score,omitempty"`
}

// AITool represents a discovered AI development tool.
type AITool struct {
    ID             string         `json:"id"`              // deterministic hash of type + location
    Type           ToolType       `json:"type"`             // "claude-code" | "cursor" | "codex" | "copilot" | "mcp" | "skill" | "dependency" | "api-key" | "github-app"
    Location       string         `json:"location"`         // repo/path
    Teams          []string       `json:"teams"`            // from CODEOWNERS or heuristic
    Identity       AgentIdentity  `json:"identity"`         // lifecycle state and approval history
    Version        string         `json:"version,omitempty"`
    Pinned         bool           `json:"pinned"`
    Permissions    []Permission   `json:"permissions"`
    DataAccess     []DataAccess   `json:"data_access"`      // what data sources does it connect to
    AutonomyLevel  AutonomyLevel  `json:"autonomy_level"`   // interactive | copilot | headless_gated | headless_auto
    ExecutionContext string       `json:"execution_context"` // "ide" | "ci" | "scheduled" | "issue_assigned"
    RiskScore      float64        `json:"risk_score"`       // 0-10
    RiskFactors    []string       `json:"risk_factors"`     // human-readable explanations
    Approved       *bool          `json:"approved"`          // nil = no manifest found
    EndpointClasses []string       `json:"endpoint_classes"`          // derived from permissions: proc.exec, fs.write, fs.read, fs.delete, net.http, net.dns, other
    DataClasses     []string       `json:"data_classes"`              // derived from context: credentials, pii, financial, internal
    MCPSupplyChain *MCPSupplyChain `json:"mcp_supply_chain,omitempty"` // MCP server package trust signals
    Metadata       map[string]any `json:"metadata,omitempty"`
}

// AgentIdentity tracks the lifecycle of a discovered AI tool.
// The same agent_id appears in Gait's IntentContext.Identity and Axym's agent_id field.
type AgentIdentity struct {
    AgentID      string          `json:"agent_id"`                 // deterministic: wrkr:<tool_id>:<org>
    Status       LifecycleStatus `json:"status"`                   // current lifecycle state
    FirstSeen    time.Time       `json:"first_seen"`               // timestamp of first discovery
    LastScan     time.Time       `json:"last_scan"`                // timestamp of most recent scan
    ApprovedBy   string          `json:"approved_by,omitempty"`    // identity of approver
    ApprovedDate *time.Time      `json:"approved_date,omitempty"`  // when approval was granted
    ApprovalExp  *time.Time      `json:"approval_expires,omitempty"` // when approval expires (default: 90 days)
    Scope        string          `json:"scope,omitempty"`          // what the approval covers
    Reason       string          `json:"reason,omitempty"`         // reason for deprecation or revocation
}

type LifecycleStatus string
const (
    StatusDiscovered  LifecycleStatus = "discovered"
    StatusUnderReview LifecycleStatus = "under_review"
    StatusApproved    LifecycleStatus = "approved"
    StatusActive      LifecycleStatus = "active"
    StatusDeprecated  LifecycleStatus = "deprecated"
    StatusRevoked     LifecycleStatus = "revoked"
)

type ToolType string
const (
    ToolClaudeCode ToolType = "claude-code"
    ToolCursor     ToolType = "cursor"
    ToolCodex      ToolType = "codex"
    ToolCopilot    ToolType = "copilot"
    ToolMCP        ToolType = "mcp"
    ToolDependency ToolType = "dependency"
    ToolSkill      ToolType = "skill"       // Agent Skills standard (agentskills.io) — cross-platform
    ToolAPIKey     ToolType = "api-key"
    ToolGitHubApp  ToolType = "github-app"
)

// AutonomyLevel classifies how much human oversight a tool operates under.
type AutonomyLevel string
const (
    AutonomyInteractive  AutonomyLevel = "interactive"    // human approves each action (default IDE usage)
    AutonomyCopilot      AutonomyLevel = "copilot"        // human triggers, tool executes with confirmation
    AutonomyHeadlessGated AutonomyLevel = "headless_gated" // runs without UI but requires approval gates
    AutonomyHeadlessAuto AutonomyLevel = "headless_auto"   // fully autonomous, no human in loop
)

// MCPSupplyChain captures trust signals for an MCP server's package origin.
type MCPSupplyChain struct {
    PackageRegistry string `json:"package_registry,omitempty"` // "npm" | "pypi" | "go" | "unknown"
    PackageName     string `json:"package_name,omitempty"`     // e.g., "@modelcontextprotocol/server-filesystem"
    Pinned          bool   `json:"pinned"`                     // version pinned or floating (npx -y = unpinned)
    PinnedVersion   string `json:"pinned_version,omitempty"`   // exact version if pinned
    Lockfile        bool   `json:"lockfile"`                   // lockfile present for this dependency
    KnownVulns      int    `json:"known_vulns"`                // count of known advisories for this package
    RegistryVerified bool  `json:"registry_verified"`          // listed in official MCP Registry
    TrustScore      float64 `json:"trust_score"`               // 0-10, computed from above signals
}

// RepoExposureSummary aggregates the combined permission surface across all tools in a repo.
type RepoExposureSummary struct {
    Repo              string   `json:"repo"`
    ToolCount         int      `json:"tool_count"`
    AutonomousTools   int      `json:"autonomous_tools"`     // tools with headless_gated or headless_auto
    CombinedRiskScore float64  `json:"combined_risk_score"`  // aggregate, not average
    PermissionUnion   []Permission `json:"permission_union"` // deduplicated union of all tool permissions
    DataAccessUnion   []DataAccess `json:"data_access_union"` // deduplicated union of all data access
    HighestAutonomy   AutonomyLevel `json:"highest_autonomy"` // worst-case autonomy level in repo
    ExposureFactors   []string `json:"exposure_factors"`      // human-readable aggregate risk explanations
}

// Permission represents an access grant for an AI tool.
type Permission struct {
    Type  string `json:"type"`  // "filesystem" | "network" | "exec" | "database" | "api"
    Scope string `json:"scope"` // what specifically
    Level string `json:"level"` // "read" | "write" | "admin"
}

// DataAccess represents a data source connection.
type DataAccess struct {
    Source   string `json:"source"`   // "postgres-prod", "s3-bucket", etc.
    Type     string `json:"type"`     // "database" | "object-store" | "api"
    Access   string `json:"access"`   // "read" | "write" | "admin"
    Approved bool   `json:"approved"`
}

// Finding represents a detected issue.
type Finding struct {
    ID               string   `json:"id"`
    Tool             AITool   `json:"tool"`
    FindingType      string   `json:"finding_type,omitempty"` // "tool_risk" | "policy_violation" | "skill_policy_conflict"
    RuleID           string   `json:"rule_id,omitempty"`      // WRKR rule ID when finding_type is policy-related
    CheckResult      string   `json:"check_result,omitempty"` // "pass" | "fail" for rule-backed findings
    ReasonCode       string   `json:"reason_code,omitempty"`  // stable machine-readable reason
    Severity         string   `json:"severity"` // "critical" | "high" | "medium" | "low"
    Title            string   `json:"title"`
    Description      string   `json:"description"`
    Remediation      string   `json:"remediation"`
    AutoFixAvailable bool     `json:"auto_fix_available"`
    RiskScore        float64  `json:"risk_score"`
}

// PolicyCheck captures deterministic pass/fail output for a single policy rule.
type PolicyCheck struct {
    RuleID      string `json:"rule_id"`       // e.g., WRKR-001
    RuleVersion string `json:"rule_version"`  // immutable semantics per rule version
    Name        string `json:"name"`
    Severity    string `json:"severity"`      // "critical" | "high" | "medium" | "low"
    Result      string `json:"result"`        // "pass" | "fail"
    Reason      string `json:"reason,omitempty"`
}

// ProfileCompliance summarizes posture conformance for a selected profile.
type ProfileCompliance struct {
    Name          string   `json:"name"`             // baseline | standard | strict
    CompliancePct float64  `json:"compliance_pct"`   // 0-100
    FailingRuleIDs []string `json:"failing_rule_ids,omitempty"`
    DeltaPct      float64  `json:"delta_pct"`        // change vs previous scan
}

// PostureScore is the deterministic weighted posture metric emitted by `wrkr score`.
type PostureScore struct {
    Score      float64            `json:"score"`       // 0-100
    Grade      string             `json:"grade"`       // A | B | C | D | F
    TrendDelta float64            `json:"trend_delta"` // score change vs previous scan
    Breakdown  map[string]float64 `json:"breakdown"`   // component -> weighted contribution
    Weights    map[string]float64 `json:"weights"`     // component -> configured weight
}

// ScanSummary provides aggregate scan statistics.
type ScanSummary struct {
    TotalTools        int `json:"total_tools"`
    KnownToSecurity   int `json:"known_to_security"`
    UnknownToSecurity int `json:"unknown_to_security"`
    HighRisk          int `json:"high_risk"`
    MediumRisk        int `json:"medium_risk"`
    LowRisk           int `json:"low_risk"`
}

// Detector is the interface that repo-level detection plugins implement.
type Detector interface {
    Name() string
    Detect(repoPath string) ([]Finding, error)
}

// OrgDetector is the interface for org-level detection plugins (GitHub App installs, IdP grants).
// These operate on org-wide API responses, not individual repo paths.
type OrgDetector interface {
    Name() string
    DetectOrg(orgID string, client OrgClient) ([]Finding, error)
}

// Finding → proof.Record conversion
func (f *Finding) ToProofRecord(signingKey proof.SigningKey) (*proof.Record, error) {
    record, err := proof.NewRecord(proof.RecordOpts{
        Type:      "scan_finding",
        Source:    "wrkr",
        AgentID:   f.Tool.Identity.AgentID,
        Event:     f.toEventData(),
        Controls:  f.toControlEvidence(),
    })
    if err != nil {
        return nil, err
    }
    return proof.Sign(record, signingKey)
}
```

### The `wrkr-manifest.yaml` open specification

`wrkr-manifest.yaml` is an open specification, versioned independently from Wrkr binary releases. The spec uses `spec_version` (`wrkr-manifest/v1`) and supports two interoperable profiles:

- Identity profile (Wrkr-generated): deterministic lifecycle records (`under_review` + `approval_status: missing` until explicit human approval).
- Policy profile (producer/consumer interchange): canonical fields `approved_tools`, `blocked_tools`, `review_pending_tools`, `policy_constraints`, `permission_scopes`, and `approver_metadata`.

The schema contract lives at `schemas/v1/manifest/manifest.schema.json`.

```yaml
# wrkr-manifest.yaml — policy profile example
spec_version: wrkr-manifest/v1
generated_at: "2026-02-21T12:00:00Z"

approved_tools:
  - tool_id: claude-code-payments
    tool_type: claude
    org: acme
    repo: acme/payments
    location: ".claude/settings.json"
    permission_scopes: ["repo.contents.read"]

blocked_tools:
  - tool_id: codex-full-auto
    tool_type: codex
    org: acme
    repo: acme/payments
    location: ".codex/config.toml"
    permission_scopes: ["proc.exec", "secret.read"]

review_pending_tools:
  - tool_id: cursor-frontend
    tool_type: cursor
    org: acme
    repo: acme/frontend
    location: ".cursor/rules/security.mdc"
    permission_scopes: ["repo.contents.read"]

policy_constraints:
  - id: require_pinned_versions
    description: MCP/tool dependencies must be pinned
    enforcement: block

permission_scopes:
  - id: repo.contents.read
    description: Read repository contents
  - id: secret.read
    description: Read CI or runtime secrets

approver_metadata:
  approver: "@maria"
  scope: read-only
  approved: "2026-02-21T12:00:00Z"
  expires: "2026-05-22T12:00:00Z"
```

---

## Rollout Plan

### Week 1–4: Ship the "Holy Shit" demo

The open-source CLI that does: scan → inventory → risk report → top 5 findings → proof records.

Distribution:

- Binary: `brew install Clyra-AI/tap/wrkr` + GitHub releases (goreleaser)
- Docker image: `ghcr.io/Clyra-AI/wrkr`
- GitHub repo with great README
- One blog post: "We scanned our org and found 31 AI tools we didn't know about"
- Submit to Hacker News, r/devops, r/netsec

### Week 5–8: Add remediation + evidence

- `wrkr fix` (auto PRs)
- `wrkr evidence` (compliance bundles with proof records)
- Second blog post: "How we passed our first AI audit with Wrkr"
- GitHub Action published to marketplace

### Week 9–12: Community + design partners

- 5–10 design partners running weekly scans
- `wrkr-manifest.yaml` convention documented and evangelized
- Plugin authoring guide published
- First external contributor adds a new detector
- Demonstrate Wrkr → Axym proof record flow: scan findings feed compliance mapping

### Week 13+: Wrkr Pro (commercial layer)

- Dashboard (inventory browser, risk trends over time)
- Scheduled scans with Slack notifications
- Approval workflows ("approve this MCP server for prod")
- SIEM export (Splunk, Sentinel, Elastic)
- SSO/RBAC
- Integration with Axym Pro and Gait Pro for unified governance dashboard
- This is where the money is. Free CLI creates the pull, Pro captures the budget.

---

## Success Metrics (6-Month Targets)

| Metric | Target |
|--------|--------|
| GitHub stars | 2,000+ |
| Weekly active CLI users | 500+ |
| Orgs scanned | 200+ |
| Design partners (paid pilot) | 10 |
| `wrkr-manifest.yaml` files in public repos | 100+ |
| External detector contributions | 5+ |
| Blog posts written about Wrkr by others | 10+ |
| Remediation PRs opened by Wrkr | 500+ (cumulative) |
| Remediation PRs merged by teams | 60%+ merge rate |
| Orgs with weekly scheduled scans | 100+ |
| First paying Wrkr Pro customer | Month 5 |
| Proof records flowing into Axym from Wrkr scans | 50+ organizations |

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| AI tool configs change format frequently | High | Medium | Plugin architecture. Detector updates don't require core changes. Community can contribute. |
| Platform vendors build native governance | Medium | High | Cross-surface is the moat. Anthropic won't govern Cursor. OpenAI won't govern Claude. Neutral layer always wins. |
| CASB vendors add "AI discovery" features | Medium | Medium | They see network, not code. Wrkr's code-level depth is structurally different. |
| Enterprises won't adopt open-source security tools | Low | High | Precedent says otherwise: Trivy, Falco, OPA, Snyk all started open source. Proof records are the trust mechanism. |
| Compliance mappings need legal review | High | Medium | Ship as "informational, not legal advice." Framework definitions live in `Clyra-AI/proof` and benefit from review across all three products. Validated mappings in Pro tier. |
| Wrkr findings don't integrate with compliance tools | Low | Medium | Proof records in shared `Clyra-AI/proof` format. Axym ingests them directly. GRC platforms can consume proof records via standard import. One format, zero translation. |
| Agent Skills standard adoption outpaces Wrkr's skill scanning | Medium | Medium | Already realized: Anthropic published Agent Skills as an open standard (agentskills.io), adopted by Codex, Copilot, Cursor, and Antigravity. Wrkr's `SkillDetector` scans the standardized `SKILL.md` format across all tools with one parser. First-mover advantage is in risk scoring and remediation depth, not format support. |
| Wrkr becomes a one-off scan tool (run once, screenshot for CISO, forget) | High | High | Primary mitigation: Dependabot-pattern auto-PRs in scheduled mode create recurring work that demands response. Secondary: identity approval expiry (90-day default) forces periodic re-engagement (~2 renewal tasks/week for a 47-tool org). Tertiary: PR-level change detection puts Wrkr in the developer workflow on every relevant PR, not just a cron job. The discovery scan is the hook; the weekly PR cadence is the retention. |
| Free/paid line is undefined — risk of giving away too much or gating too early | Medium | High | v1 free: CLI scan, risk report, remediation PRs, proof records, evidence bundle, posture regression, self-hosted GitHub Action on cron — everything a solo engineer or small team needs. Pro: dashboard (inventory browser, risk trends), Slack/webhook notifications, managed scheduling, approval workflows, SIEM export, SSO/RBAC, multi-org support. The line is: **self-hosted CLI and CI are free, managed orchestration and notifications are Pro.** The scan itself never requires a license. Revenue comes from the management layer that Maria (CISO) needs, not the scanning layer that Sam (engineer) runs. Validate with design partners in weeks 9-12 — if the free tier is too rich, tighten; if it gates adoption, loosen. |

---
title: "Detection Coverage Matrix"
description: "What Wrkr detects, what it does not detect, and why under deterministic scan constraints."
---

# Detection Coverage Matrix

## What Wrkr detects

- Repository and org configuration surfaces for Claude, Cursor, Codex, Copilot, MCP, WebMCP, A2A, and CI headless execution patterns.
- First-class agent declarations and bindings from LangChain, CrewAI, OpenAI Agents, AutoGen, LlamaIndex, MCP-client, and conservative custom-agent scaffolding surfaces.
- Direct Python and JS/TS source parsing for supported framework-native agent constructors, registrations, tool bindings, auth surfaces, and entrypoints when declaration files are absent.
- Explicit bespoke custom-source markers via `wrkr:custom-agent` annotations in Python and JS/TS source files when operators want deterministic custom-agent source coverage without broad heuristics.
- Prompt-channel override/poisoning patterns from static instruction surfaces with deterministic reason codes and evidence hashes.
- Structured GitHub Actions workflow capability extraction for `repo.write`, `pull_request.write`, `merge.execute`, `deploy.write`, `db.write`, and `iac.write`, with additive evidence keys that explain which static workflow step or permission produced each claim.
- Static MCP action-surface classification (`mcp.read`, `mcp.write`, `mcp.admin`) from saved declaration fields and saved gateway posture.
- Static non-human execution identity signals for GitHub Apps, bot users, and service-account references from workflow/config artifacts.
- Static policy/profile posture signals and ranked findings.
- Deterministic inventory and risk outputs for both tools and agents, including agent-linked attack-path edges when bindings/deployments are declared in-repo.
- Optional enrich-mode MCP metadata (`source`, `as_of`, advisory/registry schema IDs, `enrich_quality`, adapter error classes) when `--enrich` is enabled.

## What Wrkr does not detect

- Live runtime network traffic, live endpoint behavior, or post-deploy runtime side effects.
- Live runtime execution of agents or tool side effects beyond what is declared in repository and CI artifacts.
- Dynamic SaaS telemetry from external systems unless explicitly integrated in non-default paths.
- Guaranteed upstream API/schema stability for external enrich providers.

## Why

Wrkr is deterministic and file-based by default. Static discovery avoids nondeterministic live probing and keeps scan data local.
`--enrich` is an optional volatility-aware overlay; fail-closed adapter behavior preserves scan safety while quality is explicitly surfaced in output.

## Command anchors

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr scan --path ./scenarios/wrkr/agent-source-frameworks/repos --json
wrkr scan --path ./scenarios/wrkr/prompt-channel-poisoning/repos --json
wrkr scan --path ./scenarios/wrkr/webmcp-declarations/repos --json
wrkr scan --path ./scenarios/wrkr/a2a-agent-cards/repos --json
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --enrich --github-api https://api.github.com --json
```

## Q&A

### Does Wrkr detect live runtime traffic or endpoint behavior?

No. Wrkr is deterministic and file-based by default, so it detects declared configuration posture rather than runtime traffic.

### How do I confirm whether a specific tooling surface is detected?

Run `wrkr scan --json` on representative fixtures and verify the inventory findings include the expected tool/config declarations.

The expected v1 output model is tools plus agents. `inventory.agents`, `agent_privilege_map`, agent-aware `ranked_findings`, and additive agent-linked `attack_paths` are the deterministic proof surfaces for that model.

### How should I interpret MCP enrich quality fields?

Treat `enrich_quality` as explicit confidence metadata for optional network lookups: `ok`, `partial`, `stale`, or `unavailable`.

### When should I not use Wrkr as the primary tool?

Do not use Wrkr alone when your main requirement is runtime interception or live behavioral telemetry.

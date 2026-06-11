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
- Delivery-control context for harnesses, resolver files, eval configs, dry-run requirements, sandbox gates, and test gates when those controls are visible in supported instruction/config/workflow surfaces. This is detection-only context for review and validation requirements; Wrkr does not run evals or score model quality.
- Static MCP action-surface classification (`mcp.read`, `mcp.write`, `mcp.admin`) from saved declaration fields and saved gateway posture.
- Static mutable endpoint classification from OpenAPI specs, common route files, and MCP declaration hints, including additive semantics such as `payment`, `refund`, `user_admin`, `data_export`, and `production_mutation` with deterministic confidence and evidence refs.
- Static non-human execution identity signals for GitHub Apps, bot users, and service-account references from workflow/config artifacts.
- Deterministic purpose, version, and config-fingerprint metadata for supported workflow, MCP, and agent-config surfaces when local files, static declaration evidence, or explicit `wrkr:purpose` annotations are available.
- Deterministic confidence lanes that separate confirmed action paths, likely paths, semantic review candidates, and context-only evidence in buyer-facing output.
- agent-specific buyer wording only when `action_path_type` is actually agentic; plain-source, CI/CD, and broader workflow-backed paths stay labeled as action paths.
- Coverage-qualified negative-claim posture for MCP surfaces so complete coverage, reduced coverage, unsupported declarations, parse-failed candidates, and unscanned repos do not collapse into the same absence wording.
- Compact buyer-facing coverage summaries that lead with confidence, reduced-detector, parse-failure, suppressed-generated-file, blocked-detector, and unsupported-declaration counts while keeping detector-level rows in appendix and evidence JSON.
- Local evidence sidecars and declarations for enterprise control context, including `.wrkr/provenance/external-control-evidence.json`, `wrkr-control-declarations.yaml`, and `.wrkr/control-declarations.yaml`, when those files are provided inside the scanned repo root.
- Normalized credential-authority posture that distinguishes credential presence, workflow reference, path usability, access type, standing access, likely JIT, rotation evidence status, and source without exposing raw secret values.
- Field-selection redaction metadata and stable pseudonym joins for buyer-facing report artifacts when customer, design-partner, external, or investor-safe share profiles are used.
- Baseline-backed action-path drift review for new write/deploy authority, new credentials, approval-evidence regressions, resolved gaps, worsened paths, contradictions, and paths ready for control, using saved-state comparisons rather than fresh runtime probing.
- Static policy/profile posture signals and ranked findings.
- Deterministic inventory and risk outputs for both tools and agents, including agent-linked attack-path edges when bindings/deployments are declared in-repo.
- Optional enrich-mode MCP metadata (`source`, `as_of`, advisory/registry schema IDs, `enrich_quality`, adapter error classes) when `--enrich` is enabled.
- Precision-calibration and enterprise-pressure fixture gates that convert owner evidence, approval sidecars, dependency-only context, CI-only automation, contradictions, redaction, drift, and 300+ repo compactness checks into repeatable local scenarios.

## What Wrkr does not detect

- Live runtime network traffic, live endpoint behavior, post-deploy runtime side effects, or live endpoint reachability checks.
- Live runtime execution of agents or tool side effects beyond what is declared in repository and CI artifacts.
- Dynamic SaaS telemetry from external systems unless explicitly integrated in non-default paths.
- Guaranteed upstream API/schema stability for external enrich providers.

## Why

Wrkr is deterministic and file-based by default. Static discovery avoids nondeterministic live probing and keeps scan data local.
That same rule applies to enterprise control context: Wrkr consumes local evidence sidecars and declarations, and it does not default to querying provider APIs.
`--enrich` is an optional volatility-aware overlay; fail-closed adapter behavior preserves scan safety while quality is explicitly surfaced in output.

That same discipline applies to negative claims: Wrkr only uses absolute absence language when detector coverage is complete enough to support it. Reduced coverage, unsupported declarations, parse-failed candidate surfaces, and unscanned repos stay explicitly qualified in saved-state artifacts, and runtime evidence absence is framed as `not collected`, `not applicable`, `missing required`, or `missing for control claim` instead of treating static-only scans as missing runtime proof.

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

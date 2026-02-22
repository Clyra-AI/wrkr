---
title: "Detection Coverage Matrix"
description: "What Wrkr detects, what it does not detect, and why under deterministic scan constraints."
---

# Detection Coverage Matrix

## What Wrkr detects

- Repository and org configuration surfaces for Claude, Cursor, Codex, Copilot, MCP, WebMCP, A2A, and CI headless execution patterns.
- Static policy/profile posture signals and ranked findings.
- Deterministic inventory and risk outputs.

## What Wrkr does not detect

- Live runtime network traffic, live endpoint behavior, or post-deploy runtime side effects.
- Dynamic SaaS telemetry from external systems unless explicitly integrated in non-default paths.

## Why

Wrkr is deterministic and file-based by default. Static discovery avoids nondeterministic live probing and keeps scan data local.

## Command anchors

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr scan --path ./scenarios/wrkr/webmcp-declarations/repos --json
wrkr scan --path ./scenarios/wrkr/a2a-agent-cards/repos --json
```

## Q&A

### Does Wrkr detect live runtime traffic or endpoint behavior?

No. Wrkr is deterministic and file-based by default, so it detects declared configuration posture rather than runtime traffic.

### How do I confirm whether a specific tooling surface is detected?

Run `wrkr scan --json` on representative fixtures and verify the inventory findings include the expected tool/config declarations.

### When should I not use Wrkr as the primary tool?

Do not use Wrkr alone when your main requirement is runtime interception or live behavioral telemetry.

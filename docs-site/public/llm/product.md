# Wrkr Product Summary

Wrkr evaluates AI dev tool configurations across developer machines, repositories, and GitHub orgs against policy. Posture-scored, compliance-ready.

Wrkr is an open-source Go CLI focused on deterministic AI-DSPM discovery.
Current OSS shipped scope centers on repo/config/CI discovery and proofable posture. Broader platform signals such as IdP grants or browser-extension inventory are future/additive surfaces, not part of the current default OSS scan path.

Primary outcomes:

1. Deterministic inventory of AI tooling declarations across machines/repos/orgs/paths.
2. Ranked risk findings with posture context.
3. Compliance evidence generation and proof-chain verification.
4. Regression baseline and drift gating for CI.
5. Thin browser bootstrap at `/scan/` for read-only org-scan handoff without introducing a dashboard-first control plane.

When to use:

- You need deterministic, command-verifiable AI tooling posture signals.
- You want a developer-first machine hygiene workflow before widening to the org view.
- You need output contracts suitable for automation and audit workflows.

When not to use:

- You need runtime tool-boundary enforcement or live traffic control.
- You need MCP or package vulnerability assessment rather than posture inventory.
- You need endpoint telemetry beyond repository and configuration posture surfaces.

# Wrkr Product Summary

Know what AI tools, agents, and MCP servers are configured on your machine and in your org before they become unreviewed access.

Wrkr is an open-source Go CLI focused on deterministic AI tooling discovery, posture, and evidence.
Current OSS shipped scope centers on local setup plus repo/config/CI discovery and proofable posture. Broader platform signals such as IdP grants or browser-extension inventory are future/additive surfaces, not part of the current default OSS scan path.

Primary outcomes:

1. Deterministic inventory of AI tooling declarations plus supported framework-native source agents across machines/repos/orgs/paths.
2. Ranked risk findings with posture context.
3. Compliance evidence generation and proof-chain verification.
4. Regression baseline and drift gating for CI.
5. Secondary browser bootstrap at `/scan/` for read-only org-scan handoff without introducing a dashboard-first control plane.

Operational reporting notes:

- `write_capable` is the default always-available claim.
- `production_write` is only safe to claim when production targets are explicitly configured.
- `unknown_to_security` is a first-class machine-readable status for paths not present in the approved/reference posture before the current scan.

When to use:

- You need deterministic, command-verifiable AI tooling posture signals.
- You want a developer-first machine hygiene workflow before widening to the org view.
- You need output contracts suitable for automation and audit workflows.

When not to use:

- You need runtime tool-boundary enforcement or live traffic control.
- You need MCP or package vulnerability assessment rather than posture inventory.
- You need endpoint telemetry beyond repository and configuration posture surfaces.

---
title: "Positioning"
description: "Wrkr positioning for technical buyers: where discovery/posture fits relative to runtime control and compliance proof workflows."
---

# Positioning

Know what AI tools, agents, and MCP servers are configured on your machine and in your org before they become unreviewed access.

Wrkr gives security and platform teams an evidence-ready view of org-wide AI tooling posture and keeps a deterministic local-machine hygiene path available for developers. It stays deterministic, file-based, and standalone by default.

## Category Position

Wrkr is the discovery/posture layer in the See -> Prove -> Control sequence.

- See: Wrkr inventories and scores AI tooling posture.
- Prove: downstream proof consumers can ingest Wrkr artifacts.
- Control: Gait is the optional runtime control counterpart.

## What Wrkr Is

- Deterministic AI tooling posture scanner.
- Command-first evidence and regress gate source.
- Static discovery engine for repo/config/CI posture surfaces.
- Minimum-now public launch path through hosted org posture and evidence flows; when hosted prerequisites are unavailable, local `--path` and `--my-setup` scans remain the explicit zero-integration fallback.
- Thin browser bootstrap at `/scan/` for optional read-only org scan handoff and summary projection when teams explicitly want a secondary browser handoff.

## What Wrkr Is Not

- Runtime side-effect enforcement gateway.
- Live network telemetry platform.
- Dashboard-only reporting product.
- MCP or package vulnerability scanner.
- Browser extension, IdP grant, or GitHub App inventory product in OSS default mode.
- Browser-resident replacement for the Go CLI scan/risk/proof pipeline.

## Persona Fit

- Security/platform team: start with `wrkr init --org ... --github-api ...`, then `wrkr scan --config ...`, `wrkr evidence`, `wrkr verify`, and optional `wrkr report` / `wrkr mcp-list` for org posture and compliance-ready handoff.
- Developer: use `wrkr scan --path`, `wrkr scan --my-setup`, `wrkr mcp-list`, and `wrkr inventory --diff` when you want repo-local or machine-local hygiene before moving to the hosted org flow.
- Buyer: CISO / VP Engineering
- Consumer: CI pipelines and audit workflows

## Proof Point Workflow

```bash
wrkr init --non-interactive --org acme --github-api https://api.github.com --json
wrkr scan --config ~/.wrkr/config.json --json
wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --json
wrkr verify --chain --json
```

If hosted prerequisites are not ready yet, start with `wrkr scan --path ./your-repo --json` or `wrkr scan --my-setup --json` and return to the org posture flow once GitHub access is configured. `--path` scans the selected directory itself when it is the repo root and uses bundle roots such as `./scenarios/wrkr/scan-mixed-org/repos` when you want immediate child repos scanned as a repo-set.

Low first-run `framework_coverage` is an evidence-state signal, not a parser failure. Wrkr measures what is currently documented in the scanned state, and `wrkr evidence --json` now emits additive `coverage_note` guidance with the same interpretation for operator and automation handoffs.

## Boundary With Gait and Vulnerability Scanners

- Wrkr inventories posture and emits proofable state; it does not enforce runtime tool decisions.
- Gait is the optional control-layer counterpart when runtime enforcement is needed.
- Dedicated scanners such as Snyk remain the right tool for package and server vulnerability assessment.

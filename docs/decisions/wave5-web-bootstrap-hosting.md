---
title: "Wave 5 Web Bootstrap Hosting"
description: "ADR for the thin Wrkr web bootstrap shell and the docs-site hosting split between static docs and callback-capable runtime mode."
---

# Wave 5 Web Bootstrap Hosting

## Status

Accepted for Wave 5 bootstrap scope.

## Context

The docs site currently ships as a static Next export on GitHub Pages.
Wave 5 adds a thin `/scan` bootstrap flow, but the plan explicitly forbids turning Wrkr into a dashboard-first product or moving scan/risk/proof logic into Node.

The hard constraint is that a full GitHub OAuth callback flow needs a callback-capable runtime, while the current docs deployment is static-only.

## Decision

1. Keep GitHub Pages static export as the default docs-site deployment mode.
2. Add a server-capable docs-site build mode behind `WRKR_DOCS_DEPLOY_MODE=server` for future callback-capable hosting.
3. Ship `/scan` immediately as a read-only bootstrap shell that:
   - prepares an equivalent handoff request
   - points to existing Wrkr CLI and Action org-scan contracts
   - projects returned machine-readable summary artifacts without persisting them
4. Keep all scan, risk, proof, and evidence logic in the Go CLI and existing Wrkr contracts.

## Consequences

- Positive:
  - Wave 5 becomes usable on the current public docs host immediately.
  - The repo gains an explicit path to callback-capable deployment without breaking current Pages publishing.
  - The web shell stays clearly inside the See boundary.
- Negative:
  - The GitHub Pages deployment does not perform a live OAuth callback today.
  - Users still need CLI or workflow handoff for the authoritative org scan execution.

## Guardrails

- No dashboard persistence, tenant state, or hidden background scans.
- No Node duplication of Go scan/risk/proof logic.
- Any future callback service contract must stay versioned and isolated from CLI schemas.
- Failure states remain explicit: denied auth, missing callback state, unavailable backend/handoff.

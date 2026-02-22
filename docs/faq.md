---
title: "FAQ"
description: "Frequently asked technical and buyer-facing questions about Wrkr discovery, determinism, and evidence workflows."
---

# FAQ

## Frequently Asked Questions

### What is Wrkr in one sentence?

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

### Is Wrkr deterministic?

Yes. Wrkr scan/risk/proof paths are deterministic by default for fixed inputs.

### Does Wrkr need a hosted control plane?

No. Core operation is local and file-based by default.

### Does Wrkr replace runtime enforcement?

No. Wrkr is discovery/posture. Runtime enforcement is a separate control layer.

### How do I fail CI on posture drift?

Use `wrkr regress init` to establish a baseline and `wrkr regress run` in CI. Exit `5` indicates drift.

### How do I produce compliance evidence?

Use `wrkr evidence --frameworks ... --json` and verify chain integrity with `wrkr verify --chain --json`.

---
title: "Wave 4.5 Delivery-Control Context"
description: "Why Wrkr detects harness/resolver/eval control context without becoming an eval platform."
---

# Decision

Wrkr may project additive delivery-control context from deterministic local files:

- harnesses
- resolver refs
- eval config refs
- dry-run requirements
- sandbox gates
- test gates
- validation requirements

This context is detection-only. Wrkr does not execute evals, score model quality, or claim that a declared harness/test/eval control actually ran unless other evidence proves it.

# Why

- Instruction packs, resolver files, and eval harnesses materially change delivery behavior and review burden.
- Buyers and platform owners need that context in the focused BOM.
- The surface-area freeze requires that new context stay bounded and review-oriented rather than opening a new execution product line.

# Consequences

- New delivery-control fields are additive to reports and BOM output.
- Unknown or malformed eval config stays a control-context diagnostic, not a high-confidence runtime claim.
- Validation requirements can guide control review without expanding Wrkr into a hosted evaluation service.

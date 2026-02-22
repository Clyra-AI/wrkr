---
title: "Compatibility Matrix"
description: "Compatibility expectations for Wrkr command contracts, schema surfaces, and deterministic behavior across v1 lines."
---

# Compatibility Matrix

## Contract Stability

| Surface | Stability Expectation |
|---|---|
| Exit codes | Stable and versioned as API |
| `--json` envelope | Stable keys for major line |
| Schema assets in `schemas/v1` | Backward-compatible additive changes |
| Manifest spec | Managed by `spec_version` |

## Consumer Guidance

- Validate schema before processing exported artifacts.
- Treat unknown required fields as blocking.
- Treat regress drift exit `5` as a stable CI failure signal.

## Command Anchors

```bash
wrkr export --format inventory --json
wrkr manifest generate --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
```

## Q&A

### Which Wrkr surfaces are stable across the v1 contract line?

Exit codes, primary `--json` envelopes, and schemas in `schemas/v1` are treated as stable API surfaces for consumers.

### How should consumers handle unknown fields in JSON outputs?

Ignore unknown optional fields, but fail on missing required fields and schema violations.

### How do I pin compatibility in CI pipelines?

Validate exported artifacts against the intended schema version and assert expected exit-code behavior for contract-critical commands.

---
title: "Contracts and Schemas"
description: "Reference index for Wrkr command contracts, schema assets, and proof interoperability surfaces."
---

# Contracts and Schemas

## Canonical references

- Root exit codes and flags: `docs/commands/root.md`
- Command contract index: `docs/commands/index.md`
- Manifest open specification: `docs/specs/wrkr-manifest.md`
- JSON schemas: `schemas/v1/`

## Command anchors

```bash
wrkr manifest generate --json
wrkr export --format inventory --json
wrkr verify --chain --json
```

## Compatibility posture

Within the same major contract line, additive fields are expected to remain backward compatible for consumers that ignore unknown optional fields.

## Q&A

### Where are Wrkr JSON schemas and contracts defined?

Schemas live in `schemas/v1/`, while command and flag contracts are documented under `docs/commands/`.

### Which spec defines the Wrkr manifest contract?

`docs/specs/wrkr-manifest.md` is the canonical manifest specification reference.

### How should I design consumers to remain compatible over time?

Treat additive optional fields as non-breaking, validate required fields strictly, and pin expected schema/manifest versions in CI checks.

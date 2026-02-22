---
title: "Compatibility and Versioning"
description: "How Wrkr maintains command, schema, and exit-code compatibility across v1 contract evolution."
---

# Compatibility and Versioning

## Stable API surfaces

- Exit codes are API and remain stable.
- `--json` output envelopes are contractual.
- Deterministic fields are preserved for fixed inputs.

## Versioning notes

- Schema evolution is managed under `schemas/v1/`.
- Manifest spec versioning is defined in `docs/specs/wrkr-manifest.md`.

## Command anchors

```bash
wrkr score --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
wrkr manifest generate --json
```

## Q&A

### What does stable `--json` envelope mean in practice?

It means the major-line output shape remains consistent for machine consumers, with additive evolution handled without breaking existing parsers.

### Can new fields be added in v1 without a breaking release?

Yes. Additive optional fields are expected; removals or required-field breaks require explicit contract versioning.

### How should agents handle unknown fields in Wrkr JSON?

Ignore unknown optional fields and fail only when required contract fields are missing or invalid.

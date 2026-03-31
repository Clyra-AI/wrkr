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
- `regress` baseline compatibility remains in `v1` for legacy baselines created before instance identities. Equivalent current identities reconcile automatically; additive JSON fields remain the preferred evolution path.
- Stricter rejection of invalid inputs that never matched the documented command contract, such as non-scan JSON passed to `wrkr campaign aggregate`, is treated as a compatibility-preserving bug fix inside the current major line.
- Repo-local extension detector findings remain additive by default; their prior implicit promotion into authoritative inventory, lifecycle, and regress state is not a stable compatibility guarantee.

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

### How are pre-instance `regress` baselines handled?

Wrkr reconciles legacy `v1` baseline agent IDs against equivalent current instance identities at compare time. If a future change ever requires a baseline version bump, Wrkr must ship an explicit migration path and compatibility tests in the same release.

### How should agents handle unknown fields in Wrkr JSON?

Ignore unknown optional fields and fail only when required contract fields are missing or invalid.

### Does rejecting non-scan JSON in `wrkr campaign aggregate` require a new version line?

No. Campaign aggregation is documented to consume complete `wrkr scan --json` artifacts only, so rejecting other `status=ok` envelopes is a current-line contract fix rather than a versioned breaking change.

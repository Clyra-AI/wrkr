## Summary

Describe the change and operator impact.

## Contract Impact

- [ ] No public contract changes (flags/JSON/schema/exits/help/docs)
- [ ] Public contract changes are included and documented below

Contract details:

- CLI/flags/help changes:
- JSON output changes:
- Schema/versioning changes:
- Exit code behavior changes:

## Tests and Lane Evidence

List commands you ran and outcomes:

```text
make lint-fast
make test-fast
make test-contracts
make test-scenarios
make test-docs-consistency
```

Additional scoped commands:

- [ ] Acceptance lane evidence included when behavior is operator-facing.
- [ ] Cross-platform/path behavior reviewed for touched surfaces.
- [ ] Release-note or changelog claims about size, privacy, redaction, customer-safe sharing, or readability include measured artifact-size deltas, redaction test names, and fixture coverage below.

## Docs and Source of Truth

- [ ] User-visible behavior changes include docs updates in the same PR.
- [ ] Docs updates follow [`docs/map.md`](docs/map.md) source-of-truth guidance.

## Surface-Area Gate

- [ ] Any new detector, report mode, graph field, platform surface, or docs claim explains its impact on focused BOM clarity, repeat use, or evidence quality.
- [ ] Output-size / finding-noise / markdown-budget impact is documented below when buyer-facing surfaces change.
- [ ] Sprint 0 temporary freeze gate: any new scan/report field, sidecar, detector expansion, report section, or context dimension is directly required by Stories 1.1 through 4.2 or the size, redaction, and readability gates are green.

Surface-area notes:

- Focused BOM clarity impact:
- Repeat-use impact:
- Evidence-quality impact:
- Budget impact:
- Sprint 0 gate justification:
- Measured artifact-size deltas:
- Redaction test names:
- Fixture coverage:

## Risks and Follow-ups

- Determinism/fail-closed/security risks:
- Deferred follow-ups (if any):

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

## Docs and Source of Truth

- [ ] User-visible behavior changes include docs updates in the same PR.
- [ ] Docs updates follow [`docs/map.md`](docs/map.md) source-of-truth guidance.

## Surface-Area Gate

- [ ] Any new detector, report mode, graph field, platform surface, or docs claim explains its impact on focused BOM clarity, repeat use, or evidence quality.
- [ ] Output-size / finding-noise / markdown-budget impact is documented below when buyer-facing surfaces change.

Surface-area notes:

- Focused BOM clarity impact:
- Repeat-use impact:
- Evidence-quality impact:
- Budget impact:

## Risks and Follow-ups

- Determinism/fail-closed/security risks:
- Deferred follow-ups (if any):

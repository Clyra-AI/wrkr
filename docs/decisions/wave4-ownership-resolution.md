# Wave 4 Ownership Resolution

## Status

Accepted.

## Context

Large org scans need owner quality that scales beyond a single repository fallback. Wrkr already preserved the legacy `owner`, `owner_source`, and `ownership_status` fields, but operators could not distinguish explicit ownership evidence from inferred, conflicting, or missing ownership without inspecting raw files.

## Decision

Wrkr resolves ownership from deterministic local and already-acquired source evidence only:

- CODEOWNERS rules.
- `.wrkr/owners.yaml`, `.wrkr/owners.yml`, `.wrkr/owners.json`, and repo-root owner mapping files.
- Service catalog exports in `.wrkr/service-catalog.*` or repo-root `service-catalog.*`.
- Backstage `catalog-info.yaml` files.
- GitHub topics/teams only when those values are already present in acquired repository metadata.
- Deterministic repo-name fallback when no explicit owner evidence exists.

The existing compatibility fields remain unchanged. Additive fields carry the new governance state:

- `ownership_state`: `explicit_owner`, `inferred_owner`, `conflicting_owner`, or `missing_owner`.
- `ownership_confidence`: stable numeric confidence from `0` to `1`.
- `ownership_evidence_basis`: deterministic evidence strings for the resolved state.
- `ownership_conflicts`: sorted conflicting owner candidates when sources disagree.

Conflicting explicit sources are surfaced as `ownership_state=conflicting_owner`, `owner_source=multi_repo_conflict`, low confidence, and a control backlog evidence gap. Wrkr does not perform standalone network lookups for ownership by default.

## Consequences

Backlog, inventory, report, and export consumers can prioritize missing or conflicting ownership without losing compatibility with existing `owner_source` and `ownership_status` readers. Offline scans continue to work because network-derived ownership metadata is optional and must already be present in source acquisition output.

## Validation

- `go test ./core/owners ./core/source/github ./core/source/org ./core/aggregate/inventory ./core/aggregate/controlbacklog -count=1`
- `go test ./internal/scenarios -run 'TestOwnershipQuality' -count=1 -tags=scenario`

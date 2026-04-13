# ADR: Wave 14 Multi-Target Scan Contract

Date: 2026-04-13
Status: accepted

## Context

Wave 14 adds one-run mixed hosted and local scanning through repeatable `wrkr scan --target <mode>:<value>` flags.

The plan requires:

1. additive multi-target CLI behavior without breaking legacy single-target flags
2. deterministic acquisition ordering and duplicate repo collapse
3. explicit fail-closed resume rules that remain scoped to org-only target sets
4. additive `targets[]` data in scan, state, and report payloads without a schema version bump

## Decision

1. Keep legacy target flags (`--repo`, `--org`, `--github-org`, `--path`, `--my-setup`) as one-entry shims and reject mixed legacy-plus-`--target` invocations.
2. Canonicalize explicit target sets into a deterministic sorted list before acquisition, and emit `target.mode=multi` only when more than one explicit target is requested.
3. Add additive `targets[]` arrays to scan payloads, source manifests, saved state snapshots, and report JSON payloads while preserving the legacy single-target `target` object.
4. Reuse existing source boundaries per target and merge results above them, with deterministic repo de-duplication after acquisition.
5. Allow `--resume` only when every requested target is an org target, and validate both a target-set checkpoint and per-org checkpoints before reuse.

## Rationale

- Treating legacy flags as shims preserves operator muscle memory and existing automation.
- Canonical target ordering keeps repeated runs byte-stable even when users provide targets in a different order.
- Additive `targets[]` fields expose the new contract without forcing a schema version bump or breaking single-target consumers.
- Merging above existing source adapters keeps repo/org/path/my-setup acquisition logic isolated and testable.
- Target-set checkpoint validation prevents stale multi-org resume state from being silently reused for a different request.

## Consequences

- Explicit multi-target scans expose `target.mode=multi` and `targets[]`, while single-target scans keep their existing `target` shape.
- Mixed target-set failures can surface as partial results when one target degrades and the rest still complete.
- `--resume` now clearly rejects mixed hosted/local target sets with `invalid_input`.
- `wrkr init` remains single-target in this wave; multi-target defaults are intentionally deferred.

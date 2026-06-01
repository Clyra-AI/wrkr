# ADR: Wave 28 Public-Surface Assessment

Date: 2026-05-31
Status: accepted

## Context

Wave 2 of the GTM, packaging, and scale-gates plan needs Wrkr to support
credible public-surface demos without inventing private-environment claims.
Operators need a deterministic way to feed curated public repos, docs, SDKs,
blogs, release notes, status pages, and workflow references into Wrkr while
keeping public observation separate from inferred context and explicitly marking
unsupported or private-evidence-missing claims.

## Decision

1. Add an explicit `public-surface` scan target that reads a structured local
   manifest instead of scanning private repositories.
2. Keep public-surface provenance in the source layer with validated
   `source_class`, `public_ref`, optional safe local `capture_path`,
   `captured_at`, `evidence_label`, `confidence`, and `inference_rationale`.
3. Use exactly four additive evidence labels:
   `public_observed`, `public_inferred`,
   `unsupported_public_claim`, and `private_evidence_absent`.
4. Save those source-layer rows into scan state and render them back out through
   a dedicated report summary and markdown section.
5. Never convert public-surface rows into verified private runtime, approval,
   credential, deployment, or control claims without stronger private evidence.

## Rationale

- A dedicated target keeps public-evidence demos out of the normal private scan
  path and preserves determinism.
- Source-layer validation lets Wrkr fail closed on malformed URLs, unsupported
  source classes, or unsafe local capture paths before any report claim is made.
- Explicit labels make it clear what was directly observed versus inferred or
  still unsupported.
- A dedicated summary section keeps buyer-facing demos useful without leaking
  into private-control evidence semantics.

## Consequences

- `wrkr scan --target public-surface:<manifest>` now supports curated
  public-evidence manifests.
- Saved state and `source_manifest` preserve additive public-evidence rows and
  the manifest name for downstream rendering.
- `wrkr report --json` and Markdown now include a dedicated
  `public_surface_assessment` contract when the saved target is public-surface.
- Public-surface mode remains opt-in and does not scrape the internet or claim
  private reachability from public marketing or docs signals alone.

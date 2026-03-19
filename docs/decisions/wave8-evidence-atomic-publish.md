# ADR: Wave 8 Evidence Atomic Publish

Date: 2026-03-19
Status: accepted

## Context

`wrkr evidence` previously validated ownership on the target directory, cleared that directory in place, and then streamed new bundle files directly into the final `--output` path.

That behavior created two release-risk problems:

- a failed rerun could destroy the previous valid managed bundle
- a failed build could leave a partial new bundle visible at the final target path

Wrkr's evidence output is a contract artifact, not a best-effort cache, so publish semantics must be crash-safe and fail closed.

## Decision

1. Validate the final output path for ownership/marker safety without mutating it.
2. Build the entire evidence bundle in a same-parent staged directory.
3. Write the managed marker into the staged directory, not the live target.
4. Generate the manifest, sign the bundle, and verify the bundle before publishing.
5. Publish by swapping the staged directory into the final target path only after successful verification.
6. If the target already contains a managed bundle, move it aside during publish and restore it on any publish failure.
7. Treat staged-directory cleanup and backup cleanup as internal implementation details; do not expand the public CLI contract surface.

## Rationale

- Evidence consumers should never observe a partially written bundle at the final path.
- The previous known-good bundle is higher-value than a failed replacement attempt.
- Same-parent staging keeps publish behavior compatible with atomic directory rename semantics on the local filesystem.
- The user-facing contract remains simple: success publishes a complete bundle, failure does not replace it.

## Consequences

- `wrkr evidence` now has explicit build-vs-publish phases.
- Failure-path tests must cover:
  - invalid framework/no publish
  - late publish failure/restore previous bundle
  - stage/backup cleanup behavior
- Docs must describe evidence output as staged publish semantics, not in-place mutation.

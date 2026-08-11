# Post-v1.13 Customer-Truth Hardening

## Context

Design-partner assessments showed that the bounded buyer brief was working, but four projection details could still mislead or slow remediation: owner attribution counted as control evidence, generated-file suppression reduced unrelated coverage, non-core detector failures did not reach blocked-detector counts, and the buyer brief remained packaged with a large diagnostic appendix.

## Decision

- Treat approval, proof, and runtime evidence as control-relevant signals; ownership remains attribution evidence only.
- Count explicit production-target-backed paths separately from statically observed deployment surfaces so inferred delivery impact cannot be presented as customer-configured production evidence.
- Preserve generated/vendor suppression in detector diagnostics without reducing unrelated path or organization coverage. Surface-specific absence claims remain conservative.
- Build detector health rows for every detector that reports an error, not only the core detector set.
- Group repeated parse issues and carry an occurrence count.
- Keep the selected-path and composition recommendations distinct and publish one explicit effective control with its governing scope.
- Split assessment Markdown into a bounded lead and companion appendix.
- Publish a manifest-backed `customer-share/` directory containing only the selected share-profile report artifacts. Keep raw state, logs, proof internals, signing material, and private joins in the parent assessment directory.
- Compact automatic non-interactive detector progress while preserving explicit `--progress events` behavior.

## Compatibility

The scan-quality and primary-view changes are additive JSON fields or corrected derivation semantics. Direct `wrkr report --md` keeps `--md-scope full` as its default. `wrkr assess` opts into split Markdown and adds share-directory paths to its manifest.

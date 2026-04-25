# Wave 15: Control Path Graph And Credential Provenance

## Status

Accepted

## Context

Wrkr already emitted additive govern-first `action_paths`, inventory privilege maps, control backlog items, and proof-mapped governance records, but each surface projected the same control story independently.

That left two gaps:

- operators had no single versioned graph artifact they could use to join identity, credential, workflow, repo, governance-control, target, and action-capability facts
- `credential_access` stayed a coarse boolean, which made it impossible to distinguish static secrets, workload identity, inherited human credentials, OAuth delegation, JIT credentials, and unknown models in a deterministic way

Wave 2 of the source privacy and governance plan requires both the new graph contract and typed credential provenance while preserving deterministic joins and existing compatibility booleans.

## Decision

Wrkr adds a versioned additive `control_path_graph` contract with:

- `version = "1"`
- deterministic node and edge identifiers
- path-scoped nodes and edges keyed by stable `path_id`
- explicit unknown identity or credential nodes when evidence is incomplete instead of silently dropping the path
- graph summary counts by node kind and edge kind for report/evidence consumers

Wrkr also adds additive `credential_provenance` objects with:

- `type`
- `subject`
- `scope`
- `confidence`
- `evidence_basis`
- `risk_multiplier`

The authoritative provenance object is normalized once in the privilege-map build path and then reused by action paths, control backlog items, reports, and proof mapping.

Existing `credential_access` and `standing_privilege` booleans remain as compatibility projections and coarse summary signals.

## Consequences

- Saved state, report JSON, and evidence bundles now expose a single graph contract instead of forcing downstream consumers to reconstruct it.
- Control backlog items can reference graph node and edge identifiers without parsing workflow content.
- Governance ranking can treat unknown credential models as a higher-risk deterministic state without changing exit-code behavior.
- Public/customer-share report paths must redact graph identifiers and provenance subjects the same way they already redact path, repo, owner, and proof references.

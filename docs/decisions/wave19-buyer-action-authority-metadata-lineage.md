# ADR: Wave 19 Buyer Action Authority, Metadata, and Lineage

Date: 2026-05-10
Status: accepted

## Context

Wave 2 of buyer action registry hardening needs Wrkr to explain not just that a govern-first path exists, but why it exists, which credential posture it really has, which local config introduced it, and how a buyer can follow the static chain from repo and workflow to proof gaps. Before this change, credential posture lived mostly in compatibility provenance fields, purpose/version/config data was not normalized across action-path surfaces, and lineage had to be reconstructed from raw graph nodes.

## Decision

1. Add a normalized `credential_authority` structure alongside compatibility `credential_provenance` so Wrkr can separate credential presence, workflow reference, path usability, access type, standing/JIT posture, rotation evidence status, and source.
2. Normalize additive purpose and version/config metadata (`purpose`, `purpose_source`, `purpose_confidence`, `version`, `version_source`, `config_fingerprint`, `config_source`) across supported workflow, MCP, and agent-config surfaces.
3. Extend govern-first `action_paths`, Agent Action BOM items, and control-path graph nodes with that normalized metadata rather than re-deriving it in report renderers.
4. Add deterministic `action_lineage.segments[]` so buyer-facing artifacts can join repo, workflow, agent, action, credential, target, owner, approval, and proof gaps without parsing opaque graph internals.
5. Preserve v1 compatibility by keeping existing fields additive and leaving legacy `credential_provenance` / `credentials[]` surfaces intact.

## Rationale

- Buyers need an authority model that distinguishes “referenced” from “usable” credentials.
- Purpose and version/config metadata make action-registry output explainable without runtime inference.
- Explicit lineage reduces report ambiguity and makes proof or approval gaps visible instead of implied.
- Additive contracts keep existing automation stable while enabling richer buyer-facing output.

## Consequences

- Inventory, risk, control-graph, and report JSON now expose additive authority, metadata, and lineage fields.
- Public/customer-redacted report output must sanitize the new config-source, credential-reason, and lineage-label surfaces consistently.
- Govern-first remediation and backlog quality checks can reason from normalized authority instead of only from legacy provenance rollups.

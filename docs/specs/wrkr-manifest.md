# wrkr-manifest.yaml Open Specification

`wrkr-manifest.yaml` is an open, file-based interoperability contract for real AI tool approval posture.

## Scope

The specification defines how producers and consumers exchange approval posture without requiring Wrkr runtime linkage.

- Deterministic representation of discovered real-tool identities and trust status.
- Policy-oriented exchange shape for approved, blocked, and review-pending tool declarations.
- Backward-compatible schema evolution rules.

## Versioning model

Manifest specification versioning is independent from Wrkr binary releases.

- Spec field: `spec_version`
- Current spec version: `wrkr-manifest/v1`
- Wrkr-generated identity profile still emits `version: v1` and remains valid under the schema.

A Wrkr release can support multiple spec versions. Consumers must fail closed on unknown required fields.

## Canonical policy fields

Policy-oriented producers and consumers should support these canonical fields:

- `approved_tools`
- `blocked_tools`
- `review_pending_tools`
- `policy_constraints`
- `permission_scopes`
- `approver_metadata`

These fields are modeled in `schemas/v1/manifest/manifest.schema.json` as the policy profile.

## Wrkr identity profile

`wrkr manifest generate` emits identity-centric records with deterministic lifecycle posture:

- identity status starts at `under_review`
- approval state starts at `missing`
- trust deficit remains until explicit lifecycle approval
- only real tool-bearing identities are emitted; finding-only posture/bookkeeping signals such as `secret_presence`, `source_discovery`, `policy_*`, and `parse_error` stay outside the manifest identity profile

Primary fields include `agent_id`, `tool_id`, `tool_type`, `org`, `repo`, `location`, `status`, `approval_status`, `first_seen`, `last_seen`, `present`, `data_class`, `endpoint_class`, `autonomy_level`, and `risk_score`.

## Interoperability guidance

For producers:

- Emit YAML that validates against `schemas/v1/manifest/manifest.schema.json`.
- Use deterministic ordering for arrays and stable key formatting.
- Do not embed secrets or credentials.

For consumers:

- Validate schema before use.
- Treat unknown required fields or schema violations as blocking errors.
- Preserve unrecognized optional fields when round-tripping.

## Contribution model

When adding tool types, policy fields, or permission scopes:

1. Update `schemas/v1/manifest/manifest.schema.json`.
2. Update this spec and `docs/commands/manifest.md`.
3. Add compatibility coverage in `internal/e2e/manifest/` and contract checks.
4. Keep existing valid manifests backward compatible unless introducing a new `spec_version`.

## Adoption metric tracking guidance

Track public adoption with reproducible counters:

- number of public repositories containing `wrkr-manifest.yaml`
- percentage of manifests validating cleanly against the latest schema
- profile split: identity profile vs policy profile

Do not collect or transmit manifest content by default; use local or customer-approved telemetry only.

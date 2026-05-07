# ADR: Wave 17 Customer-Redacted Share Profile

Date: 2026-05-07
Status: accepted

## Context

Wave 4 requires a first-class external sharing mode for customer-ready report, BOM, and report evidence artifacts. The existing public share profile already redacted many raw identifiers, but it did not expose a dedicated contract for customer-safe sharing, redaction versioning, or policy summary metadata.

## Decision

1. Add `customer-redacted` as an explicit share profile.
2. Reuse deterministic pseudonymization so repo names, owners, local paths, proof refs, graph refs, and credential subjects stay joinable inside one artifact set.
3. Emit additive share-profile metadata describing whether redaction was applied, which redaction version generated the artifact, and the high-level redaction policy summary.
4. Preserve buyer-facing risk meaning, counts, action classes, capability labels, and confidence language while redacting sensitive identifiers.

## Rationale

- A named customer-share profile is easier to document, test, and audit than implicit “public-ish” behavior.
- Deterministic pseudonyms preserve cross-artifact joins without leaking raw customer identifiers.
- Policy metadata lets operators prove what was redacted and which contract version produced the artifact.

## Consequences

- `wrkr report --share-profile customer-redacted` produces stable customer-safe markdown, JSON, and report evidence artifacts.
- BOM and report JSON now include additive share-profile metadata fields.
- Existing internal and public flows remain available; the new profile is an explicit opt-in for customer sharing.

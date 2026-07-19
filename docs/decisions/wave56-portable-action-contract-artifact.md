# ADR: Portable Action Contract artifact envelope

Date: 2026-07-18
Status: accepted

## Decision

`wrkr export action-contracts` creates standalone artifact-schema v1 envelopes
from complete local scan state. The exporter uses `github.com/Clyra-AI/proof`
RFC 8785 JCS canonicalization for the envelope content digest and derives the
stable artifact ID from that digest. It includes normalized v3 contract content,
durable scan/composition/creation references, producer/schema metadata, and the
share-profile variant. Volatile presentation time is deliberately absent from
the canonical projection.

Exports are deterministic by contract ID. File output uses stable filenames,
atomic writes, collision refusal, and symlink-directory rejection. Version 2
contracts remain readable but are not silently promoted for export. Non-internal
profiles first use the existing recursive report redaction projection, then get
a distinct valid artifact identity.

## Boundary

The artifact is a portable proposal. It does not call Gait or Axym, grant
authority, activate a contract, approve an action, execute an effect, or mutate
saved scan state.

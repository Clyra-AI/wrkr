# ADR: Wave 1 Source Privacy Governance

Date: 2026-04-24
Status: accepted

## Context

Hosted `--repo` and `--org` scans need temporary filesystem access to selected GitHub blobs so existing deterministic detectors can run without network-specific code paths. The prior hosted materialization model kept those files under the scan-state directory after a scan and serialized that local path in some public artifacts.

That created avoidable customer privacy risk: private source could remain on disk, be confused with evidence, or leak through shareable outputs as `.wrkr/materialized-sources` paths.

## Decision

1. Default hosted source retention to `ephemeral`.
2. Add explicit retention modes: `retain_for_resume` and `retain`.
3. Keep hosted detector execution rooted at an internal-only `RepoManifest.ScanRoot`.
4. Serialize hosted repository identity through logical `RepoManifest.Location` values such as `github://org/repo`.
5. Fetch only detector-owned governance/config/policy/declaration paths by default; generic source-code extensions require `--mode deep` or `--allow-source-materialization`.
6. Emit a `source_privacy` contract in scan state, scan JSON, status, reports, evidence metadata, and SARIF where applicable.
7. Sanitize shareable artifact paths so materialized source roots are redacted if a detector or future output path accidentally carries one forward.

## Rationale

- Source materialization is an implementation detail of hosted acquisition, not a customer evidence artifact.
- Logical hosted locations preserve stable source identity without exposing local filesystem paths.
- Default sparse fetching reduces private source copied to disk while keeping high-signal governance coverage.
- Explicit source privacy metadata gives operators and auditors a machine-readable answer about retention, raw-source inclusion, serialized location mode, and cleanup status.

## Consequences

- Consumers that relied on hosted `source_manifest.repos[].location` as a local path must switch to logical source references or explicitly use internal/debug retention workflows.
- Successful hosted scans remove managed materialized source by default, so completed-run resume requires explicit `--source-retention retain`.
- Deep or generic source materialization is still available, but it is visible as an explicit operator opt-in and documented as privacy-sensitive.

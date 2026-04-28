# ADR: Wave 2 Source Boundary Safe Reads

Date: 2026-04-28
Status: accepted

## Context

Wrkr's detector walk helpers already filtered generated paths deterministically, but several walk- and glob-based detectors still opened the returned repo-relative files directly. A repo-local symlink could therefore point outside the selected scan root and be parsed as if it were in-repo evidence.

That breaks two non-negotiable Wrkr contracts:

- zero data exfiltration by default
- proof and findings must stay bounded to the selected source root

The release-boundary hardening plan requires the detector boundary, not downstream risk or proof code, to own this fail-closed behavior.

## Decision

1. Add a shared walked-file contract that preserves deterministic file ordering while resolving each candidate against the selected root before detector parsing.
2. Represent out-of-root, dangling, permission-denied, and directory-as-file cases as deterministic `parse_error.kind` values, with `unsafe_path` for root-escaping symlinks.
3. Migrate walk- and glob-driven detectors on high-risk AI-tooling surfaces to `detect.ReadFileWithinRoot` or `detect.OpenFileWithinRoot` instead of direct filesystem reads.
4. Add hygiene coverage that fails if those detector files regress to direct `os.ReadFile` or `os.Open` calls.
5. Keep external resolved paths out of public findings; only the logical repo-relative location and stable parse metadata are emitted.

## Rationale

- A central safe-walk contract makes source-boundary review obvious and repeatable across detectors.
- Detector-local parse errors are safer than downstream compensating logic because the unsafe file is never treated as valid evidence.
- Stable repo-relative diagnostics preserve deterministic output and avoid leaking host-specific absolute paths.

## Consequences

- Unsafe symlinked detector inputs now surface as deterministic parse errors instead of low-risk or successful findings.
- New detector work that walks or globs repo files must use the root-bound helper path to satisfy hygiene tests.
- Existing fixtures or baselines that depended on unsafe outside-root reads will drift in a security-correct direction.

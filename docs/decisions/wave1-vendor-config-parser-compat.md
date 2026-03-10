# ADR: Vendor Config Parser Compatibility

Date: 2026-03-10

## Status

Accepted

## Context

Wrkr's shared strict parse helpers rejected additive upstream fields in supported Claude and Codex config files. That behavior preserved strictness, but it also broke the zero-integration local-machine activation path when vendor-owned configs evolved without changing the fields Wrkr actually reads.

Wrkr still needs strict parsing for Wrkr-owned contracts such as policy files, manifests, baselines, and proof/evidence artifacts.

## Decision

- Keep the existing strict helpers as the default for Wrkr-owned contracts.
- Add explicit allow-unknown helper variants for detector adapters that read vendor-owned config files.
- Use those additive-tolerant helpers only in the Claude and Codex detectors in this wave.
- Continue treating malformed JSON/TOML/YAML as deterministic `parse_error` findings.

## Consequences

- Supported additive vendor fields no longer break local-machine discovery for Claude and Codex.
- Wrkr-owned contract parsers remain fail-closed and schema-strict.
- Future vendor adapters can opt into the same model deliberately instead of weakening the global parser boundary.

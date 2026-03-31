# wrkr campaign aggregate

## Synopsis

```bash
wrkr campaign aggregate --input-glob '<glob>' [--output <path>] [--md] [--md-path <path>] [--template public] [--segment-metadata <path>] [--json]
```

## Purpose

Aggregate multiple `wrkr scan --json` artifacts into one deterministic campaign summary for report headline metrics and methodology metadata.
Campaign aggregation accepts complete scan artifacts only. Artifacts with `partial_result=true`, `source_degraded=true`, or non-empty `source_errors` are rejected as `invalid_input` instead of being summarized.
Artifacts must also carry the expected scan contract fields (`target`, `source_manifest`, `inventory`, `privilege_budget`, and `findings`); generic `status=ok` JSON from other commands is rejected as `invalid_input`.

## Flags

- `--input-glob` (required): file glob for scan JSON artifacts.
- `--output`: optional file path to write campaign artifact JSON.
- `--md`: write deterministic public markdown artifact.
- `--md-path`: markdown output path (default `wrkr-campaign-public.md`).
- `--template`: campaign markdown template (`public`).
- `--segment-metadata`: optional schema-versioned YAML map for org `industry` and `size_band`.
- `--json`: emit machine-readable envelope.

## Example

```bash
wrkr campaign aggregate --input-glob './.tmp/campaign/*.json' --output ./.tmp/campaign-summary.json --json
wrkr campaign aggregate --input-glob './.tmp/campaign/*.json' --md --md-path ./.tmp/campaign-public.md --template public --json
wrkr campaign aggregate --input-glob './.tmp/campaign/*.json' --segment-metadata ./docs/examples/campaign-segments.v1.yaml --json
```

## Expected JSON keys

- `status`
- `campaign.schema_version`
- `campaign.generated_at`
- `campaign.methodology`
- `campaign.metrics`
  - includes approval-gap aggregates: `approved_tools`, `unapproved_tools`, `unknown_tools`, and ratio fields
  - includes additive visibility aggregates: `unknown_to_security_tools`, `unknown_to_security_agents`, `unknown_to_security_write_capable_agents`, `security_visibility_reference`
- `campaign.segments`
- `campaign.scans`
- optional `md_path` when markdown is generated

## Exit codes

- `0`: success
- `6`: invalid input (missing/invalid glob, malformed artifact, or incomplete/degraded scan artifact)
- `1`: runtime failure (read/write failure)

## Deterministic guarantees

- Input file paths are sorted before aggregation.
- Partial or degraded scan artifacts fail closed before aggregation.
- Non-scan JSON envelopes fail closed before aggregation.
- Detector inventory and per-scan outputs are sorted and stable for fixed artifacts.
- Production-write totals are emitted only when all contributing scans have configured production-target policy.
- When production targets are not configured, public markdown stays at `write-capable` wording and reports production-target status rather than a production-write count.
- Unknown-to-security campaign counts are emitted only when contributing scans carry a usable `security_visibility_reference`; otherwise Wrkr sets the reference to `unavailable` and suppresses those counts.
- Segment outputs are deterministic, with explicit `unknown` buckets when metadata is absent.

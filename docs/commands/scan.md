# wrkr scan

## Synopsis

```bash
wrkr scan [--repo <owner/repo> | --org <org> | --path <dir>] [--timeout <duration>] [--diff] [--enrich] [--baseline <path>] [--config <path>] [--state <path>] [--policy <path>] [--approved-tools <path>] [--production-targets <path>] [--production-targets-strict] [--profile baseline|standard|strict] [--github-api <url>] [--github-token <token>] [--report-md] [--report-md-path <path>] [--report-template exec|operator|audit|public] [--report-share-profile internal|public] [--report-top <n>] [--sarif] [--sarif-path <path>] [--json] [--quiet] [--explain]
```

Exactly one target source is required: `--repo`, `--org`, or `--path`.

Acquisition behavior is fail-closed by target:

- `--path` runs fully local/offline.
- `--repo` and `--org` require real GitHub acquisition via `--github-api` or `WRKR_GITHUB_API_BASE`.
- `--repo` and `--org` materialize repository contents into a deterministic local workspace under the scan state directory before detectors run.
- When GitHub acquisition is unavailable, `scan` returns `dependency_missing` with exit code `7` (no synthetic repos are emitted).

## Flags

- `--json`
- `--explain`
- `--quiet`
- `--repo`
- `--org`
- `--path`
- `--timeout`
- `--diff`
- `--enrich`
- `--baseline`
- `--config`
- `--state`
- `--policy`
- `--approved-tools`
- `--production-targets`
- `--production-targets-strict`
- `--profile`
- `--github-api`
- `--github-token`
- `--report-md`
- `--report-md-path`
- `--report-template`
- `--report-share-profile`
- `--report-top`
- `--sarif`
- `--sarif-path`

## Example

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --report-md --report-md-path ./.tmp/scan-summary.md --report-template operator --json
```

```bash
wrkr scan --org acme --github-api https://api.github.com --json
```

Expected JSON keys include `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `attack_paths`, `top_attack_paths`, `inventory`, `privilege_budget`, `agent_privilege_map`, `repo_exposure_summaries`, `profile`, `posture_score`, and optional `report` when summary output is requested.
`detector_errors` is included when non-fatal detector failures occur and partial scan results are preserved.
`partial_result`, `source_errors`, and `source_degraded` are included when source acquisition/materialization has non-fatal failures.
`sarif.path` is included when `--sarif` output is requested.
`inventory.methodology` emits machine-readable scan metadata (`wrkr_version`, timing, repo/file counts, detector inventory).
`inventory.tools[*]` includes deterministic `approval_classification` (`approved|unapproved|unknown`), and `inventory.approval_summary` emits aggregate approval-gap ratios for campaign/report workflows.
`inventory.tools[*]` also emits report-ready `tool_category` and deterministic `confidence_score` (`0.00-1.00`) for inventory breakdown tables.
`inventory.tools[*]` emits normalized `permission_surface`, `permission_tier`, `risk_tier`, `adoption_pattern`, and per-tool `regulatory_mapping` statuses.
`inventory.adoption_summary` and `inventory.regulatory_summary` provide deterministic rollups for report section tables.
`--approved-tools <path>` accepts a schema-validated YAML policy (`schemas/v1/policy/approved-tools.schema.json`) for explicit approved-list matching (`tool_ids`, `agent_ids`, `tool_types`, `orgs`, `repos` via exact/prefix sets).
Invalid `--approved-tools` policy files fail closed with `invalid_input` (exit `6`).
For `--repo` and `--org` scans, `source_manifest.repos[*].source` is `github_repo_materialized`, and `source_manifest.repos[*].location` points to the deterministic materialized local root used for detector execution.
Prompt-channel findings use stable reason codes and evidence hashes only (`pattern_family`, `evidence_snippet_hash`, `location_class`, `confidence_class`) and do not emit raw secret values.
When `--enrich` is enabled, MCP findings include enrich provenance and quality fields: `source`, `as_of`, `package`, `version`, `advisory_count`, `registry_status`, `enrich_quality` (`ok|partial|stale|unavailable`), `advisory_schema`, `registry_schema`, and `enrich_errors`.
When production target policy loading is non-fatal (`--production-targets` without `--production-targets-strict`), output may include `policy_warnings`.

Timeout/cancellation contract:

- `--timeout <duration>` bounds end-to-end scan runtime (`0` disables timeout).
- When timeout is exceeded, JSON error code is `scan_timeout` with exit code `1`.
- When canceled by signal or parent context, JSON error code is `scan_canceled` with exit code `1`.

Retry/degradation contract:

- GitHub connector retries retryable failures with bounded jittered backoff.
- HTTP `429` honors `Retry-After` and `X-RateLimit-Reset` wait semantics before retry.
- Repeated transient failures trigger connector cooldown degradation; scan surfaces this in partial-result output (`source_degraded=true` when applicable).

SARIF contract:

- `--sarif` emits a SARIF `2.1.0` report from scan findings.
- `--sarif-path` selects output path (default `wrkr.sarif`).
- Native `scan --json` payloads and proof outputs remain unchanged; SARIF is additive.

Approved-tools policy example: [`docs/examples/approved-tools.v1.yaml`](../examples/approved-tools.v1.yaml).

Production target policy files are YAML and schema-validated (`schemas/v1/policy/production-targets.schema.json`), with exact/prefix matching only. Example: [`docs/examples/production-targets.v1.yaml`](../examples/production-targets.v1.yaml).

Production write rule:

```text
production_write = has_any(write_permissions) AND matches_any_production_target
```

Every discovered entity now emits `discovery_method: static` in both `findings` and `inventory.tools` for deterministic v1 schema compatibility.

Emerging discovery surfaces are static-only in default deterministic mode:

- WebMCP detection uses repository HTML/JS/route files only.
- A2A detection uses repo-hosted agent-card JSON files only.
- MCP gateway posture is derived from local config files only.
- No live endpoint probing is performed by default.

Custom extension detectors are loaded from `.wrkr/detectors/extensions.json` when present in scanned repositories. See [`docs/extensions/detectors.md`](../extensions/detectors.md).

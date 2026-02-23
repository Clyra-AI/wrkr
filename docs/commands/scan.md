# wrkr scan

## Synopsis

```bash
wrkr scan [--repo <owner/repo> | --org <org> | --path <dir>] [--diff] [--enrich] [--baseline <path>] [--config <path>] [--state <path>] [--policy <path>] [--production-targets <path>] [--production-targets-strict] [--profile baseline|standard|strict] [--github-api <url>] [--github-token <token>] [--report-md] [--report-md-path <path>] [--report-template exec|operator|audit|public] [--report-share-profile internal|public] [--report-top <n>] [--json] [--quiet] [--explain]
```

Exactly one target source is required: `--repo`, `--org`, or `--path`.

Acquisition behavior is fail-closed by target:

- `--path` runs fully local/offline.
- `--repo` and `--org` require real GitHub acquisition via `--github-api` or `WRKR_GITHUB_API_BASE`.
- When GitHub acquisition is unavailable, `scan` returns `dependency_missing` with exit code `7` (no synthetic repos are emitted).

## Flags

- `--json`
- `--explain`
- `--quiet`
- `--repo`
- `--org`
- `--path`
- `--diff`
- `--enrich`
- `--baseline`
- `--config`
- `--state`
- `--policy`
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

## Example

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --report-md --report-md-path ./.tmp/scan-summary.md --report-template operator --json
```

```bash
wrkr scan --org acme --github-api https://api.github.com --json
```

Expected JSON keys include `status`, `target`, `findings`, `ranked_findings`, `inventory`, `privilege_budget`, `agent_privilege_map`, `repo_exposure_summaries`, `profile`, `posture_score`, and optional `report` when summary output is requested.
When production target policy loading is non-fatal (`--production-targets` without `--production-targets-strict`), output may include `policy_warnings`.

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

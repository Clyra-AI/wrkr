# wrkr scan

## Synopsis

```bash
wrkr scan [--repo <owner/repo> | --org <org> | --github-org <org> | --path <dir> | --my-setup | --target <mode>:<value> ...] [--timeout <duration>] [--diff] [--enrich] [--baseline <path>] [--config <path>] [--state <path>] [--policy <path>] [--approved-tools <path>] [--production-targets <path>] [--production-targets-strict] [--profile baseline|standard|strict|assessment] [--github-api <url>] [--github-token <token>] [--report-md] [--report-md-path <path>] [--report-template exec|operator|audit|public] [--report-share-profile internal|public] [--report-top <n>] [--sarif] [--sarif-path <path>] [--json] [--json-path <path>] [--resume] [--quiet] [--explain]
```

Use either one legacy target source (`--repo`, `--org`, `--github-org`, `--path`, or `--my-setup`) or one or more repeatable `--target <mode>:<value>` flags.
Legacy target flags remain supported as one-entry shims and cannot be combined with `--target` in the same invocation.
Supported `--target` modes are `repo`, `org`, `path`, and `my_setup`.
For `my_setup`, use `--target my_setup:local-machine`.

Acquisition behavior is fail-closed by target:

- `--path` runs fully local/offline.
- `--path` supports two deterministic interpretations:
  - `repo_root`: scan the selected directory itself as one repo when it carries repo-root signals such as `.git`, `go.mod`, `AGENTS.md`, `.codex/`, `.github/`, or other supported tool/config markers.
  - `repo_set`: scan the immediate non-hidden child repos when the selected directory is a bundle root without repo-root signals, such as `./scenarios/wrkr/scan-mixed-org/repos`.
- `repo_set` child repos are enumerated in deterministic lexical order by repo name.
- `--my-setup` runs fully local/offline against the local machine setup rooted at the current user home directory.
  It inspects supported user-home tool configs, selected environment key names, and common workspace roots for local agent project markers without emitting raw secret values.
- `--repo` and `--org` require real GitHub acquisition via `--github-api` or `WRKR_GITHUB_API_BASE`.
- Hosted GitHub token resolution order is: `--github-token`, config `auth.scan.token`, `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`.
- `--github-org` is an additive alias for `--org`.
- Explicit multi-target scans set `target.mode=multi` and add deterministic `targets[]` arrays to the top-level scan payload, saved state snapshot, and `source_manifest`.
- `--repo` and `--org` materialize repository contents into a deterministic local workspace under the scan state directory before detectors run.
- Materialized workspace root (`materialized-sources/`) is ownership-gated:
  - Wrkr-managed roots include marker `.wrkr-materialized-sources-managed` with state-bound provenance, not just a static marker body.
  - Non-empty roots without a valid marker are blocked (no recursive cleanup).
  - Marker must be a regular file with valid state-bound marker payload; symlink/directory/legacy-static/invalid marker content is blocked.
  - On `--resume`, previously materialized repo directories and checkpoint files must also be regular in-root artifacts; symlink-swapped repo roots or checkpoint files are blocked.
  - Ownership violations return `unsafe_operation_blocked` (exit `8`).
- When GitHub acquisition is unavailable, `scan` returns `dependency_missing` with exit code `7` (no synthetic repos are emitted).
- `--state` defaults to `.wrkr/last-scan.json`, with manifest/proof artifacts written alongside it.
- Scan-owned managed artifacts are published transactionally: state snapshot, lifecycle chain, proof chain/attestation, manifest, and any requested `--json-path`, `--report-md-path`, or `--sarif-path` sidecars commit as one generation.
- Invalid scan-owned artifact paths such as `--report-md-path` and `--sarif-path` are preflight-validated before any managed artifact mutation.
- `--json-path`, `--report-md-path`, and `--sarif-path` must stay unique from one another and from Wrkr-managed artifacts derived from `--state`; collisions fail closed with `invalid_input` (exit `6`) before any scan-managed artifact is written.
- Late write failures after preflight still fail closed and roll managed artifacts back to the previous committed generation instead of leaving mixed state/proof/manifest outputs behind.
- For `--path` scans, detector file reads stay bounded to the selected repo root. Root-escaping symlinked config, env, workflow, and MCP files are rejected with deterministic `parse_error.kind=unsafe_path` diagnostics instead of being read.

## Flags

- `--json`
- `--json-path`
- `--resume`
- `--explain`
- `--quiet`
- `--repo`
- `--org`
- `--github-org`
- `--path`
- `--my-setup`
- `--target`
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

## Developer personal-hygiene example

```bash
wrkr scan --my-setup --json
```

This local/offline mode inventories supported user-home tool configs, selected environment key presence, and local agent project markers. Use it when a developer wants to answer "what AI tooling is already on this machine?" before widening to the org workflow.
Environment-key presence and source bookkeeping stay in findings/risk output only; they do not become lifecycle identities, manifest identities, inventory agents, or regress tools.
For the current minimum-now launch posture, security/platform teams should start with the org example below; `--my-setup` remains the secondary local-machine path.

## Security-team org example

```bash
wrkr scan --github-org acme --github-api https://api.github.com --json --json-path ./.wrkr/scan.json
```

`--github-org` is the additive alias for `--org`. Use it when security or platform teams need the deterministic saved-state input for `wrkr report`, `wrkr evidence`, `wrkr mcp-list`, or `wrkr inventory --diff`.
Private repos and public API rate-limit avoidance usually require a GitHub token even when `--github-api` is set.
Wrkr's hosted connector currently calls these GitHub REST endpoints:

- `GET /orgs/{org}/repos?per_page=100&page=N`
- `GET /repos/{owner}/{repo}`
- `GET /repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1`
- `GET /repos/{owner}/{repo}/git/blobs/{sha}`

Fine-grained PAT guidance for the selected repositories:

- repository metadata: read-only
- repository contents: read-only

Opinionated large-org command path:

```bash
wrkr scan --github-org acme --github-api https://api.github.com --state ./.wrkr/last-scan.json --timeout 30m --json --json-path ./.wrkr/scan.json --report-md --report-md-path ./.wrkr/scan-summary.md --sarif --sarif-path ./.wrkr/wrkr.sarif
```

When `--json` is set for hosted org scans, Wrkr keeps stdout reserved for the final JSON payload and emits additive progress, retry, cooldown, resume, and completion lines to stderr only. `--quiet` suppresses those progress lines. `--json-path` writes the same final JSON payload to disk, and `--json --json-path` emits byte-identical payload bytes to both stdout and the selected file. Any requested `--json-path`, `--report-md-path`, or `--sarif-path` must be unique from one another and from scan-managed `--state` sibling artifacts.
`--resume` is supported only when every requested target is an org target. Wrkr stores internal checkpoint metadata under the scan-state directory in `org-checkpoints/` and reuses already-materialized repositories only when the checkpoint target set, per-org repo sets, and materialized-root path still match the current org-target scan.
Resume also revalidates that checkpoint files and reused repo roots are still trusted local artifacts under the managed materialized root; symlink-swapped entries fail closed as `unsafe_operation_blocked`.
Mixed target sets such as org-plus-path scans fail closed with `invalid_input` when `--resume` is requested.
If a run is interrupted after some repositories are checkpointed, rerun the same target with `--resume` and keep the same `--state` path. If `partial_result`, `source_errors`, or `source_degraded` is present, treat the scan as incomplete and rerun after the blocking condition is resolved.

Mixed target example:

```bash
wrkr scan --target org:acme --target path:./repos --github-api https://api.github.com --json
```

## Repo/path example

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile assessment --report-md --report-md-path ./.tmp/scan-summary.md --report-template operator --json
```

This is the canonical `repo_set` example for `--path`: the selected directory is a bundle of immediate child repos, so Wrkr preserves per-child repo manifests and deterministic ordering instead of collapsing the bundle into one repo.
Expected JSON keys include `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `attack_paths`, `top_attack_paths`, additive `action_paths`, additive `action_path_to_control_first`, `inventory`, `privilege_budget`, `agent_privilege_map`, `repo_exposure_summaries`, `profile`, `posture_score`, `compliance_summary`, additive `activation`, and optional `report` when summary output is requested.
Explicit multi-target runs also emit additive `targets[]` arrays at the top level and inside `source_manifest`, and saved state snapshots preserve the same additive `targets[]` contract.
For local-machine scans, `target.mode` is `my_setup`.
When `target.mode=my_setup`, `activation.items` projects concrete local tool, MCP, secret, and parse-error signals first without mutating the raw `top_findings` ranking. Policy-only items remain available in `ranked_findings` / `top_findings`.
When `target.mode=org`, `target.mode=path`, or `target.mode=multi`, `activation.items` projects govern-first candidate paths from the saved privilege map and adds `item_class` values such as `production_target_backed`, `unknown_to_security_write_path`, `approval_gap_path`, and `govern_first_candidate`.
`action_paths[*]` combines path identity, write capability, approval gap, security visibility, credential/deployment posture, delivery-chain metadata (`pull_request_write`, `merge_execute`, `deploy_write`, `delivery_chain_status`), additive workflow trigger posture (`workflow_trigger_class` such as `scheduled`, `workflow_dispatch`, or `deploy_pipeline`), production-target truth (`production_target_status`, `production_write`), additive execution-identity fields (`execution_identity`, `execution_identity_type`, `execution_identity_source`, `execution_identity_status`, `execution_identity_rationale`), attack-path score, and a stable `recommended_action` enum of `inventory|approval|proof|control`.
`action_paths[*].path_id` is an opaque deterministic identifier currently emitted in `apc-<hex>` form. Treat it as a stable join key only; do not parse business meaning from its string format.
`action_path_to_control_first` exposes one prioritized path plus deterministic summary counts (`total_paths`, `write_capable_paths`, `production_target_backed_paths`, `govern_first_paths`) without removing the legacy `attack_paths` surfaces.
`--profile assessment` narrows govern-first surfaces such as `action_paths`, `action_path_to_control_first`, activation, and report summaries for sample/test/vendor-style noise while leaving raw `findings`, proof output, and exit codes unchanged.
`warnings` is included when Wrkr can prove posture may be incomplete even though the scan succeeded, for example when known MCP-bearing declaration files failed to parse.
`detector_errors` is included when non-fatal detector failures occur and partial scan results are preserved.
`partial_result`, `source_errors`, and `source_degraded` are included when source acquisition/materialization has non-fatal failures.
When filesystem permission or stat failures prevent full detector coverage, `detector_errors[*].code` stays explicit (`permission_denied`, `path_not_found`) and `--explain` calls out that scan completeness may be reduced.
Downstream `wrkr campaign aggregate` treats these completeness markers as fail-closed input signals and rejects such artifacts instead of producing a campaign summary from incomplete scans.
`sarif.path` is included when `--sarif` output is requested.
`compliance_summary.frameworks[*].controls[*]` emits deterministic framework/control rollups with `mapped_rule_ids`, `finding_count`, and proof-derived coverage status.
`inventory.methodology` emits machine-readable scan metadata (`wrkr_version`, timing, repo/file counts, detector inventory).
`inventory.agents` is always present (possibly empty) and is deterministically sorted by org/framework/instance/location; agent entries may include additive `symbol`, `security_visibility_status`, and `location_range` when parser metadata is available.
Source coverage remains intentionally scoped:
- supported framework-native parsing covers LangChain, CrewAI, OpenAI Agents, AutoGen, LlamaIndex, and MCP-client patterns
- conservative custom-agent scaffolds come from `.wrkr/agents/custom-agent.{yaml,yml,json,toml}`
- explicit bespoke custom-source coverage uses `wrkr:custom-agent` annotations in Python or JS/TS source files
`ranked_findings[*]` and `attack_paths[*]` now include deterministic agent-aware amplification and edge rationale when agent declarations expose deployment, delegation, dynamic discovery, or bound tool/data/auth/deploy chains.
`inventory.tools[*]` includes deterministic `approval_classification` (`approved|unapproved|unknown`), and `inventory.approval_summary` emits aggregate approval-gap ratios for campaign/report workflows.
`inventory.tools[*]`, `inventory.agents[*]`, and `agent_privilege_map[*]` also emit additive `security_visibility_status` (`approved|known_unapproved|unknown_to_security`) without overloading `approval_classification`.
Workflow-backed findings may emit additive first-class workflow capabilities such as `repo.write`, `pull_request.write`, `merge.execute`, `deploy.write`, `db.write`, and `iac.write`. Each capability remains static-only and is paired with `workflow_capability.*` evidence showing which workflow permission or step pattern produced the claim.
`inventory.tools[*].locations[*]` preserves the legacy `owner` string and adds `owner_source` plus `ownership_status` so CODEOWNERS-backed ownership stays distinguishable from deterministic fallback.
`agent_privilege_map[*]` and `action_paths[*]` add `operational_owner`, additive ownership provenance, and `approval_gap_reasons` so governance-first paths can show who should act next and why the approval model is incomplete.
`inventory.security_visibility_summary` emits additive reference-basis and count fields including `unknown_to_security_write_capable_agents`.
`inventory.local_governance` is emitted for `--my-setup` scans so workstation tool/config discoveries can be compared against an `--approved-tools` baseline without turning secret-presence signals into lifecycle identities.
`inventory.non_human_identities[*]` is emitted when static repo evidence shows durable GitHub App, bot-user, or service-account execution identities behind AI-enabled delivery paths.
When a downstream workflow does not have a usable `reference_basis`, Wrkr suppresses `unknown_to_security` claims rather than fabricating them.
`inventory.tools[*]` also emits report-ready `tool_category` and deterministic `confidence_score` (`0.00-1.00`) for inventory breakdown tables.
`inventory.tools[*]` emits normalized `permission_surface`, `permission_tier`, `risk_tier`, `adoption_pattern`, and per-tool `regulatory_mapping` statuses.
`inventory.adoption_summary` and `inventory.regulatory_summary` provide deterministic rollups for report section tables.
`agent_privilege_map[*]` is instance-scoped and includes additive `agent_instance_id`, `symbol`, `location`, and `location_range` fields for multi-agent same-file repos.
`--approved-tools <path>` accepts a schema-validated YAML policy (`schemas/v1/policy/approved-tools.schema.json`) for explicit approved-list matching (`tool_ids`, `agent_ids`, `tool_types`, `orgs`, `repos` via exact/prefix sets).
Invalid `--approved-tools` policy files fail closed with `invalid_input` (exit `6`).
For `--my-setup`, omitting `--approved-tools` keeps `inventory.local_governance.reference_basis=unavailable` instead of fabricating sanctioned or unsanctioned local claims.
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
- HTTP `429` and recognizable rate-limit `403` responses retry deterministically.
- When GitHub supplies `Retry-After` or `X-RateLimit-Reset`, Wrkr uses that observed window before retrying.
- Exhausted hosted throttling keeps exit code `1` but emits JSON error code `rate_limited` so automation can distinguish retryable wait conditions from generic runtime failure.
- Repeated transient failures trigger connector cooldown degradation; scan surfaces this in partial-result output (`source_degraded=true` when applicable).
- In `--json` org mode, retry/cooldown/resume/completion operator progress is emitted to stderr only; stdout remains reserved for the final JSON payload.

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

Safe claim rule:

- `write_capable` is always available from the privilege budget and `agent_privilege_map`.
- `production_write` is safe to claim only when `--production-targets` is configured and valid.
- When production targets are missing or invalid, public/report wording must stay at `write_capable` and only expose production-target status, not a production-write count.

Every discovered entity now emits `discovery_method: static` in both `findings` and `inventory.tools` for deterministic v1 schema compatibility.
Saved lifecycle-bearing identities written beside scan state are intentionally narrower: real tool, agent, CI, skill, and MCP surfaces only. Posture/bookkeeping findings such as `secret_presence`, `source_discovery`, `policy_*`, and `parse_error` remain in findings/risk surfaces only.

`--explain` also emits short compliance rollup lines derived from the same machine-readable `compliance_summary` contract.

Emerging discovery surfaces are static-only in default deterministic mode:

- WebMCP detection uses repository HTML/JS/route files only.
- A2A detection uses repo-hosted agent-card JSON files only.
- MCP gateway posture is derived from local config files only.
- Non-human execution identities are derived from static workflow/config signals only.
- No live endpoint probing is performed by default.

Wrkr stays in the See boundary: it inventories and scores tools plus agents from files and CI declarations, but it does not claim runtime observation, enforce runtime side effects, or execute agent workflows.
Wrkr also does not assess package or MCP-server vulnerabilities in this path; use dedicated scanners such as Snyk for that class of assessment.
Gait is optional interoperability for control-layer decisions, not a prerequisite for `scan`.

Custom extension detectors are loaded from `.wrkr/detectors/extensions.json` when present in scanned repositories. Their findings remain on additive finding and risk surfaces only by default; they do not create authoritative inventory, lifecycle, regress, or action-path state unless a future explicit contract says so. See [`docs/extensions/detectors.md`](../extensions/detectors.md).
Canonical state and artifact lifecycle: [`docs/state_lifecycle.md`](../state_lifecycle.md).

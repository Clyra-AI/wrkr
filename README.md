# Wrkr — See What AI Is Doing in Your Codebase

[![Main](https://github.com/Clyra-AI/wrkr/actions/workflows/main.yml/badge.svg)](https://github.com/Clyra-AI/wrkr/actions/workflows/main.yml)
[![CodeQL](https://github.com/Clyra-AI/wrkr/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Clyra-AI/wrkr/actions/workflows/github-code-scanning/codeql)
[![Nightly](https://github.com/Clyra-AI/wrkr/actions/workflows/nightly.yml/badge.svg?event=schedule)](https://github.com/Clyra-AI/wrkr/actions/workflows/nightly.yml)

Most teams don't know what AI dev tools and agents are active across their repos, what permissions they have, or what changed since last week. Wrkr answers that in minutes. Start with a local `--path` scan for zero-integration first value, or scan a GitHub repo/org with explicit GitHub API configuration. Get ranked findings for tools and agents, then generate verifiable evidence bundles for audits. Read-only. No runtime integration required.

Wrkr can also scan the local machine setup directly with `wrkr scan --my-setup --json` to inventory user-level AI tool configs, MCP declarations, selected environment key presence, and local agent project markers without emitting raw secret values.

Wrkr is the **See** layer in the Clyra AI governance stack (See -> Prove -> Control -> Build). It discovers AI tooling and agent declarations across repositories and orgs, scores posture, tracks identity lifecycle, and emits signed proof artifacts ready for compliance review or downstream automation.

Docs: [clyra-ai.github.io/wrkr](https://clyra-ai.github.io/wrkr/) | Command contracts: [`docs/commands/`](docs/commands/) | Docs map: [`docs/map.md`](docs/map.md)

## When To Use Wrkr

- You need a deterministic inventory of AI development tools across repos or an org.
- You need ranked risk findings and posture scoring you can trend over time.
- You need file-based, verifiable evidence for audits or CI gates.
- You need stable JSON and exit-code contracts for automation pipelines.

## When Not To Use Wrkr

- You need runtime enforcement at tool execution boundaries (that is Gait, the Control layer).
- You need live network telemetry as your primary signal.
- You need probabilistic or LLM-based scoring in the scan or evidence path.

## Install

### Homebrew (recommended)

```bash
brew install Clyra-AI/tap/wrkr
```

### Go install (pinned, no extra tools)

```bash
WRKR_VERSION="v1.0.0"
go install github.com/Clyra-AI/wrkr/cmd/wrkr@"${WRKR_VERSION}"
```

### Go install (resolve latest tag with `curl` + POSIX tools)

```bash
WRKR_VERSION="$(curl -fsSL https://api.github.com/repos/Clyra-AI/wrkr/releases/latest | sed -nE 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
test -n "${WRKR_VERSION}"
go install github.com/Clyra-AI/wrkr/cmd/wrkr@"${WRKR_VERSION}"
```

No `gh` or `python3` dependency is required for these Go install paths. See [`docs/install/minimal-dependencies.md`](docs/install/minimal-dependencies.md) for the full install contract.

### Verify install path

```bash
command -v wrkr
wrkr --help
wrkr --json
```

Common locations:

- Apple Silicon Homebrew: `/opt/homebrew/bin/wrkr`
- Intel Homebrew: `/usr/local/bin/wrkr`
- Go install: `$(go env GOBIN)/wrkr` (or `$(go env GOPATH)/bin/wrkr` when `GOBIN` is unset)

## First 10 Minutes (Offline, No Setup)

Run the full scan-to-evidence workflow locally against the bundled scenarios:

```bash
# Build local CLI
make build

# Point at a local target
./.tmp/wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json

# Scan, rank, and score posture
./.tmp/wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --profile standard --json
./.tmp/wrkr report --top 5 --json
./.tmp/wrkr score --json

# Generate and verify evidence
./.tmp/wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --output ./.tmp/evidence --json
./.tmp/wrkr verify --chain --json

# Baseline and drift gate
./.tmp/wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json
./.tmp/wrkr regress run --baseline ./.wrkr/wrkr-regress-baseline.json --json
```

Expected JSON keys by command family:

- `scan`: `status`, `target`, `findings`, `ranked_findings`, `top_findings`, `attack_paths`, `top_attack_paths`, `inventory`, `privilege_budget`, `agent_privilege_map`, `repo_exposure_summaries`, `profile`, `posture_score` (optional: `detector_errors`, `partial_result`, `source_errors`, `source_degraded`, `policy_warnings`, `report`, `sarif`)
- `report`: `status`, `generated_at`, `top_findings`, `attack_paths`, `top_attack_paths`, `total_tools`, `tool_type_breakdown`, `compliance_gap_count`, `privilege_budget`, `summary` (optional: `md_path`, `pdf_path`)
- `score`: `score`, `grade`, `breakdown`, `weighted_breakdown`, `weights`, `trend_delta` (optional: `attack_paths`, `top_attack_paths`)
- `evidence`: `status`, `output_dir`, `frameworks`, `manifest_path`, `chain_path`, `framework_coverage`, `report_artifacts`
- `verify`: `chain.intact`, `chain.head_hash`
- `regress run`: deterministic drift status and reason fields

Prompt-channel findings are emitted deterministically with stable reason codes and evidence hashes (no raw secret extraction).  
When `scan --enrich` is enabled, MCP findings include enrich provenance and quality fields (`source`, `as_of`, `advisory_count`, `registry_status`, `enrich_quality`, schema IDs, and adapter error classes).
Evidence bundles include deterministic inventory artifacts at `inventory.json`, `inventory-snapshot.json`, and `inventory.yaml`.
Evidence framework IDs are normalized to upstream `Clyra-AI/proof` IDs in output (`eu-ai-act`, `pci-dss`); underscore aliases such as `eu_ai_act` and `pci_dss` are accepted as input.
Bundled scenarios can produce low initial `framework_coverage` values until approvals and controls are documented in the scanned state. Treat that as an evidence gap to close, not as a parser or product failure.
Canonical local path lifecycle for state, baseline, manifest, and proof chain: [`docs/state_lifecycle.md`](docs/state_lifecycle.md).

## What You Get

### Complete AI tool inventory

Structured detection for Claude, Cursor, Codex, Copilot, MCP, skills, and CI agent execution patterns. Local offline scanning via `--path`. Fail-closed behavior for hosted acquisition modes.

### Risk clarity, not noise

Ranked findings with repo-exposure rollups. Posture score and weighted breakdown you can trend over time to show governance improving.

### Identity lifecycle tracking

Deterministic identities in `wrkr:<tool_id>:<org>` format. Lifecycle transitions from `discovered` through `approved`, `active`, `deprecated`, and `revoked`.

### Audit-ready evidence

Signed proof records for `scan_finding`, `risk_assessment`, and lifecycle events. Agent-aware proof events now carry additive `agent_context` fields for portability, and evidence bundles keep compliance framework mappings verifiable offline. No calling home required. Low first-run `framework_coverage` means the current scan state lacks documented controls or approvals; rescan after remediation to measure improvement.

### CI drift gates

Regress baseline and run gates with stable exit behavior. Deterministic remediation planning via `wrkr fix` for top-risk findings.

### `wrkr fix` side-effect contract

wrkr fix computes a deterministic remediation plan from existing scan state and emits plan metadata; it does not mutate repository files unless --open-pr is set.
When --open-pr is set, wrkr fix writes deterministic artifacts under .wrkr/remediations/<fingerprint>/ and then creates or updates one remediation PR for the target repo.

## Scan Targets

Exactly one source target is required per `scan` invocation:

- `--repo <owner/repo>`
- `--org <org>`
- `--path <local-dir>`

Acquisition behavior:

- `--path`: local, offline, fully deterministic.
- `--repo` and `--org`: require `--github-api` or `WRKR_GITHUB_API_BASE`; unavailable acquisition fails closed with exit `7`.
- Invalid target combinations fail with exit `6`.
- `--timeout <duration>` bounds scan runtime. Timeout returns JSON error code `scan_timeout` (exit `1`); signal/parent cancellation returns `scan_canceled` (exit `1`).
- GitHub retry behavior is bounded and rate-limit aware (`Retry-After`/`X-RateLimit-Reset`); repeated transient failures enter cooldown degradation and are surfaced in partial-result output.

## Production Target Policy

Use `--production-targets <path>` to classify production-write exposure deterministically.

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --production-targets ./docs/examples/production-targets.v1.yaml --json
```

Policy contract:

- YAML file, schema-validated against `schemas/v1/policy/production-targets.schema.json`
- Exact/prefix matching only (no free-form regex)
- `production_write = has_any(write_permissions) AND matches_any_production_target`
- Optional strict mode: `--production-targets-strict` returns non-zero when the policy file is missing/invalid

Reference example: [`docs/examples/production-targets.v1.yaml`](docs/examples/production-targets.v1.yaml)

## Human-Readable Reports

Generate deterministic operator-ready markdown directly from scan:

```bash
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --report-md --report-md-path ./.tmp/scan-summary.md --report-template operator --json
```

Render report artifacts from saved state:

```bash
wrkr report --state ./.tmp/state.json --md --md-path ./.tmp/wrkr-report.md --explain
```

## Integration (One PR)

```bash
wrkr init --non-interactive --path ./scenarios/wrkr/scan-mixed-org/repos --json
wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --state ./.tmp/state.json --json
wrkr report --top 5 --json
wrkr evidence --frameworks eu-ai-act,soc2 --state ./.tmp/state.json --output ./.tmp/evidence --json
wrkr verify --chain --state ./.tmp/state.json --json
wrkr regress init --baseline ./.tmp/state.json --output ./.tmp/wrkr-regress-baseline.json --json
wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --state ./.tmp/state.json --json
```

Gate semantics:

- Exit `0`: pass
- Exit `5`: drift/regression gate fail
- Any other non-zero: contract or runtime failure; block merge

Reference guides: [`docs/adopt_in_one_pr.md`](docs/adopt_in_one_pr.md) | [`docs/integration_checklist.md`](docs/integration_checklist.md)

## PR Distribution Mode

Wrkr Action `mode=pr` can post deterministic, idempotent PR comments for relevant AI/config changes.

- Required token capability: issue comment write on the target repository (`issues:write` on `GITHUB_TOKEN` or a PAT/App token with equivalent scope).
- Token resolution order: `WRKR_GITHUB_TOKEN`, then `GITHUB_TOKEN`.
- Docs: [`docs/commands/action.md`](docs/commands/action.md) and [`action/action.yaml`](action/action.yaml).

## Release-Candidate UAT

Validate source build, `go install`, release archive install path, and Homebrew install path before tagging:

```bash
scripts/test_uat_local.sh
scripts/test_uat_local.sh --skip-global-gates

# Validate the exact public install commands shown above (brew + pinned go install)
scripts/test_uat_local.sh --release-version v1.0.0 --brew-formula Clyra-AI/tap/wrkr
```

## Where Wrkr Fits

Wrkr is the DMV registration for your AI fleet. It tells you what is on the road, what it is authorized to do, and what changed. Wrkr generates deterministic evidence artifacts from scans; Axym maps those artifacts to compliance controls and reporting workflows. Runtime enforcement remains Gait's boundary.

- **See (Wrkr):** Discover AI tooling posture and risk.
- **Prove (Axym):** Consume and verify evidence records.
- **Control (Gait):** Enforce runtime tool-boundary decisions.

Wrkr runs standalone and interoperates through shared `Clyra-AI/proof` contracts.

## Trust and Project Relationship

- Wrkr is standalone: you can install and run discovery, posture scoring, regress gating, and evidence generation without Axym or Gait.
- Axym and Gait are related projects that consume or enforce around the same proof contracts; they are optional integrations, not runtime prerequisites for Wrkr.
- The interoperability boundary is explicit and file-based via shared `Clyra-AI/proof` contracts.

## Guarantees

- Deterministic scan, risk, and proof pipeline. No LLM calls in these paths, ever.
- Zero data exfiltration by default for local scan and evidence workflows.
- Evidence is file-based, portable, and verifiable offline.
- `--json` output is machine-consumable across all command surfaces.
- Exit codes are stable API contracts:
  - `0` success
  - `1` runtime failure
  - `2` verification failure
  - `3` policy/schema violation
  - `4` approval required
  - `5` regression drift
  - `6` invalid input
  - `7` dependency missing
  - `8` unsafe operation blocked

## Command Surface

```text
wrkr init
wrkr scan
wrkr mcp-list
wrkr action pr-mode|pr-comment
wrkr report
wrkr campaign aggregate
wrkr export
wrkr inventory [--diff]
wrkr identity list|show|approve|review|deprecate|revoke
wrkr lifecycle
wrkr manifest generate
wrkr regress init|run
wrkr score
wrkr version
wrkr verify --chain
wrkr evidence
wrkr fix
```

All commands support `--json`. Human-readable rationale is available via `--explain` where supported.

## Documentation

- Docs source-of-truth map: [`docs/map.md`](docs/map.md)
- Docs taxonomy: [`docs/README.md`](docs/README.md)
- Shared README contract: [`docs/contracts/readme_contract.md`](docs/contracts/readme_contract.md)
- Cross-repo README follow-ups: [`docs/roadmap/cross-repo-readme-alignment.md`](docs/roadmap/cross-repo-readme-alignment.md)
- Mental model: [`docs/concepts/mental_model.md`](docs/concepts/mental_model.md)
- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Policy authoring: [`docs/policy_authoring.md`](docs/policy_authoring.md)
- Failure taxonomy and exits: [`docs/failure_taxonomy_exit_codes.md`](docs/failure_taxonomy_exit_codes.md)
- Threat model: [`docs/threat_model.md`](docs/threat_model.md)
- Compatibility and versioning policy: [`docs/trust/compatibility-and-versioning.md`](docs/trust/compatibility-and-versioning.md)
- Compatibility matrix: [`docs/contracts/compatibility_matrix.md`](docs/contracts/compatibility_matrix.md)
- Content visibility governance: [`docs/governance/content-visibility.md`](docs/governance/content-visibility.md)
- Trust docs: [`docs/trust/`](docs/trust/)
- Intent pages: [`docs/intent/`](docs/intent/)

Public docs: [clyra-ai.github.io/wrkr](https://clyra-ai.github.io/wrkr/)

Docs contribution path: edit canonical markdown in this repo first (`README.md` and `docs/`), then run `make test-docs-consistency`, `make test-docs-storyline`, and docs-site checks from [`docs/map.md`](docs/map.md).

## Developer Workflow

```bash
make fmt
make lint-fast
make test-fast
make test-contracts
make test-scenarios
make prepush-full
```

Docs and docs-site validation:

```bash
make test-docs-consistency
make test-docs-storyline
make docs-site-check
make docs-site-audit-prod
```

## Governance and Support

- Security policy: [`SECURITY.md`](SECURITY.md)
- Contributing guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Code of conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)
- License: [`LICENSE`](LICENSE)
- Issues: [github.com/Clyra-AI/wrkr/issues](https://github.com/Clyra-AI/wrkr/issues)

# Wrkr — See What AI Is Doing in Your Codebase

[![Main](https://github.com/Clyra-AI/wrkr/actions/workflows/main.yml/badge.svg)](https://github.com/Clyra-AI/wrkr/actions/workflows/main.yml)
[![CodeQL](https://github.com/Clyra-AI/wrkr/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Clyra-AI/wrkr/actions/workflows/github-code-scanning/codeql)
[![Nightly](https://github.com/Clyra-AI/wrkr/actions/workflows/nightly.yml/badge.svg?event=schedule)](https://github.com/Clyra-AI/wrkr/actions/workflows/nightly.yml)

Most teams don't know what AI dev tools and agents are active across their repos, what permissions they have, or what changed since last week. Wrkr answers that in minutes. Scan your GitHub org, get ranked findings, and generate audit-ready evidence. Read-only. No integration required.

Wrkr is the **See** layer in the Clyra AI governance stack (See -> Prove -> Control -> Build). It discovers AI tooling across repositories and orgs, scores posture, tracks identity lifecycle, and emits signed proof artifacts ready for compliance review or downstream automation.

Docs: [clyra-ai.github.io/wrkr](https://clyra-ai.github.io/wrkr/) | Command contracts: [`docs/commands/`](docs/commands/) | Docs map: [`docs/README.md`](docs/README.md)

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

### Go install (pinned to latest release tag)

```bash
WRKR_VERSION="$(gh release view --repo Clyra-AI/wrkr --json tagName -q .tagName 2>/dev/null || curl -fsSL https://api.github.com/repos/Clyra-AI/wrkr/releases/latest | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"tag_name\"])')"
go install github.com/Clyra-AI/wrkr/cmd/wrkr@"${WRKR_VERSION}"
```

### Verify install path

```bash
command -v wrkr
wrkr --json
```

Common locations:

- Apple Silicon Homebrew: `/opt/homebrew/bin/wrkr`
- Intel Homebrew: `/usr/local/bin/wrkr`
- Go install: `$(go env GOBIN)/wrkr` (or `$(go env GOPATH)/bin/wrkr` when `GOBIN` is unset)

## Try It (Offline, No Setup)

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
./.tmp/wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
./.tmp/wrkr verify --chain --json

# Baseline and drift gate
./.tmp/wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.tmp/wrkr-regress-baseline.json --json
./.tmp/wrkr regress run --baseline ./.tmp/wrkr-regress-baseline.json --json
```

Expected JSON keys by command family:

- `scan`: `target`, `findings`, `ranked_findings`, `inventory`, `privilege_budget`, `agent_privilege_map`, `profile`, `posture_score` (optional: `policy_warnings`, `report`)
- `report`: `top_findings`, `total_tools`, `compliance_gap_count`
- `score`: `score`, `grade`, `weighted_breakdown`, `trend_delta`
- `evidence`: `output_dir`, `manifest_path`, `chain_path`, `framework_coverage`
- `verify`: `chain.intact`, `chain.head_hash`
- `regress run`: deterministic drift status and reason fields

## What You Get

### Complete AI tool inventory

Structured detection for Claude, Cursor, Codex, Copilot, MCP, skills, and CI agent execution patterns. Local offline scanning via `--path`. Fail-closed behavior for hosted acquisition modes.

### Risk clarity, not noise

Ranked findings with repo-exposure rollups. Posture score and weighted breakdown you can trend over time to show governance improving.

### Identity lifecycle tracking

Deterministic identities in `wrkr:<tool_id>:<org>` format. Lifecycle transitions from `discovered` through `approved`, `active`, `deprecated`, and `revoked`.

### Audit-ready evidence

Signed proof records for `scan_finding`, `risk_assessment`, and lifecycle events. Evidence bundles with compliance framework mappings and offline verification. No calling home required.

### CI drift gates

Regress baseline and run gates with stable exit behavior. Deterministic remediation planning via `wrkr fix` for top-risk findings.

## Scan Targets

Exactly one source target is required per `scan` invocation:

- `--repo <owner/repo>`
- `--org <org>`
- `--path <local-dir>`

Acquisition behavior:

- `--path`: local, offline, fully deterministic.
- `--repo` and `--org`: require `--github-api` or `WRKR_GITHUB_API_BASE`; unavailable acquisition fails closed with exit `7`.
- Invalid target combinations fail with exit `6`.

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

## CI Adoption (One PR)

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

Validate source build, release archive install path, and Homebrew install path before tagging:

```bash
scripts/test_uat_local.sh
scripts/test_uat_local.sh --skip-global-gates
scripts/test_uat_local.sh --release-version v1.0.0 --brew-formula Clyra-AI/tap/wrkr
```

## Where Wrkr Fits

Wrkr is the DMV registration for your AI fleet. It tells you what is on the road, what it is authorized to do, and what changed. Wrkr generates deterministic evidence artifacts from scans; Axym maps those artifacts to compliance controls and reporting workflows. Runtime enforcement remains Gait's boundary.

- **See (Wrkr):** Discover AI tooling posture and risk.
- **Prove (Axym):** Consume and verify evidence records.
- **Control (Gait):** Enforce runtime tool-boundary decisions.

Wrkr runs standalone and interoperates through shared `Clyra-AI/proof` contracts.

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
wrkr action pr-mode|pr-comment
wrkr report
wrkr campaign aggregate
wrkr export
wrkr identity list|show|approve|review|deprecate|revoke
wrkr lifecycle
wrkr manifest generate
wrkr regress init|run
wrkr score
wrkr verify --chain
wrkr evidence
wrkr fix
```

All commands support `--json`. Human-readable rationale is available via `--explain` where supported.

## Documentation

- Docs map: [`docs/README.md`](docs/README.md)
- Mental model: [`docs/concepts/mental_model.md`](docs/concepts/mental_model.md)
- Architecture: [`docs/architecture.md`](docs/architecture.md)
- Policy authoring: [`docs/policy_authoring.md`](docs/policy_authoring.md)
- Failure taxonomy and exits: [`docs/failure_taxonomy_exit_codes.md`](docs/failure_taxonomy_exit_codes.md)
- Threat model: [`docs/threat_model.md`](docs/threat_model.md)
- Compatibility matrix: [`docs/contracts/compatibility_matrix.md`](docs/contracts/compatibility_matrix.md)
- Trust docs: [`docs/trust/`](docs/trust/)
- Intent pages: [`docs/intent/`](docs/intent/)

Public docs: [clyra-ai.github.io/wrkr](https://clyra-ai.github.io/wrkr/)

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

## Security and Feedback

- Security policy: [`SECURITY.md`](SECURITY.md)
- Contributing guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- License: [`LICENSE`](LICENSE)
- Issues: [github.com/Clyra-AI/wrkr/issues](https://github.com/Clyra-AI/wrkr/issues)

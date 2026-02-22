# Wrkr — Deterministic Discovery and Posture for AI Developer Tooling

[![Main](https://github.com/Clyra-AI/wrkr/actions/workflows/main.yml/badge.svg)](https://github.com/Clyra-AI/wrkr/actions/workflows/main.yml)
[![CodeQL](https://github.com/Clyra-AI/wrkr/actions/workflows/nightly.yml/badge.svg)](https://github.com/Clyra-AI/wrkr/actions/workflows/nightly.yml)
[![Nightly](https://github.com/Clyra-AI/wrkr/actions/workflows/nightly.yml/badge.svg?event=schedule)](https://github.com/Clyra-AI/wrkr/actions/workflows/nightly.yml)

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

Wrkr is the deterministic See-layer CLI in the See -> Prove -> Control model.
It discovers AI tooling across repositories and orgs, ranks risk, tracks identity lifecycle, and emits compliance-ready proof artifacts with stable machine contracts.

Docs: [clyra-ai.github.io/wrkr](https://clyra-ai.github.io/wrkr/) | Command contracts: [`docs/commands/`](docs/commands/) | Docs map: [`docs/README.md`](docs/README.md)

## When To Use Wrkr

- You need a deterministic inventory of AI development tools across repo/org surfaces.
- You need ranked findings for headless/autonomous agent risk and config drift.
- You need auditable, file-based evidence and proof-chain verification in CI.
- You need stable JSON and exit-code contracts for automation and agent consumption.

## When Not To Use Wrkr

- You need runtime side-effect enforcement at tool execution boundaries (Control-layer scope).
- You need live network telemetry as your primary detection signal.
- You need probabilistic/LLM scoring in scan/risk/proof paths.

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

## Try It (Offline, Deterministic)

```bash
# Build local CLI
make build

# Configure deterministic local target
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

- `scan`: `target`, `findings`, `ranked_findings`, `inventory`, `profile`, `posture_score`
- `report`: `top_findings`, `total_tools`, `compliance_gap_count`
- `score`: `score`, `grade`, `weighted_breakdown`, `trend_delta`
- `evidence`: `output_dir`, `manifest_path`, `chain_path`, `framework_coverage`
- `verify`: `chain.intact`, `chain.head_hash`
- `regress run`: deterministic drift status and reason fields

## What You Get

**Deterministic discovery coverage**

- Structured detection for Claude, Cursor, Codex, Copilot, MCP, skills, and CI agent execution patterns.
- Local/offline file scanning for `--path`; fail-closed dependency behavior for hosted acquisition modes.

**Risk clarity, not noisy dumps**

- Ranked findings and repo-exposure rollups.
- Posture score and weighted breakdown for trendable governance signals.

**Identity lifecycle and governance state**

- Deterministic identities in `wrkr:<tool_id>:<org>` format.
- Lifecycle transitions: `discovered`, `under_review`, `approved`, `active`, `deprecated`, `revoked`.

**Proof and compliance evidence**

- Signed proof records for `scan_finding`, `risk_assessment`, and lifecycle/approval events.
- Evidence bundles with framework mappings and offline verification support.

**CI-friendly drift and remediation workflows**

- Regress baseline and run gates with stable drift exit behavior.
- Deterministic remediation planning via `wrkr fix` for top-risk findings.

## Scan Target Contract (Fail-Closed)

Exactly one source target is required per `scan` invocation:

- `--repo <owner/repo>`
- `--org <org>`
- `--path <local-dir>`

Acquisition behavior:

- `--path`: local/offline deterministic scan.
- `--repo` and `--org`: require `--github-api` or `WRKR_GITHUB_API_BASE`; unavailable acquisition fails closed with exit `7`.
- Invalid target combinations fail with exit `6`.

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

## Product Boundary (See -> Prove -> Control)

- See: Wrkr discovers AI tooling posture and risk.
- Prove: Proof/Axym consume and verify evidence records.
- Control: Gait enforces runtime tool-boundary decisions.

Wrkr runs standalone and interoperates through shared `Clyra-AI/proof` contracts.

## Contract Commitments

- Deterministic scan/risk/proof pipeline (no LLM calls in these paths).
- Zero data exfiltration by default for local scan/evidence workflows.
- Evidence is file-based, portable, and verifiable.
- `--json` output is machine-consumable across command surfaces.
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
wrkr report
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

# Clyra AI Development Standards

Version: 1.0
Status: Normative
Scope: All Clyra AI projects - gait, proof, wrkr and axym.

This document defines the unified development infrastructure standards for Clyra AI projects. It covers toolchains, CI pipelines, testing, linting, security scanning, release integrity, performance budgets, and repo hygiene.

This is a **toolchain and process specification**, not a contributor workflow guide (see each project's CONTRIBUTING.md) or an architecture description (see each project's AGENTS.md).

## Language Toolchains

### Go

- **Version policy**: pin in `go.mod`; track latest stable within 2 minor releases. **Current pin: `1.25.7`** across all repos.
- **Module layout**: single module per repo, `cmd/<binary>/` for entry points, `core/` for library packages, `internal/` for non-exported packages.
- **Build**: `go build ./cmd/<binary>`.
- **Version injection**: `-ldflags "-s -w -X main.version={{ .Version }}"` via GoReleaser or manual build.
- **Dependency pinning**: exact versions in `go.mod`; `go.sum` provides integrity verification. No version ranges. Pre-commit hook runs `go-mod-tidy` to normalize.

### Python

- **Version**: 3.13+ required.
- **Package manager**: uv (astral-sh). Install via `pip install --upgrade pip uv`.
- **Project config**: `pyproject.toml` with `requires-python = ">=3.13"`.
- **Dev dependencies**: declared under `[project.optional-dependencies] dev = [...]` and installed via `uv run --python 3.13 --extra dev <command>`.
- **Dependency pinning**: `>=` constraints in pyproject.toml; uv lock file ensures reproducible installs.

### Node / TypeScript

- **Version**: Node 22+ (LTS).
- **Package install**: `npm ci` (deterministic, from lockfile).
- **Scope**: documentation sites and local UI shells only. Never used for core runtime logic.
- **Dependency pinning**: `package-lock.json` committed and used via `npm ci`.

## Cross-Repo Interoperability

All Clyra AI Go projects (proof, gait, wrkr, axym) share a dependency graph rooted in `Clyra-AI/proof`. These version contracts ensure binary compatibility, deterministic builds, and consistent behavior across the product suite.

### Pinned Versions (current)

| Component | Version | Scope |
|-----------|---------|-------|
| Go | `1.25.7` | All repos — `go.mod` + `.tool-versions` + CI (`go-version-file: go.mod`) |
| `Clyra-AI/proof` | `>= v0.4.3` | All downstream SKUs (gait, wrkr, axym) — minimum import version |
| Python | `3.13` | Scripts, SDKs — `pyproject.toml` + CI |
| Node | `22` (LTS) | Docs sites only |

### Shared Go Dependencies

All repos importing `Clyra-AI/proof` inherit these transitive dependencies. Pin to these versions in downstream `go.mod` files to prevent resolution drift:

| Dependency | Pinned Version | Purpose |
|-----------|---------------|---------|
| `github.com/gowebpki/jcs` | `v1.0.1` | RFC 8785 JSON canonicalization (signatures, digests) |
| `github.com/santhosh-tekuri/jsonschema/v5` | `v5.3.1` | JSON Schema validation for proof records and artifacts |
| `github.com/stretchr/testify` | `v1.10.0` | Test assertions — align to proof's direct pin |
| `gopkg.in/yaml.v3` | `v3.0.1` | YAML parsing for framework definitions and config |
| `github.com/spf13/cobra` | `v1.8.1` | CLI framework (proof CLI, inherited by downstream CLIs) |

### YAML Library Convention

- **Config and framework parsing** (framework YAML, policy files, manifests): use `gopkg.in/yaml.v3` — same parser as `Clyra-AI/proof`.
- **High-performance YAML** (large inventory files, streaming): `github.com/goccy/go-yaml` is permitted as an addition, not a replacement.
- **Rule**: any YAML that feeds into proof records or is shared across SKUs must parse with `gopkg.in/yaml.v3` to avoid parser-specific edge cases (anchors, merge keys, unicode normalization).

### Build and CI Toolchain Versions

Pin exact versions in all CI workflows and Makefiles. Floating versions (`@latest`) are prohibited for security and reproducibility.

| Tool | Pinned Version | Purpose |
|------|---------------|---------|
| GoReleaser | `v2.13.3` | Release builds — `.goreleaser.yaml` version 2 |
| golangci-lint | `v2.0.1` | Lint aggregator |
| gosec | `v2.23.0` | Security static analysis |
| govulncheck | `v1.1.4` | Go vulnerability database |
| cosign | `v2.5.3` | OIDC keyless code signing |
| Syft | `v1.32.0` | SBOM generation |
| Grype | `v0.99.1` | Vulnerability scanning on release artifacts |

### proof Version Tracking Policy

`Clyra-AI/proof` is the shared primitive. All downstream SKUs (gait, wrkr, axym) depend on it.

- **Minimum version**: `v0.3.0`. No SKU may pin below this.
- **Tracking policy**: all SKUs must track proof within **1 minor release** of the latest tag. When proof tags `v0.4.0`, all SKUs must upgrade within 2 weeks.
- **Breaking changes**: proof uses semver. Minor version bumps add functionality (backward-compatible). Major version bumps may break API — coordinated upgrade across all SKUs required.
- **CI validation**: each SKU's CI runs `go build ./...` against its pinned proof version. Proof's CI runs integration tests that build gait (and future wrkr/axym) against `main` to catch breaking changes before tagging.
- **Replace directives**: `replace` directives for `Clyra-AI/proof` are permitted in local development only. Never committed to `main`.

### Go Version Upgrade Protocol

1. Upgrade proof first (it's the root of the dependency tree).
2. Verify proof CI passes on the new Go version.
3. Upgrade downstream SKUs (gait, wrkr, axym) in any order.
4. Update `.tool-versions`, `go.mod`, and this document.
5. All repos must be on the same Go version within 1 week of the proof upgrade.

## Linting and Formatting

### Go

| Tool | Purpose | Version | Execution |
|------|---------|---------|-----------|
| gofmt | Code formatting | Bundled with Go | `gofmt -w .` |
| go vet | Static analysis | Bundled with Go | `go vet ./...` |
| golangci-lint | Lint aggregator | `v2.0.1` | `golangci-lint run ./...` |
| gosec | Security static analysis | `v2.23.0` | `gosec ./...` |
| govulncheck | Vulnerability database | `v1.1.4` | `govulncheck -mode=binary ./<binary>` |

**golangci-lint enabled linters**: govet, errcheck, staticcheck, ineffassign. Config in `.golangci.yml` with 5-minute timeout and tests enabled.

### Python

| Tool | Purpose | Config | Execution |
|------|---------|--------|-----------|
| ruff | Lint + format | pyproject.toml, line-length 100 | `ruff check`, `ruff format` |
| mypy | Type checking | pyproject.toml, `strict = true` | `mypy` |
| bandit | Security lint | Default rules | `bandit -q -r <package>` |

### Node

- ESLint / Next.js lint for docs-site and UI projects.
- Execution: `npm run lint` within the site directory.

### Markdown

- Internal link validation via CI script.
- Mermaid diagram syntax validation during docs-site build.
- Docs-to-CLI consistency checking (flags, exit codes, command names).

### Pre-commit Hooks

Configure via `.pre-commit-config.yaml`:

| Hook | Source | Stage |
|------|--------|-------|
| end-of-file-fixer | pre-commit/pre-commit-hooks | commit |
| trailing-whitespace | pre-commit/pre-commit-hooks | commit |
| check-added-large-files | pre-commit/pre-commit-hooks | commit |
| detect-private-key | pre-commit/pre-commit-hooks | commit |
| detect-aws-credentials | pre-commit/pre-commit-hooks | commit |
| go-fmt | dnephin/pre-commit-golang | commit |
| go-mod-tidy | dnephin/pre-commit-golang | commit |
| golangci-lint | golangci/golangci-lint | commit |
| ruff (with --fix) | astral-sh/ruff-pre-commit | commit |
| ruff-format | astral-sh/ruff-pre-commit | commit |
| site-stack-lint | local | commit |
| site-stack-build | local | push |
| make-prepush | local | push |

## Testing Matrix

Tests are organized into tiers by scope, speed, and when they run.

### Tier 1 — Unit

- **What**: isolated component tests.
- **How**: `go test ./...` (Go), `pytest` (Python).
- **When**: every PR, every push, pre-push hook.
- **Flags**: default (cached, parallel).

### Tier 2 — Integration

- **What**: cross-component deterministic tests. Direct API usage, no CLI.
- **How**: `go test ./internal/integration -count=1`.
- **When**: every PR, every push to main.
- **Patterns**: fixture helpers, golden JSON assertions, deterministic concurrency validation.

### Tier 3 — E2E

- **What**: CLI end-to-end tests. Builds binary, invokes via `exec.Command`, validates JSON output and exit codes.
- **How**: `go test ./internal/e2e -count=1`.
- **When**: push to main.
- **Flags**: `-count=1` (no cache, deterministic).

### Tier 4 — Acceptance

- **What**: version-gated acceptance scripts validating blessed workflows end-to-end.
- **How**: shell scripts (`scripts/test_*_acceptance.sh`) that run CLI commands and validate output.
- **When**: push to main, conditional on adoption-critical path changes (detected via dorny/paths-filter).
- **Pattern**: quickstart flow validation, adapter scenario testing, conformance checks, scorecard generation.

### Tier 5 — Hardening

- **What**: atomic write integrity, lock contention, stale lock recovery, network retry classification, error envelope contracts, concurrent determinism.
- **How**: shell script orchestrating targeted `go test -run <pattern> -count=1` invocations.
- **When**: nightly (cross-platform), release gates.

### Tier 6 — Chaos

- **What**: fault injection and resilience validation. Exporter stability, service boundary failures, payload limits, session resilience, trace uniqueness.
- **How**: dedicated shell scripts (`scripts/test_chaos_*.sh`) with `-count=3` or `-count=5` for stress.
- **When**: nightly, release gates.

### Tier 7 — Performance

- **What**: benchmark regression detection, command latency budgets (p50/p95/p99), resource budgets, context budgets.
- **How**: `go test -bench <regex> -benchmem -count=5` with `GOMAXPROCS=1`. Median aggregation. Comparison against baseline with max regression factor.
- **When**: nightly, release gates.
- **Determinism**: single-threaded execution (GOMAXPROCS=1), 5 samples, median selection.

### Tier 8 — Soak

- **What**: long-running session stability, concurrent contention under sustained load.
- **How**: dedicated soak scripts with `-count=4` and configurable lock profiles (`LOCK_PROFILE=swarm`, `LOCK_TIMEOUT=5s`, `LOCK_RETRY=10ms`).
- **When**: nightly.

### Tier 9 — Contract

- **What**: deterministic artifact bytes, stable exit-code contracts, JSON shape contracts, schema compatibility guards, producer-kit roundtrips, legacy compatibility.
- **How**: shell scripts validating byte-stable outputs, exit codes, required JSON fields, and schema field/enum stability.
- **When**: every push to main.

### Tier 10 — UAT

- **What**: full local install-path matrix covering source build, release-installer binary, and Homebrew paths.
- **How**: shell script running quality gates (lint, test, e2e, integration, contracts, acceptance, hardening, chaos, soak, performance) across each install path.
- **When**: manual (`make test-uat-local`), pre-release.

### Tier 11 — Scenario

- **What**: outside-in behavioral validation against human-authored scenario fixtures. Scenarios define inputs and expected outcomes externally — the implementation is evaluated against them, not tested by code it co-generated.
- **How**: `go test ./internal/scenarios -count=1 -tags=scenario`. Each scenario is a directory under `scenarios/` containing inputs, simulated service responses, and expected outputs.
- **When**: every push to main, release gates.
- **Why this tier exists**: all Clyra AI code is written by coding agents. Tiers 1–10 validate that code works as the agent intended. Tier 11 validates that the agent's intent matches the product specification. When the same agent writes implementation and tests, the tests can be tautological — validating what the code *does* instead of what it *should do*. Scenario fixtures are the specification. The agent's code is evaluated against them, not against its own tests.

**Scenario structure:**

```text
scenarios/
├── proof/
│   ├── chain-tamper-detection/
│   │   ├── README.md                    # scenario description and rationale
│   │   ├── input-records.jsonl          # 10 valid proof records
│   │   ├── tamper-record-5.jsonl        # record 5 with modified event field
│   │   └── expected.yaml                # verify: fail, break_point: record 5
│   └── cross-product-mixed-chain/
│       ├── wrkr-records.jsonl           # scan_finding records from wrkr
│       ├── axym-records.jsonl           # tool_invocation records from axym
│       ├── gait-records.jsonl           # policy_enforcement records from gait
│       └── expected.yaml                # verify: pass, total_records: 30
├── gait/
│   ├── policy-block-destructive/
│   │   ├── policy.yaml                  # policy: block rm -rf, allow cat
│   │   ├── intents.jsonl                # 5 intents (3 safe, 2 destructive)
│   │   └── expected-verdicts.jsonl      # allow, allow, allow, block, block
│   ├── delegation-chain-depth-3/
│   │   ├── tokens.jsonl                 # delegation A→B→C→D
│   │   ├── intent.json                  # intent from D
│   │   └── expected.yaml                # allow with full chain audit trail
│   └── expired-approval-1s-past/
│       ├── approval-token.json          # expires_at: T-1s
│       ├── intent.json
│       └── expected.yaml                # block, reason: APPROVAL_EXPIRED
├── wrkr/
│   ├── scan-mixed-org/
│   │   ├── repos/                       # fixture repo trees (bare git repos)
│   │   │   ├── frontend/               # .cursorrules, .agents/skills/
│   │   │   ├── backend/                # .claude/, CLAUDE.md, hooks, MCP
│   │   │   ├── data-pipeline/          # AGENTS.md, AGENTS.override.md
│   │   │   ├── infra/                  # .github/copilot-*.yml
│   │   │   └── experiments/            # .env with API keys, no manifest
│   │   ├── github-api-responses/        # canned org metadata, app installs
│   │   ├── expected-inventory.yaml      # 12 tools, types, locations, teams
│   │   ├── expected-findings.yaml       # 5 findings ranked by risk
│   │   └── expected-risk-scores.yaml    # per-tool scores within ±0.5
│   └── scan-skill-risk-signals/
│       ├── repos/skills-repo/           # skills with varying risk profiles
│       ├── expected-skill-findings.yaml # privilege breadth, invocation policy
│       └── expected-remediations.yaml   # skill hardening PRs
├── axym/
│   ├── eu-ai-act-full-coverage/
│   │   ├── proof-records.jsonl          # 500 records covering all 15 types
│   │   ├── expected-coverage.yaml       # 100% on Art. 9, 12, 13, 14, 15
│   │   └── expected-gaps.yaml           # empty — no gaps
│   ├── soc2-partial-gap/
│   │   ├── proof-records.jsonl          # records missing CC8 evidence
│   │   ├── expected-coverage.yaml       # CC6: covered, CC7: covered, CC8: gap
│   │   └── expected-gaps.yaml           # 2 gaps with remediation steps
│   └── gait-pack-ingestion/
│       ├── gait-pack.zip                # PackSpec v1 ZIP with traces + tokens
│       ├── expected-translated.jsonl    # translated proof records
│       └── expected-coverage-delta.yaml # coverage improvement from ingestion
└── cross-product/
    ├── see-prove-control-loop/
    │   ├── wrkr-scan-input/             # fixture org
    │   ├── gait-policy.yaml             # enforcement policy
    │   ├── axym-frameworks.yaml         # EU AI Act + SOC 2
    │   └── expected-final-bundle.yaml   # end-to-end expected coverage
    └── proof-record-interop/
        ├── records-from-all-3.jsonl     # mixed-source chain
        └── expected.yaml                # chain: intact, products: [wrkr, axym, gait]
```

**Authorship rules:**

- Scenario fixtures (`scenarios/`) are **human-reviewed specifications**. Changes to expected outcomes require human approval via CODEOWNERS.
- Coding agents may add new scenarios but cannot modify expected outcomes of existing scenarios without human review.
- `scenarios/README.md` documents each scenario's purpose, what product behavior it validates, and why the expected outcome is correct.
- Scenario inputs must be self-contained — no network calls, no external dependencies, no `replace` directives.

**Validation:**

- `scripts/validate_scenarios.sh` — verifies scenario directory structure, required files, YAML/JSON validity.
- `scripts/run_scenarios.sh <product>` — runs all scenarios for a product, compares actual vs expected, reports pass/fail with diffs.
- Scenario failures in CI are **blocking** — they indicate the implementation diverged from the specification.

### Tier 12 — Cross-Product Integration

- **What**: end-to-end governance loop validation. Proof records flow from Wrkr (discovery) and Gait (enforcement) into Axym (compliance mapping), producing a unified evidence chain verified by the `proof` CLI. Tests the full See → Prove → Control sequence.
- **How**: shell scripts in `scenarios/cross-product/` that build all 4 binaries, run Wrkr against fixture repos, run Gait against fixture intents, pipe records into Axym, generate a bundle, and verify the chain.
- **When**: nightly, release gates.
- **Dependency**: requires all 4 binaries (proof, gait, wrkr, axym) to be buildable from their current `main` branches. Uses `replace` directives in a temporary `go.work` workspace to test against local HEAD, not released versions.

**What Tier 12 validates:**

1. Wrkr `scan_finding` records are valid proof records (`proof verify` passes)
2. Gait `gait.gate.trace` artifacts translate to valid `policy_enforcement` proof records via Axym's GaitIngestor
3. Mixed-source records (wrkr + gait + axym) append to the same hash chain without integrity violations
4. Axym maps the combined evidence to framework controls correctly (coverage matches expected)
5. The audit bundle passes `proof verify --bundle` and contains evidence from all 3 source products
6. Agent IDs are consistent: the ID Wrkr assigns appears in Gait traces and Axym evidence

## Simulated Service Environments

External service dependencies are simulated at the HTTP/filesystem boundary, not mocked at the Go interface level. Simulations provide deterministic responses from scenario fixtures — the product code hits a real HTTP endpoint or reads a real filesystem path, but the data behind it is controlled.

### Architecture

```text
testinfra/
├── simenv/
│   ├── github/                  # simulated GitHub API server
│   │   ├── server.go            # net/http server, routes from fixtures
│   │   ├── fixtures/            # canned responses per scenario
│   │   └── README.md
│   ├── mcp/                     # simulated MCP server logs
│   │   ├── loggen.go            # generates fixture log files
│   │   └── fixtures/
│   ├── llmapi/                  # simulated LLM API middleware
│   │   ├── server.go            # returns canned tool_call responses
│   │   └── fixtures/
│   ├── ticketing/               # simulated Jira/ServiceNow
│   │   ├── server.go            # accepts attach requests, records calls
│   │   └── fixtures/
│   └── hooks/                   # simulated Claude Code hook invocations
│       ├── harness.go           # invokes gait as PreToolUse hook
│       └── fixtures/
└── testutil/
    ├── scenario_runner.go       # generic: load scenario → run product → compare expected
    ├── fixture_repo.go          # creates bare git repos from scenario directories
    └── golden_compare.go        # YAML/JSON diff with tolerance (±0.5 for risk scores)
```

### Simulation Rules

- Simulations live in `testinfra/simenv/` — shared across all products.
- Simulation servers are started per-test and listen on `localhost` with random ports.
- Product code connects to simulations via environment variables (`GITHUB_API_URL`, `MCP_LOG_PATH`, etc.) — no code changes needed.
- Simulations return fixture data only — no logic, no state machines, no conditional responses. If a scenario needs a 429 rate-limit response, the fixture contains a 429 response at the expected request index.
- Simulation responses are **frozen** — changes require human review. The simulation layer is infrastructure, not test code.
- **Never use real service credentials in CI.** Simulations replace all external dependencies. The `CLYRA_SIMENV=1` environment variable activates simulation mode.

### Per-Product Simulation Map

| Product | Dependency | Simulation | Used By |
|---------|-----------|------------|---------|
| wrkr | GitHub REST/GraphQL API | `simenv/github/` — canned repo listings, file contents, org metadata, app installs | Tier 11 scan scenarios |
| wrkr | Git clone | `testutil/fixture_repo.go` — bare git repos from scenario `repos/` directories | Tier 11 scan scenarios |
| axym | MCP server logs | `simenv/mcp/` — fixture log files with known tool invocations | Tier 11 collection scenarios |
| axym | LLM API responses | `simenv/llmapi/` — canned structured responses with tool calls | Tier 11 collection scenarios |
| axym | Jira/ServiceNow | `simenv/ticketing/` — accepts attach calls, records what was sent | Tier 11 ticket attach scenarios |
| axym | Gait packs | Direct file fixtures (PackSpec v1 ZIPs in scenario dirs) | Tier 11 ingestion scenarios |
| gait | Claude Code hooks | `simenv/hooks/` — invokes gait binary as a PreToolUse hook handler | Tier 11 policy scenarios |
| proof | (none) | Pure library — no external dependencies to simulate | Tier 11 chain scenarios |

## AI-Authored Code Safeguards

All Clyra AI products are written by coding agents. These safeguards prevent the failure modes specific to AI-authored codebases.

### The Closed-Loop Problem

When a coding agent writes both implementation and tests, correctness is circular — the tests validate the agent's understanding, which may be wrong. Safeguards operate at three levels:

#### Level 1: Specification-driven scenarios (Tier 11)

Scenario fixtures define expected behavior externally. The agent implements code that must pass scenarios it did not author. Changes to expected outcomes require human approval. This breaks the tautological loop — the agent cannot redefine what "correct" means.

#### Level 2: Contract stability (Tier 9 + schema management)

Exit codes, JSON schemas, proof record shapes, and artifact byte-stability are contract-tested. An agent that accidentally changes a public contract fails CI immediately. Contracts are versioned — the agent cannot silently evolve the interface.

#### Level 3: Cross-product integration (Tier 12)

Four separate agents (one per product) produce artifacts that must interoperate. Agent A's proof records must chain with Agent B's proof records. Agent C's policy verdicts must translate into Agent D's compliance coverage. Each agent's mistakes are caught by the other products' expectations. This is natural adversarial testing — no single agent controls the full loop.

### Authorship Tracking

- All files in `scenarios/` are protected by CODEOWNERS — human approval required for changes to expected outcomes.
- `scenarios/CHANGELOG.md` tracks when scenarios were added, by whom, and what product behavior they validate.
- Agents may propose new scenarios via PR. Human review verifies the expected outcomes are correct before merge.
- Existing scenario expected outcomes are immutable unless the product specification changes. A failing scenario means the code is wrong, not the scenario.

### Scenario Coverage Requirements

| Product | Minimum Scenarios (v1) | Critical Paths |
|---------|----------------------|----------------|
| proof | 5 | chain integrity, tamper detection, cross-product chain, signing/verification, schema validation |
| gait | 8 | policy block, policy allow, dry run, delegation chain, approval expiry, approval token, concurrent evaluation, pack integrity |
| wrkr | 6 | multi-surface scan, risk scoring accuracy, skill risk signals, identity lifecycle, remediation PR content, posture regression |
| axym | 8 | MCP collection, framework mapping (EU AI Act), framework mapping (SOC 2), gap detection, Gait pack ingestion, Wrkr record ingestion, bundle integrity, compliance regression |
| cross-product | 3 | See→Prove→Control loop, proof record interop, agent ID consistency across products |

These minimums are for v1 launch. Scenario count grows with product surface — each new FR should include at least one scenario.

## Coverage Gates

| Scope | Threshold | Enforcement |
|-------|-----------|-------------|
| Go core packages (`core/`, `cmd/`) | >= 85% | Linux CI enforces; macOS reports only |
| Go all packages | >= 75% per-package | Per-package script with allowlist support |
| Python SDK | >= 85% | pytest-cov `--cov-fail-under=85` |

**Coverage collection**: Go uses `-coverprofile=coverage.out`; Python uses `pytest --cov=<package> --cov-report=term-missing`.

**Validation scripts**: `scripts/check_go_coverage.py <coverprofile> <min_percent>`, `scripts/check_go_package_coverage.py <output> <min_percent> [allowlist_csv]`.

### Golden File Pattern

- Assertion: `AssertGoldenJSON(t, repoRelativePath, value)` compares normalized JSON byte-for-byte.
- Update: `UPDATE_GOLDEN=1 go test ./...` regenerates golden files.
- Platform normalization: newlines normalized before comparison.
- Location: `testdata/` directories within each package, or `internal/integration/testdata/` for integration goldens.

## CI Pipeline Architecture

### PR Pipeline (required, fast feedback)

- Require at least one fast lane on every `pull_request`; this lane is merge-blocking.
- Fast lane should run deterministic lint + unit + contract checks and complete quickly.
- Include at least one non-primary platform smoke lane for portability confidence.
- Use path-based change detection to gate expensive scanners, but keep baseline lint/test checks always on.
- Every PR workflow must define `concurrency` with `cancel-in-progress: true`.

### Main Pipeline (protected branch push)

- Run the full deterministic matrix after merge to the protected branch.
- Include full test suites, contract suites, and acceptance suites required by the release policy.
- Keep heavy suites path-gated where safe, but never gate foundational contract or determinism checks.

### Nightly Pipelines

| Pipeline | Typical Schedule | Scope |
|----------|------------------|-------|
| Hardening | Daily | Cross-platform hardening and resilience suites |
| Performance | Daily | Benchmark and resource-budget regression checks |
| Extended security/compliance | Daily or weekly | Full security/dependency/compliance scans not suitable for PR latency |
| Platform depth | Weekly | Full matrix on secondary platforms |

### Release Pipeline (tag push or manual dispatch)

Sequence:

1. Run release-gated acceptance and contract suites.
2. Build reproducible release artifacts for supported targets.
3. Generate and verify checksums.
4. Generate SBOM.
5. Run vulnerability scan against produced artifacts/SBOM.
6. Sign release artifacts using project-standard signing identity.
7. Generate provenance attestation.
8. Verify checksum/signature/provenance in-pipeline before publication.
9. Publish artifacts and release notes only after all gates pass.

### Workflow Contract Validation

- Treat workflow YAML and branch-protection configuration as testable contracts.
- Enforce in CI:
  - required-checks contract file exists and parses.
  - required checks list is non-empty, unique, and sorted.
  - each required check maps to a status emitted on `pull_request`.
  - all primary workflows include `concurrency` + `cancel-in-progress: true`.
  - path-filter contract fragments exist for expensive conditional lanes.
- Any workflow rename/trigger change must update contract tests in the same PR.

## Pre-Push Enforcement

### Hook Setup

```bash
make hooks
```

### Modes

| Mode | Trigger | What runs |
|------|---------|-----------|
| Default (fast) | `git push` | fast deterministic lint + test + contract checks |
| Full | explicit opt-in | full lint + full test + deep security scans |

- Pre-commit hooks handle formatting and secret detection (commit stage).
- Pre-push hooks gate on lint + test (push stage).
- Repositories should provide one command for fast mode and one for full mode.

## Branch Protection

Standard branch protection for the default branch:

| Setting | Value |
|---------|-------|
| Required status checks | Only checks emitted by `pull_request` workflows and declared in a tracked required-checks contract file |
| Strict status checks | Yes (require latest commit to pass) |
| Required conversation resolution | Yes |
| Linear history | Yes |
| Force pushes | Disabled |
| Branch deletions | Disabled |
| Enforce admins | Yes |
| Required reviews (standard) | 0 |
| Required reviews (strict) | 1 + CODEOWNERS |

Branch-protection policy rules:

- A required check must never reference a job that does not run on `pull_request`.
- Main-only, nightly-only, and release-only checks are not valid PR merge blockers.
- Branch-protection settings should be configurable from code (script/API), not only manual UI changes.

## Security Scanning

### Static Analysis

| Tool | Languages | Scope |
|------|-----------|-------|
| CodeQL | Go, Python | security-and-quality queries, push + PR |
| gosec | Go | Security patterns (hardcoded creds, dangerous functions) |
| bandit | Python | Security patterns (secrets, injection, weak crypto) |
| govulncheck | Go | Go vulnerability database, binary mode |

### Pre-commit Detection

- detect-private-key: blocks commits containing private key material.
- detect-aws-credentials: blocks commits containing AWS credential patterns.

### Release Security

| Tool | Purpose |
|------|---------|
| Grype `v0.99.1` | Vulnerability scan on release artifacts |
| Syft `v1.32.0` | SBOM generation (SPDX JSON) |
| cosign `v2.5.3` | OIDC keyless code signing (GitHub Actions identity) |
| SLSA provenance | intoto attestation with commit digest |

### Verification

```bash
sha256sum -c dist/checksums.txt
cosign verify-blob --certificate dist/checksums.txt.pem \
  --signature dist/checksums.txt.sig dist/checksums.txt
```

## Release Integrity

### Build

- **Tool**: GoReleaser `v2.13.3`.
- **Platforms**: linux/darwin/windows x amd64/arm64.
- **Binary**: single static binary per platform.
- **Archives**: tar.gz (unix), zip (windows).
- **Checksums**: `checksums.txt` with sha256.

### Versioning

- **Scheme**: semantic versioning (`vX.Y.Z`) via git tags.
- **Injection**: `main.version` via ldflags at build time.
- **Changelog**: custom rendering (not GoReleaser default).

### Signing and Provenance

- **Signing**: cosign OIDC keyless. Identity tied to GitHub Actions workflow run.
- **Provenance**: SLSA intoto format with build URI, commit digest, timestamps.
- **SBOM**: Syft SPDX JSON.

### Distribution

1. GitHub Releases (primary): binaries + checksums + signatures + SBOM + provenance.
2. Install script: platform/arch detection, checksum verification, `~/.local/bin` default.
3. Homebrew tap: formula rendering from release artifacts, gated on stable release cycle.

## Performance Budget Framework

### Benchmark Baselines

- **File**: `perf/bench_baseline.json` per project.
- **Format**: benchmark name, baseline_ns_op, max_regression_factor (default: 4.0x).
- **Execution**: `GOMAXPROCS=1`, 5 samples, median aggregation.
- **Validation**: `scripts/check_bench_regression.py <bench_output> <baseline.json> [report.json]`.
- **Benchmarked areas**: policy evaluation, artifact verification, artifact diffing, incident pack building, session checkpoints, protocol adapters.

### Command Latency Budgets

- **File**: `perf/runtime_slo_budgets.json`.
- **Metrics**: p50, p95, p99 milliseconds per command. 0% error rate required.
- **Repeats**: 7 invocations per command per gate.
- **Validation**: `scripts/check_command_budgets.py`.

### Resource Budgets

- **File**: `perf/resource_budgets.json` — memory, CPU, allocation tracking.
- **File**: `perf/context_budgets.json` — token consumption per command.
- **File**: `perf/ui_budgets.json` — component size, rendering time.
- **Validation**: dedicated scripts per budget type.

## Repo Hygiene

### Required Tracked Files

Product planning documents must be committed to Git:

- `product/PRD.md`
- `product/ROADMAP.md`
- `product/PLAN_*.md`

### Prohibited Tracked Files

Generated artifacts must never be committed:

- Build output directories (`*-out/`)
- Coverage files (`coverage-*.out`, `.coverage`)
- Built binaries
- Performance reports (`perf/bench_output.txt`, `perf/*_report.json`)

### Validation

- **Script**: `scripts/check_repo_hygiene.sh` — validates tracked vs prohibited files.
- **Enforcement**: runs as part of `make lint`.
- **Remediation**: `git rm --cached <path>`.

### Skills Validation

- **Script**: `scripts/validate_repo_skills.py`.
- **Checks**: frontmatter schema (name, description), naming conventions (`^[a-z0-9][a-z0-9-]{0,63}$`), cross-provider constraints, body content requirements.
- **Enforcement**: runs as part of `make lint`.

### Ecosystem Index Validation

- **Script**: `scripts/validate_community_index.py`.
- **Checks**: JSON schema compliance, entry sorting (deterministic diffs), field constraints.
- **Enforcement**: runs as part of `make lint`.

## Documentation Standards

### Docs Site

- **Framework**: Next.js static export to GitHub Pages.
- **Build**: `npm ci && npm run build` in docs-site directory.
- **Validation**: link checking, Mermaid diagram syntax, docs-CLI consistency, build success.

### Frontmatter Convention

All docs should include YAML frontmatter for SEO metadata:

```yaml
---
title: "Page Title"
description: "One-sentence description for meta tags and search results."
---
```

### FAQ Pattern

Buyer-facing docs should include a FAQ section:

```markdown
## Frequently Asked Questions

### Question text here?

Answer text here.
```

FAQ sections are automatically extracted and emitted as FAQPage JSON-LD schema.

### LLM/AEO Surface

Each project should maintain:

- `llms.txt` — structured product summary for LLM consumption.
- `ai-sitemap.xml` — machine-readable sitemap pointing to LLM-optimized content.
- `llm/*.md` — topic-specific LLM reference files (product, faq, quickstart, security, contracts).

### PR Template

Pull request templates should require:

- Testing: `make fmt && make lint && make test` passed.
- Hardening review: error categories, exit codes, determinism, security, privacy.
- Operational notes: docs updates, docs sync, discoverability, terminology, evidence.

## Determinism Standards

These standards ensure reproducible builds, tests, and artifacts across environments.

| Area | Standard |
|------|----------|
| Benchmarks | `GOMAXPROCS=1` for single-threaded determinism |
| Hardening/E2E tests | `-count=1` (no test cache) |
| Golden files | `UPDATE_GOLDEN=1` to regenerate; byte-for-byte match in CI |
| Artifact paths | Deterministic output directories |
| JSON canonicalization | RFC 8785 (JCS) for all JSON in digests or signatures |
| Zip files | Fixed epoch (1980-01-01), stable file ordering, fixed modes/compression |
| Exit codes | Stable API surface — changes require versioned migration |

## Exit Code Contract

All CLI tools use a shared exit code contract. Exit codes are API surface and must remain stable across versions.

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Internal / runtime failure |
| 2 | Verification failure |
| 3 | Policy block |
| 4 | Approval required |
| 5 | Regression failed |
| 6 | Invalid input |
| 7 | Dependency missing |
| 8 | Unsafe operation blocked |

All commands must support `--json` for machine-readable output. Most should support `--explain` for human-readable rationale.

## Schema Management

- **Location**: `schemas/v1/` with one JSON Schema file per artifact type.
- **Validation**: `ValidateJSON(schemaPath, data)` and `ValidateJSONL(schemaPath, data)` helpers.
- **Test fixtures**: paired `valid_*` / `invalid_*` files for each schema.
- **Compatibility**: schemas are versioned; backward-compatible within major version. Adding optional fields is safe; removing or retyping fields requires a new major version.
- **Authoring**: hand-maintained (no auto-generation). Schema changes trigger contract tests.

## Test Utilities

Standard test helper patterns:

| Helper | Purpose |
|--------|---------|
| `RepoRoot(t)` | Locate repository root from caller |
| `BuildBinary(t, root)` | Build binary in temp directory |
| `CommandExitCode(t, err)` | Extract exit code from exec.ExitError |
| `WriteFile(t, path, content)` | Create test files with parent directories |
| `AssertGoldenJSON(t, path, value)` | Golden file assertion with UPDATE_GOLDEN |
| `WriteGoldenJSON(t, path, value)` | Write golden fixture |
| `MustReadFile(t, path)` | Read file or fail test |
| `FormatJSON(raw)` | Pretty-print JSON for comparison |

All tests writing temporary files must use `t.TempDir()` — never write to the source tree.

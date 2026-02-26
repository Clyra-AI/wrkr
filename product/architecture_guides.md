# Wrkr Architecture Execution Guide

Version: 1.0  
Status: Normative  
Scope: Wrkr only (`/Users/davidahmann/Projects/wrkr`)

This document is the actionable architecture companion to `/Users/davidahmann/Projects/wrkr/product/dev_guides.md`.

`dev_guides.md` defines toolchain/process standards.  
This file defines architecture execution rules, PR gates, and required artifacts.

## 1) Purpose

Use this guide to make architecture decisions auditable and repeatable, not opinion-based.

Every architecture-impacting change MUST show:

1. What contract changes (if any)
2. What failure modes are introduced/changed
3. What cost/performance impact is expected
4. What tests prove behavior under normal and fault conditions

## 2) Architecture Baseline (Wrkr)

Wrkr remains a deterministic, offline-first, fail-closed CLI and evidence pipeline.

Required boundaries (do not collapse):

- Source
- Detection
- Aggregation
- Identity
- Risk
- Proof emission
- Compliance mapping/evidence output

Any PR that crosses boundaries directly MUST include an ADR (see Section 9).

### 2.1 Current Wrkr Package Map (Implementation Clarification, Non-Breaking)

This map clarifies where the required boundaries live in the current codebase so architecture reviews remain concrete and auditable.

| Boundary | Primary packages (current Wrkr layout) |
|---|---|
| Source | `core/source/*`, `core/config`, source acquisition paths in `core/cli/scan.go` |
| Detection | `core/detect/*`, detector registration in `core/detect/defaults` |
| Aggregation | `core/aggregate/*` |
| Identity | `core/identity`, `core/lifecycle`, `core/manifest`, `core/manifestgen` |
| Risk | `core/risk/*`, `core/score/*`, policy evaluators in `core/policy/*` |
| Proof emission | `core/proofemit`, `core/verify` |
| Compliance/evidence output | `core/evidence`, `core/compliance`, `core/proofmap`, `core/export/*`, reporting in `core/report/*` |

Supporting contract layers:

- Contract tests and governance checks: `testinfra/contracts`, `testinfra/hygiene`
- Scenario contract and outside-in behavior checks: `internal/scenarios`, `scenarios/`
- Full acceptance matrix: `internal/acceptance`

## 3) TDD Standard (Required)

### 3.1 Red-Green-Refactor Contract

For behavior changes, teams MUST follow:

1. Add/adjust failing test(s) that encode intended behavior.
2. Implement minimal code to pass.
3. Refactor while keeping tests green.

### 3.2 Minimum test additions by change type

| Change type | Minimum required tests |
|---|---|
| Parser/schema changes | unit parser tests + contract fixture/golden |
| CLI output/exit changes | CLI contract tests (`--json`, exits) |
| Risk scoring/policy logic | deterministic ranking/policy tests + regression fixtures |
| Proof/evidence changes | chain/evidence contract tests + compatibility assertions |
| External adapter changes | error mapping tests + stale/partial/unavailable paths |
| Concurrency/state changes | contention/lifecycle tests + atomic write safety |

### 3.3 TDD evidence required in PR description

Every architecture-impacting PR MUST include:

- `Test intent`: what behavior was encoded first
- `Commands run`: exact command list
- `Result`: pass/fail summary

Minimum command baseline:

```bash
make lint-fast
make test-fast
make test-contracts
make test-scenarios
```

If architecture boundaries, risk logic, adapters, or failure semantics changed:

```bash
make prepush-full
```

## 4) Beyond 12-Factor: Cloud-Native Execution Factors

Wrkr is not a web service, but modern cloud-native factors still apply to CLI/runtime architecture.

The following are REQUIRED where applicable:

### 4.1 Contract-first interfaces

- CLI JSON keys and exit codes are API contracts.
- Contract changes MUST be explicit, versioned, and documented in the same PR.

### 4.2 Telemetry-first operability

- Emit machine-readable rationale (`--json`, explain metadata).
- Error classes and quality signals (for example enrich quality) MUST be explicit, not inferred.

### 4.3 AuthN/AuthZ and least privilege

- Scan paths default to least privilege and local operation.
- Any new network path MUST be explicit/opt-in and fail closed on dependency loss.

### 4.4 Externalized config, deterministic defaults

- Runtime config via flags/env/config files.
- Defaults MUST preserve offline deterministic behavior.

### 4.5 Immutable build and supply-chain integrity

- Reproducible builds, pinned dependencies, signed artifacts, SBOM/provenance.
- No floating `@latest` in CI-critical tooling.

### 4.6 Policy as code

- High-risk behavior is enforced via deterministic policy/profile rules.
- Rule IDs and remediation semantics must remain stable.

### 4.7 Failure visibility and graceful degradation

- Partial failure behavior MUST be explicit in outputs.
- Ambiguous high-risk paths MUST fail closed.

### 4.8 Backpressure and bounded work

- New loops/fan-out must define limits and deterministic ordering.
- Performance budgets must be updated when behavior changes materially.

## 5) Frugal Architecture and FinOps-by-Design

Frugality is a first-class non-functional requirement.

### 5.1 Required cost posture

- Prefer static/local analysis over remote lookups.
- Keep enrich-like network intelligence optional and explicitly non-deterministic.
- Avoid persistent background processes and hidden daemons.

### 5.2 Required PR cost note

PRs that affect scan/report/evidence/regress performance MUST include:

- CPU impact estimate (low/medium/high)
- Memory impact estimate (low/medium/high)
- I/O/network impact estimate (low/medium/high)
- Expected runtime delta for representative scenarios

### 5.3 Performance guardrails

When touching hot paths, run:

```bash
make test-perf
```

If command budgets regress, PR MUST include mitigation or approved exception.

## 6) Chaos Engineering Operating Standard

Chaos is not optional; it is a reliability gate for risk-bearing paths.

### 6.1 Required hypothesis format

Each chaos addition MUST define:

- `Steady state`: measurable normal behavior
- `Fault`: injected failure mode
- `Expected`: deterministic failure class/exit/recovery behavior
- `Abort condition`: when to stop

### 6.2 Minimum chaos coverage triggers

Add/extend chaos tests when introducing:

- New external dependency path
- New filesystem safety path
- New retry/backoff behavior
- New concurrency lock/state workflow

### 6.3 Required command

```bash
make test-chaos
```

Release-risk changes also run:

```bash
make test-hardening
```

## 7) Fowler-Style App Architecture Governance

Wrkr favors explicit boundaries and evolutionary fitness functions.

### 7.1 Design rules

- Prefer simple modular design over speculative abstractions.
- Isolate vendor/provider schema handling behind adapter boundaries.
- Avoid boundary leakage (for example risk directly reading raw source internals).
- No shared mutable global state across layers.

### 7.2 Fitness functions (must stay green)

- Determinism and byte-stability checks
- Contract and schema compatibility checks
- Fail-closed safety checks
- Scenario acceptance checks

## 8) System Architecture Best Practices (Operational)

### 8.1 Reliability

- Define expected failure behavior per command (exit code + error class).
- Keep dependency outages visible and actionable in JSON outputs.

### 8.2 Security

- No secret extraction in outputs.
- No default scan-data exfiltration.
- Treat unpinned third-party execution paths as first-class risk signals.

### 8.3 Data and evidence

- Evidence artifacts are portable, verifiable, and reproducible.
- Chain integrity remains independently verifiable.

### 8.4 Cross-product interoperability

- `Clyra-AI/proof` contracts are non-negotiable interfaces.
- Cross-product integration failures are blocking.

### 8.5 Failure/Degradation Matrix (Current Wrkr Behavior Clarification)

Use this matrix to preserve deterministic failure semantics when changing runtime behavior.

| Condition | Expected behavior class | Current signal surface |
|---|---|---|
| `scan --repo/--org` without reachable GitHub base URL | Fail closed | exit `7`, error code `dependency_missing` |
| `scan --enrich` without explicit network source | Fail closed | exit `7`, error code `dependency_missing` |
| Policy file/schema violation | Fail closed | exit `3`, error code `policy_schema_violation` |
| Production targets invalid in strict mode | Fail closed | exit `6`, error code `invalid_input` |
| Production targets invalid in non-strict mode | Graceful degradation with explicit warning | JSON warning surface (`policy_warnings`) with deterministic continuation |
| Per-repo failures during org acquisition | Partial result, deterministic failure list | `source_manifest.failures[]` populated and sorted |
| Unsafe evidence output path (non-managed/symlink/marker misuse) | Fail closed | exit `8`, error code `unsafe_operation_blocked` |

When modifying any row behavior, update:

- CLI/error contract tests
- docs command references and failure-taxonomy docs
- ADR section (per Section 9)

## 9) Required ADR for Architecture-Impacting Changes

Create/update an ADR section in PR description (or link to product ADR file) when:

- Changing boundaries or data flow between architecture layers
- Introducing a new provider/adapter dependency
- Changing contract semantics or risk model behavior
- Altering failure handling class for any command

ADR minimum template:

```text
Title:
Context:
Decision:
Alternatives considered:
Tradeoffs:
Rollback plan:
Validation plan (commands + acceptance criteria):
```

## 10) PR Gate Checklist (Must Pass)

- [ ] Boundary impact assessed; ADR provided when required
- [ ] TDD evidence included (test intent + commands run)
- [ ] Contract impact documented (JSON keys, exits, schemas)
- [ ] Failure-mode deltas documented (fail-open/fail-closed rationale)
- [ ] Cost/perf impact documented
- [ ] Required lanes executed for scope (`prepush`/`prepush-full` + risk lanes)
- [ ] Docs updated for user-visible behavior changes in same PR

## 11) Command Matrix (Architecture-focused)

| Change scope | Required command set |
|---|---|
| Standard behavior change | `make prepush` |
| Architecture/risk/adapter/failure change | `make prepush-full` |
| Contract/schema/evidence change | `make test-contracts` + `make test-scenarios` |
| Reliability/fault-tolerance change | `make test-hardening` + `make test-chaos` |
| Performance-sensitive change | `make test-perf` |

## 12) Non-goals

- This guide does not replace contributor onboarding docs.
- This guide does not redefine Wrkr product scope.
- This guide does not allow nondeterministic behavior in default scan/risk/proof paths.

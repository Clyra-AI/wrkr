---
name: code-review
description: Perform Codex-style full-repository review for Wrkr (not PR-limited), with severity-ranked findings focused on contract compatibility, boundary-enforced controls, fail-closed safety, determinism, portability, release integrity, and docs/CLI correctness.
disable-model-invocation: true
---

# Full-Repo Code Review (Wrkr)

Execute this workflow for: "review the codebase", "audit repo health", "run a full code review", or "find risks in Wrkr."

## Reviewer Personality

- Contract-first: behavior and guarantees over style.
- Boundary-first: controls enforced at execution boundaries, not prompt/UI wording.
- Regression-first: look for latent breakage paths.
- Fail-closed safety bias: block safety/control weakening.
- Determinism-first: same input/state must yield same verdict/artifact.
- Additive evolution bias: prefer compatibility-preserving contract growth.
- Core-authority bias: policy/sign/verify logic belongs in one authoritative runtime.
- Scenario-driven: each finding includes concrete break path and impact.
- Portability-aware: Linux/macOS/CI/toolchain/path behavior.
- Signal over noise: findings-first, severity-ranked output.

## Scope

- Repository root: `.`
- Review entire repo, not only current diffs.
- Prioritize high-risk surfaces first, then remaining components.

## High-Risk Surfaces (Priority Order)

1. `core/source`, `core/detect`, `core/identity`, `core/risk`, `core/proof`, `core/regress`
2. `cmd/wrkr` CLI behavior, flags, exit codes, JSON outputs
3. State/persistence and side-effect surfaces (atomic writes, lock strategy, output path ownership checks, destructive operations)
4. `core/mcp` and adapter boundaries
5. `sdk/python` wrapper behavior and error mapping
6. `schemas/v1` and compatibility-sensitive artifacts
7. CI/release gates (`.github/workflows`, required checks, post-merge monitoring)
8. `docs`, `README.md`, and `docs-site` command/contract accuracy

## Workflow

1. Build repository map and contract map from code/tests/help text:
   - stable/public vs internal surfaces
   - schema/version/CLI/exit-code/error-envelope contracts
   - deprecation/shim and migration expectations where present
2. Run baseline validation where feasible (lint/build/tests) and record gaps if not run.
3. Review each subsystem for:
   - Contract compatibility breaks before implementation logic quality
   - Boundary control placement drift (execution boundary weakened, prompt/UI boundary relied upon)
   - Safety/control bypasses
   - Fail-open behavior in ambiguous high-risk paths
   - Destructive filesystem operations on user-supplied paths without trusted ownership checks (regular-file marker validation, no marker-name-only trust)
   - Determinism or reproducibility breaks
   - Additive-evolution violations (breaking changes without compatibility path)
   - Machine-readable failure semantics drift (error taxonomy, stable JSON envelope, retryability hints)
   - Authoritative-core violations (adapters/wrappers owning policy/sign/verify logic)
   - Crash-unsafe state handling (non-atomic writes, weak locking, contention/permission gaps)
   - Unsafe side-effect patterns (missing stop controls, missing plan/apply split, unscoped approvals, missing destructive budgets)
   - Operator observability gaps (non-deterministic diagnostics, missing correlation IDs, weak local structured logs)
   - CI gate integrity drift (fast/core/acceptance/cross-platform/chaos/perf lanes not mapped to merge policy)
   - Integrity verification weakening
   - Release integrity regressions (supply-chain verification, release/post-merge regression monitoring)
   - False-green test/CI paths
   - Portability/toolchain/path assumptions
   - Finding-class boundary leaks (non-tool findings entering identity/regress tool state)
   - Lifecycle-state clobbering (`present=false` or removed identities rewritten as present)
   - Schema/CLI contract drift
   - Governance artifacts drift where required (ADR/risk register/non-goals/DoD)
   - Adoption-path breaks (quickstart path, expected outputs, integration diagrams, troubleshooting-first docs)
   - Docs/examples that do not match real behavior
4. Verify findings with concrete evidence (file refs, commands, test output).
5. Rank findings by severity and confidence.
6. Report minimum blocker set for safe release posture.

## Severity Model

- P0: release blocker, severe safety/integrity break, high reputational risk.
- P1: major behavioral regression or control bypass with real user impact.
- P2: meaningful correctness/portability/docs-contract issue.
- P3: minor maintainability concern.

## Finding Format

- `Severity`: P0/P1/P2/P3
- `Title`: short and action-oriented
- `Location`: file + line
- `Problem`: what is wrong
- `Break Scenario`: concrete failure path
- `Impact`: user/safety/CI/compliance effect
- `Fix Direction`: minimal safe correction

## Review Rules

- Findings are primary output; summaries stay brief.
- Treat contract compatibility breaks (schema/CLI/exit/error envelope) without versioned migration path as at least `P1`.
- Treat fail-open ambiguity on high-risk paths as at least `P1`.
- Treat adapter/wrapper ownership of policy/sign/verify decisions as at least `P1`.
- Treat crash-unsafe persistence or lock/contention safety gaps as at least `P1`.
- Treat release-integrity verification gaps or missing post-merge regression monitoring as at least `P1`.
- Treat recursive cleanup/delete on caller-selected paths with weak ownership gating as at least `P1`.
- Treat finding-boundary leaks that can cause false drift/exit `5` as at least `P1`.
- Treat lifecycle-state clobbering that reintroduces removed identities as at least `P2`.
- Do not report style nits unless they cause runtime/contract risk.
- Do not claim tests/commands were run if they were not.
- Separate facts from inference.
- If no findings, explicitly state `No material findings` and list residual risks/testing gaps.

## Command Anchors

- `wrkr scan --json` to verify baseline runtime diagnostics and dependency posture.
- `wrkr regress run --baseline <baseline-path> --json` to validate policy verdict/exit behavior.
- `wrkr verify --chain --json` to check artifact integrity and signature status.

## Output Contract

1. `Findings` (required, ordered by severity)
2. `Subsystem Coverage` (Green/Yellow/Red per major area)
3. `Open Questions / Assumptions` (if any)
4. `Residual Risk / Testing Gaps`
5. `Final Judgment`:
   - technical health today
   - minimum blockers (if any)
   - top 3 risk concentrations
   - contract compatibility verdict (stable/additive/breaking and migration status)
   - boundary and fail-closed verdict
   - determinism/state-safety verdict
   - release-integrity and post-merge monitoring verdict

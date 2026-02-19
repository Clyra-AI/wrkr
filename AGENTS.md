# AGENTS.md - Wrkr Repository Guide

Version: 1.0  
Last Updated: 2026-02-19  
Scope: This repository (`wrkr`) only.

## 1) Scope and Intent

- Build and maintain **Wrkr** only (the "See" product in See -> Prove -> Control).
- Do not implement Axym or Gait product features in this repo, except required interoperability via shared `Clyra-AI/proof` contracts.
- Treat these docs as authoritative for product and engineering behavior:
  - `product/wrkr.md`
  - `product/dev_guides.md`
  - `product/Clyra_AI.md`

## 2) Product North Star

Wrkr is an open-source Go CLI that discovers AI tooling across repos/orgs, scores risk, and emits compliance-ready proof artifacts.

Every change should improve one or more of:

- Discovery coverage (tools/configs/CI/headless usage)
- Risk clarity (top actionable findings, reduced noise)
- Deterministic evidence output (signed proof records, chain integrity)
- Time-to-value (fast install and useful scan output)

## 3) Non-Negotiable Engineering Constraints

- Deterministic pipeline only: **no LLM calls** in scan/risk/proof paths.
- Zero data exfiltration by default: scan data stays in user environment.
- Evidence is file-based and verifiable: output must be portable and auditable.
- Same input -> same output (inventory, risk scores, proof records), barring explicit timestamp/version fields.
- Prefer boring, auditable implementations over clever abstractions.

## 4) Required Architecture Boundaries

Keep changes aligned to these logical layers:

- Source layer (repo/org/platform inputs)
- Detection engine (tool-specific detectors)
- Aggregation engine (repo exposure + autonomy rollups)
- Identity engine (deterministic agent IDs + lifecycle)
- Risk scoring engine (blast radius, privilege, trust deficit)
- Proof emission (record creation, signing, chain append)
- Compliance mapping/evidence output

Do not collapse these boundaries in ways that reduce testability or determinism.

## 5) Detection Best Practices

Detection must prioritize structured parsing over brittle text matching.

- Parse JSON/YAML/TOML with typed or schema-backed decoders when possible.
- Avoid regex-only logic for structured configs.
- Never extract raw secrets; only flag presence/risk context.
- Every detector should return stable, explainable findings.

Minimum high-priority surfaces to preserve:

- Claude Code: `.claude/`, `CLAUDE.md`, `.mcp.json`
- Cursor: `.cursor/rules/*.mdc`, `.cursorrules`, `.cursor/mcp.json`
- Codex: `.codex/config.toml`, `.codex/config.yaml`, `AGENTS.md`, `AGENTS.override.md`
- Copilot: `.github/copilot-*`, `.vscode/mcp.json`
- Skills: `.claude/skills/`, `.agents/skills/`
- CI agent usage: `.github/workflows/`, Jenkinsfiles, headless/autonomous execution patterns
- MCP declarations, transport, annotations, and supply-chain trust signals

## 6) Identity and Risk Rules

Preserve these conventions in data model and behavior:

- Deterministic identity format: `wrkr:<tool_id>:<org>`
- Lifecycle states: `discovered`, `under_review`, `approved`, `active`, `deprecated`, `revoked`
- Autonomy levels: `interactive`, `copilot`, `headless_gated`, `headless_auto`
- Risk must include:
  - tool-level risk
  - repo aggregate exposure risk
  - autonomy/execution-context amplification
  - MCP/skill supply-chain trust effects

Findings should remain ranked and actionable (default emphasis on top risks, not noisy bulk output).

## 7) Proof and Contract Requirements

- Emit proof records using `Clyra-AI/proof` primitives.
- Keep proof record types consistent (`scan_finding`, `risk_assessment`, lifecycle/approval events).
- Maintain chain integrity and verifiability.
- Treat exit codes as API surface:
  - `0` success
  - `1` runtime failure
  - `2` verification failure
  - `3` policy/schema violation
  - `4` approval required
  - `5` regression drift
  - `6` invalid input
  - `7` dependency missing
  - `8` unsafe operation blocked

CLI output expectations:

- `--json` for machine-readable output
- `--explain` for human-readable rationale
- `--quiet` for CI-friendly operation

## 8) Toolchain and Dependency Standards

- Go is primary runtime language (single static binary model).
- Target toolchain versions:
  - Go `1.25.7`
  - Python `3.13+` (scripts/tools)
  - Node `22+` (docs/UI only; not core runtime logic)
- Use exact/pinned dependency versions where applicable.
- Avoid floating `@latest` in CI/build tooling.
- Keep `Clyra-AI/proof` dependency current with org policy (within one minor release of latest, and never below minimum supported baseline).
- For shared YAML config behavior, keep compatibility with `gopkg.in/yaml.v3`.

## 9) Testing and Validation Expectations

Any behavior change should include or update tests at the right level.

- Unit: isolated parser/scorer/mapper behavior
- Integration: cross-component deterministic behavior
- E2E: CLI behavior, output contracts, and exit codes
- Scenario/spec tests: outside-in fixtures validating intended product behavior
- Contract tests: schema/output compatibility and stable artifacts

Determinism requirements:

- Use no-cache flags where appropriate (for example `-count=1` in non-unit tiers).
- Golden outputs must be byte-stable unless intentionally updated.
- Keep benchmark/perf checks reproducible.

## 10) Security, Privacy, and Repo Hygiene

- Never commit secrets, credentials, generated binaries, or transient reports.
- Keep scans and logs scrubbed of secret values.
- Treat unpinned third-party execution paths (hooks, MCP packages, CI agent invocations) as first-class risk surfaces.
- Prefer fail-closed behavior for ambiguous high-risk conditions.

## 11) Documentation and Change Hygiene

- Keep docs and CLI behavior aligned.
- If commands, flags, exit codes, schema fields, or risk semantics change, update docs in `product/` and any user-facing command docs in the same PR.
- Keep terminology consistent with Wrkr domain language: discovery, posture, risk, identity lifecycle, proof records, regression.

## 12) Pull Request Checklist (Agent and Human)

- [ ] Change is in scope for Wrkr (not Axym/Gait product logic)
- [ ] Deterministic behavior preserved
- [ ] No scan-data exfiltration introduced
- [ ] Proof/exit-code contracts preserved or explicitly versioned
- [ ] Tests added/updated at the correct layer
- [ ] Docs updated for externally visible changes
- [ ] Dependency/toolchain changes are pinned and justified

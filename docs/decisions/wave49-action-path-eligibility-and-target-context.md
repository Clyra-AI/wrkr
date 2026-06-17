# ADR: Wave 49 Action-Path Eligibility And Target Context

Date: 2026-06-15

## Context

Wave 3 of the stdout-scale and buyer-BOM hardening plan found that Wrkr still
blurred three different things in the same buyer-facing lane:

1. executable or governable action paths
2. static target context such as OpenAPI specs, route files, and dependency-only
   signals
3. agent instruction and tool-config surfaces such as `AGENTS.md`,
   `CLAUDE.md`, `.cursor/rules`, Codex/Cursor/Claude configs, and skill files

That blur let repo-wide authority or deploy context leak onto static surfaces,
and it let buyer-facing BOM output talk about action contracts before Wrkr had
proved a real binding.

## Decision

1. Add additive action-path eligibility metadata:
   `action_path_eligible` plus `action_binding_state` with
   `bound`, `partially_bound`, `unbound_context`, and `contradictory`.
2. Treat agent instruction and tool-config files as a dedicated
   `agent_instruction_surface` path type instead of generic AI workflow text.
3. Treat dependency-only signals as a dedicated `dependency_only_signal` path
   type instead of lumping them into the generic unknown executable bucket.
4. Strip credential and authority projections from target-context surfaces when
   Wrkr cannot prove a real correlation binding.
5. Keep unbound target surfaces out of primary/top BOM slots and place them in a
   first-class Target Surface Context markdown section with explicit
   correlation-needed language.
6. Expand Action Contract readiness to separate `blocked`,
   `needs_proof_evidence`, and `needs_correlation` from the existing owner,
   approval, report-only, ready, and contradiction states.

## Consequences

- Buyer-facing output now distinguishes governable action paths from static
  context and instruction-governance surfaces.
- Static context can still remain visible and ranked as evidence-backed context,
  but it no longer automatically inherits governable status from repo-wide
  signals alone.
- Consumers that read action-path and BOM JSON must accept the additive
  `action_path_eligible`, `action_binding_state`, `agent_instruction_surface`,
  `dependency_only_signal`, and new Action Contract readiness values.

## Alternatives Considered

1. Keep the old confidence-lane model and only rewrite markdown copy.
   Rejected because JSON/BOM consumers would still see misleading semantics.
2. Remove static target surfaces from action paths entirely.
   Rejected because buyers still need correlation-needed context in the same
   saved-state artifact.
3. Make instruction surfaces always ineligible.
   Rejected because tool-bound configs can be real control surfaces when Wrkr
   has deterministic binding evidence.

## Tradeoffs

- The read model is more explicit, but it adds new additive contract fields and
  new enum values.
- Some existing scans will show fewer top action paths and more correlation
  guidance, which is intentionally more conservative.

## Rollback Plan

1. Revert the new eligibility metadata and readiness enums.
2. Restore instruction surfaces to `ai_assisted_workflow` and dependency-only
   signals to `unknown_executable_path`.
3. Re-run contract, scenario, and hardening lanes to confirm the prior BOM
   semantics are fully restored.

## Validation Plan

- `go test ./core/risk ./core/report ./core/aggregate/controlbacklog -count=1`
- `go test ./internal/scenarios -run 'TestWave3ActionPathSemanticScenario|TestTargetClassificationScenario' -count=1 -tags=scenario`
- `make test-contracts`
- `make prepush-full`

Acceptance criteria:

- unbound OpenAPI/routes/source targets stay visible but do not become the BOM
  primary path
- instruction surfaces use path-type-specific wording
- Action Contract readiness distinguishes blocked, proof-needed, and
  correlation-needed states

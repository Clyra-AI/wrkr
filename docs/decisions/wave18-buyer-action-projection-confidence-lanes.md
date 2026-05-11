# ADR: Wave 18 Buyer Action Projection and Confidence Lanes

Date: 2026-05-10
Status: accepted

## Context

Wave 1 of buyer action registry hardening requires Wrkr's buyer-facing action-path story to stay consistent across govern-first `action_paths`, top-risk report sections, Agent Action BOM output, markdown empty-state messaging, evidence bundles, and redacted share profiles. Before this change, several report surfaces recalculated or inferred posture independently, and semantic instruction findings could read too similarly to confirmed executable paths.

## Decision

1. Make Risk own one canonical action-path projector that derives confidence lane, govern-first priority, risk tier, control state, risk zone, review burden, and empty-state summary inputs.
2. Add explicit confidence lanes: `confirmed_action_path`, `likely_action_path`, `semantic_review_candidate`, and `context_only`.
3. Have report, BOM, and linked control-backlog rendering consume projected path fields instead of re-deriving buyer posture independently.
4. Replace the old positive-empty-state shortcut with reason-coded `empty_state_status` and `empty_state_reasons` metadata.
5. Preserve saved control-backlog mutations by decorating existing backlog rows from projected action paths when a backlog is already present, rather than blindly rebuilding it during report generation.

## Rationale

- A single projector keeps buyer-facing artifacts deterministic and internally coherent.
- Explicit confidence lanes let Wrkr surface semantic review signals without overstating execution authority.
- Reason-coded empty-state metadata is safer than inferring "clean" posture from the absence of one count.
- Decorating existing backlog rows preserves lifecycle and approval mutations that intentionally happen without rescanning.

## Consequences

- Govern-first path ordering now factors confidence-lane semantics in addition to delivery, credential, production, and approval signals.
- Report JSON, markdown, evidence bundles, and Agent Action BOM summaries now expose additive lane and empty-state metadata.
- Semantic instruction/config signals remain visible, but they read as review candidates rather than confirmed executable control paths.

# ADR: Wave 12 Packaged Action Wrapper

Date: 2026-03-26
Status: accepted

## Context

Wrkr already had CLI-based action surfaces and a repo-local wrapper under `action/`, but the launch plan required a real packaged GitHub Action surface with explicit inputs, outputs, and scheduled-mode behavior that stayed thin over the CLI.

## Decision

1. Ship a repo-root `action.yml` composite action as the packaged automation surface.
2. Keep `scripts/action_entrypoint.sh` as the single implementation entrypoint.
3. Preserve `action/action.yaml` and `action/entrypoint.sh` as compatibility shims so internal paths and older references do not drift during the transition.
4. Expose deterministic outputs for mode, summary path, posture score, trend delta, compliance delta, and SARIF path.

## Rationale

- A composite wrapper keeps distribution thin and auditable.
- Centralizing logic in one entrypoint prevents the packaged action from diverging from CLI behavior.
- Explicit outputs make scheduled-mode posture deltas useful in downstream workflows without inventing a service dependency.
- Compatibility shims reduce churn while the repo moves from local wrapper to packaged surface.

## Consequences

- Public docs can truthfully reference a packaged action surface in the Wrkr repo.
- Scheduled remediation dispatch remains explicit and repo-targeted; non-repo remediation requests fail closed.
- Action CI now covers both the root action package and the shared entrypoint implementation.

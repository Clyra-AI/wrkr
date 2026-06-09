---
name: adhoc-plan
description: Convert user-provided recommendations into a timestamped, execution-ready backlog plan using the active repo profile. Use when a repo needs a one-off plan that should not overwrite PLAN_NEXT.
disable-model-invocation: true
---

# Adhoc Plan

This is a local discovery wrapper for the shared Factory skill at `factory/skills/adhoc-plan/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/adhoc-plan/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/adhoc-plan/SKILL.md` and follow that Factory skill using the active `wrkr` repo profile unless the user provides another explicit profile.

Project wrapper policy:

- Write generated plans under profile `plan_output_dir`, currently `product/plans/adhoc`.
- Treat the PR as plan-only for local validation: run lightweight plan validation only, and do not run full repo validation before PR creation.
- After PR creation, follow the Factory skill's shipping and merge process exactly, including the shared `commit-push` land gate for PR checks, Codex review, branch protection, merge, default-branch sync, and any profile-configured post-merge behavior.
- If branch protection, review, permissions, or policy blocks merge inside the Factory/shared shipping gate, report the concrete blocker.

Do not treat this wrapper as the source of truth for plan content. The Factory skill is authoritative for the generated plan structure.
Do not treat this wrapper as an override for Factory merge, CI polling, Codex review, or post-merge rules.

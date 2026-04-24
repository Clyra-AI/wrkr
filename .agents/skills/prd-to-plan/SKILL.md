---
name: prd-to-plan
description: Convert a profile-defined PRD or product contract into a zero-ambiguity execution plan with repo paths, story-level validation, API/contract mapping, docs/OSS readiness, and CI matrix wiring.
disable-model-invocation: true
---

# PRD To Plan

This is a local discovery wrapper for the shared Factory skill at `factory/skills/prd-to-plan/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/prd-to-plan/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/prd-to-plan/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

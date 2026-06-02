---
name: plan-verify-repair
description: Verify implemented Factory plans against original source requirements, run all required validation lanes, create a repair branch when gaps exist, and fix gaps until all requirements are satisfied.
disable-model-invocation: true
---

# Plan Verify Repair

This is a local discovery wrapper for the shared Factory skill at `factory/skills/plan-verify-repair/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/plan-verify-repair/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/plan-verify-repair/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

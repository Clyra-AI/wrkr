---
name: validation-gate
description: Run visible deterministic checks and decide promotion readiness. Use after execution to validate the patch against required commands, test lanes, and contract checks.
disable-model-invocation: true
---

# Validation Gate

This is a local discovery wrapper for the shared Factory skill at `factory/skills/validation-gate/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/validation-gate/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/validation-gate/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

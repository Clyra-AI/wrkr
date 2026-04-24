---
name: ship-pr
description: Turn a validated change into a pull request and drive it through CI and merge policy. Use when a branch is ready to ship and the workflow allows PR creation or merge progression.
disable-model-invocation: true
---

# Ship PR

This is a local discovery wrapper for the shared Factory skill at `factory/skills/ship-pr/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/ship-pr/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/ship-pr/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

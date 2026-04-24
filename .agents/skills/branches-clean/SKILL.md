---
name: branches-clean
description: Delete non-default local and configured-remote branches one-by-one using the active repo profile, safety checks, and a final prune/report.
disable-model-invocation: true
---

# Branches Clean

This is a local discovery wrapper for the shared Factory skill at `factory/skills/branches-clean/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/branches-clean/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/branches-clean/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

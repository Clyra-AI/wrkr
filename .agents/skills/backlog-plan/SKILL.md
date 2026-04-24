---
name: backlog-plan
description: Convert repo-owned strategic ideas into a timestamped, execution-ready backlog plan using the active repo profile.
disable-model-invocation: true
---

# Backlog Plan

This is a local discovery wrapper for the shared Factory skill at `factory/skills/backlog-plan/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/backlog-plan/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/backlog-plan/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

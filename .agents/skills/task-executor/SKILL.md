---
name: task-executor
description: Implement one bounded task packet inside an isolated workspace. Use when the system has explicit task scope, allowed paths, commands, and acceptance checks for a builder worker.
disable-model-invocation: true
---

# Task Executor

This is a local discovery wrapper for the shared Factory skill at `factory/skills/task-executor/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/task-executor/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/task-executor/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

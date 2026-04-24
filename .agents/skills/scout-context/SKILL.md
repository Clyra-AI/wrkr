---
name: scout-context
description: Gather the smallest useful context set for a work item. Use when a worker needs relevant files, constraints, risks, and related changes without loading the entire repository.
disable-model-invocation: true
---

# Scout Context

This is a local discovery wrapper for the shared Factory skill at `factory/skills/scout-context/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/scout-context/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/scout-context/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

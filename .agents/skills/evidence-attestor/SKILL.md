---
name: evidence-attestor
description: Attach and verify provenance for shipped proof packets or externally consumed artifacts. Use when policy, workflow, or shipping requires tamper-evident evidence.
disable-model-invocation: true
---

# Evidence Attestor

This is a local discovery wrapper for the shared Factory skill at `factory/skills/evidence-attestor/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/evidence-attestor/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/evidence-attestor/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

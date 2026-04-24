---
name: repo-audit
description: Audit a repository against the factory operating model. Use when a team needs a gap assessment for repo contracts, standards compliance, workflow readiness, safety posture, or evidence completeness.
disable-model-invocation: true
---

# Repo Audit

This is a local discovery wrapper for the shared Factory skill at `factory/skills/repo-audit/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/repo-audit/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/repo-audit/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

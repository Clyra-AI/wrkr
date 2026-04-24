---
name: app-audit
description: Run a profile-driven evidence-based OSS/product readiness audit across product model, onboarding, architecture, DX, security, release readiness, and market wedge.
disable-model-invocation: true
---

# App Audit

This is a local discovery wrapper for the shared Factory skill at `factory/skills/app-audit/SKILL.md`.

Before using this skill:

1. Verify `factory/skills/app-audit/SKILL.md` exists.
2. If it is missing, stop and ask the user to run:

```bash
git submodule update --init factory
```

Then read `factory/skills/app-audit/SKILL.md` and follow that Factory skill exactly, using the active `wrkr` repo profile unless the user provides another explicit profile.

Do not treat this wrapper as the source of truth. The Factory skill is authoritative.

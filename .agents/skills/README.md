# Wrkr Skill Wrappers

`.agents/skills/` contains local discovery wrappers for shared Factory development-process skills, local Factory maintenance, and Wrkr-specific local skills.

Shared wrapper and maintenance skills kept in this project:

- `adhoc-plan`
- `app-audit`
- `backlog-plan`
- `branches-clean`
- `code-review`
- `commit-push`
- `cut-release`
- `factory-sync`
- `plan-implement`

Project-local skills kept in this project:

- `initial-plan`
- `pr-comments`

The shared Factory skill at `factory/skills/<name>/SKILL.md` is authoritative for Factory-backed wrappers. `factory-sync` is a local maintenance wrapper for updating the Factory submodule pointer.

Requirements:

1. No secrets, private tokens, or non-public operational endpoints in skill files.
2. Keep instructions deterministic, contract-safe, and fail-closed.
3. Use only repository-scoped, auditable command guidance.
4. Follow governance policy: [`docs/governance/content-visibility.md`](../../docs/governance/content-visibility.md).

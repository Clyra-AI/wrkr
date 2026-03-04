# Governance: Content Visibility Policy

This policy defines what content is allowed in `product/` and `.agents/skills/` for the public Wrkr repository.

## Policy A: `product/` visibility

`product/` is public by default and is intended for planning, architecture, and product intent artifacts relevant to Wrkr OSS delivery.

Allowed content:

- Roadmaps, plans, architecture notes, and execution checklists.
- Publicly shareable requirements and acceptance criteria.
- Redacted audit/review summaries that avoid sensitive operational detail.

Prohibited content:

- Secrets, credentials, tokens, internal URLs, or private customer identifiers.
- Unredacted internal security findings that reveal exploit details.
- Personal data or non-public incident details.

Enforcement:

- Any sensitive details must be removed or replaced with redacted placeholders before commit.
- If a plan requires private context, store private material outside this repository and link only to a non-sensitive summary.

## Policy B: `.agents/skills/` visibility

`.agents/skills/` is public and treated as a transparency artifact for deterministic contributor/automation workflows.

Allowed content:

- Skill workflow instructions, deterministic command sequences, and repository-scoped guidance.
- References to public repo paths, tests, and validation commands.

Prohibited content:

- Embedded secrets, private API endpoints, non-public tokens, or privileged operational procedures not suitable for OSS disclosure.
- Instructions that weaken fail-closed, determinism, or contract safety guarantees.

Enforcement:

- Keep skill files instructional and deterministic; no environment-specific secret handling instructions.
- Review skill updates with the same contract rigor as CLI/docs changes.

## Directory notices and review checklist

- `product/README.md` and `.agents/skills/README.md` are required directory notices.
- PRs touching either directory must include:
  - policy conformance statement
  - redaction confirmation (if applicable)
  - docs/test validation evidence

# Cross-Repo README Contract (Wrkr-first)

This document defines the required README structure shared across Wrkr/Proof/Gait repositories.

## Required sections

1. Install
2. First 10 Minutes
3. Integration
4. Command Surface
5. Governance and Support

## Section requirements

### Install

- Include at least one pinned install path.
- Include minimal-dependency guidance (no hidden mandatory helpers).
- Include verification command(s) after install.

### First 10 Minutes

- Foreground the developer-machine path before the org/audit path.
- Include the copy-paste sequence `wrkr scan --my-setup`, `wrkr mcp-list`, `wrkr scan --github-org`, `wrkr inventory --diff`.
- Show deterministic `--json` command anchors.
- Include one concrete personal-setup output example with realistic privilege findings.
- Link to canonical state lifecycle behavior.

### Integration

- Provide CI-adoption workflow and gate semantics.
- Clarify standalone usage vs optional ecosystem integrations.
- Link to deeper integration docs.

### Command Surface

- Enumerate stable command families.
- Reference JSON/exit-code contract expectations.

### Governance and Support

- Link contributing, security policy, code of conduct, changelog, and issue workflows.
- Include docs source-of-truth guidance.

## Validation

Run:

```bash
make test-docs-consistency
make test-docs-storyline
```

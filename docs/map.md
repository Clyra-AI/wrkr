# Docs Source-of-Truth Map

This page defines where to edit and how to validate docs changes.

## Source-of-truth model

| Surface | Edit location | Validation commands |
|---|---|---|
| Product/readme landing content | `README.md` | `make test-docs-consistency` |
| Command contracts | `docs/commands/*.md` | `make test-docs-consistency` |
| Workflow and operator docs | `docs/examples/*.md`, `docs/intent/*.md`, `docs/state_lifecycle.md` | `make test-docs-consistency && make test-docs-storyline` |
| Governance/trust docs | `docs/trust/*.md`, `docs/governance/*.md`, `CONTRIBUTING.md`, community health files | `make test-docs-consistency` |
| Docs-site rendering | `docs-site/` (layout and static pages only) | `make docs-site-install && make docs-site-lint && make docs-site-build && make docs-site-check` |
| LLM snapshots for assistants/crawlers | `docs-site/public/llms.txt`, `docs-site/public/llm/*.md` | `make test-docs-consistency && make docs-site-check` |

## Editing rule

Edit canonical documentation in repository markdown first (`README.md` + `docs/`), then update docs-site-specific projection files when needed.

## Required validation bundle

Run this bundle before merge when docs are touched:

```bash
make test-docs-consistency
make test-docs-storyline
make docs-site-install
make docs-site-lint
make docs-site-build
make docs-site-check
```

## Trust positioning reference

Wrkr runs standalone for deterministic discovery/posture/evidence workflows and interoperates with Axym/Gait via shared proof contracts.

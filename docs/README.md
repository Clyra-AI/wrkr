---
title: "Wrkr Documentation Map"
description: "Canonical map of Wrkr docs, with normative surfaces and ownership boundaries."
---

# Wrkr Documentation Map

This file defines where each topic lives so docs remain contract-aligned and non-duplicative.
For editing/validation workflow, see [`docs/map.md`](map.md).

## Canonical Surface Taxonomy

- Discovery and posture
- Risk and ranking
- Identity lifecycle
- Proof and evidence
- Regression and CI gating

## Start Here

1. `README.md` for product overview and first-run value.
2. `docs/examples/quickstart.md` for the evaluator-safe scenario-first workflow.
3. `docs/examples/security-team.md` for the hosted org posture path after the scenario pass.
4. `docs/concepts/mental_model.md` for boundary and workflow model.
5. `docs/architecture.md` for deterministic pipeline boundaries.
6. `docs/integration_checklist.md` for adoption in CI.
7. `docs/commands/index.md` for command contract references.
8. `docs/install/minimal-dependencies.md` for the pinned/reproducible install contract.

## Technical Foundations

- Architecture: `docs/architecture.md`
- Mental model: `docs/concepts/mental_model.md`
- State lifecycle (canonical local artifact paths): `docs/state_lifecycle.md`
- Failure taxonomy and exits: `docs/failure_taxonomy_exit_codes.md`
- Policy authoring: `docs/policy_authoring.md`
- Built-in policy rules: `docs/policy_builtin_rules.md`
- Extension detectors: `docs/extensions/detectors.md`
- Threat model: `docs/threat_model.md`

## Contracts and Trust

- Manifest spec: `docs/specs/wrkr-manifest.md`
- Compatibility and versioning policy: `docs/trust/compatibility-and-versioning.md`
- Compatibility matrix: `docs/contracts/compatibility_matrix.md`
- README cross-repo contract: `docs/contracts/readme_contract.md`
- Install contract: `docs/install/minimal-dependencies.md`
- Deterministic guarantees: `docs/trust/deterministic-guarantees.md`
- goja AST-only guardrails: `docs/trust/goja-ast-only.md`
- MCP enrich quality model: `docs/trust/mcp-enrich-quality-model.md`
- Proof verification: `docs/trust/proof-chain-verification.md`
- Security and privacy posture: `docs/trust/security-and-privacy.md`

## Operator and Adoption

- Adopt in one PR: `docs/adopt_in_one_pr.md`
- Integration checklist: `docs/integration_checklist.md`
- Command quickstart: `docs/examples/quickstart.md`
- Operator playbooks: `docs/examples/operator-playbooks.md`
- Prompt-channel + attack-path runbook: `docs/intent/detect-prompt-channel-and-attack-path-risk.md`
- Evidence templates: `docs/evidence_templates.md`

## Positioning and GTM

- Positioning: `docs/positioning.md`
- FAQ: `docs/faq.md`
- Intent guides: `docs/intent/*.md`
- Cross-repo README alignment tracker: `docs/roadmap/cross-repo-readme-alignment.md`

## Community and Support

- Contributing guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Changelog: `CHANGELOG.md`

## Ownership Rules

- `docs/commands/*` and `docs/specs/*` are command/spec contract anchors.
- `docs/trust/*` is the canonical machine-readable trust layer.
- If a user-visible command behavior changes, docs must be updated in the same change.

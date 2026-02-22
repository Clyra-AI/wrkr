---
title: "Wrkr Documentation Map"
description: "Canonical map of Wrkr docs, with normative surfaces and ownership boundaries."
---

# Wrkr Documentation Map

This file defines where each topic lives so docs remain contract-aligned and non-duplicative.

## Canonical Surface Taxonomy

- Discovery and posture
- Risk and ranking
- Identity lifecycle
- Proof and evidence
- Regression and CI gating

## Start Here

1. `README.md` for product overview and first-run value.
2. `docs/concepts/mental_model.md` for boundary and workflow model.
3. `docs/architecture.md` for deterministic pipeline boundaries.
4. `docs/integration_checklist.md` for adoption in CI.
5. `docs/commands/index.md` for command contract references.

## Technical Foundations

- Architecture: `docs/architecture.md`
- Mental model: `docs/concepts/mental_model.md`
- Failure taxonomy and exits: `docs/failure_taxonomy_exit_codes.md`
- Policy authoring: `docs/policy_authoring.md`
- Threat model: `docs/threat_model.md`

## Contracts and Trust

- Manifest spec: `docs/specs/wrkr-manifest.md`
- Compatibility matrix: `docs/contracts/compatibility_matrix.md`
- Deterministic guarantees: `docs/trust/deterministic-guarantees.md`
- Proof verification: `docs/trust/proof-chain-verification.md`
- Security and privacy posture: `docs/trust/security-and-privacy.md`

## Operator and Adoption

- Adopt in one PR: `docs/adopt_in_one_pr.md`
- Integration checklist: `docs/integration_checklist.md`
- Command quickstart: `docs/examples/quickstart.md`
- Operator playbooks: `docs/examples/operator-playbooks.md`
- Evidence templates: `docs/evidence_templates.md`

## Positioning and GTM

- Positioning: `docs/positioning.md`
- FAQ: `docs/faq.md`
- Intent guides: `docs/intent/*.md`

## Ownership Rules

- `docs/commands/*` and `docs/specs/*` are command/spec contract anchors.
- `docs/trust/*` is the canonical machine-readable trust layer.
- If a user-visible command behavior changes, docs must be updated in the same change.

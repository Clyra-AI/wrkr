---
title: "Evidence Templates"
description: "Template structures for sharing Wrkr posture and evidence outputs with engineering, security, and audit stakeholders."
---

# Evidence Templates

## Executive Summary Template

- Scope: repo/org/path target and scan date.
- Top findings: highest-risk deterministic findings.
- Posture summary: score/grade and profile status.
- Drift status: baseline compare result.

## Operator Template

- Command execution set.
- Output paths and JSON keys verified.
- Exit code outcomes.
- Next deterministic remediation actions.

## Audit Packet Template

- `wrkr evidence` output manifest path.
- Proof chain verification result.
- Framework coverage summary.
- Control evidence status (`control-evidence.json`) showing existing and missing proof for approval, owner, least-privilege, rotation, deployment-gate, production-access, and review-cadence requirements.
- Contract references (`docs/specs/wrkr-manifest.md`, `docs/contracts/compatibility_matrix.md`).

## Command Anchors

```bash
wrkr report --top 5 --json
wrkr score --json
wrkr evidence --frameworks eu-ai-act,soc2 --output ./.tmp/evidence --json
wrkr verify --chain --json
```

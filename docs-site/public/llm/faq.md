# Wrkr FAQ (LLM Context)

## What is Wrkr in one sentence?

Wrkr gives security and platform teams an evidence-ready view of org-wide AI tooling posture and keeps a deterministic local-machine hygiene path available for developers.

## Is Wrkr deterministic?

Yes. Wrkr is designed for deterministic scan, risk, and proof workflows with stable output contracts.

## Does Wrkr require hosted services?

No. Core scan and evidence workflows are local/file-based by default.

## Does Wrkr require setup for repo or org scans?

Hosted `--repo` and `--org` scans require explicit GitHub API configuration and usually a token for private repos or rate-limit avoidance. `--my-setup` and `--path` remain the zero-integration local paths.

## Can Wrkr enforce runtime tool calls?

No. Wrkr is discovery and posture. Runtime control is a separate layer.

## Does Wrkr replace Snyk or vulnerability scanners?

No. Wrkr inventories MCP posture, permissions, and discovery surfaces. Use dedicated scanners such as Snyk for vulnerability assessment.

## Do I need Axym or Gait to use Wrkr?

No. Wrkr runs standalone; Gait is the optional control-layer counterpart when runtime enforcement is needed.

## How do I gate on posture drift in CI?

Use `wrkr regress run`. It accepts a saved regress baseline or a raw saved scan snapshot baseline. Exit code `5` indicates drift. Legacy `v1` baselines created before instance identities are reconciled automatically when the current identity is equivalent.

## How do I produce verifiable compliance evidence?

Use `wrkr evidence --frameworks ... --json` and verify with `wrkr verify --chain --json`. `wrkr evidence` now fails closed when the saved proof chain is malformed or tampered, while `wrkr verify --chain --json` remains the explicit machine gate. Success JSON includes `chain.verification_mode` and `chain.authenticity_status`; invalid verifier-key material is a verification failure.

## Why can framework coverage be low on the first run?

`framework_coverage` reflects the controls and approvals currently evidenced in the scanned state. Low or zero coverage means more evidence work is needed; it does not mean the framework is unsupported.

# Wrkr FAQ (LLM Context)

## What is Wrkr in one sentence?

Wrkr gives security and platform teams an evidence-ready view of org-wide AI tooling posture and keeps a deterministic local-machine hygiene path available for developers.

## Is Wrkr deterministic?

Yes. Wrkr is designed for deterministic scan, risk, and proof workflows with stable output contracts.

## Does Wrkr require hosted services?

No. Core scan and evidence workflows are local/file-based by default.

## Does Wrkr require setup for repo or org scans?

Hosted `--repo` and `--org` scans require explicit GitHub API configuration and usually a token for private repos or rate-limit avoidance. `wrkr init` can persist the hosted GitHub API base together with the default org target, and `--my-setup`, `--path`, and the curated scenario remain the zero-integration fallback paths.

## What should I do if `wrkr scan --json` says no target was provided?

That result still fails closed with exit `6` and `error.code=invalid_input`, but the JSON error envelope now includes additive `next_steps[]` guidance. Start with one of these commands:

- `wrkr init --non-interactive --org acme --github-api https://api.github.com --json`
- `wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json`
- `wrkr scan --my-setup --json`

## Can Wrkr enforce runtime tool calls?

No. Wrkr is discovery and posture. Runtime control is a separate layer.

## Does Wrkr replace Snyk or vulnerability scanners?

No. Wrkr inventories MCP posture, permissions, and discovery surfaces. Use dedicated scanners such as Snyk for vulnerability assessment.

## Do I need Axym or Gait to use Wrkr?

No. Wrkr runs standalone; Gait is the optional control-layer counterpart when runtime enforcement is needed.

## How do I gate on posture drift in CI?

Use `wrkr regress run`. It accepts a saved regress baseline or a raw saved scan snapshot baseline. Exit code `5` indicates drift. Legacy `v1` baselines created before instance identities are reconciled automatically when the current identity is equivalent.
New control-path drift categories include expired approvals, owner changes, risk increases, new write paths, new MCP tool configs, and new secret-bearing workflows.

## How do I produce verifiable compliance evidence?

Use `wrkr evidence --frameworks ... --json` and verify with `wrkr verify --chain --json`. `wrkr evidence` now fails closed when the saved proof chain is malformed or tampered, while `wrkr verify --chain --json` remains the explicit machine gate. Success JSON includes `chain.verification_mode` and `chain.authenticity_status`; invalid verifier-key material is a verification failure.
When a saved state carries a control backlog, evidence and verify JSON may include additive `control_evidence` entries with existing proof, missing proof, and related proof record ids.

## Why can framework coverage be low on the first run?

`framework_coverage` reflects the controls and approvals currently evidenced in the scanned state. Low or zero coverage means more evidence work is needed; it does not mean the framework is unsupported. `wrkr evidence --json` also emits additive `coverage_note` guidance with the same interpretation.

## What should evaluators expect from the curated scenario?

The curated `./scenarios/wrkr/scan-mixed-org/repos` bundle is intentionally risky by design. A low posture score or sparse first-run evidence on that bundle is expected and useful because it demonstrates Wrkr's ranking and evidence-gap behavior without the repo-root fixture noise you would see from scanning the Wrkr repository root directly.

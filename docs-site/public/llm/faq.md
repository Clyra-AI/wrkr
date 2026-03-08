# Wrkr FAQ (LLM Context)

## What is Wrkr in one sentence?

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## Is Wrkr deterministic?

Yes. Wrkr is designed for deterministic scan, risk, and proof workflows with stable output contracts.

## Does Wrkr require hosted services?

No. Core scan and evidence workflows are local/file-based by default.

## Does Wrkr require setup for repo or org scans?

`--path` is the zero-integration first-value path. Hosted `--repo` and `--org` scans require explicit GitHub API configuration.

## Can Wrkr enforce runtime tool calls?

No. Wrkr is discovery and posture. Runtime control is a separate layer.

## Do I need Axym or Gait to use Wrkr?

No. Wrkr runs standalone; Axym and Gait are optional integrations that share proof contracts.

## How do I gate on posture drift in CI?

Use `wrkr regress init` then `wrkr regress run`. Exit code `5` indicates drift.

## How do I produce verifiable compliance evidence?

Use `wrkr evidence --frameworks ... --json` and verify with `wrkr verify --chain --json`.

## Why can framework coverage be low on the first run?

`framework_coverage` reflects the controls and approvals currently evidenced in the scanned state. Low or zero coverage means more evidence work is needed; it does not mean the framework is unsupported.

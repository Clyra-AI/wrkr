# Wrkr FAQ (LLM Context)

## What is Wrkr in one sentence?

Wrkr evaluates your AI dev tool configurations across your GitHub repo/org against policy. Posture-scored, compliance-ready.

## Is Wrkr deterministic?

Yes. Wrkr is designed for deterministic scan, risk, and proof workflows with stable output contracts.

## Does Wrkr require hosted services?

No. Core scan and evidence workflows are local/file-based by default.

## Can Wrkr enforce runtime tool calls?

No. Wrkr is discovery and posture. Runtime control is a separate layer.

## How do I gate on posture drift in CI?

Use `wrkr regress init` then `wrkr regress run`. Exit code `5` indicates drift.

## How do I produce verifiable compliance evidence?

Use `wrkr evidence --frameworks ... --json` and verify with `wrkr verify --chain --json`.

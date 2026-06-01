# ADR: Wave 27 Deployment Mode Metadata

Date: 2026-05-31
Status: accepted

## Context

Wave 2 of the GTM, packaging, and scale-gates plan needs Wrkr to make the
customer data boundary explicit across scan, report, and evidence artifacts.
Operators need a deterministic way to declare whether the surrounding operating
model is strictly local, customer-controlled storage, connected SaaS metadata,
or managed platform without confusing that declaration with live network
behavior, hosted uploads, or source retention changes.

## Decision

1. Add one canonical additive `deployment_mode` contract shared by scan, report,
   evidence, source-privacy metadata, and portable evidence manifests.
2. Use exactly four normalized values:
   `local_only`, `customer_controlled_storage`,
   `connected_saas_metadata`, and `managed_platform`.
3. Default `deployment_mode` to `local_only` whenever no explicit alternate mode
   is supplied.
4. Keep deployment mode as descriptive metadata only. It must not by itself
   enable network calls, hosted uploads, source retention, or managed execution.
5. Preserve deployment mode through redacted/customer-safe artifacts so buyers
   and security reviewers can see the declared posture without exposing private
   evidence paths.

## Rationale

- One shared enum keeps scan, report, evidence, and source-privacy contracts in
  sync instead of letting each surface invent different posture labels.
- Defaulting to `local_only` preserves Wrkr's existing local-first, zero-default
  exfiltration posture.
- Treating deployment mode as metadata, not behavior, prevents accidental
  coupling between customer posture declarations and scanner execution paths.
- Keeping the label through redacted artifacts helps customer review workflows
  explain the data boundary without widening artifact content.

## Consequences

- `wrkr scan --json`, `wrkr report --json`, `wrkr evidence --json`, report
  summaries, evidence bundle manifests, and source-privacy metadata now all
  carry additive `deployment_mode`.
- `source_privacy.deployment_mode` mirrors the same value inside the richer
  privacy contract.
- Docs and customer-review workflows can now explain the declared data posture
  directly from machine-readable artifacts.
- Future public-surface, website, or packaging work must reuse this shared
  deployment-mode contract instead of adding parallel posture labels.

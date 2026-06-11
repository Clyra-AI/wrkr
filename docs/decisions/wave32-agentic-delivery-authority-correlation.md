# ADR: Wave 32 Agentic Delivery-System Authority Correlation

Date: 2026-06-10
Status: accepted

## Context

Wave 3 of the scan-output-signal-hardening plan requires Wrkr to treat
instruction, skillpack, MCP, and agent-rule edits as delivery-system changes
when they can actually reach meaningful authority. Before this change, those
surfaces were visible as ordinary config or semantic-review paths, which made it
hard to distinguish:

1. a low-signal instruction file with no reachable authority
2. a skill or tool config that can publish, deploy, or reuse standing
   credentials
3. a path that is additionally exposed to review-bypass risk because local
   provenance says protections or approvals are missing or conflicting

## Decision

1. Add one canonical `agentic_delivery_system_change` projection for delivery
   surfaces only: instructions, skillpacks, agent rules, MCP configs, and tool
   configs.
2. Derive authority impact from existing govern-first facts instead of inventing
   a new execution model. Production mutation, deploy or release authority,
   credential reach, write scope, and review-bypass risk are all projected from
   existing action-path, provenance, and control-evidence fields.
3. Keep review-state reasoning deterministic and bounded. Missing approval,
   protected review, partial review evidence, and review-bypass risk are exposed
   directly, while buyer-facing BOM output can add bounded reachable-tool and
   reachable-target summaries without duplicating another control model.

## Consequences

- Buyer-facing BOM output now calls out delivery-system changes as first-class
  governance changes instead of burying them in generic config rows.
- Ranking favors the reachable authority of a delivery-system change rather than
  the mere existence of a changed prompt or config artifact.
- Bare instruction files without meaningful authority stay visible but do not
  crowd out higher-impact delivery-system changes.

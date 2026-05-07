# ADR: Wave 16 Cross-Detector Reachability Signals

Date: 2026-05-07
Status: accepted

## Context

Wave 3 requires Wrkr to explain real MCP and agent paths without inventing joins across unrelated repos or locations. Before this change, the buyer-facing BOM could only project reachability when multiple findings happened to share the same file location, which missed common repo-level joins such as “this source-bound LangChain tool calls the MCP server declared elsewhere in the repo.”

## Decision

1. Keep authoritative detection findings separate from candidate findings.
2. Add normalized MCP and framework candidate evidence to saved state instead of promoting them directly into inventory.
3. Correlate buyer-facing BOM reachability by deterministic repo/location and repo/name joins only.
4. Preserve explicit confidence and evidence-strength labels on source-level framework findings so customer output can distinguish constructor-only, tool-binding, credential-bearing, and workflow-backed evidence.

## Rationale

- Candidate findings let Wrkr explain likely MCP/framework presence without overclaiming an authoritative server or action path.
- Repo/name joins are strong enough for saved-state buyer output while still fail-closed against unrelated cross-repo matches.
- Confidence labels improve customer readability without introducing probabilistic or generative behavior.

## Consequences

- `wrkr mcp-list` can now report `found`, `candidate_only`, `reduced_coverage`, or `not_detected` from saved state.
- Buyer-facing BOM output can project reachable endpoints and deployment targets and can join source-bound tool names back to saved MCP server declarations in the same repo.
- Low-confidence candidates stay out of authoritative inventory and govern-first ranking until stronger source/config evidence exists.

# ADR: Wave 22 Workflow Chain, Graph V2, and Intent Lineage

Date: 2026-05-26
Status: accepted

## Context

Wave 2 of the Sprint 3 Agentic SDLC plan needs Wrkr to describe delegated delivery paths as more than isolated action-path rows. Before this change, Wrkr had deterministic action paths, a first-generation control-path graph, and buyer-facing lineage segments, but it did not expose a stable workflow-chain artifact, could not model intent or PR/MR joins as first-class graph nodes, and forced downstream consumers to infer end-to-end delivery flow from loosely related fields.

## Decision

1. Add a first-class deterministic `workflow_chains` artifact that groups action paths by repo, PR/MR, workflow, task/intent source, tool, credential, owner, approval, target, evidence, and outcome keys.
2. Keep workflow-chain refs additive on action paths and Agent Action BOM items so downstream consumers can join into the artifact without reparsing graph internals.
3. Extend `control_path_graph` additively with V2 node kinds for intent, task, human identity, agent team, PR/MR, approval identity, policy identity, deployment path, asset identity, evidence identity, workflow run, CI/CD run, and outcome.
4. Extend `action_lineage.segments[]` additively with intent, task, human, PR, workflow-run, control, deployment, outcome, and evidence segments while preserving the existing repo/workflow/agent/action/credential/target/owner/approval/proof chain.
5. Rebuild graph, workflow-chain refs, and lineage from the same decorated action-path projection so report, backlog, and evidence surfaces stay deterministic and joinable.

## Rationale

- Buyers need one deterministic object that represents delegated SDLC flow end to end.
- Graph V2 should be additive so existing graph consumers keep working while newer report surfaces gain more structure.
- Workflow chains and lineage are different views over the same path facts; deriving them from one projection avoids drift.
- Explicit unknown states are safer than silently omitting missing PR, approval, or outcome metadata.

## Consequences

- Risk-report, report-summary, evidence-bundle, and Agent Action BOM contracts now expose workflow-chain refs and a top-level workflow-chain artifact.
- Public and redacted report paths must sanitize the new workflow-chain labels, refs, and provenance surfaces alongside existing graph and lineage joins.
- Future provenance sidecars, evidence packets, and focused BOM experiences can extend these artifacts instead of inventing separate delivery-flow models.

## Validation Plan

- `go test ./core/aggregate/agentresolver ./core/aggregate/attackpath ./core/risk ./core/report ./testinfra/contracts -count=1`
- `make test-contracts`
- `scripts/validate_scenarios.sh`
- Acceptance criteria:
  - Workflow chains collapse duplicate paths deterministically and emit explicit unknown PR/outcome states.
  - Control Path Graph V2 carries additive node and edge kinds plus summary rollups.
  - Action-path and BOM outputs expose workflow-chain refs and extended lineage segments without breaking existing consumers.

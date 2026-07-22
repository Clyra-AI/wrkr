# Wrkr Schemas v1

This directory contains versioned JSON/YAML schemas for Wrkr runtime and artifact contracts.

- `cli/`: shared CLI success/error envelope contracts.
- `assess/assessment-manifest.schema.json`: canonical repeatable-assessment manifest contract for `wrkr assess` output directories.
- `agent-action-bom.schema.json`: canonical Agent Action BOM artifact contract for report and evidence outputs.
- `composed-action-path.schema.json`, frozen `proposed-action-contract.schema.json` (v2), and `proposed-action-contract-v3.schema.json`: deterministic report-only proposed Action Contract surfaces. Embeddings accept explicit v2/v3 alternatives; v3 keeps required authority, observed evidence, typed readiness/effect preconditions, confirmation/approval/compensation, and immutable revision/lifecycle evidence distinct. The composition schema also accepts the bounded three-to-five-stage pattern IDs, ordered system/trust-boundary/correlation fields, alternate-route refs, explicit truncation receipts, and separate `reachability_state` / `observed_execution` claims.
- `proposed-action-contract-artifact.schema.json`: opt-in portable envelope v1 with RFC 8785 JCS digest, redaction variant, durable source/composition refs, and a v3 contract payload.
- `report/action-contract-packet.schema.json`: opt-in buyer packet v1 projected from one normalized portable artifact, with bounded path, authority, credential, readiness, effect, approval, compensation, evidence-gap, and imported-lifecycle sections shared by JSON and Markdown.
- `scenarios/cross-product/action-contract-interop/expected/fixture-manifest.json`: release-level fixture contract pinning exact production-generated artifact/packet bytes to producer version, artifact schema `1`, contract schema `3`, packet schema `1`, identities, and SHA-256 digests. Regenerate with the explicit check/update script; never hand-author downstream projections.
- `evidence/external-control-evidence.schema.json`: canonical local sidecar contract for imported ownership, approval, branch, deployment, and policy control evidence.
- `evidence/control-declarations.schema.json`: canonical local declaration contract for owners, targets, controls, and review dispositions.
- `evidence/agentic-evidence-packets.schema.json`: canonical local sidecar contract for typed Agentic SDLC evidence packets.
- `external-control-evidence.schema.json` is the canonical local external sidecar schema for ownership, approval, freshness, branch/deployment constraints, and control evidence refs.
- `provenance/pr-mr-provenance.schema.json`: canonical local sidecar contract for provider-neutral PR/MR provenance, reviewers, approvals, checks, deployments, branch protections, and environment gates.
- `proof-outputs/lifecycle-transition-record.schema.json`, `proof-outputs/evidence-record.schema.json`, and `proof-outputs/decision-trace-record.schema.json`: Wrkr-specific proof record type schemas registered at emission time and usable with standalone `proof verify --custom-type-schema` for per-record schema validation.
- `evidence/external-control-evidence.schema.json`: local provider evidence may correlate directly to an immutable proposed Action Contract ID or family/revision and carry typed, producer-bounded Gait/Axym lifecycle observations. Those observations remain outside contract content/scope identity and are never Wrkr-owned transitions.
- Local declaration inputs now also include versioned `wrkr-control-declarations.yaml` / `.wrkr/control-declarations.yaml` semantics for declared owners, target classes, non-production paths, control evidence links, review dispositions, and stable `resolution_key` / selector correlation.
- Action-path, report-summary, BOM, and regress baseline contracts now also carry additive `resolution_key`, selector-fallback trace fields, and review-lifecycle input metadata so recurring customer review loops survive harmless `path_id` churn.
- Agent Action BOM, report summary, and risk-report schemas now also carry additive policy-coverage, buyer-facing action-path posture (`control_state`, `risk_zone`, `review_burden`), normalized runtime-evidence/Gait coverage projection, additive imported control-evidence correlation metadata (`constraint_evidence_classes`, `constraint_evidence_refs`, external-control record counts, repo/service/workflow/environment correlation keys), optional `introduced_by` attribution fields, additive `agentic_delivery_system_change` and `decision_trace_refs` projection fields, nested provider-neutral provenance detail, additive evidence-packet correlation fields, and the additive `github_workflow_token` credential kind used by the demo-readiness control-loop workflows.
- The same v1 contracts now also carry additive provider-neutral runtime/model/host fields, retained-state posture refs/digests, canonical `agent_identity` read-model projections, thin `decision_precedent` context, and bounded `delivery_control_context` fields for harness/resolver/eval validation requirements.
- Agent Action BOM summary now also carries additive `primary_view` workflow-BOM and composition fields for the default or explicit `--focus-path` selection: selected `path_id`, optional leading `composition_id`, bounded `composition_stage_map[]`, selection reason, path map, credential/delegation/target summaries, current coverage, proposed control, expected outcome, proposed Action Contract refs, evidence/control posture, additive `risk_tier`, additive concise `recommended_next_actions[]`, additive `coverage_status`, and appendix refs.
- Decision trace records and evidence bundles carry additive composition correlation refs (`resolution_key`, `composition_ids[]`, `proposed_action_contract_refs[]`, `workflow_chain_refs[]`, and `composition_refs[]`) so Gait and Axym joins do not need heuristic matching.
- Report-summary and Agent Action BOM summary contracts now also carry additive `repeat_usage_signals` fields that count privacy-safe local artifact families such as baselines, assess reruns, regress artifacts, evidence exports, ticket exports, and action-contract exports.
- Report-summary contracts also include additive `evidence_packets` and `recent_pr_review` surfaces for local PR/MR review workflows that stay offline by default.
- Report-summary contracts also include additive `workflow_highlights` and `focus_view` sections for workflow-first buyer reports and named low-click review presets.
- Regress baseline/result contracts now also carry additive action-path and composition comparison state (`action_paths_captured`, `action_paths[]`, ordered multi-stage semantics, reachability/correlation/alternate-route evidence, `comparison_status`, `comparison_issues[]`, `drift_category_count`, and `drift_categories[]`) so recurring drift review can fail closed without implying a clean no-drift result.
- Agent Action BOM summary contracts now also carry additive `drift_review` metadata when report or assess output is baseline-backed.
- Action-path and BOM contracts also carry additive `evidence_decisions[]` and `contradictions[]` for source precedence, freshness, rejected candidates, and enterprise-evidence conflicts.
- Report and BOM action-path contracts also carry `closure_requirements`, `lifecycle_queue`, `governance_disposition`, and `evidence_completeness` so accepted-risk, suppression, closure guidance, lifecycle ownership work, and evidence sufficiency stay explicit in v1.
- Risk-report, report-summary, and Agent Action BOM contracts now also carry additive `composed_action_paths[]`, `composed_action_path_to_control_first`, `composition_ids[]`, and `proposed_action_contract_refs[]` fields. Composition stage roles live inside the `composed_action_path` object, while `proposed_action_contract.report_only=true` preserves the boundary that Wrkr proposes controls and Gait/runtime systems enforce them. Version 3 adds `revision`, optional `supersedes_ref`, and `lifecycle_observations[]`; imported Gait/Axym observations are evidence references, not Wrkr-owned transitions.
- `findings/`: finding and extension-detector descriptor contracts.
- `inventory/` and `risk/`: deterministic privilege, credential-provenance, action-path, and govern-first contracts.
- `manifest/`: open `wrkr-manifest.yaml` interoperability specification.
- `regress/`: posture regression baseline and drift-result contracts.
- `report/`: deterministic shareable report-summary contracts, including additive design-partner summary mode, expanded share-profile metadata, action-surface registry remediation, and field-selection redaction metadata.

Canonical enum additions in the v1 schema line include:

- `control_resolution_state`: `detected_control`, `declared_control`, `external_control_reference`, `no_visible_control`, `not_applicable`, `contradictory_control`
- canonical evidence states: `verified`, `declared`, `inferred`, `unknown`, `contradictory`
- freshness states: `fresh`, `stale`, `expired`, `unknown`
- `target_class`: `production_impacting`, `release_adjacent`, `customer_data_adjacent`, `internal_tooling`, `developer_productivity`, `test_demo_sandbox`, `unknown`
- `action_path_type`: `ai_assisted_workflow`, `agent_framework`, `automation_bot`, `ci_cd_workflow`, `legacy_script`, `plain_source_code`, `unknown_executable_path`
- coverage-qualified absence states: `not_found_with_complete_coverage`, `not_found_with_reduced_coverage`, `not_scanned`, `unsupported_surface`, `candidate_parse_failed`
- runtime absence states: `not_collected`, `not_applicable`, `missing_required`, `missing_for_control_claim`
- composition stage roles: `source`, `transform`, `sink`, `internal_sink`, `external_sink`, `privileged_sink`, `destructive_sink`
- composition claim states: `static_only`, `partially_evidenced`, `declared_policy_only`, `runtime_controlled`, `observed_execution`, `contradictory`, `unknown`
- composition system classes: `repo`, `ci`, `package`, `cloud`, `saas`, `communications`, `unknown`
- composition reachability states: `possible`, `incomplete`, `observed`
- composition truncation reasons: `depth_cap`, `path_cap`, `candidate_cap`, `reference_cap`

Compatibility aliases can remain present in v1 where existing consumers still expect them, but schema examples and user-facing docs should lead with the canonical evidence-state fields instead of unsupported blanket `missing_*` wording.

Deterministic Sprint 2 example fixtures live under `testinfra/contracts/fixtures/sprint2/` and cover `external-control-evidence.schema.json`, `wrkr-control-declarations.yaml`, report action-path evidence decisions, contradictions, accepted-risk governance, lifecycle queue items, and `evidence_completeness`.

# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-4611e5399b5c85b9
- Artifact: paca-e29630c61873abe6
- Contract: pac-3d718739c1914c4f
- Family: pacf-f1ebb01ae13ce9bf
- Revision: 1
- Supersedes: none
- Contract digest: sha256:7194462741f8c6f95e4463d56bea9d99ce3666b68b9a87d08432391f2508dc24
- Artifact digest: sha256:e29630c61873abe6841c696c7630a748443b30c860327ab57520d9d31082f092
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-91a21be2ceb5, wch-b24d4aaedc8e
- Report only: true

## Composed Path

- Composition: cap-110b7a48410900f0
- Pattern: secret_to_network
- Target: built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Outcome: network_egress
- Reachability: possible static reachability; not observed execution
- Stage `cas-3fb346f96b15e310`: role=source tool=codex location=AGENTS.md actions=read evidence=unknown freshness=unknown
- Stage `cas-5b17487c1de956a8`: role=external_sink tool=claude location=.mcp.json actions=deploy, egress, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-df1a9edce4333f58` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation
- `pacr-eb142f1e80dbf354` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation
- `pacr-ff39fdf73a19c65a` credential_subject_constraint: required=credential_subject:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation
- `pacr-77a91a5d884609db` delegation_root: required=delegation_root:required observed=authority-b29daa99b287a631 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation
- `pacr-1e822b4b44b7bfe9` originating_intent: required=originating_task_or_intent:required observed=intent:mcp integration evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation
- `pacr-534ec8f882bb7859` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation
- `pacr-985a0005058f38e5` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation
- `pacr-37582334526ef3c5` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation
- `pacr-9fbb747ec221020d` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation

## Credential Posture

- Required mode: ephemeral
- Evidence: unknown
- Freshness: unknown
- Requirement refs: pacp-c1e4062e25a98c76, pacr-37582334526ef3c5, pacr-ff39fdf73a19c65a
- Wrkr activation grant: false

## Readiness Checks

- `pacp-c1e4062e25a98c76` credential_mode: required=credential_mode:ephemeral observed=ephemeral result=ephemeral evidence=unknown freshness=unknown producers=credential_authority
- `pacp-023911ca32ab295e` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-f80dd381e63e83b0` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ffdd4bb0e947a53d` expected_effect: required=effect:network_egress observed=network_egress result=network_egress evidence=unknown freshness=unknown producers=action_path
- `pacp-cea9561fb612c48d` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b28c78e6ec3ec93e` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-e8b88ec8fb850e44` policy_digest: required=policy_digest:required observed=sha256:5ab243ed873402f27d5c600d28e33936b7d939c2251e1c02a4bd89f512c2b4fe result=sha256:5ab243ed873402f27d5c600d28e33936b7d939c2251e1c02a4bd89f512c2b4fe evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-27a4bcfeae5f0ee0` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-7dff3acf9ea3ad1b` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-6377b2020e999ba5` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-84b68ba57822f176` target: required=target:bounded observed=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a result=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a evidence=unknown freshness=unknown producers=action_path
- `pacp-8e55dfaf69f07a02` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: network_egress
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=false kind=not_required procedure=not_recorded target=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a window=PT24H verification_required=false evidence=verified freshness=unknown

## Evidence Gaps

- `pacr-df1a9edce4333f58` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-eb142f1e80dbf354` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-ff39fdf73a19c65a` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:missing, authority:credential_subject_constraint:unknown
- `pacr-77a91a5d884609db` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-1e822b4b44b7bfe9` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-534ec8f882bb7859` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-985a0005058f38e5` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-37582334526ef3c5` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-9fbb747ec221020d` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `pacp-c1e4062e25a98c76` precondition:credential_mode: evidence=unknown freshness=unknown reasons=precondition:credential_mode:unknown
- `pacp-023911ca32ab295e` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-f80dd381e63e83b0` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-ffdd4bb0e947a53d` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-cea9561fb612c48d` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-b28c78e6ec3ec93e` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-e8b88ec8fb850e44` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-27a4bcfeae5f0ee0` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-7dff3acf9ea3ad1b` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-6377b2020e999ba5` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-84b68ba57822f176` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-8e55dfaf69f07a02` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-59aafb497f6e4421` proposal_creation from wrkr: evidence=verified freshness=fresh refs=interop:secret-to-network proof=proof:interop:secret-to-network

## Presentation Limits

- authority_requirements.pacr-1e822b4b44b7bfe9.evidence_refs: reason=item_cap omitted=9
- authority_requirements.pacr-37582334526ef3c5.evidence_refs: reason=item_cap omitted=9
- authority_requirements.pacr-534ec8f882bb7859.evidence_refs: reason=item_cap omitted=9
- authority_requirements.pacr-77a91a5d884609db.evidence_refs: reason=item_cap omitted=9
- authority_requirements.pacr-985a0005058f38e5.evidence_refs: reason=item_cap omitted=9
- authority_requirements.pacr-9fbb747ec221020d.evidence_refs: reason=item_cap omitted=9
- authority_requirements.pacr-df1a9edce4333f58.evidence_refs: reason=item_cap omitted=9
- authority_requirements.pacr-eb142f1e80dbf354.evidence_refs: reason=item_cap omitted=9
- authority_requirements.pacr-ff39fdf73a19c65a.evidence_refs: reason=item_cap omitted=9
- readiness_checks.pacp-023911ca32ab295e.evidence_refs: reason=item_cap omitted=9
- readiness_checks.pacp-27a4bcfeae5f0ee0.evidence_refs: reason=item_cap omitted=9
- readiness_checks.pacp-6377b2020e999ba5.evidence_refs: reason=item_cap omitted=9
- truncations: 9 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-df1a9edce4333f58 before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

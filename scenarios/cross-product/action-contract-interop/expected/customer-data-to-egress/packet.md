# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-9a4d740747ac39d4
- Artifact: paca-bbaba1fc508e21ae
- Contract: pac-df3e7ad71c8ff97b
- Family: pacf-e23713ce8893f35c
- Revision: 1
- Supersedes: none
- Contract digest: sha256:f6334b210b3086f7f3d7e104fb3b84543c4c66c99fce0a8f2759926c1ff024e1
- Artifact digest: sha256:bbaba1fc508e21ae4cff1e4668cf97b63367e6f08e059c38e1acfcd528490b7c
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-91a21be2ceb5, wch-b994b4ec715e
- Report only: true

## Composed Path

- Composition: cap-0b34926aa0a8d7d1
- Pattern: sensitive_read_to_egress
- Target: built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Outcome: data_egress
- Reachability: possible static reachability; not observed execution
- Stage `cas-6f18acfc4d46a22c`: role=source tool=claude location=.mcp.json actions=deploy, egress, read, write evidence=unknown freshness=unknown
- Stage `cas-5f33b6f63f24d412`: role=external_sink tool=mcp location=.mcp.json actions=deploy, egress, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-a4bdc949eaad9c4c` affected_system_owner: required=affected_system_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation, permission:deploy.write
- `pacr-3166070f4672b095` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation, permission:deploy.write
- `pacr-8e48fa96f1ed5293` credential_subject_constraint: required=subject:built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a observed=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation, permission:deploy.write
- `pacr-96ff1d0e53c55655` delegation_root: required=delegation_root:required observed=authority-b29daa99b287a631 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation, permission:deploy.write
- `pacr-623233d18274f3d0` originating_intent: required=composition:cap-0b34926aa0a8d7d1 observed=sensitive_read_to_egress evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation, permission:deploy.write
- `pacr-e9aa5c9846905ea3` permitted_agent_role: required=roles:external_sink,source observed=external_sink,source evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation, permission:deploy.write
- `pacr-8d6aed260bc01053` policy_authority: required=policy_authority:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation, permission:deploy.write
- `pacr-8d80e37c9abc01b9` requester_identity: required=requester_identity:required observed=stage:cas-6f18acfc4d46a22c evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation, permission:deploy.write
- `pacr-26619ec37de99aec` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy, mutable_endpoint_semantic:production_mutation, permission:deploy.write

## Credential Posture

- Required mode: ephemeral
- Evidence: unknown
- Freshness: unknown
- Requirement refs: pacp-13dbf78718fdaa5f, pacr-8d80e37c9abc01b9, pacr-8e48fa96f1ed5293
- Wrkr activation grant: false

## Readiness Checks

- `pacp-13dbf78718fdaa5f` credential_mode: required=credential_mode:ephemeral observed=ephemeral result=ephemeral evidence=unknown freshness=unknown producers=credential_authority
- `pacp-a93d1426ceaa825c` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-50ee2b6957cae33b` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-1cbc019327bf1354` expected_effect: required=effect:data_egress observed=data_egress result=data_egress evidence=unknown freshness=unknown producers=action_path
- `pacp-4690e9900499f4a5` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ed70870b3ac4a843` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-5afb4bb9dad2c634` policy_digest: required=policy_digest:required observed=sha256:0cc8fccb07377946636ef6a08731103e648422e5884acc4c4619026f2183df41 result=sha256:0cc8fccb07377946636ef6a08731103e648422e5884acc4c4619026f2183df41 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-2287b403a530fc9b` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-e0d2df8d59c09de8` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-f93a7c7e8e061325` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-1191a2f2fb249216` target: required=target:bounded observed=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a result=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a evidence=unknown freshness=unknown producers=action_path
- `pacp-09eb6ad8fd5ca2e9` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: data_egress
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=false kind=not_required procedure=not_recorded target=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a window=PT24H verification_required=false evidence=verified freshness=unknown

## Evidence Gaps

- `pacr-a4bdc949eaad9c4c` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:missing, authority:affected_system_owner:unknown
- `pacr-3166070f4672b095` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-8e48fa96f1ed5293` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-96ff1d0e53c55655` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-623233d18274f3d0` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-e9aa5c9846905ea3` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:unknown
- `pacr-8d6aed260bc01053` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:missing, authority:policy_authority:unknown
- `pacr-8d80e37c9abc01b9` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:unknown
- `pacr-26619ec37de99aec` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `pacp-13dbf78718fdaa5f` precondition:credential_mode: evidence=unknown freshness=unknown reasons=precondition:credential_mode:unknown
- `pacp-a93d1426ceaa825c` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-50ee2b6957cae33b` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-1cbc019327bf1354` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-4690e9900499f4a5` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-ed70870b3ac4a843` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-5afb4bb9dad2c634` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-2287b403a530fc9b` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-e0d2df8d59c09de8` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-f93a7c7e8e061325` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-1191a2f2fb249216` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-09eb6ad8fd5ca2e9` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-6bde8ed5d5994de4` proposal_creation from wrkr: evidence=verified freshness=fresh refs=interop:customer-data-to-egress proof=proof:interop:customer-data-to-egress

## Presentation Limits

- approval_requirement.evidence_refs: reason=item_cap omitted=10
- authority_requirements.pacr-26619ec37de99aec.evidence_refs: reason=item_cap omitted=10
- authority_requirements.pacr-3166070f4672b095.evidence_refs: reason=item_cap omitted=10
- authority_requirements.pacr-623233d18274f3d0.evidence_refs: reason=item_cap omitted=10
- authority_requirements.pacr-8d6aed260bc01053.evidence_refs: reason=item_cap omitted=10
- authority_requirements.pacr-8d80e37c9abc01b9.evidence_refs: reason=item_cap omitted=10
- authority_requirements.pacr-8e48fa96f1ed5293.evidence_refs: reason=item_cap omitted=10
- authority_requirements.pacr-96ff1d0e53c55655.evidence_refs: reason=item_cap omitted=10
- authority_requirements.pacr-a4bdc949eaad9c4c.evidence_refs: reason=item_cap omitted=10
- authority_requirements.pacr-e9aa5c9846905ea3.evidence_refs: reason=item_cap omitted=10
- compensation_requirement.evidence_refs: reason=item_cap omitted=10
- confirmation_requirement.evidence_refs: reason=item_cap omitted=10
- truncations: 12 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-a4bdc949eaad9c4c before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

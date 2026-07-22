# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-f8f4fab3f412b01a
- Artifact: paca-52c5b8b751de2460
- Contract: pac-a1fca3a904d2d74f
- Family: pacf-e23713ce8893f35c
- Revision: 1
- Supersedes: none
- Contract digest: sha256:118e6e21f3c4fcf273c4101b926863aa27450014df9bb2fb61d078d808dcc41d
- Artifact digest: sha256:52c5b8b751de2460bfbb2868918826afcfd03e733fa19186e981941354b2e509
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

- `pacr-a4bdc949eaad9c4c` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:deploy control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy
- `pacr-3166070f4672b095` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:deploy control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy
- `pacr-b9fe356efabde989` credential_subject_constraint: required=credential_subject:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:deploy control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy
- `pacr-96ff1d0e53c55655` delegation_root: required=delegation_root:required observed=authority-b29daa99b287a631 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:deploy control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy
- `pacr-5e5ee94abc102c65` originating_intent: required=originating_task_or_intent:required observed=intent:deploy control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:deploy control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy
- `pacr-579900eb3b2d53e5` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:deploy control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy
- `pacr-8d6aed260bc01053` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:deploy control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy
- `pacr-8d80e37c9abc01b9` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:deploy control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy
- `pacr-26619ec37de99aec` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, deploy-control, intent:deploy control, intent:mcp integration, matched_target:built_in:deploy_workflow, mutable_endpoint_semantic:deploy

## Credential Posture

- Required mode: ephemeral
- Evidence: unknown
- Freshness: unknown
- Requirement refs: pacp-13dbf78718fdaa5f, pacr-8d80e37c9abc01b9, pacr-b9fe356efabde989
- Wrkr activation grant: false

## Readiness Checks

- `pacp-13dbf78718fdaa5f` credential_mode: required=credential_mode:ephemeral observed=ephemeral result=ephemeral evidence=unknown freshness=unknown producers=credential_authority
- `pacp-a93d1426ceaa825c` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-50ee2b6957cae33b` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-1cbc019327bf1354` expected_effect: required=effect:data_egress observed=data_egress result=data_egress evidence=unknown freshness=unknown producers=action_path
- `pacp-4690e9900499f4a5` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ed70870b3ac4a843` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-5afb4bb9dad2c634` policy_digest: required=policy_digest:required observed=sha256:177a3d5e883bea48caf239da2bed7259f239e548d52808875566190c2060d703 result=sha256:177a3d5e883bea48caf239da2bed7259f239e548d52808875566190c2060d703 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-2287b403a530fc9b` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
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

- `pacr-a4bdc949eaad9c4c` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-3166070f4672b095` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-b9fe356efabde989` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:missing, authority:credential_subject_constraint:unknown
- `pacr-96ff1d0e53c55655` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-5e5ee94abc102c65` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-579900eb3b2d53e5` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-8d6aed260bc01053` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-8d80e37c9abc01b9` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
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

- authority_requirements.pacr-26619ec37de99aec.evidence_refs: reason=item_cap omitted=14
- authority_requirements.pacr-3166070f4672b095.evidence_refs: reason=item_cap omitted=14
- authority_requirements.pacr-579900eb3b2d53e5.evidence_refs: reason=item_cap omitted=14
- authority_requirements.pacr-5e5ee94abc102c65.evidence_refs: reason=item_cap omitted=14
- authority_requirements.pacr-8d6aed260bc01053.evidence_refs: reason=item_cap omitted=14
- authority_requirements.pacr-8d80e37c9abc01b9.evidence_refs: reason=item_cap omitted=14
- authority_requirements.pacr-96ff1d0e53c55655.evidence_refs: reason=item_cap omitted=14
- authority_requirements.pacr-a4bdc949eaad9c4c.evidence_refs: reason=item_cap omitted=14
- authority_requirements.pacr-b9fe356efabde989.evidence_refs: reason=item_cap omitted=14
- readiness_checks.pacp-09eb6ad8fd5ca2e9.evidence_refs: reason=item_cap omitted=14
- readiness_checks.pacp-1191a2f2fb249216.evidence_refs: reason=item_cap omitted=14
- readiness_checks.pacp-13dbf78718fdaa5f.evidence_refs: reason=item_cap omitted=14
- truncations: 9 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-a4bdc949eaad9c4c before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

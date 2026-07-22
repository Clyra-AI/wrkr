# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-16700cff8b802af0
- Artifact: paca-2afbe229b04068fd
- Contract: pac-19d425bca289c621
- Family: pacf-b22999eccf014a87
- Revision: 1
- Supersedes: none
- Contract digest: sha256:6562698efba00c8dfa63743bea2d5c1bcb90f0de0b593f7823fab2772f51bf53
- Artifact digest: sha256:2afbe229b04068fdf8f6c383e23d2fb035da2a0ec7c032d534c2f5490dcf1385
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-2514b320edea, wch-b994b4ec715e
- Report only: true

## Composed Path

- Composition: cap-14bc8696b685eccb
- Pattern: workflow_mutation_to_production
- Target: built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Outcome: production_mutation
- Reachability: possible static reachability; not observed execution
- Stage `cas-ebbb0e503d3a0ab1`: role=transform tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown
- Stage `cas-51c04b56e19390e4`: role=privileged_sink tool=mcp location=.mcp.json actions=deploy, egress, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-17616b39cf505d8d` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-e14e49d8501c137a` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-db4739815ffa2d01` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key,provena … [truncated] evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-8e59eeb4a0d9aa01` delegation_root: required=delegation_root:required observed=authority-b3aed31f4204875e evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-5f5ed7532d8cd055` originating_intent: required=originating_task_or_intent:required observed=intent:deploy control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-301b879263e7180a` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-6be6c0dd308dd851` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-968ce78cf764fa89` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-c7c800831e94b9c1` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-6dbd9e0015c58d68, pacr-968ce78cf764fa89, pacr-db4739815ffa2d01
- Wrkr activation grant: false

## Readiness Checks

- `pacp-6dbd9e0015c58d68` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-d4ab6b89b9a791c6` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-df4fe901e3522cae` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-a83b4afadfd1e1ae` expected_effect: required=effect:production_mutation observed=production_mutation result=production_mutation evidence=unknown freshness=unknown producers=action_path
- `pacp-85a14bd4660c2dbc` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-1ddd128516d5191f` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-38254e8db383d489` policy_digest: required=policy_digest:required observed=sha256:fad9fbe43288241247b6f78a25ff629fddcea7ee67a6558b278d599ce58ff270 result=sha256:fad9fbe43288241247b6f78a25ff629fddcea7ee67a6558b278d599ce58ff270 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-0de20de770d00f59` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-70e25bc76ed6f83a` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-acc4f8836f1a5545` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ac91f9e944a181f0` target: required=target:bounded observed=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a result=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a evidence=unknown freshness=unknown producers=action_path
- `pacp-9b785ff47eaa3d2d` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: production_mutation
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=true kind=documented_recovery procedure=not_recorded target=built_in:deploy_workflow+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a window=PT24H verification_required=true evidence=unknown freshness=unknown

## Evidence Gaps

- `pacr-17616b39cf505d8d` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-e14e49d8501c137a` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-db4739815ffa2d01` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-8e59eeb4a0d9aa01` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-5f5ed7532d8cd055` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-301b879263e7180a` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-6be6c0dd308dd851` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-968ce78cf764fa89` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-c7c800831e94b9c1` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `pacp-6dbd9e0015c58d68` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-d4ab6b89b9a791c6` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-df4fe901e3522cae` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-a83b4afadfd1e1ae` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-85a14bd4660c2dbc` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-1ddd128516d5191f` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-38254e8db383d489` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-0de20de770d00f59` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-70e25bc76ed6f83a` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-acc4f8836f1a5545` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-ac91f9e944a181f0` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-9b785ff47eaa3d2d` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-bface16c61e2f236` proposal_creation from wrkr: evidence=verified freshness=fresh refs=interop:workflow-to-deploy proof=proof:interop:workflow-to-deploy

## Presentation Limits

- authority_requirements.pacr-17616b39cf505d8d.evidence_refs: reason=item_cap omitted=33
- authority_requirements.pacr-301b879263e7180a.evidence_refs: reason=item_cap omitted=33
- authority_requirements.pacr-5f5ed7532d8cd055.evidence_refs: reason=item_cap omitted=33
- authority_requirements.pacr-6be6c0dd308dd851.evidence_refs: reason=item_cap omitted=33
- authority_requirements.pacr-8e59eeb4a0d9aa01.evidence_refs: reason=item_cap omitted=33
- authority_requirements.pacr-968ce78cf764fa89.evidence_refs: reason=item_cap omitted=33
- authority_requirements.pacr-c7c800831e94b9c1.evidence_refs: reason=item_cap omitted=33
- authority_requirements.pacr-db4739815ffa2d01.evidence_refs: reason=item_cap omitted=33
- authority_requirements.pacr-db4739815ffa2d01.observed_value: reason=value_rune_cap omitted=20
- authority_requirements.pacr-e14e49d8501c137a.evidence_refs: reason=item_cap omitted=33
- readiness_checks.pacp-0de20de770d00f59.evidence_refs: reason=item_cap omitted=33
- readiness_checks.pacp-1ddd128516d5191f.evidence_refs: reason=item_cap omitted=33
- truncations: 10 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-17616b39cf505d8d before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

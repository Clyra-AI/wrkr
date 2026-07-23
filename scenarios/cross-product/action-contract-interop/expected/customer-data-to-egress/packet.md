# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-3935a04d2bd40619
- Artifact: paca-727514ab02593894
- Contract: pac-aa15bb4cb576f32f
- Family: pacf-e93233d7c6817604
- Revision: 1
- Supersedes: none
- Contract digest: sha256:8a87d12fc99f0ac05cd1654c2640d97f72bde4ce2fbc1250c1d3c6ebe08b8dd9
- Artifact digest: sha256:727514ab02593894bd09e6c293a4e4d73f8c8d47b97c06a1828f40900fc7be99
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-b994b4ec715e, wch-bd1e152cd6ba
- Report only: true

## Composed Path

- Composition: cap-3c6d2db68ff522d4
- Pattern: sensitive_read_to_egress
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Outcome: data_egress
- Reachability: possible static reachability; not observed execution
- Stage `cas-930ac179f9997975`: role=source tool=ci_agent location=.github/workflows/release.yml actions=credential_access, deploy, execute, read, write evidence=unknown freshness=unknown
- Stage `cas-5f33b6f63f24d412`: role=external_sink tool=mcp location=.mcp.json actions=deploy, egress, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-b34c8d4507cf346e` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-a3a918dd502318e6` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-975b3ddf3d62967e` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-bae32c341d559409` delegation_root: required=delegation_root:required observed=authority-bfc23b0d135943e8 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-7b7d1173d70c8fc7` originating_intent: required=originating_task_or_intent:required observed=intent:deploy control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-57a0dbe454ea0b3a` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-dc9a7b08532121e0` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-72966071e6b62b53` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-3ed3d065e4f61c7c` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-5bc25e393a8d1f2a, pacr-72966071e6b62b53, pacr-975b3ddf3d62967e
- Wrkr activation grant: false

## Readiness Checks

- `pacp-5bc25e393a8d1f2a` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-4d3acc50f2443a38` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-145a103fd5514a60` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b3b6b72f451e0cc9` expected_effect: required=effect:data_egress observed=data_egress result=data_egress evidence=unknown freshness=unknown producers=action_path
- `pacp-807fb488594c7ec5` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-c35deb063d257ec5` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-604868f6eec03ba9` policy_digest: required=policy_digest:required observed=sha256:bc694b0c6d64468c1f1f052cbfa90e1d5dd2831f3c0febbfcad62390e2a3d846 result=sha256:bc694b0c6d64468c1f1f052cbfa90e1d5dd2831f3c0febbfcad62390e2a3d846 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-292cd5b8b3d6b7fe` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-ec46d03c011aeef4` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-dc7b25fcf11945be` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-a8a8d3279a82bb15` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a evidence=unknown freshness=unknown producers=action_path
- `pacp-45ba207bd5c9adae` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: data_egress
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=false kind=not_required procedure=not_recorded target=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a window=PT24H verification_required=false evidence=verified freshness=unknown

## Evidence Gaps

- `pacr-b34c8d4507cf346e` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-a3a918dd502318e6` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-975b3ddf3d62967e` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-bae32c341d559409` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-7b7d1173d70c8fc7` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-57a0dbe454ea0b3a` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-dc9a7b08532121e0` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-72966071e6b62b53` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-3ed3d065e4f61c7c` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `pacp-5bc25e393a8d1f2a` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-4d3acc50f2443a38` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-145a103fd5514a60` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-b3b6b72f451e0cc9` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-807fb488594c7ec5` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-c35deb063d257ec5` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-604868f6eec03ba9` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-292cd5b8b3d6b7fe` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-ec46d03c011aeef4` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-dc7b25fcf11945be` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-a8a8d3279a82bb15` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-45ba207bd5c9adae` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-6bde8ed5d5994de4` proposal_creation from wrkr: evidence=verified freshness=fresh refs=interop:customer-data-to-egress proof=proof:interop:customer-data-to-egress

## Presentation Limits

- authority_requirements.pacr-3ed3d065e4f61c7c.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-57a0dbe454ea0b3a.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-72966071e6b62b53.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-7b7d1173d70c8fc7.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-975b3ddf3d62967e.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-a3a918dd502318e6.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-b34c8d4507cf346e.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-bae32c341d559409.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-dc9a7b08532121e0.evidence_refs: reason=item_cap omitted=43
- readiness_checks.pacp-145a103fd5514a60.evidence_refs: reason=item_cap omitted=43
- readiness_checks.pacp-292cd5b8b3d6b7fe.evidence_refs: reason=item_cap omitted=43
- readiness_checks.pacp-45ba207bd5c9adae.evidence_refs: reason=item_cap omitted=43
- truncations: 9 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-b34c8d4507cf346e before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

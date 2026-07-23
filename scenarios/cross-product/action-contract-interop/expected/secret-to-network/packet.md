# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-20f45a95e1c2a155
- Artifact: paca-866d80c44d8ac5ea
- Contract: pac-38d7ba888b960130
- Family: pacf-7320bf2d792fead5
- Revision: 1
- Supersedes: none
- Contract digest: sha256:f75bbf3ce9fa7b87ac95cbea26706b083b329a8b94666f5eaaa175f4ce29836a
- Artifact digest: sha256:866d80c44d8ac5ea3d4d74eb24b2c46c58c2bd1cd1baa8488bccc00191c79a6c
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-b994b4ec715e, wch-bd1e152cd6ba
- Report only: true

## Composed Path

- Composition: cap-4094e4563b004b86
- Pattern: secret_to_network
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a
- Outcome: network_egress
- Reachability: possible static reachability; not observed execution
- Stage `cas-930ac179f9997975`: role=source tool=ci_agent location=.github/workflows/release.yml actions=credential_access, deploy, execute, read, write evidence=unknown freshness=unknown
- Stage `cas-5f33b6f63f24d412`: role=external_sink tool=mcp location=.mcp.json actions=deploy, egress, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-e5cba36563e4deaa` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-151dc49115e7affb` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-90cd47595b50fd75` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-5f4c3be74d16d164` delegation_root: required=delegation_root:required observed=authority-bfc23b0d135943e8 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-1f937b8a35c72658` originating_intent: required=originating_task_or_intent:required observed=intent:deploy control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-d5b4fdcb8f458b5e` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-77d5c0d0e259d142` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-e8811b91b1070f48` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-caf2d346e179c9a0` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-52a1722ed9d740d8, pacr-90cd47595b50fd75, pacr-e8811b91b1070f48
- Wrkr activation grant: false

## Readiness Checks

- `pacp-52a1722ed9d740d8` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-795a0d9562f842df` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-9957f68f70a09db9` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-3ac68c1d671df0b2` expected_effect: required=effect:network_egress observed=network_egress result=network_egress evidence=unknown freshness=unknown producers=action_path
- `pacp-78ab14f4d77657a0` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-7bf8d1910bc3fd7c` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-cdd5cc5e32af09a8` policy_digest: required=policy_digest:required observed=sha256:8ab6dac93685ff6bfa2f7fef5fa91ab2e548c06c082e7bae4c833be90a2592f2 result=sha256:8ab6dac93685ff6bfa2f7fef5fa91ab2e548c06c082e7bae4c833be90a2592f2 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-e63bfaadbc62c1f8` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-ce44d5bc8d88f3e9` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-2bf0afbc3a43823b` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ef4ee50d2abca2ee` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a evidence=unknown freshness=unknown producers=action_path
- `pacp-2db95af791369cd2` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: network_egress
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=false kind=not_required procedure=not_recorded target=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation+endpoint:(surface=mcp,operation=deploy-control)+endpoint_group:meg-a0626bd85b5a window=PT24H verification_required=false evidence=verified freshness=unknown

## Evidence Gaps

- `pacr-e5cba36563e4deaa` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-151dc49115e7affb` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-90cd47595b50fd75` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-5f4c3be74d16d164` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-1f937b8a35c72658` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-d5b4fdcb8f458b5e` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-77d5c0d0e259d142` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-e8811b91b1070f48` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-caf2d346e179c9a0` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `pacp-52a1722ed9d740d8` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-795a0d9562f842df` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-9957f68f70a09db9` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-3ac68c1d671df0b2` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-78ab14f4d77657a0` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-7bf8d1910bc3fd7c` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-cdd5cc5e32af09a8` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-e63bfaadbc62c1f8` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-ce44d5bc8d88f3e9` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-2bf0afbc3a43823b` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-ef4ee50d2abca2ee` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-2db95af791369cd2` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-59aafb497f6e4421` proposal_creation from wrkr: evidence=verified freshness=fresh refs=interop:secret-to-network proof=proof:interop:secret-to-network

## Presentation Limits

- authority_requirements.pacr-151dc49115e7affb.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-1f937b8a35c72658.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-5f4c3be74d16d164.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-77d5c0d0e259d142.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-90cd47595b50fd75.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-caf2d346e179c9a0.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-d5b4fdcb8f458b5e.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-e5cba36563e4deaa.evidence_refs: reason=item_cap omitted=43
- authority_requirements.pacr-e8811b91b1070f48.evidence_refs: reason=item_cap omitted=43
- readiness_checks.pacp-2bf0afbc3a43823b.evidence_refs: reason=item_cap omitted=43
- readiness_checks.pacp-2db95af791369cd2.evidence_refs: reason=item_cap omitted=43
- readiness_checks.pacp-3ac68c1d671df0b2.evidence_refs: reason=item_cap omitted=43
- truncations: 9 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-e5cba36563e4deaa before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

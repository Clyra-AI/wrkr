# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-84c2cc0575667b24
- Artifact: paca-e142d882fa267ef6
- Contract: pac-22fd12c82bb43339
- Family: pacf-3b1a1959823f569c
- Revision: 2
- Supersedes: pac-4f2e6a1b08b62a49
- Contract digest: sha256:792277a6ed493679005e2183c2dd4a70696f56c7c8cd472514acdf658abb3cca
- Artifact digest: sha256:e142d882fa267ef6cd1847c2c3d419a5382307d27c8b514591c8d2df3527ac02
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-789ab4b4420d, wch-bd1e152cd6ba
- Report only: true

## Composed Path

- Composition: cap-8f551b1507faf761
- Pattern: code_to_deploy
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Outcome: production_deploy
- Reachability: possible static reachability; not observed execution
- Stage `cas-9b871b9cb6fbbe5b`: role=source tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown
- Stage `cas-becc17a64dfb3bf0`: role=privileged_sink tool=ci_agent location=.github/workflows/release.yml actions=credential_access, deploy, execute, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-4fb25de3e66a0af8` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-5917ec1d1bdc4a30` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-15185ff6719048f5` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-b2fc5c701fb433bb` delegation_root: required=delegation_root:required observed=authority-886e303d2470b313 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-d1887bb946f03347` originating_intent: required=originating_task_or_intent:required observed=intent:release evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-59c412679bb84965` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-3c26daa1b2a53015` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-6bea95fe08297d5c` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-98e178dbfe49ee9a` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-98ba85a16f35331b, pacr-15185ff6719048f5, pacr-6bea95fe08297d5c
- Wrkr activation grant: false

## Readiness Checks

- `pacp-98ba85a16f35331b` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-609f5752fc22282d` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-8bc10b68a131817c` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-13624d5708c12f2c` expected_effect: required=effect:production_deploy observed=production_deploy result=production_deploy evidence=unknown freshness=unknown producers=action_path
- `pacp-55d6d9d92571fd64` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-4aee5f849f584009` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-ff9198909549703c` policy_digest: required=policy_digest:required observed=sha256:ac76d933303b8799967aa5b087c44bba502f2c75ac72bfd06e420a8e716aa21b result=sha256:ac76d933303b8799967aa5b087c44bba502f2c75ac72bfd06e420a8e716aa21b evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-f51cfb3702936ae2` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-2f47ef15b33d05b4` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-63ff6f4e5fc7ba17` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-83768abd48320eb8` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-3dfc810bc2449485` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: production_deploy
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=true kind=documented_recovery procedure=not_recorded target=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation window=PT24H verification_required=true evidence=unknown freshness=unknown

## Evidence Gaps

- `pacr-4fb25de3e66a0af8` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-5917ec1d1bdc4a30` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-15185ff6719048f5` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-b2fc5c701fb433bb` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-d1887bb946f03347` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-59c412679bb84965` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-3c26daa1b2a53015` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-6bea95fe08297d5c` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-98e178dbfe49ee9a` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `pacp-98ba85a16f35331b` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-609f5752fc22282d` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-8bc10b68a131817c` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-13624d5708c12f2c` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-55d6d9d92571fd64` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-4aee5f849f584009` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-ff9198909549703c` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-f51cfb3702936ae2` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-2f47ef15b33d05b4` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-63ff6f4e5fc7ba17` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-83768abd48320eb8` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-3dfc810bc2449485` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-9cc32651c6f22c57` supersession from gait: evidence=verified freshness=fresh refs=interop:supersession proof=proof:interop:supersession

## Presentation Limits

- authority_requirements.pacr-15185ff6719048f5.evidence_refs: reason=item_cap omitted=39
- authority_requirements.pacr-3c26daa1b2a53015.evidence_refs: reason=item_cap omitted=39
- authority_requirements.pacr-4fb25de3e66a0af8.evidence_refs: reason=item_cap omitted=39
- authority_requirements.pacr-5917ec1d1bdc4a30.evidence_refs: reason=item_cap omitted=39
- authority_requirements.pacr-59c412679bb84965.evidence_refs: reason=item_cap omitted=39
- authority_requirements.pacr-6bea95fe08297d5c.evidence_refs: reason=item_cap omitted=39
- authority_requirements.pacr-98e178dbfe49ee9a.evidence_refs: reason=item_cap omitted=39
- authority_requirements.pacr-b2fc5c701fb433bb.evidence_refs: reason=item_cap omitted=39
- authority_requirements.pacr-d1887bb946f03347.evidence_refs: reason=item_cap omitted=39
- readiness_checks.pacp-13624d5708c12f2c.evidence_refs: reason=item_cap omitted=39
- readiness_checks.pacp-2f47ef15b33d05b4.evidence_refs: reason=item_cap omitted=39
- readiness_checks.pacp-3dfc810bc2449485.evidence_refs: reason=item_cap omitted=39
- truncations: 9 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-4fb25de3e66a0af8 before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

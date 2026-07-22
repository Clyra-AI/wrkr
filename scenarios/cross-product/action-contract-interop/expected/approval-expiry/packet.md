# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-596c403de5b40716
- Artifact: paca-7ac8091e1a23ddd3
- Contract: pac-a240c093177d88ea
- Family: pacf-6c1fd28e712919fe
- Revision: 1
- Supersedes: none
- Contract digest: sha256:aad519f3c7079ca2498aa2ed00c2f9d2e7d5a8312f558b2d113696db9809a6e9
- Artifact digest: sha256:7ac8091e1a23ddd37c5c2f78e188fef783ae1456577aa1974f65cd8db03203b2
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-2514b320edea, wch-57b96c696b0e
- Report only: true

## Composed Path

- Composition: cap-06ce45a1db0e11c2
- Pattern: package_change_to_release
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Outcome: release_publish
- Reachability: possible static reachability; not observed execution
- Stage `cas-bf0668849c098b73`: role=source tool=ci_agent location=.github/workflows/release.yml actions=credential_access, deploy, execute, read, write evidence=unknown freshness=unknown
- Stage `cas-882a86f00ef6b73f`: role=privileged_sink tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-6ff0e3404f306831` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:source_control_write
- `pacr-c32abc0dbf72c8cc` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:source_control_write
- `pacr-3fbeab57f0467185` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key,provena … [truncated] evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:source_control_write
- `pacr-59585c80ccd398fc` delegation_root: required=delegation_root:required observed=authority-91e3587bd04e9073 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:source_control_write
- `pacr-1ad923320bea6a2b` originating_intent: required=originating_task_or_intent:required observed=intent:release evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:source_control_write
- `pacr-9be2273474a01446` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:source_control_write
- `pacr-c47514699b33d6ab` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:source_control_write
- `pacr-f2d0a61a2880fe74` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:source_control_write
- `pacr-543379870af45a65` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:source_control_write

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-a41092fa2b9ef6b5, pacr-3fbeab57f0467185, pacr-f2d0a61a2880fe74
- Wrkr activation grant: false

## Readiness Checks

- `pacp-a41092fa2b9ef6b5` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-4b0597d0f1e5b310` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b1ebe118dfc42c59` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b2ba7328614e8e2b` expected_effect: required=effect:release_publish observed=release_publish result=release_publish evidence=unknown freshness=unknown producers=action_path
- `pacp-8baef5b81c298826` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-969143b6db918c1a` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-f115e0daa6fca481` policy_digest: required=policy_digest:required observed=sha256:28966de11892a012d8e8bf65141070475776b302479bf8233238e33e4162dc62 result=sha256:28966de11892a012d8e8bf65141070475776b302479bf8233238e33e4162dc62 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-9a9b7dfd38b5c7c7` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-dc59596a2edee46e` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-f49bdc36780c406b` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b51a65bab86ec0d3` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-5fb58a6fe2f74899` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: release_publish
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=unknown freshness=expired
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=true kind=documented_recovery procedure=not_recorded target=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation window=PT24H verification_required=true evidence=unknown freshness=unknown

## Evidence Gaps

- `pacr-6ff0e3404f306831` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-c32abc0dbf72c8cc` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-3fbeab57f0467185` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-59585c80ccd398fc` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-1ad923320bea6a2b` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-9be2273474a01446` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-c47514699b33d6ab` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-f2d0a61a2880fe74` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-543379870af45a65` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `pacp-a41092fa2b9ef6b5` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-4b0597d0f1e5b310` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-b1ebe118dfc42c59` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-b2ba7328614e8e2b` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-8baef5b81c298826` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-969143b6db918c1a` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-f115e0daa6fca481` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-9a9b7dfd38b5c7c7` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-dc59596a2edee46e` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-f49bdc36780c406b` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-b51a65bab86ec0d3` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-5fb58a6fe2f74899` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-3d1578dfa4c371e1` gait_activation_request from gait: evidence=unknown freshness=expired refs=interop:approval-expiry proof=proof:interop:approval-expiry

## Presentation Limits

- authority_requirements.pacr-1ad923320bea6a2b.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-3fbeab57f0467185.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-3fbeab57f0467185.observed_value: reason=value_rune_cap omitted=20
- authority_requirements.pacr-543379870af45a65.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-59585c80ccd398fc.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-6ff0e3404f306831.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-9be2273474a01446.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-c32abc0dbf72c8cc.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-c47514699b33d6ab.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-f2d0a61a2880fe74.evidence_refs: reason=item_cap omitted=37
- readiness_checks.pacp-4b0597d0f1e5b310.evidence_refs: reason=item_cap omitted=37
- readiness_checks.pacp-5fb58a6fe2f74899.evidence_refs: reason=item_cap omitted=37
- truncations: 10 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-6ff0e3404f306831 before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

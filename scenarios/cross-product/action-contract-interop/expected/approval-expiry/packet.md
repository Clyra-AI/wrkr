# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-bca6c9b37f7bc48c
- Artifact: paca-43037451fb36ffe3
- Contract: pac-b109812f52d952b4
- Family: pacf-6c1fd28e712919fe
- Revision: 1
- Supersedes: none
- Contract digest: sha256:f709e307c52928ae5b5d954299c489460d9aeed8d02a770274ab0fb7ef0a1039
- Artifact digest: sha256:43037451fb36ffe31c02ea89cf92982de5e22abfc31f1c0f617838dfcba2f10c
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

- `pacr-6ff0e3404f306831` affected_system_owner: required=affected_system_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_access:true, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control
- `pacr-c32abc0dbf72c8cc` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_access:true, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control
- `pacr-6d5eb51209fa60aa` credential_subject_constraint: required=subject:built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_access:true, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control
- `pacr-59585c80ccd398fc` delegation_root: required=delegation_root:required observed=authority-91e3587bd04e9073 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_access:true, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control
- `pacr-09e31bd0a744f995` originating_intent: required=composition:cap-06ce45a1db0e11c2 observed=package_change_to_release evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_access:true, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control
- `pacr-c527efa7c60bab96` permitted_agent_role: required=roles:privileged_sink,source observed=privileged_sink,source evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_access:true, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control
- `pacr-c47514699b33d6ab` policy_authority: required=policy_authority:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_access:true, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control
- `pacr-f2d0a61a2880fe74` requester_identity: required=requester_identity:required observed=stage:cas-bf0668849c098b73 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_access:true, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control
- `pacr-543379870af45a65` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_access:true, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control

## Credential Posture

- Required mode: ephemeral
- Evidence: unknown
- Freshness: unknown
- Requirement refs: pacp-a41092fa2b9ef6b5, pacr-6d5eb51209fa60aa, pacr-f2d0a61a2880fe74
- Wrkr activation grant: false

## Readiness Checks

- `pacp-a41092fa2b9ef6b5` credential_mode: required=credential_mode:ephemeral observed=ephemeral result=ephemeral evidence=unknown freshness=unknown producers=credential_authority
- `pacp-4b0597d0f1e5b310` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b1ebe118dfc42c59` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b2ba7328614e8e2b` expected_effect: required=effect:release_publish observed=release_publish result=release_publish evidence=unknown freshness=unknown producers=action_path
- `pacp-8baef5b81c298826` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-969143b6db918c1a` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-f115e0daa6fca481` policy_digest: required=policy_digest:required observed=sha256:add072f5f85ce92201ab8b2207c46d0309d9bcdbfee012611ce54b52c79d2d90 result=sha256:add072f5f85ce92201ab8b2207c46d0309d9bcdbfee012611ce54b52c79d2d90 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-9a9b7dfd38b5c7c7` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
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

- `pacr-6ff0e3404f306831` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:missing, authority:affected_system_owner:unknown
- `pacr-c32abc0dbf72c8cc` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-6d5eb51209fa60aa` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-59585c80ccd398fc` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-09e31bd0a744f995` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-c527efa7c60bab96` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:unknown
- `pacr-c47514699b33d6ab` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:missing, authority:policy_authority:unknown
- `pacr-f2d0a61a2880fe74` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:unknown
- `pacr-543379870af45a65` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:required
- `pacp-a41092fa2b9ef6b5` precondition:credential_mode: evidence=unknown freshness=unknown reasons=precondition:credential_mode:unknown
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

- approval_requirement.evidence_refs: reason=item_cap omitted=27
- authority_requirements.pacr-09e31bd0a744f995.evidence_refs: reason=item_cap omitted=27
- authority_requirements.pacr-543379870af45a65.evidence_refs: reason=item_cap omitted=27
- authority_requirements.pacr-59585c80ccd398fc.evidence_refs: reason=item_cap omitted=27
- authority_requirements.pacr-6d5eb51209fa60aa.evidence_refs: reason=item_cap omitted=27
- authority_requirements.pacr-6ff0e3404f306831.evidence_refs: reason=item_cap omitted=27
- authority_requirements.pacr-c32abc0dbf72c8cc.evidence_refs: reason=item_cap omitted=27
- authority_requirements.pacr-c47514699b33d6ab.evidence_refs: reason=item_cap omitted=27
- authority_requirements.pacr-c527efa7c60bab96.evidence_refs: reason=item_cap omitted=27
- authority_requirements.pacr-f2d0a61a2880fe74.evidence_refs: reason=item_cap omitted=27
- compensation_requirement.evidence_refs: reason=item_cap omitted=27
- confirmation_requirement.evidence_refs: reason=item_cap omitted=27
- truncations: 12 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-6ff0e3404f306831 before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-90d8ff7e3616b315
- Artifact: paca-f78364b796a80f2c
- Contract: pac-c6e98434993896a2
- Family: pacf-53c0ad5be7817026
- Revision: 1
- Supersedes: none
- Contract digest: sha256:8a3b54e80b6603ba7d50ab57d63ed21c9f08c57eda6441aca2877a69f1cb5925
- Artifact digest: sha256:f78364b796a80f2c24bca7772010380d6264c3039d7e812ae4197fcd4c529eaa
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-2514b320edea, wch-63302c190caa
- Report only: true

## Composed Path

- Composition: cap-06112dd46da2187c
- Pattern: code_to_deploy
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Outcome: production_deploy
- Reachability: possible static reachability; not observed execution
- Stage `cas-9b871b9cb6fbbe5b`: role=source tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown
- Stage `cas-653ad7b5691b8c61`: role=privileged_sink tool=compiled_action location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-bf52d248caa65478` affected_system_owner: required=affected_system_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-ceaa5acd4f2058fa` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-95ffb34fa0518893` credential_subject_constraint: required=subject:built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-abe2f86501d599e2` delegation_root: required=delegation_root:required observed=authority-b3aed31f4204875e evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-099b6ec907769bcf` originating_intent: required=composition:cap-06112dd46da2187c observed=code_to_deploy evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-77b8f1e197d2387d` permitted_agent_role: required=roles:privileged_sink,source observed=privileged_sink,source evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-1ae91431d7d08c0f` policy_authority: required=policy_authority:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-8472b190b3715a19` requester_identity: required=requester_identity:required observed=stage:cas-9b871b9cb6fbbe5b evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-e84f48b3d40a8c54` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow

## Credential Posture

- Required mode: ephemeral
- Evidence: unknown
- Freshness: unknown
- Requirement refs: pacp-6c4ed593958332c3, pacr-8472b190b3715a19, pacr-95ffb34fa0518893
- Wrkr activation grant: false

## Readiness Checks

- `pacp-6c4ed593958332c3` credential_mode: required=credential_mode:ephemeral observed=ephemeral result=ephemeral evidence=unknown freshness=unknown producers=credential_authority
- `pacp-b1680c529bdfd9b5` effect_contract: required=effect_contract:required observed=not_observed result=failed evidence=contradictory freshness=unknown producers=control_declaration, gait_policy
- `pacp-ba766039f2c90e2c` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-d53099ff4ad65bc8` expected_effect: required=effect:production_deploy observed=production_deploy result=production_deploy evidence=unknown freshness=unknown producers=action_path
- `pacp-839ae2b8a1a233a4` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-57f46698dd39d012` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-1651282d3d1af65e` policy_digest: required=policy_digest:required observed=sha256:6ce51a1d768337b806c22a6487af6a668c089fcf61f98c1d74e4827dd7ed98a8 result=sha256:6ce51a1d768337b806c22a6487af6a668c089fcf61f98c1d74e4827dd7ed98a8 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-c23d6cb554f180ce` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-540547e8117ee349` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-5592dad56fa153a8` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-51840a11c75b41cb` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-a0f344188f2fba7b` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

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

- `pacr-bf52d248caa65478` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:missing, authority:affected_system_owner:unknown
- `pacr-ceaa5acd4f2058fa` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-95ffb34fa0518893` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-abe2f86501d599e2` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-099b6ec907769bcf` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-77b8f1e197d2387d` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:unknown
- `pacr-1ae91431d7d08c0f` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:missing, authority:policy_authority:unknown
- `pacr-8472b190b3715a19` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:unknown
- `pacr-e84f48b3d40a8c54` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:required
- `pacl-e977a42a397c18e4` lifecycle:gait_effect: evidence=contradictory freshness=fresh reasons=none
- `pacp-6c4ed593958332c3` precondition:credential_mode: evidence=unknown freshness=unknown reasons=precondition:credential_mode:unknown
- `pacp-b1680c529bdfd9b5` precondition:effect_contract: evidence=contradictory freshness=unknown reasons=precondition:effect_contract:failed, precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-ba766039f2c90e2c` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-d53099ff4ad65bc8` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-839ae2b8a1a233a4` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-57f46698dd39d012` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-1651282d3d1af65e` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-c23d6cb554f180ce` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-540547e8117ee349` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-5592dad56fa153a8` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-51840a11c75b41cb` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-a0f344188f2fba7b` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-e977a42a397c18e4` gait_effect from gait: evidence=contradictory freshness=fresh refs=interop:failed-effect-validation proof=proof:interop:failed-effect-validation

## Presentation Limits

- approval_requirement.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-099b6ec907769bcf.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-1ae91431d7d08c0f.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-77b8f1e197d2387d.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-8472b190b3715a19.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-95ffb34fa0518893.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-abe2f86501d599e2.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-bf52d248caa65478.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-ceaa5acd4f2058fa.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-e84f48b3d40a8c54.evidence_refs: reason=item_cap omitted=21
- compensation_requirement.evidence_refs: reason=item_cap omitted=21
- confirmation_requirement.evidence_refs: reason=item_cap omitted=21
- truncations: 12 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-bf52d248caa65478 before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

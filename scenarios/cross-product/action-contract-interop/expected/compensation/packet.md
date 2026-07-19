# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-6f299238ecf46ff6
- Artifact: paca-7a6a565d72d5b1a3
- Contract: pac-9c73a51e622a8257
- Family: pacf-7d71940f2e697bfd
- Revision: 1
- Supersedes: none
- Contract digest: sha256:ed58dd8568c1f769ec2a34053704e4938ca0e57e8518e4d02bfe55a559756fc4
- Artifact digest: sha256:7a6a565d72d5b1a355ed58d414fd290d80b84640b526a628ca65eec12441c35f
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-2514b320edea, wch-63302c190caa
- Report only: true

## Composed Path

- Composition: cap-0aa390bd0c5db408
- Pattern: package_change_to_release
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Outcome: release_publish
- Reachability: possible static reachability; not observed execution
- Stage `cas-d93a010f3ae84c95`: role=source tool=compiled_action location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown
- Stage `cas-882a86f00ef6b73f`: role=privileged_sink tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-533be8ab758a94db` affected_system_owner: required=affected_system_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-3d491303f43f46f3` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-d896aac9b8f31248` credential_subject_constraint: required=subject:built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-2fc2c5994f3b196e` delegation_root: required=delegation_root:required observed=authority-b3aed31f4204875e evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-dd6f246dc377f7e4` originating_intent: required=composition:cap-0aa390bd0c5db408 observed=package_change_to_release evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-1e4579f72022e3f5` permitted_agent_role: required=roles:privileged_sink,source observed=privileged_sink,source evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-d38724511d32c457` policy_authority: required=policy_authority:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-3190be934a507333` requester_identity: required=requester_identity:required observed=stage:cas-d93a010f3ae84c95 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow
- `pacr-1441d51532a88fce` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, credential_likely_scope:source_control_write, credential_present:true, credential_referenced_by_workflow:true, credential_target_system:source_control, matched_target:built_in:deploy_workflow

## Credential Posture

- Required mode: ephemeral
- Evidence: unknown
- Freshness: unknown
- Requirement refs: pacp-823d0aa357f5970d, pacr-3190be934a507333, pacr-d896aac9b8f31248
- Wrkr activation grant: false

## Readiness Checks

- `pacp-823d0aa357f5970d` credential_mode: required=credential_mode:ephemeral observed=ephemeral result=ephemeral evidence=unknown freshness=unknown producers=credential_authority
- `pacp-e3602ab0b2fa5ee0` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-1287c4d1aeda06dc` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-aa1e71493ee92fd3` expected_effect: required=effect:release_publish observed=release_publish result=release_publish evidence=unknown freshness=unknown producers=action_path
- `pacp-d95745a70c2e0a60` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-f356fb098205721a` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-a445b21b29148072` policy_digest: required=policy_digest:required observed=sha256:67d3e4697b873ed580a9b528738bf67350a50714e9ce769a0bccb011f9250194 result=sha256:67d3e4697b873ed580a9b528738bf67350a50714e9ce769a0bccb011f9250194 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ff01ec5b04af48a0` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-2c16750a26bab153` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-ba973cdaad240dfe` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-cff653313f039704` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-35cd859a1384ea05` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: release_publish
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=true kind=documented_recovery procedure=compensation:rollback-release target=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation window=PT15M verification_required=true evidence=verified freshness=fresh

## Evidence Gaps

- `pacr-533be8ab758a94db` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:missing, authority:affected_system_owner:unknown
- `pacr-3d491303f43f46f3` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-d896aac9b8f31248` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-2fc2c5994f3b196e` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-dd6f246dc377f7e4` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-1e4579f72022e3f5` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:unknown
- `pacr-d38724511d32c457` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:missing, authority:policy_authority:unknown
- `pacr-3190be934a507333` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:unknown
- `pacr-1441d51532a88fce` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `pacp-823d0aa357f5970d` precondition:credential_mode: evidence=unknown freshness=unknown reasons=precondition:credential_mode:unknown
- `pacp-e3602ab0b2fa5ee0` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-1287c4d1aeda06dc` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-aa1e71493ee92fd3` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-d95745a70c2e0a60` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-f356fb098205721a` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-a445b21b29148072` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-ff01ec5b04af48a0` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-2c16750a26bab153` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-ba973cdaad240dfe` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-cff653313f039704` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-35cd859a1384ea05` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-712eea864612d483` axym_verification from axym: evidence=verified freshness=fresh refs=interop:compensation proof=proof:interop:compensation

## Presentation Limits

- approval_requirement.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-1441d51532a88fce.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-1e4579f72022e3f5.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-2fc2c5994f3b196e.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-3190be934a507333.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-3d491303f43f46f3.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-533be8ab758a94db.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-d38724511d32c457.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-d896aac9b8f31248.evidence_refs: reason=item_cap omitted=21
- authority_requirements.pacr-dd6f246dc377f7e4.evidence_refs: reason=item_cap omitted=21
- compensation_requirement.evidence_refs: reason=item_cap omitted=22
- confirmation_requirement.evidence_refs: reason=item_cap omitted=21
- truncations: 12 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-533be8ab758a94db before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

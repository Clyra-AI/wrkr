# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-67da017388666ab9
- Artifact: paca-cba93845fa57325b
- Contract: pac-da0d7804747279b6
- Family: pacf-6dd3f601d0fa58eb
- Revision: 1
- Supersedes: none
- Contract digest: sha256:94dfee700651b7f696f2a31dddb77211b690b4dcfc1036a6ff6d03acbde33c55
- Artifact digest: sha256:cba93845fa57325b64eae8ea7ad6a659839c4a35ed7628aa1025ee0ef52ca4e5
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-2514b320edea, wch-63302c190caa
- Report only: true

## Composed Path

- Composition: cap-0653e7cbe88f7adf
- Pattern: package_change_to_release
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Outcome: release_publish
- Reachability: possible static reachability; not observed execution
- Stage `cas-9b871b9cb6fbbe5b`: role=source tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown
- Stage `cas-653ad7b5691b8c61`: role=privileged_sink tool=compiled_action location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-e4441db036f339e3` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-ecda69edd00e59f3` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-247b2399a67ee678` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key,provena … [truncated] evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-4a509e0cb3141753` delegation_root: required=delegation_root:required observed=authority-b3aed31f4204875e evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-f711495f0e61d28d` originating_intent: required=originating_task_or_intent:required observed=intent:release evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-64ded6e1a4c2b802` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-08178f15ef8e2b27` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-781435f42536915c` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-6758294791831216` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-efb97cb3c669927d, pacr-247b2399a67ee678, pacr-781435f42536915c
- Wrkr activation grant: false

## Readiness Checks

- `pacp-efb97cb3c669927d` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-a088f5c197cd550f` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-087874f93b15d9f2` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-f835ded4dbd5439a` expected_effect: required=effect:release_publish observed=release_publish result=release_publish evidence=unknown freshness=unknown producers=action_path
- `pacp-e337bd0fa1fa3706` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-426573989e45a6b2` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-713293589be153ab` policy_digest: required=policy_digest:required observed=sha256:90ef018c8591931f8cafc2a34ae8e441dc04a0f800278c9d1057363b343558db result=sha256:90ef018c8591931f8cafc2a34ae8e441dc04a0f800278c9d1057363b343558db evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-8b400c811105d884` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-b0f00ca426d2414a` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-82b6a6ee6ff2505c` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-817324f40e240394` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-4bf9f04ba9d9aef9` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: release_publish
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=true kind=documented_recovery procedure=not_recorded target=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation window=PT24H verification_required=true evidence=unknown freshness=unknown

## Evidence Gaps

- `pacr-e4441db036f339e3` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-ecda69edd00e59f3` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-247b2399a67ee678` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-4a509e0cb3141753` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-f711495f0e61d28d` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-64ded6e1a4c2b802` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-08178f15ef8e2b27` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-781435f42536915c` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-6758294791831216` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `pacp-efb97cb3c669927d` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-a088f5c197cd550f` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-087874f93b15d9f2` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-f835ded4dbd5439a` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-e337bd0fa1fa3706` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-426573989e45a6b2` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-713293589be153ab` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-8b400c811105d884` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-b0f00ca426d2414a` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-82b6a6ee6ff2505c` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-817324f40e240394` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-4bf9f04ba9d9aef9` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-044e8ea0487a3701` proposal_creation from wrkr: evidence=verified freshness=fresh refs=interop:package-to-release proof=proof:interop:package-to-release

## Presentation Limits

- authority_requirements.pacr-08178f15ef8e2b27.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-247b2399a67ee678.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-247b2399a67ee678.observed_value: reason=value_rune_cap omitted=20
- authority_requirements.pacr-4a509e0cb3141753.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-64ded6e1a4c2b802.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-6758294791831216.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-781435f42536915c.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-e4441db036f339e3.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-ecda69edd00e59f3.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-f711495f0e61d28d.evidence_refs: reason=item_cap omitted=31
- readiness_checks.pacp-087874f93b15d9f2.evidence_refs: reason=item_cap omitted=31
- readiness_checks.pacp-426573989e45a6b2.evidence_refs: reason=item_cap omitted=31
- truncations: 10 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-e4441db036f339e3 before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-bc69eeb4c70f1d47
- Artifact: paca-595fe377dafb85bf
- Contract: pac-076654bdd0811da3
- Family: pacf-2b33c8acadaf9bde
- Revision: 2
- Supersedes: pac-830dabfefce7b1e0
- Contract digest: sha256:1f713b2774e68865de4b7859e327411d46493ec2a8d0bdd54ec19799c82929a0
- Artifact digest: sha256:595fe377dafb85bfb7740e92a0c625bedca48696f731b723e18017da8b3797e0
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-2514b320edea
- Report only: true

## Composed Path

- Composition: cap-3488ebd9ffe13f74
- Pattern: code_to_deploy
- Target: local/demo-app+production_impacting
- Target class: production_impacting
- Affected asset: local/demo-app+production_impacting
- Outcome: production_deploy
- Reachability: possible static reachability; not observed execution
- Stage `cas-9b871b9cb6fbbe5b`: role=source tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown
- Stage `cas-882a86f00ef6b73f`: role=privileged_sink tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-f6a558acc5c2a8e4` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-9682045d034dba06` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-7989908a91d15c29` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key,provena … [truncated] evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-ee0648e536ebe8b8` delegation_root: required=delegation_root:required observed=authority-b3aed31f4204875e evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-a0f47059378c608d` originating_intent: required=originating_task_or_intent:required observed=intent:release automation evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-e6462759dbdba6f0` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-0fe16d0a33ce5068` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-2f4da322e02f744d` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-21947418c4f269f1` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-361685b6d25b8fd7, pacr-2f4da322e02f744d, pacr-7989908a91d15c29
- Wrkr activation grant: false

## Readiness Checks

- `pacp-361685b6d25b8fd7` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-5a0dfa761dfbab17` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-d1f77d5540afe0b0` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-242f680b5076e856` expected_effect: required=effect:production_deploy observed=production_deploy result=production_deploy evidence=unknown freshness=unknown producers=action_path
- `pacp-a60fc0f83031b893` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-5f6e9f352f90c226` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-3ec947b83f0c4def` policy_digest: required=policy_digest:required observed=sha256:fa661b2645568637a0938dfe8bdc02edbef30019892600bf76f35640f5e6a58d result=sha256:fa661b2645568637a0938dfe8bdc02edbef30019892600bf76f35640f5e6a58d evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ce787cb6d8f6bc7c` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-ad142b6535afcb09` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-e9ef0161702598ff` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-cb625f86bddde3b3` target: required=target:bounded observed=local/demo-app+production_impacting result=local/demo-app+production_impacting evidence=unknown freshness=unknown producers=action_path
- `pacp-6f764d4a76f10ad2` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: production_deploy
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=true kind=documented_recovery procedure=not_recorded target=local/demo-app+production_impacting window=PT24H verification_required=true evidence=unknown freshness=unknown

## Evidence Gaps

- `pacr-f6a558acc5c2a8e4` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-9682045d034dba06` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-7989908a91d15c29` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-ee0648e536ebe8b8` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-a0f47059378c608d` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-e6462759dbdba6f0` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-0fe16d0a33ce5068` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-2f4da322e02f744d` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-21947418c4f269f1` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `pacp-361685b6d25b8fd7` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-5a0dfa761dfbab17` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-d1f77d5540afe0b0` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-242f680b5076e856` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-a60fc0f83031b893` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-5f6e9f352f90c226` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-3ec947b83f0c4def` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-ce787cb6d8f6bc7c` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-ad142b6535afcb09` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-e9ef0161702598ff` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-cb625f86bddde3b3` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-6f764d4a76f10ad2` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-9cc32651c6f22c57` supersession from gait: evidence=verified freshness=fresh refs=interop:supersession proof=proof:interop:supersession

## Presentation Limits

- authority_requirements.pacr-0fe16d0a33ce5068.evidence_refs: reason=item_cap omitted=22
- authority_requirements.pacr-21947418c4f269f1.evidence_refs: reason=item_cap omitted=22
- authority_requirements.pacr-2f4da322e02f744d.evidence_refs: reason=item_cap omitted=22
- authority_requirements.pacr-7989908a91d15c29.evidence_refs: reason=item_cap omitted=22
- authority_requirements.pacr-7989908a91d15c29.observed_value: reason=value_rune_cap omitted=20
- authority_requirements.pacr-9682045d034dba06.evidence_refs: reason=item_cap omitted=22
- authority_requirements.pacr-a0f47059378c608d.evidence_refs: reason=item_cap omitted=22
- authority_requirements.pacr-e6462759dbdba6f0.evidence_refs: reason=item_cap omitted=22
- authority_requirements.pacr-ee0648e536ebe8b8.evidence_refs: reason=item_cap omitted=22
- authority_requirements.pacr-f6a558acc5c2a8e4.evidence_refs: reason=item_cap omitted=22
- readiness_checks.pacp-242f680b5076e856.evidence_refs: reason=item_cap omitted=22
- readiness_checks.pacp-361685b6d25b8fd7.evidence_refs: reason=item_cap omitted=22
- truncations: 10 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-f6a558acc5c2a8e4 before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-9fde6052dbd1fcc0
- Artifact: paca-d87451a4437126d1
- Contract: pac-f505d9252a552135
- Family: pacf-d7654d6666f3a346
- Revision: 1
- Supersedes: none
- Contract digest: sha256:660fa647a9dbf357cc693a7860f396bdbda50e610bc6ba245caff8bd91824a8b
- Artifact digest: sha256:d87451a4437126d1a4988fcf20aae6f0b87a6998fdbf5289fdf46ffc0d2e9376
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-2514b320edea, wch-e09776c197c7
- Report only: true

## Composed Path

- Composition: cap-04370928364635c9
- Pattern: code_to_deploy
- Target: built_in:deploy_workflow+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:release_automation
- Outcome: production_deploy
- Reachability: possible static reachability; not observed execution
- Stage `cas-9b871b9cb6fbbe5b`: role=source tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown
- Stage `cas-ab465825ec2b08e4`: role=privileged_sink tool=skill location=.agents/skills/release/SKILL.md actions=deploy, execute, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-9f06573b17b074df` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-c313bd0c78d83db3` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-c97b139903ddb538` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key,provena … [truncated] evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-c5872611a2264a82` delegation_root: required=delegation_root:required observed=authority-b3aed31f4204875e evidence=contradictory freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-57a981b244d7db3b` originating_intent: required=originating_task_or_intent:required observed=intent:release automation evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-4766b8a31f88eedb` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-9301c432e05c77fd` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-72ffe78854c97e4e` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true
- `pacr-97afc6905762276c` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_likely_scope:source_control_write, credential_present:true

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-5ec86b18589ad4d5, pacr-72ffe78854c97e4e, pacr-c97b139903ddb538
- Wrkr activation grant: false

## Readiness Checks

- `pacp-5ec86b18589ad4d5` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-f4f95d66c641f251` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-86633f4d449b8bfb` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-94dd87a8c94e1149` expected_effect: required=effect:production_deploy observed=production_deploy result=production_deploy evidence=unknown freshness=unknown producers=action_path
- `pacp-732b92bbc81d456c` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b4c3f8068bd0a543` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-b461d184960386b7` policy_digest: required=policy_digest:required observed=sha256:6c84e1ce10c6ef406c942d0fbeb43ce83a16fa9e1532a547ddea6fc8fff98cea result=sha256:6c84e1ce10c6ef406c942d0fbeb43ce83a16fa9e1532a547ddea6fc8fff98cea evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-42982e218369daa4` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-001ebe549bd920c7` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-c6cd3ef0e88960fd` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ac0637a1c33aa740` target: required=target:bounded observed=built_in:deploy_workflow+built_in:release_automation result=built_in:deploy_workflow+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-29846cf020ae2b30` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: production_deploy
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=false mode=not_required evidence=verified freshness=unknown
- Approval: required=false minimum=0 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=verified freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=true kind=documented_recovery procedure=not_recorded target=built_in:deploy_workflow+built_in:release_automation window=PT24H verification_required=true evidence=unknown freshness=unknown

## Evidence Gaps

- `pacr-9f06573b17b074df` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-c313bd0c78d83db3` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-c97b139903ddb538` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-c5872611a2264a82` authority:delegation_root: evidence=contradictory freshness=unknown reasons=authority:delegation_root:unknown, authority:excessive_child_scope
- `pacr-57a981b244d7db3b` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-4766b8a31f88eedb` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-9301c432e05c77fd` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-72ffe78854c97e4e` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-97afc6905762276c` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `pacp-5ec86b18589ad4d5` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-f4f95d66c641f251` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-86633f4d449b8bfb` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-94dd87a8c94e1149` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-732b92bbc81d456c` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-b4c3f8068bd0a543` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-b461d184960386b7` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-42982e218369daa4` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-001ebe549bd920c7` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-c6cd3ef0e88960fd` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-ac0637a1c33aa740` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-29846cf020ae2b30` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-6875d9ac2e72efe2` gait_rejection from gait: evidence=verified freshness=fresh refs=interop:excessive-child-authority proof=proof:interop:excessive-child-authority

## Presentation Limits

- authority_requirements.pacr-4766b8a31f88eedb.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-57a981b244d7db3b.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-72ffe78854c97e4e.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-9301c432e05c77fd.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-97afc6905762276c.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-9f06573b17b074df.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-c313bd0c78d83db3.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-c5872611a2264a82.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-c97b139903ddb538.evidence_refs: reason=item_cap omitted=31
- authority_requirements.pacr-c97b139903ddb538.observed_value: reason=value_rune_cap omitted=20
- readiness_checks.pacp-001ebe549bd920c7.evidence_refs: reason=item_cap omitted=31
- readiness_checks.pacp-29846cf020ae2b30.evidence_refs: reason=item_cap omitted=31
- truncations: 10 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-9f06573b17b074df before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

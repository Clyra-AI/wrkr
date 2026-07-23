# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-49af294d0c28224d
- Artifact: paca-bd280e0ee6b65754
- Contract: pac-ab7ff3726abf6ef2
- Family: pacf-d5dd2e874f0b7e17
- Revision: 1
- Supersedes: none
- Contract digest: sha256:830ff92e2e3e231b7863ff208424cc1d58f91f6345e6cc5baac2dcbe23cf9039
- Artifact digest: sha256:bd280e0ee6b657540adb248f6e72c499c816f34803c87b4ad202244a30aa7b64
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-bd1e152cd6ba, wch-e09776c197c7
- Report only: true

## Composed Path

- Composition: cap-6a1d3809a60d33aa
- Pattern: code_to_deploy
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Outcome: production_deploy
- Reachability: possible static reachability; not observed execution
- Stage `cas-a41df894cca6fa9c`: role=source tool=skill location=.agents/skills/release/SKILL.md actions=deploy, execute, read, write evidence=unknown freshness=unknown
- Stage `cas-becc17a64dfb3bf0`: role=privileged_sink tool=ci_agent location=.github/workflows/release.yml actions=credential_access, deploy, execute, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-ff28c1721f48677c` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-614e66a95dc33acd` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-698efcf1890592eb` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-4c93e608a1bed040` delegation_root: required=delegation_root:required observed=authority-b29daa99b287a631 evidence=contradictory freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-0f6e1e9b42456a76` originating_intent: required=originating_task_or_intent:required observed=intent:release evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-e9ea28a70a017d2e` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-fb2c83d2d25765d5` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-bfc5346636d76e10` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-71342b770b8305f1` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-b40f5e63400e37ab, pacr-698efcf1890592eb, pacr-bfc5346636d76e10
- Wrkr activation grant: false

## Readiness Checks

- `pacp-b40f5e63400e37ab` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-fc47da9bf891aae3` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-e739442e6f36b53b` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-d4a54fa34fc0842b` expected_effect: required=effect:production_deploy observed=production_deploy result=production_deploy evidence=unknown freshness=unknown producers=action_path
- `pacp-0b7e21b21888af06` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-9c5c839bdf0dbf31` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-72cf5ccca046916c` policy_digest: required=policy_digest:required observed=sha256:ed902a44e56f468fb0d2d38f3a989635eed36385637d167f70f7268bab54a213 result=sha256:ed902a44e56f468fb0d2d38f3a989635eed36385637d167f70f7268bab54a213 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-4262cda91d431ca0` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-9f86adbed88a5804` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-3dc91ab49dc7521e` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-289e07e6d2b6724a` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-2b303fe14ee875e5` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

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

- `pacr-ff28c1721f48677c` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-614e66a95dc33acd` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-698efcf1890592eb` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-4c93e608a1bed040` authority:delegation_root: evidence=contradictory freshness=unknown reasons=authority:delegation_root:unknown, authority:excessive_child_scope
- `pacr-0f6e1e9b42456a76` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-e9ea28a70a017d2e` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-fb2c83d2d25765d5` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-bfc5346636d76e10` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-71342b770b8305f1` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `pacp-b40f5e63400e37ab` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-fc47da9bf891aae3` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-e739442e6f36b53b` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-d4a54fa34fc0842b` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-0b7e21b21888af06` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-9c5c839bdf0dbf31` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-72cf5ccca046916c` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-4262cda91d431ca0` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-9f86adbed88a5804` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-3dc91ab49dc7521e` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-289e07e6d2b6724a` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-2b303fe14ee875e5` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-6875d9ac2e72efe2` gait_rejection from gait: evidence=verified freshness=fresh refs=interop:excessive-child-authority proof=proof:interop:excessive-child-authority

## Presentation Limits

- authority_requirements.pacr-0f6e1e9b42456a76.evidence_refs: reason=item_cap omitted=40
- authority_requirements.pacr-4c93e608a1bed040.evidence_refs: reason=item_cap omitted=40
- authority_requirements.pacr-614e66a95dc33acd.evidence_refs: reason=item_cap omitted=40
- authority_requirements.pacr-698efcf1890592eb.evidence_refs: reason=item_cap omitted=40
- authority_requirements.pacr-71342b770b8305f1.evidence_refs: reason=item_cap omitted=40
- authority_requirements.pacr-bfc5346636d76e10.evidence_refs: reason=item_cap omitted=40
- authority_requirements.pacr-e9ea28a70a017d2e.evidence_refs: reason=item_cap omitted=40
- authority_requirements.pacr-fb2c83d2d25765d5.evidence_refs: reason=item_cap omitted=40
- authority_requirements.pacr-ff28c1721f48677c.evidence_refs: reason=item_cap omitted=40
- readiness_checks.pacp-0b7e21b21888af06.evidence_refs: reason=item_cap omitted=40
- readiness_checks.pacp-289e07e6d2b6724a.evidence_refs: reason=item_cap omitted=40
- readiness_checks.pacp-2b303fe14ee875e5.evidence_refs: reason=item_cap omitted=40
- truncations: 9 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-ff28c1721f48677c before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

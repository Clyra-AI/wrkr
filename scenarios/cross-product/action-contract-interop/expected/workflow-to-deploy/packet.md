# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-5d9077e3c5117c60
- Artifact: paca-8001527ad443d2d3
- Contract: pac-78931e17d6204821
- Family: pacf-4eb827fcc0c1ca88
- Revision: 1
- Supersedes: none
- Contract digest: sha256:309b56a66140b12954e7fb58053545a9522b4681162be5b7d199c7a3c19cfdb0
- Artifact digest: sha256:8001527ad443d2d388b19ad498327cff53011b3b96db9762929b484bf00a1625
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-86520c168374, wch-e09776c197c7
- Report only: true

## Composed Path

- Composition: cap-1c42e101ce243ce9
- Pattern: workflow_mutation_to_production
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Outcome: production_mutation
- Reachability: possible static reachability; not observed execution
- Stage `cas-724be5488c20c42d`: role=transform tool=ci_agent location=.github/workflows/release.yml actions=credential_access, deploy, execute, read, write evidence=unknown freshness=unknown
- Stage `cas-ab465825ec2b08e4`: role=privileged_sink tool=skill location=.agents/skills/release/SKILL.md actions=deploy, execute, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-0fd5587f1b76b96b` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access, credential_reference_observed
- `pacr-33bf1a5bf122d5eb` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access, credential_reference_observed
- `pacr-410f227306c79846` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access, credential_reference_observed
- `pacr-eb17bcbffc40e5ca` delegation_root: required=delegation_root:required observed=authority-16b128ce8beb8f5d evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access, credential_reference_observed
- `pacr-e46b5cbc297e991b` originating_intent: required=originating_task_or_intent:required observed=intent:release evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access, credential_reference_observed
- `pacr-5a0910fd7439cf1b` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access, credential_reference_observed
- `pacr-b4bd4488ef220fa3` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access, credential_reference_observed
- `pacr-76c6ec8873ba58c7` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access, credential_reference_observed
- `pacr-23f423c27e33022c` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access, credential_reference_observed

## Credential Posture

- Required mode: ephemeral
- Evidence: unknown
- Freshness: unknown
- Requirement refs: pacp-100f0b7bdd4a16b2, pacr-410f227306c79846, pacr-76c6ec8873ba58c7
- Wrkr activation grant: false

## Readiness Checks

- `pacp-100f0b7bdd4a16b2` credential_mode: required=credential_mode:ephemeral observed=ephemeral result=ephemeral evidence=unknown freshness=unknown producers=credential_authority
- `pacp-3071f2236a6a2ceb` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-9acdc96792b4c2ff` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ec93b0673f888fdf` expected_effect: required=effect:production_mutation observed=production_mutation result=production_mutation evidence=unknown freshness=unknown producers=action_path
- `pacp-7af11b7b920417d8` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-243a37181fa02f22` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-1400c1d64ff543aa` policy_digest: required=policy_digest:required observed=sha256:03d99265acb7145344f58373455923989e47058488900e984cc758d73cc177e1 result=sha256:03d99265acb7145344f58373455923989e47058488900e984cc758d73cc177e1 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-9233f8b1f30a7593` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-9e68964dc3b437ef` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-86533bb3a16417b5` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-26e62bda8d9235f9` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-a0bbc7d7e8bf9e98` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

## Expected and Forbidden Effects

- Expected: production_mutation
- Forbidden: effect:not_unbounded

## Confirmation and Approval

- Confirmation: required=true mode=explicit_confirmation evidence=unknown freshness=unknown
- Approval: required=true minimum=2 roles=control_owner, security_reviewer separation=requester_must_not_approve validity=PT24H evidence=unknown freshness=unknown
- Reapproval triggers: contract_content_change, scope_digest_change

## Compensation

- Required=true kind=documented_recovery procedure=not_recorded target=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation window=PT24H verification_required=true evidence=unknown freshness=unknown

## Evidence Gaps

- `approval` approval: evidence=unknown freshness=unknown reasons=approval:evidence_missing, approval:required, approval:scope_digest_missing
- `pacr-0fd5587f1b76b96b` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-33bf1a5bf122d5eb` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-410f227306c79846` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-eb17bcbffc40e5ca` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-e46b5cbc297e991b` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-5a0910fd7439cf1b` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-b4bd4488ef220fa3` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-76c6ec8873ba58c7` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-23f423c27e33022c` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `confirmation` confirmation: evidence=unknown freshness=unknown reasons=confirmation:evidence_missing, confirmation:required
- `pacp-100f0b7bdd4a16b2` precondition:credential_mode: evidence=unknown freshness=unknown reasons=precondition:credential_mode:unknown
- `pacp-3071f2236a6a2ceb` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-9acdc96792b4c2ff` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-ec93b0673f888fdf` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-7af11b7b920417d8` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-243a37181fa02f22` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-1400c1d64ff543aa` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-9233f8b1f30a7593` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-9e68964dc3b437ef` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-86533bb3a16417b5` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-26e62bda8d9235f9` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-a0bbc7d7e8bf9e98` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-bface16c61e2f236` proposal_creation from wrkr: evidence=verified freshness=fresh refs=interop:workflow-to-deploy proof=proof:interop:workflow-to-deploy

## Presentation Limits

- authority_requirements.pacr-0fd5587f1b76b96b.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-23f423c27e33022c.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-33bf1a5bf122d5eb.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-410f227306c79846.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-5a0910fd7439cf1b.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-76c6ec8873ba58c7.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-b4bd4488ef220fa3.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-e46b5cbc297e991b.evidence_refs: reason=item_cap omitted=37
- authority_requirements.pacr-eb17bcbffc40e5ca.evidence_refs: reason=item_cap omitted=37
- readiness_checks.pacp-100f0b7bdd4a16b2.evidence_refs: reason=item_cap omitted=37
- readiness_checks.pacp-1400c1d64ff543aa.evidence_refs: reason=item_cap omitted=37
- readiness_checks.pacp-243a37181fa02f22.evidence_refs: reason=item_cap omitted=37
- truncations: 9 additional presentation-limit records omitted

## Next Action

- Action: Resolve approval before requesting a Gait activation decision.
- Reason: approval remains unknown
- Owner: contract owner

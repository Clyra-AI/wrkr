# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-161fc0bcd58107e9
- Artifact: paca-03398e52ba41362d
- Contract: pac-dfb952d2a2811197
- Family: pacf-551683d10a9e914d
- Revision: 1
- Supersedes: none
- Contract digest: sha256:8f302817cd70e5e886a27ac9b11d287222e8458db645a566c221ab7d089947ec
- Artifact digest: sha256:03398e52ba41362d91ae335829109070aa20eaefb8ee8e1461c8dfa151b7dee8
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-789ab4b4420d, wch-bd1e152cd6ba
- Report only: true

## Composed Path

- Composition: cap-894dfab60e80457d
- Pattern: code_to_deploy
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Outcome: production_deploy
- Reachability: possible static reachability; not observed execution
- Stage `cas-930ac179f9997975`: role=source tool=ci_agent location=.github/workflows/release.yml actions=credential_access, deploy, execute, read, write evidence=unknown freshness=unknown
- Stage `cas-882a86f00ef6b73f`: role=privileged_sink tool=agnt_agent location=.github/workflows/release.yml actions=deploy, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-1feca1ce57cde7c3` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-56232a9cc86b0657` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-7d36c1ff5587898c` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-c6ae69d327e85033` delegation_root: required=delegation_root:required observed=authority-bfc23b0d135943e8 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-b3a437682c6a5c8b` originating_intent: required=originating_task_or_intent:required observed=intent:release evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-947cdf963274300e` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-ba876ec04e3f2090` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-b257b5787ef41672` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-6a9541ec35bb26f9` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-f51e237be307906c, pacr-7d36c1ff5587898c, pacr-b257b5787ef41672
- Wrkr activation grant: false

## Readiness Checks

- `pacp-f51e237be307906c` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-c307b0619c1f4669` effect_contract: required=effect_contract:required observed=not_observed result=failed evidence=contradictory freshness=unknown producers=control_declaration, gait_policy
- `pacp-1180e91556c5d75f` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-645cb943abd8397d` expected_effect: required=effect:production_deploy observed=production_deploy result=production_deploy evidence=unknown freshness=unknown producers=action_path
- `pacp-35f2785682713aa7` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b9e7664d67b7327b` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-ec0fb84968773e61` policy_digest: required=policy_digest:required observed=sha256:c76ad37ae83d2394cc120de410084e077293d571ab83290b0c1e004214ed8075 result=sha256:c76ad37ae83d2394cc120de410084e077293d571ab83290b0c1e004214ed8075 evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-b953c2307a57f713` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-29bc81f8eb3adcc1` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-28bc43e0c50f22aa` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-770eb9f9662c0742` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-37efcaf892cc3445` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

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

- `pacr-1feca1ce57cde7c3` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-56232a9cc86b0657` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-7d36c1ff5587898c` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-c6ae69d327e85033` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-b3a437682c6a5c8b` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-947cdf963274300e` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-ba876ec04e3f2090` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-b257b5787ef41672` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-6a9541ec35bb26f9` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `pacl-e977a42a397c18e4` lifecycle:gait_effect: evidence=contradictory freshness=fresh reasons=none
- `pacp-f51e237be307906c` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-c307b0619c1f4669` precondition:effect_contract: evidence=contradictory freshness=unknown reasons=precondition:effect_contract:failed, precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-1180e91556c5d75f` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-645cb943abd8397d` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-35f2785682713aa7` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-b9e7664d67b7327b` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-ec0fb84968773e61` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-b953c2307a57f713` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-29bc81f8eb3adcc1` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-28bc43e0c50f22aa` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-770eb9f9662c0742` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-37efcaf892cc3445` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-e977a42a397c18e4` gait_effect from gait: evidence=contradictory freshness=fresh refs=interop:failed-effect-validation proof=proof:interop:failed-effect-validation

## Presentation Limits

- authority_requirements.pacr-1feca1ce57cde7c3.evidence_refs: reason=item_cap omitted=38
- authority_requirements.pacr-56232a9cc86b0657.evidence_refs: reason=item_cap omitted=38
- authority_requirements.pacr-6a9541ec35bb26f9.evidence_refs: reason=item_cap omitted=38
- authority_requirements.pacr-7d36c1ff5587898c.evidence_refs: reason=item_cap omitted=38
- authority_requirements.pacr-947cdf963274300e.evidence_refs: reason=item_cap omitted=38
- authority_requirements.pacr-b257b5787ef41672.evidence_refs: reason=item_cap omitted=38
- authority_requirements.pacr-b3a437682c6a5c8b.evidence_refs: reason=item_cap omitted=38
- authority_requirements.pacr-ba876ec04e3f2090.evidence_refs: reason=item_cap omitted=38
- authority_requirements.pacr-c6ae69d327e85033.evidence_refs: reason=item_cap omitted=38
- readiness_checks.pacp-1180e91556c5d75f.evidence_refs: reason=item_cap omitted=38
- readiness_checks.pacp-28bc43e0c50f22aa.evidence_refs: reason=item_cap omitted=38
- readiness_checks.pacp-29bc81f8eb3adcc1.evidence_refs: reason=item_cap omitted=38
- truncations: 9 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-1feca1ce57cde7c3 before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

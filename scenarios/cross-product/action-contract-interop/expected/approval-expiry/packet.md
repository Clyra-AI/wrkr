# Wrkr Action Contract Packet

Wrkr proposes and reports this contract. Gait alone decides activation and runtime enforcement; Axym verifies downstream evidence.

## Contract and Artifact Identity

- Packet: pacpkt-703452bbe98d9124
- Artifact: paca-dde22ebd44b8f4a6
- Contract: pac-c2e2cbefc4dc3791
- Family: pacf-55f758ded9e42f84
- Revision: 1
- Supersedes: none
- Contract digest: sha256:1c2a1df5d4cb6e59e395df5a062850bb8ae14bcd14d87262d7b227e60d9095e5
- Artifact digest: sha256:dde22ebd44b8f4a648b2b5ad1151c469694902b1d5ea0e67257e6f3a5181e476
- Share profile: internal
- Source scan refs: saved_scan:v1
- Creation evidence: wch-bd1e152cd6ba
- Report only: true

## Composed Path

- Composition: cap-18961d92fa2fad87
- Pattern: package_change_to_release
- Target: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Target class: production_impacting
- Affected asset: built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation
- Outcome: release_publish
- Reachability: possible static reachability; not observed execution
- Stage `cas-930ac179f9997975`: role=source tool=ci_agent location=.github/workflows/release.yml actions=credential_access, deploy, execute, read, write evidence=unknown freshness=unknown
- Stage `cas-becc17a64dfb3bf0`: role=privileged_sink tool=ci_agent location=.github/workflows/release.yml actions=credential_access, deploy, execute, read, write evidence=unknown freshness=unknown

## Authority Requirements

- `pacr-8a0684edd81a5be1` affected_system_owner: required=affected_system_owner:required observed=owner:system:@local/demo evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-d46c56997d03521a` business_owner: required=business_owner:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-c238b6879d672f85` credential_subject_constraint: required=credential_subject:required observed=binding_subject:cloud_admin_key,binding_subject:workflow_kubernetes_deploy,provenance_subject:broad_pat,provenance_subject:cloud_admin_key evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-44d1e4b8f062084d` delegation_root: required=delegation_root:required observed=authority-bfc23b0d135943e8 evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-e4179cdb170f2ff8` originating_intent: required=originating_task_or_intent:required observed=intent:release evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-d713cfbe4c71401d` permitted_agent_role: required=permitted_agent_role:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-fd81566365518444` policy_authority: required=policy_authority:required observed=policy:gait://release-control evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-2235a80f56736851` requester_identity: required=requester_identity:required observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access
- `pacr-bf2fc3de3afd4266` separation_of_duties: required=requester_must_not_approve observed=not_observed evidence=unknown freshness=unknown refs=.gait/policy.yaml, approval_status=unapproved, authority_standing:true, baseline:discovered_surface, binding_subject:cloud_admin_key, binding_subject:workflow_kubernetes_deploy, credential_access:true, credential_likely_scope:cloud_or_infra_access

## Credential Posture

- Required mode: ephemeral
- Evidence: contradictory
- Freshness: unknown
- Requirement refs: pacp-bf50d2ec76b84ae8, pacr-2235a80f56736851, pacr-c238b6879d672f85
- Wrkr activation grant: false

## Readiness Checks

- `pacp-bf50d2ec76b84ae8` credential_mode: required=credential_mode:ephemeral observed=standing result=standing evidence=contradictory freshness=unknown producers=credential_authority
- `pacp-a019dea82de5acb0` effect_contract: required=effect_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-7f0dec0436ff9405` environment: required=environment:declared observed=production result=production evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-ba4fe8a7b9e5f2dc` expected_effect: required=effect:release_publish observed=release_publish result=release_publish evidence=unknown freshness=unknown producers=action_path
- `pacp-7cc8594be1adc6da` forbidden_effect: required=effect:not_unbounded observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-340144de93dd20fb` freshness: required=fresh observed=unknown result=unknown evidence=unknown freshness=unknown producers=evidence_policy
- `pacp-4771e8ee3d427469` policy_digest: required=policy_digest:required observed=sha256:0c379e9645f23c374d7bf081ff5c6d369f3ac7ea49db1a823a40e2c07ba89cac result=sha256:0c379e9645f23c374d7bf081ff5c6d369f3ac7ea49db1a823a40e2c07ba89cac evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-3531ca4b0c555dd5` producer: required=producer:approved observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-1994506befa8f568` required_check: required=check:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=ci, control_declaration, gait_policy
- `pacp-7ed1ef483fecb641` sandbox: required=sandbox:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy
- `pacp-d40be4e1dcaad109` target: required=target:bounded observed=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation result=built_in:deploy_workflow+built_in:kubernetes+built_in:release_automation evidence=unknown freshness=unknown producers=action_path
- `pacp-44a5716c48dcec31` validation_contract: required=validation_contract:required observed=not_observed result=not_observed evidence=unknown freshness=unknown producers=control_declaration, gait_policy

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

- `pacr-8a0684edd81a5be1` authority:affected_system_owner: evidence=unknown freshness=unknown reasons=authority:affected_system_owner:unknown
- `pacr-d46c56997d03521a` authority:business_owner: evidence=unknown freshness=unknown reasons=authority:business_owner:missing, authority:business_owner:unknown
- `pacr-c238b6879d672f85` authority:credential_subject_constraint: evidence=unknown freshness=unknown reasons=authority:credential_subject_constraint:unknown
- `pacr-44d1e4b8f062084d` authority:delegation_root: evidence=unknown freshness=unknown reasons=authority:delegation_root:unknown
- `pacr-e4179cdb170f2ff8` authority:originating_intent: evidence=unknown freshness=unknown reasons=authority:originating_intent:unknown
- `pacr-d713cfbe4c71401d` authority:permitted_agent_role: evidence=unknown freshness=unknown reasons=authority:permitted_agent_role:missing, authority:permitted_agent_role:unknown
- `pacr-fd81566365518444` authority:policy_authority: evidence=unknown freshness=unknown reasons=authority:policy_authority:unknown
- `pacr-2235a80f56736851` authority:requester_identity: evidence=unknown freshness=unknown reasons=authority:requester_identity:missing, authority:requester_identity:unknown
- `pacr-bf2fc3de3afd4266` authority:separation_of_duties: evidence=unknown freshness=unknown reasons=authority:separation_of_duties:missing, authority:separation_of_duties:unknown
- `compensation` compensation: evidence=unknown freshness=unknown reasons=compensation:evidence_missing, compensation:required
- `pacp-bf50d2ec76b84ae8` precondition:credential_mode: evidence=contradictory freshness=unknown reasons=precondition:credential_mode:contradictory, precondition:credential_mode:unknown
- `pacp-a019dea82de5acb0` precondition:effect_contract: evidence=unknown freshness=unknown reasons=precondition:effect_contract:missing, precondition:effect_contract:unknown
- `pacp-7f0dec0436ff9405` precondition:environment: evidence=unknown freshness=unknown reasons=precondition:environment:unknown
- `pacp-ba4fe8a7b9e5f2dc` precondition:expected_effect: evidence=unknown freshness=unknown reasons=precondition:expected_effect:unknown
- `pacp-7cc8594be1adc6da` precondition:forbidden_effect: evidence=unknown freshness=unknown reasons=precondition:forbidden_effect:missing, precondition:forbidden_effect:unknown
- `pacp-340144de93dd20fb` precondition:freshness: evidence=unknown freshness=unknown reasons=precondition:freshness:not_fresh, precondition:freshness:unknown
- `pacp-4771e8ee3d427469` precondition:policy_digest: evidence=unknown freshness=unknown reasons=precondition:policy_digest:unknown
- `pacp-3531ca4b0c555dd5` precondition:producer: evidence=unknown freshness=unknown reasons=precondition:producer:missing, precondition:producer:unknown
- `pacp-1994506befa8f568` precondition:required_check: evidence=unknown freshness=unknown reasons=precondition:required_check:missing, precondition:required_check:unknown
- `pacp-7ed1ef483fecb641` precondition:sandbox: evidence=unknown freshness=unknown reasons=precondition:sandbox:missing, precondition:sandbox:unknown
- `pacp-d40be4e1dcaad109` precondition:target: evidence=unknown freshness=unknown reasons=precondition:target:unknown
- `pacp-44a5716c48dcec31` precondition:validation_contract: evidence=unknown freshness=unknown reasons=precondition:validation_contract:missing, precondition:validation_contract:unknown

## Imported Gait and Axym Evidence

- `pacl-3d1578dfa4c371e1` gait_activation_request from gait: evidence=unknown freshness=expired refs=interop:approval-expiry proof=proof:interop:approval-expiry

## Presentation Limits

- authority_requirements.pacr-2235a80f56736851.evidence_refs: reason=item_cap omitted=35
- authority_requirements.pacr-44d1e4b8f062084d.evidence_refs: reason=item_cap omitted=35
- authority_requirements.pacr-8a0684edd81a5be1.evidence_refs: reason=item_cap omitted=35
- authority_requirements.pacr-bf2fc3de3afd4266.evidence_refs: reason=item_cap omitted=35
- authority_requirements.pacr-c238b6879d672f85.evidence_refs: reason=item_cap omitted=35
- authority_requirements.pacr-d46c56997d03521a.evidence_refs: reason=item_cap omitted=35
- authority_requirements.pacr-d713cfbe4c71401d.evidence_refs: reason=item_cap omitted=35
- authority_requirements.pacr-e4179cdb170f2ff8.evidence_refs: reason=item_cap omitted=35
- authority_requirements.pacr-fd81566365518444.evidence_refs: reason=item_cap omitted=35
- readiness_checks.pacp-1994506befa8f568.evidence_refs: reason=item_cap omitted=35
- readiness_checks.pacp-340144de93dd20fb.evidence_refs: reason=item_cap omitted=35
- readiness_checks.pacp-3531ca4b0c555dd5.evidence_refs: reason=item_cap omitted=35
- truncations: 9 additional presentation-limit records omitted

## Next Action

- Action: Resolve pacr-8a0684edd81a5be1 before requesting a Gait activation decision.
- Reason: authority:affected_system_owner remains unknown
- Owner: contract owner

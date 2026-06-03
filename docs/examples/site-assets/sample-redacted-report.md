# Wrkr Deterministic Report

- Generated at: 2026-01-01T00:00:00Z
- Template: ciso
- Share profile: customer-redacted

## Executive Rollup

- total_groups=12 total_paths=20
- group=xrg-ef3bf0cab866 count=1 severity=critical priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-4bd1cfe8
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 credential_access paths grouped by production_impacting and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=standing
- group=xrg-ca230a7008b5 count=4 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-1a6e2fbd, path-aea359df, path-c427c00e
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=4 egress paths grouped by developer_productivity and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-72044fd98ef0 count=3 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-45689901, path-e20cb15e, path-f557e358
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=3 read paths grouped by test_demo_sandbox and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-0c18386d7513 count=2 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-7462113c, path-7bc48b8c
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=2 read paths grouped by developer_productivity and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-4ed90b3e19cb count=2 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-ad8e5de2, path-fa61c8c4
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=2 read paths grouped by unknown and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-d1fc21252ebb count=2 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-2f2bda2d, path-31e098e8
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=2 write paths grouped by developer_productivity and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-343a544f0af3 count=1 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-6c68d1b5
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 read paths grouped by developer_productivity and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-9082d90b7239 count=1 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-316db0d7
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 execute paths grouped by developer_productivity and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-b4eb30e04fc1 count=1 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-445e7c6c
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 egress paths grouped by unknown and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-b339af3f7b36 count=1 severity=low priority=inventory_hygiene closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-9ed20f75
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 read paths grouped by test_demo_sandbox and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-c3730c7e7271 count=1 severity=low priority=inventory_hygiene closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-827d9232
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 read paths grouped by unknown and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-c6684b5fc5ea count=1 severity=low priority=inventory_hygiene closure=remediate evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-efbe1d8d
  recommendation=remediate standing production deploy paths first
  rationale=1 write paths grouped by test_demo_sandbox and unknown evidence | closure=remediate repo_cluster=single_repo credential_authority=unknown

## Workflow Chain Highlights

- Total buyer-facing workflow paths: 17

- path=path-4bd1cfe8 repo=repo-eb0de2 workflow=loc-415e1600 type=ci_cd_workflow target=production_impacting autonomy=prod or customer impacting readiness=blocked authority=deploy_key | standing | workflow_secret_ref blast_radius=production-impacting authority approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=partial evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- path=path-445e7c6c repo=repo-10e08a workflow=loc-d5d3368a type=plain_source_code target=unknown autonomy=sensitive code or infra readiness=review required authority=unknown | unknown | unknown blast_radius=unknown approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=insufficient evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- path=path-f290d9be repo=repo-1cf387 workflow=loc-6d5c8bdb type=ai_assisted_workflow target=developer_productivity autonomy=sensitive code or infra readiness=review required authority=unknown | unknown | unknown blast_radius=developer productivity approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=insufficient evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- path=path-aea359df repo=repo-10e08a workflow=loc-f27ac6f3 type=ai_assisted_workflow target=developer_productivity autonomy=sensitive code or infra readiness=review required authority=unknown | unknown | unknown blast_radius=developer productivity approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=insufficient evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- path=path-31e098e8 repo=repo-10e08a workflow=loc-f27ac6f3 type=ai_assisted_workflow target=developer_productivity autonomy=sensitive code or infra readiness=review required authority=unknown | unknown | unknown blast_radius=developer productivity approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=insufficient evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.

## Assessment Summary

- Scope: static posture from saved scan state only; no runtime observation or enforcement
- Governable paths: 20
- Write-capable paths: 3
- Production-target-backed paths: 0
- Top path to control first: repo-eb0de2 loc-415e1600 (proof, trigger=deploy_pipeline)
- Ownerless exposure: explicit=0 inferred=20 unresolved=0 conflict=0
- Proof chain: redacted://proof-chain.json
- Exposure groups: 14

## Scan Quality

- Mode: governance
- Coverage summary: confidence=complete reduced_detectors=0 parse_failures=0 suppressed_generated_files=0 blocked_detectors=0 unsupported_declarations=0 impact=Coverage for scanned inputs was complete enough to support scoped negative claims.
- mcp_server absence_status=not_found_with_complete_coverage reasons=detector:mcp=complete,detector:webmcp=complete,webmcp:no_candidate_inputs impact=Complete MCP coverage supported a clean negative result for the scanned surfaces.
- mcp_server absence_status=not_found_with_complete_coverage reasons=detector:mcp=complete,detector:webmcp=complete,mcp:no_candidate_inputs,webmcp:no_candidate_inputs impact=Complete MCP coverage supported a clean negative result for the scanned surfaces.
- mcp_server absence_status=not_found_with_complete_coverage reasons=detector:mcp=complete,detector:webmcp=complete,mcp:no_candidate_inputs,webmcp:no_candidate_inputs impact=Complete MCP coverage supported a clean negative result for the scanned surfaces.

## Control Backlog

- repo-10e08a loc-e026f56c owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-123533ff:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-c03c9950:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-64d4853d:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-01c44c06:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-0db9f46c owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-475fb3a9:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-6b74588a:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-771658ef:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-54fd540e:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=high credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-f27ac6f3 owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-38202f3a:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-b969654b:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-42652f50:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-9ef55ba8:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=high credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-f27ac6f3 owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-7e0bc613:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-355921b4:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-fc60fd8a:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-484c5f4d:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-d5d3368a owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-cf97cb28:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-4b5bab15:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-d425aa53:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-eee180f3:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-d5d3368a owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(57)
  closure_requirements=clr-4dbb5bec:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-685ddba1:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-1dfeb0c7:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-80b35933:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-6ebdb617 owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(56)
  closure_requirements=clr-af76f2bb:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-b9be2d17:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-666a3926:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-ec24d20b:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-0f9c7c loc-f32a51ab owner=owner-1cb36bca queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-dd3d2bfb:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-82c20c33:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-6e629ae6:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-879c7a9f:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=high credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-0f9c7c loc-a54ff182 owner=owner-1cb36bca queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(56)
  closure_requirements=clr-18a11361:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-3f80bca6:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-d05b814c:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-1b9565c2:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-8b2df8 loc-d7e67997 owner=owner-abe8a52e queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(57)
  closure_requirements=clr-8fd42371:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-ed206a78:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-356326c4:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-0c9bf6e6:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.

## Scan Quality Appendix

- mcp status=complete attempted=2 parsed=2 partial=0 suppressed=0 failures=0 reasons=
- webmcp status=complete attempted=0 parsed=0 partial=0 suppressed=0 failures=0 reasons=no_candidate_inputs
- dependency status=complete attempted=1 parsed=1 partial=0 suppressed=0 failures=0 reasons=
- mcp status=complete attempted=1 parsed=1 partial=0 suppressed=0 failures=0 reasons=
- webmcp status=complete attempted=0 parsed=0 partial=0 suppressed=0 failures=0 reasons=no_candidate_inputs
- mcp status=complete attempted=0 parsed=0 partial=0 suppressed=0 failures=0 reasons=no_candidate_inputs
- webmcp status=complete attempted=0 parsed=0 partial=0 suppressed=0 failures=0 reasons=no_candidate_inputs
- mcp status=complete attempted=1 parsed=1 partial=0 suppressed=0 failures=0 reasons=
- webmcp status=complete attempted=0 parsed=0 partial=0 suppressed=0 failures=0 reasons=no_candidate_inputs
- ciagent status=complete attempted=1 parsed=1 partial=0 suppressed=0 failures=0 reasons=
- mcp status=complete attempted=0 parsed=0 partial=0 suppressed=0 failures=0 reasons=no_candidate_inputs
- webmcp status=complete attempted=0 parsed=0 partial=0 suppressed=0 failures=0 reasons=no_candidate_inputs

## CISO control backlog summary (headline_posture)

- posture score 56.62 (F)
- profile status fail at 43.75%
- tools=20 write_capable=3 credential_access=1 exec_capable=5
- bundled framework mappings stay available; profile compliance reflects only controls evidenced in the current deterministic scan state
- report scope stays at static posture and offline-verifiable proof; it does not claim runtime observation or control-layer enforcement
- security_visibility reference=initial_scan unknown_to_security_tools=20 unknown_to_security_agents=20 unknown_to_security_write_capable_agents=3
- 22 findings map to EU Artificial Intelligence Act ARTICLE-12 (Record-Keeping)
- 32 findings map to EU Artificial Intelligence Act ARTICLE-14 (Human Oversight)
- coverage still reflects only controls evidenced in the current scan state; remediate gaps, rescan, and regenerate report/evidence artifacts
- production_write=0 (status=configured)
- source_privacy deployment_mode=local_only retention=ephemeral retained=false raw_source_in_artifacts=false serialized_locations=filesystem cleanup_status=not_applicable
- control_path_graph version=1 nodes=544 edges=506
- control_path_graph nodes[action_capability]=23
- control_path_graph nodes[agent]=20
- control_path_graph nodes[agent_team]=20
- control_path_graph nodes[approval_identity]=20
- control_path_graph nodes[asset_identity]=20
- control_path_graph nodes[control_path]=20
- control_path_graph nodes[credential]=1
- control_path_graph nodes[deployment_path]=20
- control_path_graph nodes[evidence_identity]=20
- control_path_graph nodes[execution_identity]=20
- control_path_graph nodes[governance_control]=160
- control_path_graph nodes[human_identity]=20
- control_path_graph nodes[intent]=20
- control_path_graph nodes[outcome]=20
- control_path_graph nodes[policy_identity]=20
- control_path_graph nodes[pull_request]=20
- control_path_graph nodes[repo]=20
- control_path_graph nodes[task]=20
- control_path_graph nodes[tool]=20
- control_path_graph nodes[workflow]=20
- control_path_graph nodes[workflow_run]=20
- control_path_graph edges[agent_controls_path]=20
- control_path_graph edges[agent_team_uses_tool]=20
- control_path_graph edges[approval_authorizes_deploy]=20
- control_path_graph edges[checks_gate_approval]=20
- control_path_graph edges[credential_authorizes_workflow]=1
- control_path_graph edges[deploy_affects_asset]=20
- control_path_graph edges[evidence_proves_outcome]=20
- control_path_graph edges[execution_uses_credential]=1
- control_path_graph edges[human_delegates_task]=20
- control_path_graph edges[path_enables_action]=23
- control_path_graph edges[path_executes_workflow]=20
- control_path_graph edges[path_governed_by]=160
- control_path_graph edges[path_runs_as]=20
- control_path_graph edges[path_uses_tool]=20
- control_path_graph edges[pull_request_runs_checks]=20
- control_path_graph edges[repo_produces_pull_request]=20
- control_path_graph edges[request_to_human]=20
- control_path_graph edges[task_executed_by_agent_team]=20
- control_path_graph edges[tool_uses_credential]=1
- control_path_graph edges[workflow_changes_repo]=20
- control_path_graph edges[workflow_in_repo]=20

Impact: profile compliance is failing and introduces immediate governance risk
Action: resolve failing or missing controls, regenerate evidence, and rerun scan with the same deterministic inputs
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=179

## Top governance control backlog items (top_prioritized_risks)

- #1 10.00 confirmed_action_path [critical] lane=confirmed_action_path action=proof state=block_recommended zone=credential_bearing review=critical repo=repo-eb0de2 location=loc-415e1600
- #2 5.67 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-10e08a location=loc-d5d3368a
- #3 10.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-1cf387 location=loc-6d5c8bdb
- #4 5.67 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-10e08a location=loc-f27ac6f3
- #5 8.20 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-10e08a location=loc-f27ac6f3
- #6 8.20 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-0f9c7c location=loc-f32a51ab
- #7 4.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-10e08a location=loc-d5d3368a
- #8 4.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-1cf387 location=loc-6d5c8bdb
- #9 3.60 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-0f9c7c location=loc-a54ff182
- #10 3.60 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-1cf387 location=loc-315161dd
- #11 3.60 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-10e08a location=loc-6ebdb617
- #12 6.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=coding_help review=critical repo=repo-10e08a location=loc-0db9f46c
- #13 3.60 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-1cf387 location=loc-20c5bf90
- #14 3.60 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=coding_help review=critical repo=repo-10e08a location=loc-e026f56c
- #15 7.29 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=coding_help review=critical repo=repo-8b2df8 location=loc-d7e67997
- #16 3.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=coding_help review=critical repo=repo-1cf387 location=loc-e98d5093
- #17 3.96 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-eb0de2 location=loc-227c2c26
- #18 3.60 context_only_evidence [low] lane=context_only action=inventory state=inventory_only zone=coding_help review=high repo=repo-0f9c7c location=loc-a28316bc
- #19 9.80 context_only_evidence [low] lane=context_only action=inventory state=inventory_only zone=repo_write review=high repo=repo-1cf387 location=loc-768f8ff8
- #20 4.60 context_only_evidence [low] lane=context_only action=inventory state=inventory_only zone=coding_help review=high repo=repo-0f9c7c location=loc-33ef32bf
- attack paths: none generated from current findings

Impact: top 20 risks concentrate the highest blast-radius findings
Action: work highest score first and apply deterministic least-privilege remediation
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=179

## Risk and approval movement (change_since_previous)

- risk score trend current=10.00 delta=0.00 (no previous reference)
- profile compliance delta current=43.75 delta=0.00 (no previous reference)
- posture score trend delta current=56.62 delta=0.00 (no previous reference)

Impact: change deltas remain within expected deterministic variance
Action: continue baseline comparison on every governance scan cadence
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=179

## Executive ownership and approval actions (lifecycle_actions)

- identities=20 pending_action=41 under_review=0 revoked=0 deprecated=0
- gap inactive_but_credentialed severity=high repo=repo-eb0de2 location=loc-415e1600
- gap missing_approval severity=high repo=repo-10e08a location=loc-0db9f46c
- gap missing_approval severity=high repo=repo-10e08a location=loc-f27ac6f3
- gap missing_approval severity=high repo=repo-0f9c7c location=loc-f32a51ab
- gap missing_approval severity=high repo=repo-1cf387 location=loc-768f8ff8
- gap missing_approval severity=high repo=repo-eb0de2 location=loc-415e1600
- gap missing_approval severity=medium repo=repo-10e08a location=loc-e026f56c
- gap missing_approval severity=medium repo=repo-10e08a location=loc-f27ac6f3
- gap missing_approval severity=medium repo=repo-10e08a location=loc-d5d3368a
- gap missing_approval severity=medium repo=repo-10e08a location=loc-d5d3368a
- gap missing_approval severity=medium repo=repo-10e08a location=loc-6ebdb617
- gap missing_approval severity=medium repo=repo-0f9c7c location=loc-a54ff182
- gap missing_approval severity=medium repo=repo-0f9c7c location=loc-a28316bc
- gap missing_approval severity=medium repo=repo-0f9c7c location=loc-33ef32bf
- gap missing_approval severity=medium repo=repo-8b2df8 location=loc-d7e67997
- gap missing_approval severity=medium repo=repo-1cf387 location=loc-6d5c8bdb
- gap missing_approval severity=medium repo=repo-1cf387 location=loc-6d5c8bdb
- gap missing_approval severity=medium repo=repo-1cf387 location=loc-20c5bf90
- gap missing_approval severity=medium repo=repo-1cf387 location=loc-315161dd
- gap missing_approval severity=medium repo=repo-1cf387 location=loc-e98d5093
- gap missing_approval severity=medium repo=repo-eb0de2 location=loc-227c2c26
- gap owner_inferred severity=medium repo=repo-10e08a location=loc-e026f56c
- gap owner_inferred severity=medium repo=repo-10e08a location=loc-0db9f46c
- gap owner_inferred severity=medium repo=repo-10e08a location=loc-f27ac6f3
- gap owner_inferred severity=medium repo=repo-10e08a location=loc-f27ac6f3
- gap owner_inferred severity=medium repo=repo-10e08a location=loc-d5d3368a
- gap owner_inferred severity=medium repo=repo-10e08a location=loc-d5d3368a
- gap owner_inferred severity=medium repo=repo-10e08a location=loc-6ebdb617
- gap owner_inferred severity=medium repo=repo-0f9c7c location=loc-f32a51ab
- gap owner_inferred severity=medium repo=repo-0f9c7c location=loc-a54ff182
- gap owner_inferred severity=medium repo=repo-0f9c7c location=loc-a28316bc
- gap owner_inferred severity=medium repo=repo-0f9c7c location=loc-33ef32bf
- gap owner_inferred severity=medium repo=repo-8b2df8 location=loc-d7e67997
- gap owner_inferred severity=medium repo=repo-1cf387 location=loc-768f8ff8
- gap owner_inferred severity=medium repo=repo-1cf387 location=loc-6d5c8bdb
- gap owner_inferred severity=medium repo=repo-1cf387 location=loc-6d5c8bdb
- gap owner_inferred severity=medium repo=repo-1cf387 location=loc-20c5bf90
- gap owner_inferred severity=medium repo=repo-1cf387 location=loc-315161dd
- gap owner_inferred severity=medium repo=repo-1cf387 location=loc-e98d5093
- gap owner_inferred severity=medium repo=repo-eb0de2 location=loc-227c2c26
- gap owner_inferred severity=medium repo=repo-eb0de2 location=loc-415e1600
- transition agent-b5d97428 ->discovered (first_seen)
- transition agent-7736d637 ->discovered (first_seen)
- transition agent-897dbff8 ->discovered (first_seen)
- transition agent-b29c45ca ->discovered (first_seen)
- transition agent-2d482eed ->discovered (first_seen)

Impact: 41 identities require lifecycle approval/review/revocation handling
Action: prioritize under_review and revoked identities before enabling additional autonomy
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=179

## Evidence and proof verification (proof_verification_footer)

- chain_path=redacted://proof-chain.json
- head_hash=sha256:demo-proof-head
- record_count=179
- record_type decision=20
- record_type risk_assessment=27
- record_type scan_finding=132

Impact: proof chain references are attached for deterministic traceability
Action: preserve chain path and head hash when distributing this artifact
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=179

## Next executive control actions (next_actions)

- review govern-first path path-4bd1cfe8 in repo-eb0de2:loc-415e1600 (action=proof score=10.00)
- review 41 lifecycle records requiring approval/review/revocation action
- verify proof chain integrity before sharing artifacts externally

Impact: deterministic next actions focus operators on highest leverage controls
Action: execute checklist items in order and rescan to confirm posture improvement
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=179

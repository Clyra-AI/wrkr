# Wrkr Deterministic Report

- Generated at: 2026-01-01T00:00:00Z
- Template: ciso
- Share profile: customer-redacted

## Executive Rollup

- total_groups=13 total_paths=22
- group=xrg-ef3bf0cab866 count=1 severity=critical priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-4bd1cfe8
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 credential_access paths grouped by production_impacting and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=standing
- group=xrg-504feb2957f4 count=2 severity=critical priority=control_first closure=remediate evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-2f2bda2d, path-31e098e8
  recommendation=remediate standing production deploy paths first
  rationale=2 deploy paths grouped by developer_productivity and unknown evidence | closure=remediate repo_cluster=single_repo credential_authority=unknown
- group=xrg-ca230a7008b5 count=5 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-1a6e2fbd, path-7d58f43e, path-aea359df
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=5 egress paths grouped by developer_productivity and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-0c18386d7513 count=2 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-7462113c, path-7bc48b8c
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=2 read paths grouped by developer_productivity and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-4ed90b3e19cb count=2 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-ad8e5de2, path-fa61c8c4
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=2 read paths grouped by unknown and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-72044fd98ef0 count=2 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-45689901, path-e20cb15e
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=2 read paths grouped by test_demo_sandbox and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-b4eb30e04fc1 count=2 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-445e7c6c, path-4e78dcfb
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=2 egress paths grouped by unknown and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-27c8ba42b953 count=1 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-f557e358
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 read paths grouped by test_demo_sandbox and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=none
- group=xrg-343a544f0af3 count=1 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-6c68d1b5
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 read paths grouped by developer_productivity and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-9082d90b7239 count=1 severity=high priority=review_queue closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-316db0d7
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 execute paths grouped by developer_productivity and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-b339af3f7b36 count=1 severity=low priority=inventory_hygiene closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-9ed20f75
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 read paths grouped by test_demo_sandbox and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=unknown
- group=xrg-c6684b5fc5ea count=1 severity=low priority=inventory_hygiene closure=remediate evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-efbe1d8d
  recommendation=remediate standing production deploy paths first
  rationale=1 write paths grouped by test_demo_sandbox and unknown evidence | closure=remediate repo_cluster=single_repo credential_authority=unknown
- group=xrg-e18e7d78ad58 count=1 severity=low priority=inventory_hygiene closure=attach_evidence evidence=unknown owner=inferred repo_cluster=single_repo contradictions=consistent examples=path-827d9232
  recommendation=attach missing approval, proof, or runtime evidence before promotion
  rationale=1 read paths grouped by unknown and unknown evidence | closure=attach_evidence repo_cluster=single_repo credential_authority=none

## Workflow Chain Highlights

- Total buyer-facing workflow paths: 19

- path=path-31e098e8 repo=repo-10e08a workflow=loc-f27ac6f3 type=agent_instruction_surface target=developer_productivity autonomy=prod or customer impacting readiness=review required authority=no credential authority linked blast_radius=production-impacting authority approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=insufficient evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- path=path-2f2bda2d repo=repo-0f9c7c workflow=loc-f32a51ab type=agent_instruction_surface target=developer_productivity autonomy=prod or customer impacting readiness=review required authority=no credential authority linked blast_radius=production-impacting authority approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=insufficient evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- path=path-4bd1cfe8 repo=repo-eb0de2 workflow=loc-415e1600 type=ci_cd_workflow target=production_impacting autonomy=prod or customer impacting readiness=blocked authority=credential-9d82507e | workflow | standing blast_radius=production-impacting authority approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=partial evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- path=path-445e7c6c repo=repo-10e08a workflow=loc-d5d3368a type=agent_instruction_surface target=unknown autonomy=sensitive code or infra readiness=review required authority=no credential authority linked blast_radius=unknown approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=insufficient evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- path=path-4e78dcfb repo=repo-eb0de2 workflow=loc-756c99ad type=plain_source_code target=unknown autonomy=sensitive code or infra readiness=review required authority=no credential authority linked blast_radius=unknown approval=approval evidence not found proof=path-specific proof not found runtime=runtime evidence not collected session=not_collected boundary=report_only recommendation=attach approval evidence for the exact workflow path
  evidence=control=visible control evidence detected | owner=owner evidence inferred | coverage=insufficient evidence coverage
  explanation=The authority is visible, but approval evidence for this exact workflow path is still missing or weak.

## Assessment Summary

- Scope: static posture from saved scan state only; no runtime observation or enforcement
- Governable paths: 22
- Write-capable paths: 3
- Production-target-backed paths: 2
- Top path to control first: repo-10e08a loc-f27ac6f3 (control, trigger=deploy_pipeline)
- Ownerless exposure: explicit=0 inferred=22 unresolved=0 conflict=0
- Proof chain: redacted://proof-chain.json
- Exposure groups: 15

## Policy Outcomes

- Rule WRKR-A006 is fail across 8 occurrence(s) in 4 repo(s): repo-b583bb, repo-a24cd4, repo-88604b, plus 1 more.
- Rule WRKR-A007 is fail across 8 occurrence(s) in 4 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 1 more.
- Rule WRKR-011 is pass across 5 occurrence(s) in 5 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 2 more.
- Rule WRKR-012 is pass across 5 occurrence(s) in 5 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 2 more.
- Rule WRKR-013 is pass across 5 occurrence(s) in 5 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 2 more.
- Rule WRKR-A003 is pass across 5 occurrence(s) in 5 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 2 more.
- Rule WRKR-A008 is pass across 5 occurrence(s) in 5 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 2 more.
- Rule WRKR-A009 is pass across 5 occurrence(s) in 5 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 2 more.
- Rule WRKR-A010 is pass across 5 occurrence(s) in 5 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 2 more.
- Rule WRKR-014 is pass across 4 occurrence(s) in 4 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 1 more.
- Rule WRKR-015 is pass across 4 occurrence(s) in 4 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 1 more.
- Rule WRKR-016 is pass across 4 occurrence(s) in 4 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 1 more.
- Rule WRKR-A001 is pass across 4 occurrence(s) in 4 repo(s): repo-b583bb, repo-fbf3f7, repo-88604b, plus 1 more.
- Rule WRKR-A002 is fail across 4 occurrence(s) in 2 repo(s): repo-a24cd4, repo-34614a.
- Rule WRKR-A004 is pass across 4 occurrence(s) in 4 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 1 more.
- Rule WRKR-A005 is fail across 4 occurrence(s) in 2 repo(s): repo-fbf3f7, repo-a24cd4.
- Rule WRKR-A002 is pass across 3 occurrence(s) in 3 repo(s): repo-b583bb, repo-fbf3f7, repo-88604b.
- Rule WRKR-A005 is pass across 3 occurrence(s) in 3 repo(s): repo-b583bb, repo-88604b, repo-34614a.
- Rule WRKR-014 is fail across 2 occurrence(s) in 1 repo(s): repo-88604b.
- Rule WRKR-015 is fail across 2 occurrence(s) in 1 repo(s): repo-88604b.
- Rule WRKR-016 is fail across 2 occurrence(s) in 1 repo(s): repo-34614a.
- Rule WRKR-A001 is fail across 2 occurrence(s) in 1 repo(s): repo-a24cd4.
- Rule WRKR-A004 is fail across 2 occurrence(s) in 1 repo(s): repo-34614a.
- Rule WRKR-A006 is pass across 1 occurrence(s) in 1 repo(s): repo-fbf3f7.
- Rule WRKR-A007 is pass across 1 occurrence(s) in 1 repo(s): repo-88604b.

## Scan Quality

- Mode: governance
- Coverage summary: confidence=complete reduced_detectors=0 parse_failures=0 suppressed_generated_files=0 blocked_detectors=0 unsupported_declarations=0 impact=Coverage for scanned inputs was complete enough to support scoped negative claims.
- mcp_server absence_status=not_found_with_complete_coverage reasons=detector:mcp=complete,detector:webmcp=complete,webmcp:no_candidate_inputs impact=Complete MCP coverage supported a clean negative result for the scanned surfaces.
- mcp_server absence_status=not_found_with_complete_coverage reasons=detector:mcp=complete,detector:webmcp=complete,mcp:no_candidate_inputs,webmcp:no_candidate_inputs impact=Complete MCP coverage supported a clean negative result for the scanned surfaces.

## Control Backlog

- repo-10e08a loc-f27ac6f3 owner=owner-c115ecf5 queue=control_first visibility=primary action=remediate sla=7d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Add or verify deployment gates, tighten write scope, attach path-specific proof, and rescan until this deploy-capable path drops out of the control-first queue.
  completeness=insufficient evidence coverage(58)
  closure_requirements=clr-38202f3a:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-b969654b:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-42652f50:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-9ef55ba8:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified. | clr-3e07300c:Prove the deployment or branch-protection constraint for this path before treating delivery controls as verified.
  lifecycle_queue=missing_approval severity=high credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-0f9c7c loc-f32a51ab owner=owner-1cb36bca queue=control_first visibility=primary action=remediate sla=7d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Add or verify deployment gates, tighten write scope, attach path-specific proof, and rescan until this deploy-capable path drops out of the control-first queue.
  completeness=insufficient evidence coverage(58)
  closure_requirements=clr-dd3d2bfb:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-82c20c33:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-6e629ae6:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-879c7a9f:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified. | clr-a8c0516b:Prove the deployment or branch-protection constraint for this path before treating delivery controls as verified.
  lifecycle_queue=missing_approval severity=high credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-e026f56c owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-123533ff:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-c03c9950:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-64d4853d:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-01c44c06:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-0db9f46c owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-475fb3a9:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-6b74588a:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-771658ef:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-54fd540e:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=high credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-f27ac6f3 owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact instruction surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-7e0bc613:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-355921b4:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-fc60fd8a:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-484c5f4d:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-d5d3368a owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this MCP configuration surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact MCP configuration surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-cf97cb28:Assign explicit owner evidence for this MCP configuration surface and attach a linked owner record before approving or expanding it. | clr-4b5bab15:Attach approval evidence for this exact MCP configuration surface with scope and expiry before treating it as governed. | clr-d425aa53:Attach a path-specific policy or proof reference for this exact MCP configuration surface and rescan so proof is no longer inferred or absent. | clr-eee180f3:Collect runtime evidence for this MCP configuration surface and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-d5d3368a owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this MCP configuration surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact MCP configuration surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-4dbb5bec:Assign explicit owner evidence for this MCP configuration surface and attach a linked owner record before approving or expanding it. | clr-685ddba1:Attach approval evidence for this exact MCP configuration surface with scope and expiry before treating it as governed. | clr-1dfeb0c7:Attach a path-specific policy or proof reference for this exact MCP configuration surface and rescan so proof is no longer inferred or absent. | clr-80b35933:Collect runtime evidence for this MCP configuration surface and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-6ebdb617 owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact instruction surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(56)
  closure_requirements=clr-af76f2bb:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-b9be2d17:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-666a3926:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-ec24d20b:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=missing_approval severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-0f9c7c loc-a54ff182 owner=owner-1cb36bca queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact instruction surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(56)
  closure_requirements=clr-18a11361:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-3f80bca6:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-d05b814c:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-1b9565c2:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified.
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
- mcp status=complete attempted=1 parsed=1 partial=0 suppressed=0 failures=0 reasons=
- webmcp status=complete attempted=0 parsed=0 partial=0 suppressed=0 failures=0 reasons=no_candidate_inputs

## CISO control backlog summary (headline_posture)

- posture score 51.89 (F)
- profile status fail at 43.75%
- tools=22 write_capable=3 credential_access=1 exec_capable=5
- bundled framework mappings stay available; profile compliance reflects only controls evidenced in the current deterministic scan state
- report scope stays at static posture and offline-verifiable proof; it does not claim runtime observation or control-layer enforcement
- security_visibility reference=initial_scan unknown_to_security_tools=22 unknown_to_security_agents=22 unknown_to_security_write_capable_agents=3
- 22 findings map to EU Artificial Intelligence Act ARTICLE-12 (Record-Keeping)
- 32 findings map to EU Artificial Intelligence Act ARTICLE-14 (Human Oversight)
- coverage still reflects only controls evidenced in the current scan state; remediate gaps, rescan, and regenerate report/evidence artifacts
- production_write=2 (status=configured)
- source_privacy deployment_mode=local_only retention=ephemeral retained=false raw_source_in_artifacts=false serialized_locations=filesystem cleanup_status=not_applicable
- control_path_graph version=1 nodes=604 edges=562
- control_path_graph nodes[action_capability]=29
- control_path_graph nodes[agent]=22
- control_path_graph nodes[agent_team]=22
- control_path_graph nodes[approval_identity]=22
- control_path_graph nodes[asset_identity]=22
- control_path_graph nodes[control_path]=22
- control_path_graph nodes[credential]=1
- control_path_graph nodes[deployment_path]=22
- control_path_graph nodes[evidence_identity]=22
- control_path_graph nodes[execution_identity]=22
- control_path_graph nodes[governance_control]=176
- control_path_graph nodes[human_identity]=22
- control_path_graph nodes[intent]=22
- control_path_graph nodes[outcome]=22
- control_path_graph nodes[policy_identity]=22
- control_path_graph nodes[pull_request]=22
- control_path_graph nodes[repo]=22
- control_path_graph nodes[target]=2
- control_path_graph nodes[task]=22
- control_path_graph nodes[tool]=22
- control_path_graph nodes[workflow]=22
- control_path_graph nodes[workflow_run]=22
- control_path_graph edges[agent_controls_path]=22
- control_path_graph edges[agent_team_uses_tool]=22
- control_path_graph edges[approval_authorizes_deploy]=22
- control_path_graph edges[checks_gate_approval]=22
- control_path_graph edges[credential_authorizes_workflow]=1
- control_path_graph edges[deploy_affects_asset]=22
- control_path_graph edges[evidence_proves_outcome]=22
- control_path_graph edges[execution_uses_credential]=1
- control_path_graph edges[human_delegates_task]=22
- control_path_graph edges[path_enables_action]=29
- control_path_graph edges[path_executes_workflow]=22
- control_path_graph edges[path_governed_by]=176
- control_path_graph edges[path_runs_as]=22
- control_path_graph edges[path_targets_surface]=2
- control_path_graph edges[path_uses_tool]=22
- control_path_graph edges[pull_request_runs_checks]=22
- control_path_graph edges[repo_produces_pull_request]=22
- control_path_graph edges[request_to_human]=22
- control_path_graph edges[task_executed_by_agent_team]=22
- control_path_graph edges[tool_uses_credential]=1
- control_path_graph edges[workflow_changes_repo]=22
- control_path_graph edges[workflow_in_repo]=22

Impact: profile compliance is failing and introduces immediate governance risk
Action: resolve failing or missing controls, regenerate evidence, and rerun scan with the same deterministic inputs
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=130

## Top governance control backlog items (top_prioritized_risks)

- #1 8.20 likely_action_path [critical] lane=likely_action_path action=control state=approval_required zone=production_data review=critical repo=repo-10e08a location=loc-f27ac6f3
- #2 8.20 likely_action_path [critical] lane=likely_action_path action=control state=approval_required zone=production_data review=critical repo=repo-0f9c7c location=loc-f32a51ab
- #3 10.00 confirmed_action_path [critical] lane=confirmed_action_path action=proof state=block_recommended zone=credential_bearing review=critical repo=repo-eb0de2 location=loc-415e1600
- #4 5.67 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-10e08a location=loc-d5d3368a
- #5 10.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-eb0de2 location=loc-756c99ad
- #6 10.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-1cf387 location=loc-6d5c8bdb
- #7 5.67 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-10e08a location=loc-f27ac6f3
- #8 7.29 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=coding_help review=critical repo=repo-8b2df8 location=loc-d7e67997
- #9 4.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-10e08a location=loc-d5d3368a
- #10 4.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-1cf387 location=loc-6d5c8bdb
- #11 4.40 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-eb0de2 location=loc-756c99ad
- #12 3.60 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-0f9c7c location=loc-a54ff182
- #13 3.60 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-1cf387 location=loc-315161dd
- #14 3.60 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-10e08a location=loc-6ebdb617
- #15 3.60 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-1cf387 location=loc-20c5bf90
- #16 6.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=coding_help review=critical repo=repo-10e08a location=loc-0db9f46c
- #17 3.60 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=coding_help review=critical repo=repo-10e08a location=loc-e026f56c
- #18 3.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=coding_help review=critical repo=repo-1cf387 location=loc-e98d5093
- #19 3.96 review_candidate [high] lane=semantic_review_candidate action=proof state=approval_required zone=coding_help review=critical repo=repo-eb0de2 location=loc-227c2c26
- #20 3.60 context_only_evidence [low] lane=context_only action=inventory state=inventory_only zone=coding_help review=high repo=repo-0f9c7c location=loc-a28316bc
- #21 9.80 context_only_evidence [low] lane=context_only action=inventory state=inventory_only zone=repo_write review=high repo=repo-1cf387 location=loc-768f8ff8
- #22 4.60 context_only_evidence [low] lane=context_only action=inventory state=inventory_only zone=coding_help review=high repo=repo-0f9c7c location=loc-33ef32bf
- attack paths: none generated from current findings

Impact: top 22 risks concentrate the highest blast-radius findings
Action: work highest score first and apply deterministic least-privilege remediation
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=130

## Risk and approval movement (change_since_previous)

- risk score trend current=10.00 delta=0.00 (no previous reference)
- profile compliance delta current=43.75 delta=0.00 (no previous reference)
- posture score trend delta current=51.89 delta=0.00 (no previous reference)

Impact: change deltas remain within expected deterministic variance
Action: continue baseline comparison on every governance scan cadence
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=130

## Executive ownership and approval actions (lifecycle_actions)

- identities=22 pending_action=45 under_review=0 revoked=0 deprecated=0
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
- gap missing_approval severity=medium repo=repo-eb0de2 location=loc-756c99ad
- gap missing_approval severity=medium repo=repo-eb0de2 location=loc-756c99ad
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
- gap owner_inferred severity=medium repo=repo-eb0de2 location=loc-756c99ad
- gap owner_inferred severity=medium repo=repo-eb0de2 location=loc-756c99ad
- transition agent-b5d97428 ->discovered (first_seen)
- transition agent-7736d637 ->discovered (first_seen)
- transition agent-897dbff8 ->discovered (first_seen)
- transition agent-b29c45ca ->discovered (first_seen)
- transition agent-2d482eed ->discovered (first_seen)

Impact: 45 identities require lifecycle approval/review/revocation handling
Action: prioritize under_review and revoked identities before enabling additional autonomy
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=130

## Evidence and proof verification (proof_verification_footer)

- chain_path=redacted://proof-chain.json
- head_hash=sha256:demo-proof-head
- record_count=130
- record_type decision_trace=13
- record_type lifecycle_transition=22
- record_type risk_assessment=29
- record_type scan_finding=66

Impact: proof chain references are attached for deterministic traceability
Action: preserve chain path and head hash when distributing this artifact
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=130

## Next executive control actions (next_actions)

- review govern-first path path-31e098e8 in repo-10e08a:loc-f27ac6f3 (action=control score=8.20)
- review 45 lifecycle records requiring approval/review/revocation action
- verify proof chain integrity before sharing artifacts externally

Impact: deterministic next actions focus operators on highest leverage controls
Action: execute checklist items in order and rescan to confirm posture improvement
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=130

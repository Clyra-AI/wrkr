# Wrkr Deterministic Report

- Generated at: 2026-01-01T00:00:00Z
- Template: ciso
- Share profile: customer-redacted

## Executive Rollup

- Summary: 13 grouped exposures across 20 action paths.
- credential access affecting production impacting: 1 path; critical severity; review queue priority; attach evidence closure.
  Evidence: confirmed path: action path detected, single repository scope; inferred relationship: owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-31990a09.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 1 credential access path grouped by production impacting and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: standing.
- deploy affecting developer productivity: 2 paths; critical severity; control first priority; remediate closure.
  Evidence: confirmed path: single repository scope; inferred relationship: action relationship, owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-2f2bda2d, path-31e098e8.
  Recommendation: resolve credential authority, then remediate the highest-impact paths first.
  Rationale: 2 deploy paths grouped by developer productivity and unknown evidence | closure: remediate repo cluster: single repo credential authority: unknown.
- egress affecting developer productivity: 4 paths; high severity; review queue priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: action relationship, owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-1a6e2fbd, path-aea359df, path-c427c00e.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 4 egress paths grouped by developer productivity and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: unknown.
- read affecting developer productivity: 2 paths; high severity; review queue priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: action relationship, owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-7462113c, path-7bc48b8c.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 2 read paths grouped by developer productivity and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: unknown.
- read affecting unknown: 2 paths; high severity; review queue priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: action relationship, owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-049802e2, path-fa61c8c4.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 2 read paths grouped by unknown and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: unknown.
- read affecting test demo sandbox: 2 paths; high severity; review queue priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: action relationship, owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-45689901, path-e20cb15e.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 2 read paths grouped by test demo sandbox and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: unknown.
- read affecting test demo sandbox: 1 path; high severity; review queue priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: action relationship, owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-f557e358.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 1 read path grouped by test demo sandbox and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: none.
- read affecting developer productivity: 1 path; high severity; review queue priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: action relationship, owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-6c68d1b5.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 1 read path grouped by developer productivity and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: unknown.
- execute affecting developer productivity: 1 path; high severity; review queue priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: action relationship, owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-316db0d7.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 1 execute path grouped by developer productivity and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: unknown.
- egress affecting unknown: 1 path; high severity; review queue priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: action relationship, owner inferred; unresolved context: evidence state unknown; contradictions consistent. Examples: path-445e7c6c.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 1 egress path grouped by unknown and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: unknown.
- read affecting test demo sandbox: 1 path; low severity; inventory hygiene priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: owner inferred; unresolved context: path classification, evidence state unknown; contradictions consistent. Examples: path-9ed20f75.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 1 read path grouped by test demo sandbox and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: unknown.
- write affecting test demo sandbox: 1 path; low severity; inventory hygiene priority; remediate closure.
  Evidence: confirmed path: single repository scope; inferred relationship: owner inferred; unresolved context: path classification, evidence state unknown; contradictions consistent. Examples: path-efbe1d8d.
  Recommendation: resolve credential authority, then remediate the highest-impact paths first.
  Rationale: 1 write path grouped by test demo sandbox and unknown evidence | closure: remediate repo cluster: single repo credential authority: unknown.
- read affecting unknown: 1 path; low severity; inventory hygiene priority; attach evidence closure.
  Evidence: confirmed path: single repository scope; inferred relationship: owner inferred; unresolved context: path classification, evidence state unknown; contradictions consistent. Examples: path-827d9232.
  Recommendation: attach or import approval, proof, or runtime evidence before making a control claim.
  Rationale: 1 read path grouped by unknown and unknown evidence | closure: attach evidence repo cluster: single repo credential authority: none.

## Workflow Chain Highlights

- Total buyer-facing workflow paths: 16

- Path path-31e098e8: agent instruction surface in repo-10e08a via loc-f27ac6f3; target developer productivity; autonomy prod or customer impacting; readiness review required.
  Authority: no credential authority linked; blast radius production impacting authority; boundary report only.
  Evidence: approval evidence not imported or observed; proof evidence not imported or observed; runtime not collected; session not collected; visible control evidence detected; owner evidence inferred; insufficient evidence coverage.
  Recommendation: attach scoped approval evidence for this agent instruction surface before allowing deploy/egress/execute against developer-productivity systems.
  Explanation: The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- Path path-2f2bda2d: agent instruction surface in repo-0f9c7c via loc-f32a51ab; target developer productivity; autonomy prod or customer impacting; readiness review required.
  Authority: no credential authority linked; blast radius production impacting authority; boundary report only.
  Evidence: approval evidence not imported or observed; proof evidence not imported or observed; runtime not collected; session not collected; visible control evidence detected; owner evidence inferred; insufficient evidence coverage.
  Recommendation: attach scoped approval evidence for this agent instruction surface before allowing deploy/egress/execute against developer-productivity systems.
  Explanation: The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- Path path-31990a09: CI/CD workflow in repo-eb0de2 via loc-415e1600; target production impacting; autonomy prod or customer impacting; readiness blocked.
  Authority: credential-9d82507e | workflow | standing; blast radius production impacting authority; boundary report only.
  Evidence: approval evidence not imported or observed; proof evidence not imported or observed; runtime not collected; session not collected; visible control evidence detected; owner evidence inferred; partial evidence coverage.
  Recommendation: replace standing credential authority on this CI/CD workflow path with brokered or repo-scoped JIT access.
  Explanation: This path is already blocked with standing credential metadata, so replacement or JIT reduction should lead before correlation work.
- Path path-445e7c6c: agent instruction surface in repo-10e08a via loc-d5d3368a; target unknown; autonomy sensitive code or infra; readiness review required.
  Authority: no credential authority linked; blast radius unknown; boundary report only.
  Evidence: approval evidence not imported or observed; proof evidence not imported or observed; runtime not collected; session not collected; visible control evidence detected; owner evidence inferred; insufficient evidence coverage.
  Recommendation: attach scoped approval evidence for this agent instruction surface before allowing egress/read.
  Explanation: The authority is visible, but approval evidence for this exact workflow path is still missing or weak.
- Path path-f290d9be: agent instruction surface in repo-1cf387 via loc-6d5c8bdb; target developer productivity; autonomy sensitive code or infra; readiness review required.
  Authority: no credential authority linked; blast radius developer productivity; boundary report only.
  Evidence: approval evidence not imported or observed; proof evidence not imported or observed; runtime not collected; session not collected; visible control evidence detected; owner evidence inferred; insufficient evidence coverage.
  Recommendation: attach scoped approval evidence for this agent instruction surface before allowing egress/read against developer-productivity systems.
  Explanation: The authority is visible, but approval evidence for this exact workflow path is still missing or weak.

## Assessment Summary

- Scope: static posture from saved scan state only; no runtime observation or enforcement
- Governable paths: 20
- Write-capable paths: 3
- Production-target-backed paths: 2
- Top path to control first: repo-10e08a loc-f27ac6f3 (control, trigger=deploy_pipeline)
- Ownerless exposure: explicit=0 inferred=20 unresolved=0 conflict=0
- Proof chain: redacted://proof-chain.json
- Exposure groups: 14

## Policy Outcomes

- Rule WRKR-A006 is fail across 8 occurrence(s) in 4 repo(s): repo-b583bb, repo-a24cd4, repo-88604b, plus 1 more.
- Rule WRKR-A007 is fail across 8 occurrence(s) in 4 repo(s): repo-b583bb, repo-fbf3f7, repo-a24cd4, plus 1 more.
- Rule WRKR-A005 is fail across 6 occurrence(s) in 3 repo(s): repo-fbf3f7, repo-a24cd4, repo-34614a.
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
- Rule WRKR-A002 is pass across 3 occurrence(s) in 3 repo(s): repo-b583bb, repo-fbf3f7, repo-88604b.
- Rule WRKR-014 is fail across 2 occurrence(s) in 1 repo(s): repo-88604b.
- Rule WRKR-015 is fail across 2 occurrence(s) in 1 repo(s): repo-88604b.
- Rule WRKR-016 is fail across 2 occurrence(s) in 1 repo(s): repo-34614a.
- Rule WRKR-A001 is fail across 2 occurrence(s) in 1 repo(s): repo-a24cd4.
- Rule WRKR-A004 is fail across 2 occurrence(s) in 1 repo(s): repo-34614a.
- Rule WRKR-A005 is pass across 2 occurrence(s) in 2 repo(s): repo-b583bb, repo-88604b.
- Rule WRKR-A006 is pass across 1 occurrence(s) in 1 repo(s): repo-fbf3f7.
- Rule WRKR-A007 is pass across 1 occurrence(s) in 1 repo(s): repo-88604b.

## Scan Quality

- Mode: governance
- Coverage summary: confidence=complete reduced_detectors=0 parse_failures=0 suppressed_generated_files=0 blocked_detectors=0 unsupported_declarations=0 impact=Coverage for scanned inputs was complete enough to support scoped negative claims.
- mcp_server absence_status=not_found_with_complete_coverage across 2 repo(s) reasons=detector:mcp=complete,detector:webmcp=complete,mcp:no_candidate_inputs,webmcp:no_candidate_inputs impact=Complete MCP coverage supported a clean negative result for the scanned surfaces.
- mcp_server absence_status=not_found_with_complete_coverage reasons=detector:mcp=complete,detector:webmcp=complete,webmcp:no_candidate_inputs impact=Complete MCP coverage supported a clean negative result for the scanned surfaces.

## Control Backlog

- repo-10e08a loc-f27ac6f3 owner=owner-c115ecf5 queue=control_first visibility=primary action=remediate sla=7d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Add or verify deployment gates, tighten write scope, attach path-specific proof, and rescan until this deploy-capable path drops out of the control-first queue.
  completeness=insufficient evidence coverage(58)
  closure_requirements=clr-38202f3a:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-b969654b:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-42652f50:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-9ef55ba8:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified. | clr-3e07300c:Prove the deployment or branch-protection constraint for this path before treating delivery controls as verified.
  lifecycle_queue=approval_evidence_not_found severity=high credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-0f9c7c loc-f32a51ab owner=owner-1cb36bca queue=control_first visibility=primary action=remediate sla=7d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Add or verify deployment gates, tighten write scope, attach path-specific proof, and rescan until this deploy-capable path drops out of the control-first queue.
  completeness=insufficient evidence coverage(58)
  closure_requirements=clr-dd3d2bfb:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-82c20c33:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-6e629ae6:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-879c7a9f:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified. | clr-a8c0516b:Prove the deployment or branch-protection constraint for this path before treating delivery controls as verified.
  lifecycle_queue=approval_evidence_not_found severity=high credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-e026f56c owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-123533ff:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-c03c9950:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-64d4853d:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-01c44c06:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=approval_evidence_not_found severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-0db9f46c owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-475fb3a9:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-6b74588a:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-771658ef:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-54fd540e:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=approval_evidence_not_found severity=high credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-f27ac6f3 owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact instruction surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-7e0bc613:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-355921b4:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-fc60fd8a:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-484c5f4d:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=approval_evidence_not_found severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-d5d3368a owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this MCP configuration surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact MCP configuration surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-cf97cb28:Assign explicit owner evidence for this MCP configuration surface and attach a linked owner record before approving or expanding it. | clr-4b5bab15:Attach approval evidence for this exact MCP configuration surface with scope and expiry before treating it as governed. | clr-d425aa53:Attach a path-specific policy or proof reference for this exact MCP configuration surface and rescan so proof is no longer inferred or absent. | clr-eee180f3:Collect runtime evidence for this MCP configuration surface and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=approval_evidence_not_found severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-d5d3368a owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this MCP configuration surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact MCP configuration surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(59)
  closure_requirements=clr-4dbb5bec:Assign explicit owner evidence for this MCP configuration surface and attach a linked owner record before approving or expanding it. | clr-685ddba1:Attach approval evidence for this exact MCP configuration surface with scope and expiry before treating it as governed. | clr-1dfeb0c7:Attach a path-specific policy or proof reference for this exact MCP configuration surface and rescan so proof is no longer inferred or absent. | clr-80b35933:Collect runtime evidence for this MCP configuration surface and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=approval_evidence_not_found severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-10e08a loc-6ebdb617 owner=owner-c115ecf5 queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact instruction surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(56)
  closure_requirements=clr-af76f2bb:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-b9be2d17:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-666a3926:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-ec24d20b:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=approval_evidence_not_found severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-0f9c7c loc-a54ff182 owner=owner-1cb36bca queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact instruction surface and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(56)
  closure_requirements=clr-18a11361:Assign explicit owner evidence for this instruction surface and attach a linked owner record before approving or expanding it. | clr-3f80bca6:Attach approval evidence for this exact instruction surface with scope and expiry before treating it as governed. | clr-d05b814c:Attach a path-specific policy or proof reference for this exact instruction surface and rescan so proof is no longer inferred or absent. | clr-1b9565c2:Collect runtime evidence for this instruction surface and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=approval_evidence_not_found severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.
- repo-8b2df8 loc-d7e67997 owner=owner-abe8a52e queue=control_first visibility=primary action=attach_evidence sla=14d closure=Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. remediation=Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain.
  completeness=insufficient evidence coverage(57)
  closure_requirements=clr-b26fea82:Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it. | clr-5cea0e3f:Attach approval evidence for this exact path with scope and expiry before treating it as governed. | clr-b6f09a3d:Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent. | clr-f00e0000:Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified.
  lifecycle_queue=approval_evidence_not_found severity=medium credential_status=no_credential_access closure=Attach fresh approval evidence with owner, expiry, and review scope.

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

- posture score 51.98 (F)
- profile status fail at 43.75%
- tools=20 write_capable=3 credential_access=1 exec_capable=5
- bundled framework mappings stay available; profile compliance reflects only controls evidenced in the current deterministic scan state
- report scope stays at static posture and offline-verifiable proof; it does not claim runtime observation or control-layer enforcement
- security_visibility reference=initial_scan unknown_to_security_tools=20 unknown_to_security_agents=20 unknown_to_security_write_capable_agents=3
- 22 findings map to EU Artificial Intelligence Act ARTICLE-12 (Record-Keeping)
- 32 findings map to EU Artificial Intelligence Act ARTICLE-14 (Human Oversight)
- coverage still reflects only controls evidenced in the current scan state; remediate gaps, rescan, and regenerate report/evidence artifacts
- production_write=2 (status=configured)
- source_privacy deployment_mode=local_only retention=ephemeral retained=false raw_source_in_artifacts=false serialized_locations=filesystem cleanup_status=not_applicable
- control_path_graph version=1 nodes=550 edges=512
- control_path_graph nodes[action_capability]=27
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
- control_path_graph nodes[target]=2
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
- control_path_graph edges[path_enables_action]=27
- control_path_graph edges[path_executes_workflow]=20
- control_path_graph edges[path_governed_by]=160
- control_path_graph edges[path_runs_as]=20
- control_path_graph edges[path_targets_surface]=2
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
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=146

## Top governance control backlog items (top_prioritized_risks)

- #1 8.20 likely_action_path [critical] lane=likely_action_path action=control state=approval_required zone=production_data review=critical repo=repo-10e08a location=loc-f27ac6f3
- #2 8.20 likely_action_path [critical] lane=likely_action_path action=control state=approval_required zone=production_data review=critical repo=repo-0f9c7c location=loc-f32a51ab
- #3 10.00 confirmed_action_path [critical] lane=confirmed_action_path action=proof state=block_recommended zone=credential_bearing review=critical repo=repo-eb0de2 location=loc-415e1600
- #4 5.67 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-10e08a location=loc-d5d3368a
- #5 10.00 likely_action_path [high] lane=likely_action_path action=proof state=approval_required zone=external_egress review=critical repo=repo-1cf387 location=loc-6d5c8bdb
- attack paths: none generated because the saved static graph did not include attack-path joins for the current high-impact action paths; review the governable action paths separately.

Impact: top 5 risks concentrate the highest blast-radius findings
Action: work highest score first and apply deterministic least-privilege remediation
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=146

## Risk and approval movement (change_since_previous)

- risk score trend current=10.00 delta=0.00 (no previous reference)
- profile compliance delta current=43.75 delta=0.00 (no previous reference)
- posture score trend delta current=51.98 delta=0.00 (no previous reference)

Impact: change deltas remain within expected deterministic variance
Action: continue baseline comparison on every governance scan cadence
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=146

## Executive ownership and approval actions (lifecycle_actions)

- identities=20 pending_action=40 under_review=0 revoked=0 deprecated=0
- gap approval_evidence_not_found severity=high repo=repo-10e08a location=loc-0db9f46c
- gap approval_evidence_not_found severity=high repo=repo-10e08a location=loc-f27ac6f3
- gap approval_evidence_not_found severity=high repo=repo-0f9c7c location=loc-f32a51ab
- gap approval_evidence_not_found severity=high repo=repo-1cf387 location=loc-768f8ff8
- gap approval_evidence_not_found severity=high repo=repo-eb0de2 location=loc-415e1600
- gap approval_evidence_not_found severity=medium repo=repo-10e08a location=loc-e026f56c
- gap approval_evidence_not_found severity=medium repo=repo-10e08a location=loc-f27ac6f3
- gap approval_evidence_not_found severity=medium repo=repo-10e08a location=loc-d5d3368a
- gap approval_evidence_not_found severity=medium repo=repo-10e08a location=loc-d5d3368a
- gap approval_evidence_not_found severity=medium repo=repo-10e08a location=loc-6ebdb617
- gap approval_evidence_not_found severity=medium repo=repo-0f9c7c location=loc-a54ff182
- gap approval_evidence_not_found severity=medium repo=repo-0f9c7c location=loc-a28316bc
- gap approval_evidence_not_found severity=medium repo=repo-0f9c7c location=loc-33ef32bf
- gap approval_evidence_not_found severity=medium repo=repo-8b2df8 location=loc-d7e67997
- gap approval_evidence_not_found severity=medium repo=repo-1cf387 location=loc-6d5c8bdb
- gap approval_evidence_not_found severity=medium repo=repo-1cf387 location=loc-6d5c8bdb
- gap approval_evidence_not_found severity=medium repo=repo-1cf387 location=loc-20c5bf90
- gap approval_evidence_not_found severity=medium repo=repo-1cf387 location=loc-315161dd
- gap approval_evidence_not_found severity=medium repo=repo-1cf387 location=loc-e98d5093
- gap approval_evidence_not_found severity=medium repo=repo-eb0de2 location=loc-227c2c26
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

Impact: 40 identities require lifecycle approval/review/revocation handling
Action: prioritize under_review and revoked identities before enabling additional autonomy
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=146

## Evidence and proof verification (proof_verification_footer)

- chain_path=redacted://proof-chain.json
- head_hash=sha256:demo-proof-head
- record_count=146
- record_type decision_trace=11
- record_type lifecycle_transition=20
- record_type risk_assessment=52
- record_type scan_finding=63

Impact: proof chain references are attached for deterministic traceability
Action: preserve chain path and head hash when distributing this artifact
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=146

## Next executive control actions (next_actions)

- review govern-first path path-31e098e8 in repo-10e08a:loc-f27ac6f3 (action=control score=8.20)
- review 40 lifecycle records requiring approval/review/revocation action
- verify proof chain integrity before sharing artifacts externally

Impact: deterministic next actions focus operators on highest leverage controls
Action: execute checklist items in order and rescan to confirm posture improvement
Proof: chain=redacted://proof-chain.json head=sha256:demo-proof-head records=146

package proofmap

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	proof "github.com/Clyra-AI/proof"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
)

type MappedRecord struct {
	RecordType          string
	AgentID             string
	Timestamp           time.Time
	Event               map[string]any
	Metadata            map[string]any
	Relationship        *proof.Relationship
	ApprovedScope       string
	PermissionsEnforced bool
}

type SecurityVisibilityContext struct {
	Summary          agginventory.SecurityVisibilitySummary
	StatusByInstance map[string]string
}

const (
	maxFindingRiskProofRecords = 25
	maxAttackPathProofRecords  = 25
	maxActionPathProofRecords  = 25
	maxDecisionTraceRecords    = 25
)

func hasSecurityVisibilityReference(summary agginventory.SecurityVisibilitySummary) bool {
	return strings.TrimSpace(summary.ReferenceBasis) != ""
}

func MapFindings(findings []model.Finding, profile *profileeval.Result, visibility SecurityVisibilityContext, now time.Time) []MappedRecord {
	ordered := append([]model.Finding(nil), findings...)
	model.SortFindings(ordered)
	groups := map[string][]model.Finding{}
	for _, finding := range ordered {
		key := CanonicalFindingKey(finding)
		groups[key] = append(groups[key], finding)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	records := make([]MappedRecord, 0, len(keys))
	for _, key := range keys {
		items := groups[key]
		representative := selectRepresentative(items)
		event := map[string]any{
			"finding_type": representative.FindingType,
			"severity":     representative.Severity,
			"tool_type":    representative.ToolType,
			"location":     representative.Location,
			"repo":         representative.Repo,
			"org":          canonicalOrg(representative.Org),
			"autonomy":     representative.Autonomy,
			"permissions":  append([]string(nil), representative.Permissions...),
			"evidence":     evidenceMap(representative.Evidence),
		}
		if agentContext := agentContextForFinding(representative); len(agentContext) > 0 {
			event["agent_id"] = agentIDForFinding(representative)
			event["agent_context"] = agentContext
			if instanceID, ok := agentContext["agent_instance_id"].(string); ok && strings.TrimSpace(instanceID) != "" && hasSecurityVisibilityReference(visibility.Summary) {
				if status := strings.TrimSpace(visibility.StatusByInstance[instanceID]); status != "" {
					event["security_visibility_status"] = status
					event["security_visibility_reference"] = visibility.Summary.ReferenceBasis
				}
			}
		}
		if representative.RuleID != "" {
			event["rule_id"] = representative.RuleID
		}
		if representative.CheckResult != "" {
			event["check_result"] = representative.CheckResult
		}
		if representative.Remediation != "" {
			event["remediation"] = representative.Remediation
		}
		if representative.Detector != "" {
			event["detector"] = representative.Detector
		}
		if representative.ParseError != nil {
			event["parse_error"] = map[string]any{
				"kind":     representative.ParseError.Kind,
				"format":   representative.ParseError.Format,
				"path":     representative.ParseError.Path,
				"detector": representative.ParseError.Detector,
				"message":  representative.ParseError.Message,
			}
		}
		if representative.FindingType == "skill_policy_conflict" {
			event["conflict_metadata"] = evidenceMap(representative.Evidence)
		}
		if representative.FindingType == "policy_violation" {
			event["profile_context"] = profileContext(profile)
		}

		types := uniqueSortedFindingTypes(items)
		ruleIDs := uniqueSortedRuleIDs(items)
		metadata := map[string]any{
			"canonical_finding_key": key,
			"source_findings_count": len(items),
			"source_finding_types":  types,
			"linked_rule_ids":       ruleIDs,
		}
		addPolicyOutcomeMetadata(metadata, representative, items)
		if isPolicyFinding(representative) {
			if sourceKeys := sourceFindingKeys(items); len(sourceKeys) > 0 {
				metadata["source_finding_keys"] = sourceKeys
			}
		}
		if hasWRKR014(items) && hasSkillConflict(items) {
			metadata["wrkr014_linked"] = true
			metadata["conflict_link_key"] = key
		}
		if profile != nil {
			metadata["profile_name"] = profile.ProfileName
			metadata["profile_status"] = profile.Status
			metadata["profile_compliance_percent"] = profile.CompliancePercent
		}
		agentID := agentIDForFinding(representative)
		if agentContext := agentContextForFinding(representative); len(agentContext) > 0 {
			if agentInstanceID, ok := agentContext["agent_instance_id"].(string); ok && strings.TrimSpace(agentInstanceID) != "" {
				metadata["agent_instance_id"] = agentInstanceID
				if hasSecurityVisibilityReference(visibility.Summary) {
					if status := strings.TrimSpace(visibility.StatusByInstance[agentInstanceID]); status != "" {
						metadata["security_visibility_status"] = status
						metadata["security_visibility_reference"] = visibility.Summary.ReferenceBasis
					}
				}
			}
			if framework, ok := agentContext["framework"].(string); ok && strings.TrimSpace(framework) != "" {
				metadata["agent_framework"] = framework
			}
		}

		records = append(records, sanitizeMappedRecord(MappedRecord{
			RecordType:   "scan_finding",
			AgentID:      agentID,
			Timestamp:    canonicalTime(now),
			Event:        event,
			Metadata:     metadata,
			Relationship: buildFindingRelationship(representative, key, ruleIDs, agentID),
		}))
	}
	return records
}

func MapRisk(report risk.Report, posture score.Result, profile profileeval.Result, visibility SecurityVisibilityContext, now time.Time) []MappedRecord {
	findingRiskRecords := boundedScoredFindings(report)
	attackPathRecords := boundedAttackPaths(report)
	actionPathRecords := boundedActionPaths(report.ActionPaths, maxActionPathProofRecords)

	records := make([]MappedRecord, 0, len(findingRiskRecords))
	for idx, item := range findingRiskRecords {
		event := map[string]any{
			"assessment_type": "finding_risk",
			"canonical_key":   item.CanonicalKey,
			"risk_score":      item.Score,
			"blast_radius":    item.BlastRadius,
			"privilege_level": item.Privilege,
			"trust_deficit":   item.TrustDeficit,
			"endpoint_class":  item.EndpointClass,
			"data_class":      item.DataClass,
			"autonomy_level":  item.AutonomyLevel,
			"finding": map[string]any{
				"finding_type": item.Finding.FindingType,
				"rule_id":      item.Finding.RuleID,
				"severity":     item.Finding.Severity,
				"tool_type":    item.Finding.ToolType,
				"location":     item.Finding.Location,
				"repo":         item.Finding.Repo,
				"org":          canonicalOrg(item.Finding.Org),
			},
			"reasons": append([]string(nil), item.Reasons...),
		}
		if agentContext := agentContextForFinding(item.Finding); len(agentContext) > 0 {
			event["agent_id"] = agentIDForFinding(item.Finding)
			event["agent_context"] = agentContext
			findingMap := event["finding"].(map[string]any)
			findingMap["agent_id"] = agentIDForFinding(item.Finding)
			if instanceID, ok := agentContext["agent_instance_id"].(string); ok && strings.TrimSpace(instanceID) != "" && hasSecurityVisibilityReference(visibility.Summary) {
				if status := strings.TrimSpace(visibility.StatusByInstance[instanceID]); status != "" {
					event["security_visibility_status"] = status
					event["security_visibility_reference"] = visibility.Summary.ReferenceBasis
					findingMap["security_visibility_status"] = status
				}
			}
		}
		agentID := agentIDForFinding(item.Finding)
		metadata := map[string]any{
			"rank":              idx + 1,
			"canonical_finding": item.CanonicalKey,
		}
		if agentContext := agentContextForFinding(item.Finding); len(agentContext) > 0 {
			if agentInstanceID, ok := agentContext["agent_instance_id"].(string); ok && strings.TrimSpace(agentInstanceID) != "" {
				metadata["agent_instance_id"] = agentInstanceID
				if hasSecurityVisibilityReference(visibility.Summary) {
					if status := strings.TrimSpace(visibility.StatusByInstance[agentInstanceID]); status != "" {
						metadata["security_visibility_status"] = status
					}
				}
			}
			if framework, ok := agentContext["framework"].(string); ok && strings.TrimSpace(framework) != "" {
				metadata["agent_framework"] = framework
			}
		}
		records = append(records, sanitizeMappedRecord(MappedRecord{
			RecordType:   "risk_assessment",
			AgentID:      agentID,
			Timestamp:    canonicalTime(now),
			Event:        event,
			Relationship: buildFindingRiskRelationship(item, agentID),
			Metadata:     metadata,
		}))
	}
	for idx, path := range attackPathRecords {
		event := map[string]any{
			"assessment_type": "attack_path_risk",
			"path_id":         path.PathID,
			"path_score":      path.PathScore,
			"org":             path.Org,
			"repo":            path.Repo,
			"entry_node_id":   path.EntryNodeID,
			"pivot_node_id":   path.PivotNodeID,
			"target_node_id":  path.TargetNodeID,
			"entry_exposure":  path.EntryExposure,
			"pivot_privilege": path.PivotPrivilege,
			"target_impact":   path.TargetImpact,
			"edge_rationale":  append([]string(nil), path.EdgeRationale...),
			"explain":         append([]string(nil), path.Explain...),
		}
		records = append(records, sanitizeMappedRecord(MappedRecord{
			RecordType:   "risk_assessment",
			Timestamp:    canonicalTime(now),
			Event:        event,
			Relationship: buildAttackPathRelationship(path),
			Metadata: map[string]any{
				"rank":               idx + 1,
				"canonical_finding":  "attack_path",
				"attack_path_id":     path.PathID,
				"attack_path_source": append([]string(nil), path.SourceFindings...),
			},
		}))
	}
	for idx, path := range actionPathRecords {
		event := map[string]any{
			"assessment_type":            "action_path_governance",
			"path_id":                    path.PathID,
			"org":                        path.Org,
			"repo":                       path.Repo,
			"tool_type":                  path.ToolType,
			"location":                   path.Location,
			"write_capable":              path.WriteCapable,
			"write_path_classes":         append([]string(nil), path.WritePathClasses...),
			"inventory_risk":             path.InventoryRisk,
			"control_priority":           path.ControlPriority,
			"risk_tier":                  path.RiskTier,
			"recommended_action":         path.RecommendedAction,
			"security_visibility_status": path.SecurityVisibilityStatus,
			"approval_gap_reasons":       append([]string(nil), path.ApprovalGapReasons...),
			"governance_controls":        append([]agginventory.GovernanceControlMapping(nil), path.GovernanceControls...),
			"credential_access":          path.CredentialAccess,
			"production_write":           path.ProductionWrite,
			"attack_path_refs":           append([]string(nil), path.AttackPathRefs...),
			"source_finding_keys":        append([]string(nil), path.SourceFindingKeys...),
			"matched_production_targets": append([]string(nil), path.MatchedProductionTargets...),
		}
		if path.CredentialProvenance != nil {
			event["credential_provenance"] = agginventory.CloneCredentialProvenance(path.CredentialProvenance)
		}
		if path.TrustDepth != nil {
			event["trust_depth"] = agginventory.CloneTrustDepth(path.TrustDepth)
		}
		records = append(records, sanitizeMappedRecord(MappedRecord{
			RecordType: "risk_assessment",
			AgentID:    path.AgentID,
			Timestamp:  canonicalTime(now),
			Event:      event,
			Metadata: map[string]any{
				"rank":              idx + 1,
				"canonical_finding": "action_path_governance",
				"action_path_id":    path.PathID,
			},
		}))
	}
	if report.ControlPathGraph != nil {
		pathIDs := make([]string, 0, len(report.ControlPathGraph.Nodes))
		nodeIDs := make([]string, 0, len(report.ControlPathGraph.Nodes))
		for _, node := range report.ControlPathGraph.Nodes {
			if strings.TrimSpace(node.PathID) != "" {
				pathIDs = append(pathIDs, strings.TrimSpace(node.PathID))
			}
			if strings.TrimSpace(node.NodeID) != "" {
				nodeIDs = append(nodeIDs, strings.TrimSpace(node.NodeID))
			}
		}
		edgeIDs := make([]string, 0, len(report.ControlPathGraph.Edges))
		for _, edge := range report.ControlPathGraph.Edges {
			if strings.TrimSpace(edge.EdgeID) != "" {
				edgeIDs = append(edgeIDs, strings.TrimSpace(edge.EdgeID))
			}
		}
		event := map[string]any{
			"assessment_type": "control_path_graph",
			"graph_version":   report.ControlPathGraph.Version,
			"graph_summary":   report.ControlPathGraph.Summary,
			"path_ids":        uniqueSortedStrings(pathIDs),
			"node_ids":        uniqueSortedStrings(nodeIDs),
			"edge_ids":        uniqueSortedStrings(edgeIDs),
		}
		records = append(records, sanitizeMappedRecord(MappedRecord{
			RecordType: "risk_assessment",
			Timestamp:  canonicalTime(now),
			Event:      event,
			Metadata: map[string]any{
				"canonical_finding": "control_path_graph",
			},
		}))
	}

	postureEvent := map[string]any{
		"assessment_type":    "posture_score",
		"score":              posture.Score,
		"grade":              posture.Grade,
		"breakdown":          posture.Breakdown,
		"weighted_breakdown": posture.WeightedBreakdown,
		"weights":            posture.Weights,
		"trend_delta":        posture.TrendDelta,
		"profile": map[string]any{
			"name":               profile.ProfileName,
			"status":             profile.Status,
			"compliance_percent": profile.CompliancePercent,
			"compliance_delta":   profile.DeltaPercent,
			"minimum_compliance": profile.MinCompliance,
			"failing_rules":      append([]string(nil), profile.Fails...),
			"profile_rationale":  append([]string(nil), profile.Rationale...),
		},
		"repo_risk": append([]risk.RepoAggregate(nil), report.Repos...),
		"attack_paths": map[string]any{
			"count": len(report.AttackPaths),
			"top":   report.TopAttackPaths,
		},
	}
	if hasSecurityVisibilityReference(visibility.Summary) {
		postureEvent["security_visibility"] = map[string]any{
			"reference_basis":                          visibility.Summary.ReferenceBasis,
			"unknown_to_security_tools":                visibility.Summary.UnknownToSecurityTools,
			"unknown_to_security_agents":               visibility.Summary.UnknownToSecurityAgents,
			"unknown_to_security_write_capable_agents": visibility.Summary.UnknownToSecurityWriteCapableAgents,
		}
	}
	records = append(records, sanitizeMappedRecord(MappedRecord{
		RecordType:   "risk_assessment",
		Timestamp:    canonicalTime(now),
		Event:        postureEvent,
		Relationship: buildPostureRelationship(profile.ProfileName),
		Metadata: map[string]any{
			"canonical_finding": "posture_score",
			"profile_name":      profile.ProfileName,
		},
	}))

	return records
}

func MapDecisionTraces(paths []risk.ActionPath, now time.Time) []MappedRecord {
	candidates := boundedDecisionTracePaths(paths, maxDecisionTraceRecords)
	records := make([]MappedRecord, 0, len(candidates))
	for idx, path := range candidates {
		projected := risk.ProjectActionPath(path)
		traceID := decisionTraceID(projected)
		evidenceRefs := decisionTraceEvidenceRefs(projected)
		proofRefs := decisionTraceProofRefs(projected)
		event := map[string]any{
			"event_type":     "decision_trace",
			"trace_id":       traceID,
			"path_id":        projected.PathID,
			"resolution_key": strings.TrimSpace(projected.ResolutionKey),
			"actor": map[string]any{
				"agent_id":     strings.TrimSpace(projected.AgentID),
				"identity_ref": decisionTraceIdentityRef(projected),
				"introduced":   decisionTraceActor(projected),
			},
			"authority": map[string]any{
				"impact":              decisionTraceAuthorityImpact(projected),
				"credential_reach":    decisionTraceCredentialReach(projected),
				"reachable_targets":   append([]string(nil), projected.MatchedProductionTargets...),
				"high_stakes_presets": decisionTracePresetNames(projected),
			},
			"policy_checked": map[string]any{
				"status":        strings.TrimSpace(projected.PolicyCoverageStatus),
				"policy_refs":   append([]string(nil), projected.PolicyRefs...),
				"evidence_refs": append([]string(nil), projected.PolicyEvidenceRefs...),
			},
			"approval_exception_reason": decisionTraceApprovalOrExceptionReason(projected),
			"context_used":              decisionTraceContextUsed(projected),
			"what_changed": map[string]any{
				"artifact":     strings.TrimSpace(projected.Location),
				"surface_type": decisionTraceSurfaceType(projected),
				"purpose":      strings.TrimSpace(projected.Purpose),
			},
			"evidence_refs":       evidenceRefs,
			"autonomy_tier":       strings.TrimSpace(projected.AutonomyTier),
			"recommended_control": strings.TrimSpace(projected.RecommendedControl),
			"evidence_states":     decisionTraceEvidenceStates(projected),
			"outcome": map[string]any{
				"recommended_control":        strings.TrimSpace(projected.RecommendedControl),
				"delegation_readiness_state": strings.TrimSpace(projected.DelegationReadinessState),
				"control_state":              strings.TrimSpace(projected.ControlState),
				"review_state":               decisionTraceReviewState(projected),
			},
			"proof_refs": proofRefs,
		}
		if workflowChains := cloneNonEmptyStrings(projected.WorkflowChainRefs); len(workflowChains) > 0 {
			event["workflow_chain_refs"] = workflowChains
			if whatChanged, ok := event["what_changed"].(map[string]any); ok {
				whatChanged["workflow_chains"] = workflowChains
			}
		}
		if compositionIDs := cloneNonEmptyStrings(projected.CompositionIDs); len(compositionIDs) > 0 {
			event["composition_ids"] = compositionIDs
		}
		if proposedContractRefs := cloneNonEmptyStrings(projected.ProposedActionContractRefs); len(proposedContractRefs) > 0 {
			event["proposed_action_contract_refs"] = proposedContractRefs
		}
		if gaitCoverage := decisionTraceGaitCoverageSummary(projected.GaitCoverage); len(gaitCoverage) > 0 {
			event["gait_coverage"] = gaitCoverage
		}
		metadata := map[string]any{
			"rank":                idx + 1,
			"path_id":             strings.TrimSpace(projected.PathID),
			"trace_id":            traceID,
			"resolution_key":      strings.TrimSpace(projected.ResolutionKey),
			"source_finding_keys": append([]string(nil), projected.SourceFindingKeys...),
		}
		if workflowChains := cloneNonEmptyStrings(projected.WorkflowChainRefs); len(workflowChains) > 0 {
			metadata["workflow_chain_refs"] = workflowChains
		}
		if compositionIDs := cloneNonEmptyStrings(projected.CompositionIDs); len(compositionIDs) > 0 {
			metadata["composition_ids"] = compositionIDs
		}
		if proposedContractRefs := cloneNonEmptyStrings(projected.ProposedActionContractRefs); len(proposedContractRefs) > 0 {
			metadata["proposed_action_contract_refs"] = proposedContractRefs
		}
		records = append(records, sanitizeMappedRecord(MappedRecord{
			RecordType:   "decision_trace",
			AgentID:      strings.TrimSpace(projected.AgentID),
			Timestamp:    canonicalTime(now),
			Event:        event,
			Metadata:     metadata,
			Relationship: buildDecisionTraceRelationship(projected, traceID),
		}))
	}
	return records
}

func cloneNonEmptyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func boundedScoredFindings(report risk.Report) []risk.ScoredFinding {
	if len(report.TopN) > 0 {
		return append([]risk.ScoredFinding(nil), report.TopN...)
	}
	return boundedSlice(report.Ranked, maxFindingRiskProofRecords)
}

func boundedAttackPaths(report risk.Report) []riskattack.ScoredPath {
	if len(report.TopAttackPaths) > 0 {
		return append([]riskattack.ScoredPath(nil), report.TopAttackPaths...)
	}
	return boundedSlice(report.AttackPaths, maxAttackPathProofRecords)
}

func boundedActionPaths(paths []risk.ActionPath, limit int) []risk.ActionPath {
	return boundedSlice(paths, limit)
}

func boundedDecisionTracePaths(paths []risk.ActionPath, limit int) []risk.ActionPath {
	candidates := make([]risk.ActionPath, 0, len(paths))
	for _, path := range paths {
		projected := risk.ProjectActionPath(path)
		if strings.TrimSpace(projected.ConfidenceLane) == risk.ConfidenceLaneContextOnly {
			continue
		}
		if len(projected.HighStakesPresets) == 0 && strings.TrimSpace(projected.ControlPriority) != risk.ControlPriorityControlFirst {
			continue
		}
		candidates = append(candidates, projected)
	}
	return boundedSlice(candidates, limit)
}

func boundedSlice[T any](items []T, limit int) []T {
	if limit <= 0 || len(items) <= limit {
		return append([]T(nil), items...)
	}
	return append([]T(nil), items[:limit]...)
}

func MapTransition(transition lifecycle.Transition, eventType string) MappedRecord {
	resolvedEventType := strings.TrimSpace(eventType)
	if resolvedEventType == "" {
		resolvedEventType = "lifecycle_transition"
	}
	recordType := transitionMappedRecordType(resolvedEventType)

	diff := map[string]any{}
	for key, value := range transition.Diff {
		diff[key] = value
	}
	event := map[string]any{
		"event_type":     resolvedEventType,
		"previous_state": transition.PreviousState,
		"new_state":      transition.NewState,
		"trigger":        transition.Trigger,
		"diff":           diff,
	}

	scope := stringValue(diff, "scope")
	if scope != "" {
		event["scope"] = scope
	}
	approver := stringValue(diff, "approver")
	if approver != "" {
		event["approver"] = approver
	}
	expires := stringValue(diff, "expires")
	if expires != "" {
		event["expires"] = expires
	}
	for _, key := range []string{
		"owner",
		"control_id",
		"evidence_url",
		"review_cadence",
		"accepted_risk",
		"reason",
	} {
		if value, ok := diff[key]; ok {
			event[key] = value
		}
	}

	timestamp := time.Now().UTC().Truncate(time.Second)
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(transition.Timestamp)); err == nil {
		timestamp = parsed.UTC().Truncate(time.Second)
	}
	return sanitizeMappedRecord(MappedRecord{
		RecordType:    recordType,
		AgentID:       strings.TrimSpace(transition.AgentID),
		Timestamp:     timestamp,
		Event:         event,
		Relationship:  buildTransitionRelationship(strings.TrimSpace(transition.AgentID), approver, transition.NewState),
		ApprovedScope: scope,
		Metadata: map[string]any{
			"transition_trigger": transition.Trigger,
			"event_type":         resolvedEventType,
		},
	})
}

func transitionMappedRecordType(eventType string) string {
	switch strings.TrimSpace(eventType) {
	case "", "lifecycle_transition":
		return "lifecycle_transition"
	case "approval", "approval_recorded", "risk_accepted":
		return "approval"
	case "owner_assigned", "evidence_attached", "least_privilege_verified", "rotation_evidence_attached", "deployment_gate_present", "production_access_classified", "proof_artifact_generated", "review_cadence_set":
		return "evidence"
	default:
		return "decision"
	}
}

func CanonicalFindingKey(finding model.Finding) string {
	if (finding.FindingType == "policy_violation" || finding.FindingType == "policy_check") && finding.RuleID == "WRKR-014" {
		return "skill_policy_conflict:" + canonicalOrg(finding.Org) + ":" + strings.TrimSpace(finding.Repo)
	}
	if finding.FindingType == "skill_policy_conflict" {
		return "skill_policy_conflict:" + canonicalOrg(finding.Org) + ":" + strings.TrimSpace(finding.Repo)
	}
	if isPolicyFinding(finding) {
		return "policy_outcome:" + canonicalOrg(finding.Org) + ":" + outputsignal.PolicyOutcomeIDForFinding(finding)
	}
	parts := []string{
		strings.TrimSpace(finding.FindingType),
		strings.TrimSpace(finding.RuleID),
		strings.TrimSpace(finding.ToolType),
		artifactString(finding.Location),
		strings.TrimSpace(finding.Repo),
		canonicalOrg(finding.Org),
	}
	if identityComponent := findingIdentityComponent(finding); identityComponent != "" {
		parts = append(parts[:4], append([]string{identityComponent}, parts[4:]...)...)
	}
	return strings.Join(parts, "|")
}

func selectRepresentative(findings []model.Finding) model.Finding {
	for _, finding := range findings {
		if finding.FindingType == "skill_policy_conflict" {
			return finding
		}
	}
	for _, finding := range findings {
		if finding.FindingType == "policy_violation" && finding.RuleID == "WRKR-014" {
			return finding
		}
	}
	for _, finding := range findings {
		if finding.FindingType == "policy_check" && finding.RuleID == "WRKR-014" {
			return finding
		}
	}
	for _, finding := range findings {
		if finding.FindingType == "policy_violation" {
			return finding
		}
	}
	return findings[0]
}

func isPolicyFinding(finding model.Finding) bool {
	return finding.FindingType == "policy_check" || finding.FindingType == "policy_violation"
}

func addPolicyOutcomeMetadata(metadata map[string]any, representative model.Finding, items []model.Finding) {
	if metadata == nil || !isPolicyFinding(representative) {
		return
	}
	outcomes := outputsignal.BuildPolicyOutcomes(items)
	if len(outcomes) == 0 {
		return
	}
	outcome := outcomes[0]
	metadata["policy_outcome_id"] = outputsignal.PolicyOutcomeIDForFinding(representative)
	metadata["affected_repo_count"] = outcome.AffectedRepoCount
	metadata["top_repo_refs"] = append([]string(nil), outcome.TopRepoRefs...)
	if outcome.SuppressedCount > 0 {
		metadata["suppressed_count"] = outcome.SuppressedCount
	}
}

func sourceFindingKeys(findings []model.Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, finding := range findings {
		keys = append(keys, risk.CanonicalKeyForFinding(finding))
	}
	return uniqueSortedStrings(keys)
}

func sanitizeMappedRecord(record MappedRecord) MappedRecord {
	record.AgentID = artifactString(record.AgentID)
	record.Event = artifactMap(record.Event)
	record.Metadata = artifactMap(record.Metadata)
	record.ApprovedScope = artifactString(record.ApprovedScope)
	record.Relationship = sanitizeRelationship(record.Relationship)
	return record
}

func artifactMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = artifactAny(value)
	}
	return out
}

func artifactAny(value any) any {
	switch typed := value.(type) {
	case string:
		return artifactString(typed)
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, artifactString(item))
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, artifactAny(item))
		}
		return out
	case map[string]any:
		return artifactMap(typed)
	case []map[string]any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, artifactMap(item))
		}
		return out
	default:
		return value
	}
}

func artifactString(value string) string {
	return sourceprivacy.NewSanitizer().String(value)
}

func sanitizeRelationship(rel *proof.Relationship) *proof.Relationship {
	if rel == nil {
		return nil
	}
	out := *rel
	if rel.ParentRef != nil {
		parent := sanitizeRelationshipRef(*rel.ParentRef)
		out.ParentRef = &parent
	}
	out.EntityRefs = make([]proof.RelationshipRef, 0, len(rel.EntityRefs))
	for _, ref := range rel.EntityRefs {
		out.EntityRefs = append(out.EntityRefs, sanitizeRelationshipRef(ref))
	}
	out.Edges = make([]proof.RelationshipEdge, 0, len(rel.Edges))
	for _, edge := range rel.Edges {
		out.Edges = append(out.Edges, proof.RelationshipEdge{
			Kind:  edge.Kind,
			From:  sanitizeRelationshipRef(edge.From),
			To:    sanitizeRelationshipRef(edge.To),
			Extra: edge.Extra,
		})
	}
	out.RelatedRecordIDs = append([]string(nil), rel.RelatedRecordIDs...)
	out.RelatedEntityIDs = make([]string, 0, len(rel.RelatedEntityIDs))
	for _, id := range rel.RelatedEntityIDs {
		out.RelatedEntityIDs = append(out.RelatedEntityIDs, artifactString(id))
	}
	return &out
}

func sanitizeRelationshipRef(ref proof.RelationshipRef) proof.RelationshipRef {
	ref.ID = artifactString(ref.ID)
	return ref
}

func evidenceMap(evidence []model.Evidence) map[string]any {
	if len(evidence) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(evidence))
	for _, item := range evidence {
		key := strings.TrimSpace(item.Key)
		if key == "" {
			continue
		}
		value := strings.TrimSpace(item.Value)
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			out[key] = parsed
			continue
		}
		if parsed, err := strconv.ParseBool(value); err == nil {
			out[key] = parsed
			continue
		}
		out[key] = artifactString(value)
	}
	if len(out) == 0 {
		return map[string]any{}
	}
	return out
}

func profileContext(profile *profileeval.Result) map[string]any {
	if profile == nil {
		return map[string]any{}
	}
	return map[string]any{
		"profile":            profile.ProfileName,
		"profile_status":     profile.Status,
		"compliance_percent": profile.CompliancePercent,
		"minimum_compliance": profile.MinCompliance,
		"failing_rules":      append([]string(nil), profile.Fails...),
		"profile_rationale":  append([]string(nil), profile.Rationale...),
	}
}

func uniqueSortedRuleIDs(findings []model.Finding) []string {
	set := map[string]struct{}{}
	for _, finding := range findings {
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID == "" {
			continue
		}
		set[ruleID] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedFindingTypes(findings []model.Finding) []string {
	set := map[string]struct{}{}
	for _, finding := range findings {
		value := strings.TrimSpace(finding.FindingType)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func hasWRKR014(findings []model.Finding) bool {
	for _, finding := range findings {
		if finding.RuleID == "WRKR-014" {
			return true
		}
	}
	return false
}

func hasSkillConflict(findings []model.Finding) bool {
	for _, finding := range findings {
		if finding.FindingType == "skill_policy_conflict" {
			return true
		}
	}
	return false
}

func agentIDForFinding(finding model.Finding) string {
	if instanceID := agentInstanceIDForFinding(finding); instanceID != "" {
		return identity.AgentID(instanceID, canonicalOrg(finding.Org))
	}
	return identity.AgentID(identity.ToolID(finding.ToolType, finding.Location), canonicalOrg(finding.Org))
}

func canonicalOrg(org string) string {
	trimmed := strings.TrimSpace(org)
	if trimmed == "" {
		return "local"
	}
	return trimmed
}

func canonicalTime(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC().Truncate(time.Second)
	}
	return now.UTC().Truncate(time.Second)
}

func stringValue(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}
	typed, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(typed)
}

func agentContextForFinding(finding model.Finding) map[string]any {
	agentID := strings.TrimSpace(agentIDForFinding(finding))
	if agentID == "" {
		return nil
	}

	context := map[string]any{
		"agent_id": agentID,
	}
	if instanceID := agentInstanceIDForFinding(finding); instanceID != "" {
		context["agent_instance_id"] = instanceID
	}
	if strings.TrimSpace(finding.FindingType) == "agent_framework" {
		context["framework"] = strings.TrimSpace(finding.ToolType)
	}
	if symbol := evidenceStringValue(finding, "symbol"); symbol != "" {
		context["name"] = symbol
	}
	if approvalStatus := evidenceStringValue(finding, "approval_status"); approvalStatus != "" {
		context["approval_status"] = approvalStatus
	}
	if deploymentStatus := evidenceStringValue(finding, "deployment_status"); deploymentStatus != "" {
		context["deployment_status"] = deploymentStatus
	}
	if dataClass := evidenceStringValue(finding, "data_class"); dataClass != "" {
		context["data_class"] = dataClass
	}
	if boundTools := evidenceListValue(finding, "bound_tools"); len(boundTools) > 0 {
		context["bound_tools"] = boundTools
	}
	if boundDataSources := evidenceListValue(finding, "data_sources"); len(boundDataSources) > 0 {
		context["bound_data_sources"] = boundDataSources
	}
	if boundAuthSurfaces := evidenceListValue(finding, "auth_surfaces"); len(boundAuthSurfaces) > 0 {
		context["bound_auth_surfaces"] = boundAuthSurfaces
	}
	if deploymentArtifacts := evidenceListValue(finding, "deployment_artifacts"); len(deploymentArtifacts) > 0 {
		context["deployment_artifacts"] = deploymentArtifacts
	}
	for _, key := range []string{"kill_switch", "dynamic_discovery", "auto_deploy", "human_gate", "delegation"} {
		if value := evidenceStringValue(finding, key); value != "" {
			context[key] = value
		}
	}
	if len(context) == 1 {
		return nil
	}
	return context
}

func buildFindingRelationship(finding model.Finding, canonicalKey string, ruleIDs []string, agentID string) *proof.Relationship {
	toolID := identity.ToolID(finding.ToolType, finding.Location)
	entityRefs := relationshipRefs(
		proof.RelationshipRef{Kind: "agent", ID: agentID},
		proof.RelationshipRef{Kind: "tool", ID: toolID},
		proof.RelationshipRef{Kind: "resource", ID: scopedID("org", canonicalOrg(finding.Org))},
		proof.RelationshipRef{Kind: "resource", ID: scopedID("repo", strings.TrimSpace(finding.Repo))},
		proof.RelationshipRef{Kind: "evidence", ID: scopedID("finding", strings.TrimSpace(canonicalKey))},
	)
	policyRef := policyRefForRuleIDs(ruleIDs)
	if policyID := policyRefID(policyRef); policyID != "" {
		entityRefs = relationshipRefs(append(entityRefs, proof.RelationshipRef{Kind: "policy", ID: policyID})...)
	}
	edges := relationshipEdges(
		proof.RelationshipEdge{
			Kind: "calls",
			From: proof.RelationshipRef{Kind: "agent", ID: agentID},
			To:   proof.RelationshipRef{Kind: "tool", ID: toolID},
		},
		proof.RelationshipEdge{
			Kind: "derived_from",
			From: proof.RelationshipRef{Kind: "evidence", ID: scopedID("finding", strings.TrimSpace(canonicalKey))},
			To:   proof.RelationshipRef{Kind: "tool", ID: toolID},
		},
	)
	if policyID := policyRefID(policyRef); policyID != "" {
		edges = relationshipEdges(append(edges, proof.RelationshipEdge{
			Kind: "governed_by",
			From: proof.RelationshipRef{Kind: "tool", ID: toolID},
			To:   proof.RelationshipRef{Kind: "policy", ID: policyID},
		})...)
	}
	return buildRelationshipEnvelope(entityRefs, policyRef, agentID, edges)
}

func buildFindingRiskRelationship(item risk.ScoredFinding, agentID string) *proof.Relationship {
	toolID := identity.ToolID(item.Finding.ToolType, item.Finding.Location)
	canonicalKey := strings.TrimSpace(item.CanonicalKey)
	findingEvidenceID := scopedID("finding", canonicalKey)
	riskEvidenceID := scopedID("risk", canonicalKey)

	entityRefs := relationshipRefs(
		proof.RelationshipRef{Kind: "agent", ID: agentID},
		proof.RelationshipRef{Kind: "tool", ID: toolID},
		proof.RelationshipRef{Kind: "resource", ID: scopedID("org", canonicalOrg(item.Finding.Org))},
		proof.RelationshipRef{Kind: "resource", ID: scopedID("repo", strings.TrimSpace(item.Finding.Repo))},
		proof.RelationshipRef{Kind: "evidence", ID: findingEvidenceID},
		proof.RelationshipRef{Kind: "evidence", ID: riskEvidenceID},
	)
	policyRef := policyRefForRuleID(item.Finding.RuleID)
	if policyID := policyRefID(policyRef); policyID != "" {
		entityRefs = relationshipRefs(append(entityRefs, proof.RelationshipRef{Kind: "policy", ID: policyID})...)
	}
	edges := relationshipEdges(
		proof.RelationshipEdge{
			Kind: "calls",
			From: proof.RelationshipRef{Kind: "agent", ID: agentID},
			To:   proof.RelationshipRef{Kind: "tool", ID: toolID},
		},
		proof.RelationshipEdge{
			Kind: "derived_from",
			From: proof.RelationshipRef{Kind: "evidence", ID: riskEvidenceID},
			To:   proof.RelationshipRef{Kind: "evidence", ID: findingEvidenceID},
		},
	)
	if policyID := policyRefID(policyRef); policyID != "" {
		edges = relationshipEdges(append(edges, proof.RelationshipEdge{
			Kind: "governed_by",
			From: proof.RelationshipRef{Kind: "tool", ID: toolID},
			To:   proof.RelationshipRef{Kind: "policy", ID: policyID},
		})...)
	}
	return buildRelationshipEnvelope(entityRefs, policyRef, agentID, edges)
}

func buildAttackPathRelationship(path riskattack.ScoredPath) *proof.Relationship {
	pathID := strings.TrimSpace(path.PathID)
	entryNodeID := strings.TrimSpace(path.EntryNodeID)
	pivotNodeID := strings.TrimSpace(path.PivotNodeID)
	targetNodeID := strings.TrimSpace(path.TargetNodeID)
	pathEvidenceID := scopedID("attack_path", pathID)
	entryResourceID := scopedID("attack_node", entryNodeID)
	pivotResourceID := scopedID("attack_node", pivotNodeID)
	targetResourceID := scopedID("attack_node", targetNodeID)

	entityRefs := relationshipRefs(
		proof.RelationshipRef{Kind: "resource", ID: scopedID("org", canonicalOrg(path.Org))},
		proof.RelationshipRef{Kind: "resource", ID: scopedID("repo", strings.TrimSpace(path.Repo))},
		proof.RelationshipRef{Kind: "evidence", ID: pathEvidenceID},
		proof.RelationshipRef{Kind: "resource", ID: entryResourceID},
		proof.RelationshipRef{Kind: "resource", ID: pivotResourceID},
		proof.RelationshipRef{Kind: "resource", ID: targetResourceID},
	)
	edges := relationshipEdges(
		proof.RelationshipEdge{
			Kind: "derived_from",
			From: proof.RelationshipRef{Kind: "evidence", ID: pathEvidenceID},
			To:   proof.RelationshipRef{Kind: "resource", ID: entryResourceID},
		},
		proof.RelationshipEdge{
			Kind: "derived_from",
			From: proof.RelationshipRef{Kind: "evidence", ID: pathEvidenceID},
			To:   proof.RelationshipRef{Kind: "resource", ID: pivotResourceID},
		},
		proof.RelationshipEdge{
			Kind: "derived_from",
			From: proof.RelationshipRef{Kind: "evidence", ID: pathEvidenceID},
			To:   proof.RelationshipRef{Kind: "resource", ID: targetResourceID},
		},
		proof.RelationshipEdge{
			Kind: "targets",
			From: proof.RelationshipRef{Kind: "resource", ID: entryResourceID},
			To:   proof.RelationshipRef{Kind: "resource", ID: targetResourceID},
		},
	)
	if entryNodeID != "" && pivotNodeID != "" {
		edges = relationshipEdges(append(edges, proof.RelationshipEdge{
			Kind: "targets",
			From: proof.RelationshipRef{Kind: "resource", ID: entryResourceID},
			To:   proof.RelationshipRef{Kind: "resource", ID: pivotResourceID},
		})...)
	}
	if pivotNodeID != "" && targetNodeID != "" {
		edges = relationshipEdges(append(edges, proof.RelationshipEdge{
			Kind: "targets",
			From: proof.RelationshipRef{Kind: "resource", ID: pivotResourceID},
			To:   proof.RelationshipRef{Kind: "resource", ID: targetResourceID},
		})...)
	}
	return buildRelationshipEnvelope(entityRefs, nil, "", edges)
}

func buildPostureRelationship(profileName string) *proof.Relationship {
	trimmedProfile := strings.TrimSpace(profileName)
	if trimmedProfile == "" {
		trimmedProfile = "default"
	}
	entityRefs := relationshipRefs(
		proof.RelationshipRef{Kind: "evidence", ID: scopedID("posture_score", trimmedProfile)},
		proof.RelationshipRef{Kind: "resource", ID: scopedID("profile", trimmedProfile)},
	)
	return buildRelationshipEnvelope(entityRefs, nil, "", nil)
}

func buildDecisionTraceRelationship(path risk.ActionPath, traceID string) *proof.Relationship {
	toolID := identity.ToolID(path.ToolType, path.Location)
	refs := []proof.RelationshipRef{
		proof.RelationshipRef{Kind: "agent", ID: strings.TrimSpace(path.AgentID)},
		proof.RelationshipRef{Kind: "tool", ID: toolID},
		proof.RelationshipRef{Kind: "resource", ID: scopedID("org", canonicalOrg(path.Org))},
		proof.RelationshipRef{Kind: "resource", ID: scopedID("repo", strings.TrimSpace(path.Repo))},
		proof.RelationshipRef{Kind: "evidence", ID: scopedID("decision_trace", traceID)},
		proof.RelationshipRef{Kind: "resource", ID: scopedID("path", strings.TrimSpace(path.PathID))},
	}
	for _, compositionID := range path.CompositionIDs {
		refs = append(refs, proof.RelationshipRef{Kind: "resource", ID: scopedID("composition", compositionID)})
	}
	for _, contractRef := range path.ProposedActionContractRefs {
		refs = append(refs, proof.RelationshipRef{Kind: "evidence", ID: scopedID("proposed_action_contract", contractRef)})
	}
	for _, workflowRef := range path.WorkflowChainRefs {
		refs = append(refs, proof.RelationshipRef{Kind: "resource", ID: scopedID("workflow_chain", workflowRef)})
	}
	entityRefs := relationshipRefs(refs...)
	edges := relationshipEdges(
		proof.RelationshipEdge{
			Kind: "calls",
			From: proof.RelationshipRef{Kind: "agent", ID: strings.TrimSpace(path.AgentID)},
			To:   proof.RelationshipRef{Kind: "tool", ID: toolID},
		},
		proof.RelationshipEdge{
			Kind: "derived_from",
			From: proof.RelationshipRef{Kind: "evidence", ID: scopedID("decision_trace", traceID)},
			To:   proof.RelationshipRef{Kind: "resource", ID: scopedID("path", strings.TrimSpace(path.PathID))},
		},
	)
	return buildRelationshipEnvelope(entityRefs, nil, strings.TrimSpace(path.AgentID), edges)
}

func decisionTraceEvidenceStates(path risk.ActionPath) map[string]string {
	states := map[string]string{
		"approval":   strings.TrimSpace(path.ApprovalEvidenceState),
		"owner":      strings.TrimSpace(path.OwnerEvidenceState),
		"proof":      strings.TrimSpace(path.ProofEvidenceState),
		"runtime":    strings.TrimSpace(path.RuntimeEvidenceState),
		"target":     strings.TrimSpace(path.TargetEvidenceState),
		"credential": strings.TrimSpace(path.CredentialEvidenceState),
	}
	for key, value := range states {
		if value == "" {
			delete(states, key)
		}
	}
	if len(states) == 0 {
		return nil
	}
	return states
}

func decisionTraceGaitCoverageSummary(coverage *risk.GaitCoverage) map[string]string {
	if coverage == nil {
		return nil
	}
	out := map[string]string{
		"policy_decision":    strings.TrimSpace(coverage.PolicyDecision.Status),
		"approval":           strings.TrimSpace(coverage.Approval.Status),
		"jit_credential":     strings.TrimSpace(coverage.JITCredential.Status),
		"freeze_window":      strings.TrimSpace(coverage.FreezeWindow.Status),
		"kill_switch":        strings.TrimSpace(coverage.KillSwitch.Status),
		"action_outcome":     strings.TrimSpace(coverage.ActionOutcome.Status),
		"proof_verification": strings.TrimSpace(coverage.ProofVerification.Status),
	}
	for key, value := range out {
		if value == "" {
			delete(out, key)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func decisionTraceIdentityRef(path risk.ActionPath) string {
	if path.AgentIdentity != nil && strings.TrimSpace(path.AgentIdentity.IdentityKey) != "" {
		return strings.TrimSpace(path.AgentIdentity.IdentityKey)
	}
	return strings.TrimSpace(path.AgentID)
}

func buildTransitionRelationship(agentID, approver, newState string) *proof.Relationship {
	state := strings.TrimSpace(newState)
	evidenceID := lifecycleEvidenceID(agentID, state)
	entityRefs := relationshipRefs(
		proof.RelationshipRef{Kind: "agent", ID: agentID},
		proof.RelationshipRef{Kind: "agent", ID: strings.TrimSpace(approver)},
		proof.RelationshipRef{Kind: "evidence", ID: evidenceID},
	)
	edges := relationshipEdges(
		proof.RelationshipEdge{
			Kind: "derived_from",
			From: proof.RelationshipRef{Kind: "evidence", ID: evidenceID},
			To:   proof.RelationshipRef{Kind: "agent", ID: agentID},
		},
	)
	return buildRelationshipEnvelope(entityRefs, nil, agentID, edges)
}

func buildRelationshipEnvelope(entityRefs []proof.RelationshipRef, policyRef *proof.PolicyRef, agentID string, edges []proof.RelationshipEdge) *proof.Relationship {
	normalizedRefs := relationshipRefs(entityRefs...)
	normalizedEdges := relationshipEdges(edges...)
	relatedEntityIDs := make([]string, 0, len(normalizedRefs))
	for _, ref := range normalizedRefs {
		relatedEntityIDs = append(relatedEntityIDs, ref.ID)
	}
	relatedEntityIDs = uniqueSortedStrings(relatedEntityIDs)
	agentChain := []proof.AgentChainHop{}
	if strings.TrimSpace(agentID) != "" {
		agentChain = append(agentChain, proof.AgentChainHop{Identity: strings.TrimSpace(agentID), Role: "requester"})
	}
	relationship := &proof.Relationship{
		EntityRefs:       normalizedRefs,
		PolicyRef:        policyRef,
		AgentChain:       agentChain,
		Edges:            normalizedEdges,
		RelatedEntityIDs: relatedEntityIDs,
	}
	if len(relationship.EntityRefs) == 0 && relationship.PolicyRef == nil && len(relationship.AgentChain) == 0 && len(relationship.Edges) == 0 && len(relationship.RelatedEntityIDs) == 0 {
		return nil
	}
	return relationship
}

func policyRefForRuleID(ruleID string) *proof.PolicyRef {
	trimmed := strings.TrimSpace(ruleID)
	if trimmed == "" {
		return nil
	}
	return &proof.PolicyRef{
		PolicyID:       "wrkr-policy",
		MatchedRuleIDs: []string{trimmed},
	}
}

func policyRefForRuleIDs(ruleIDs []string) *proof.PolicyRef {
	normalized := uniqueSortedStrings(ruleIDs)
	if len(normalized) == 0 {
		return nil
	}
	return &proof.PolicyRef{
		PolicyID:       "wrkr-policy",
		MatchedRuleIDs: normalized,
	}
}

func decisionTraceID(path risk.ActionPath) string {
	raw := strings.Join([]string{
		strings.TrimSpace(path.PathID),
		strings.TrimSpace(path.Location),
		strings.TrimSpace(path.RecommendedControl),
		strings.Join(decisionTracePresetNames(path), ","),
	}, "|")
	return "dt-" + shortHash(raw)
}

func decisionTraceActor(path risk.ActionPath) string {
	if path.IntroducedBy != nil {
		if path.IntroducedBy.Provenance != nil && strings.TrimSpace(path.IntroducedBy.Provenance.Author) != "" {
			return strings.TrimSpace(path.IntroducedBy.Provenance.Author)
		}
		if strings.TrimSpace(path.IntroducedBy.Author) != "" {
			return strings.TrimSpace(path.IntroducedBy.Author)
		}
		if strings.TrimSpace(path.IntroducedBy.Reference) != "" {
			return strings.TrimSpace(path.IntroducedBy.Reference)
		}
	}
	return firstNonEmpty(strings.TrimSpace(path.AgentID), strings.TrimSpace(path.ToolType), strings.TrimSpace(path.Location))
}

func decisionTraceAuthorityImpact(path risk.ActionPath) string {
	if path.AgenticDeliverySystemChange != nil && strings.TrimSpace(path.AgenticDeliverySystemChange.AuthorityImpact) != "" {
		return strings.TrimSpace(path.AgenticDeliverySystemChange.AuthorityImpact)
	}
	switch {
	case path.ProductionWrite:
		return "production_mutation"
	case path.DeployWrite || path.MergeExecute:
		return "release_or_deploy"
	case path.CredentialAccess:
		return "credential_authority"
	default:
		return "review_surface"
	}
}

func decisionTraceSurfaceType(path risk.ActionPath) string {
	if path.AgenticDeliverySystemChange != nil && strings.TrimSpace(path.AgenticDeliverySystemChange.SurfaceType) != "" {
		return strings.TrimSpace(path.AgenticDeliverySystemChange.SurfaceType)
	}
	return "workflow_path"
}

func decisionTraceCredentialReach(path risk.ActionPath) string {
	if path.AgenticDeliverySystemChange != nil && strings.TrimSpace(path.AgenticDeliverySystemChange.CredentialReach) != "" {
		return strings.TrimSpace(path.AgenticDeliverySystemChange.CredentialReach)
	}
	if path.CredentialAccess {
		return "credential_access_present"
	}
	return "no_visible_credential"
}

func decisionTraceReviewState(path risk.ActionPath) string {
	if path.AgenticDeliverySystemChange != nil && strings.TrimSpace(path.AgenticDeliverySystemChange.ReviewState) != "" {
		return strings.TrimSpace(path.AgenticDeliverySystemChange.ReviewState)
	}
	if path.ApprovalGap {
		return "approval_missing"
	}
	return "review_unknown"
}

func decisionTraceApprovalOrExceptionReason(path risk.ActionPath) string {
	switch {
	case len(path.ApprovalGapReasons) > 0:
		return strings.Join(uniqueSortedStrings(path.ApprovalGapReasons), ",")
	case len(path.Contradictions) > 0:
		reasons := []string{}
		for _, item := range path.Contradictions {
			reasons = append(reasons, item.ReasonCodes...)
		}
		return strings.Join(uniqueSortedStrings(reasons), ",")
	case path.IntroducedBy != nil && path.IntroducedBy.Provenance != nil && len(path.IntroducedBy.Provenance.MissingEvidence) > 0:
		return strings.Join(uniqueSortedStrings(path.IntroducedBy.Provenance.MissingEvidence), ",")
	default:
		return "no_exception_recorded"
	}
}

func decisionTraceContextUsed(path risk.ActionPath) []string {
	values := []string{}
	for _, preset := range decisionTracePresetNames(path) {
		values = append(values, "preset:"+preset)
	}
	for _, ref := range path.WorkflowChainRefs {
		values = append(values, "workflow_chain:"+strings.TrimSpace(ref))
	}
	if path.IntroducedBy != nil && strings.TrimSpace(path.IntroducedBy.Reference) != "" {
		values = append(values, "review_ref:"+strings.TrimSpace(path.IntroducedBy.Reference))
	}
	if path.ActionLineage != nil {
		for _, segment := range path.ActionLineage.Segments {
			if strings.TrimSpace(segment.Kind) == "" {
				continue
			}
			values = append(values, "lineage:"+strings.TrimSpace(segment.Kind))
		}
	}
	values = uniqueSortedStrings(values)
	if len(values) > 10 {
		values = values[:10]
	}
	return values
}

func decisionTraceEvidenceRefs(path risk.ActionPath) []string {
	values := append([]string(nil), path.ControlEvidenceRefs...)
	values = append(values, path.PolicyEvidenceRefs...)
	values = append(values, path.TargetClassEvidenceRefs...)
	values = append(values, path.ActionPathTypeEvidenceRefs...)
	values = append(values, path.AttackPathRefs...)
	if path.IntroducedBy != nil {
		values = append(values, attribution.EvidenceRefs(path.IntroducedBy)...)
	}
	return uniqueSortedStrings(values)
}

func decisionTraceProofRefs(path risk.ActionPath) []string {
	values := append([]string(nil), path.PolicyEvidenceRefs...)
	if path.GaitCoverage != nil {
		values = append(values, path.GaitCoverage.ProofVerification.EvidenceRefs...)
	}
	return uniqueSortedStrings(values)
}

func decisionTracePresetNames(path risk.ActionPath) []string {
	values := make([]string, 0, len(path.HighStakesPresets))
	for _, item := range path.HighStakesPresets {
		if strings.TrimSpace(item.Preset) == "" {
			continue
		}
		values = append(values, strings.TrimSpace(item.Preset))
	}
	return uniqueSortedStrings(values)
}

func shortHash(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:6])
}

func policyRefID(policyRef *proof.PolicyRef) string {
	if policyRef == nil {
		return ""
	}
	if digest := strings.ToLower(strings.TrimSpace(policyRef.PolicyDigest)); digest != "" {
		return digest
	}
	if policyID := strings.TrimSpace(policyRef.PolicyID); policyID != "" {
		return policyID
	}
	if policyVersion := strings.TrimSpace(policyRef.PolicyVersion); policyVersion != "" {
		return "policy-version:" + policyVersion
	}
	return ""
}

func relationshipRefs(refs ...proof.RelationshipRef) []proof.RelationshipRef {
	type key struct {
		kind string
		id   string
	}
	seen := map[key]struct{}{}
	out := make([]proof.RelationshipRef, 0, len(refs))
	for _, ref := range refs {
		kind := strings.ToLower(strings.TrimSpace(ref.Kind))
		id := strings.TrimSpace(ref.ID)
		if kind == "" || id == "" {
			continue
		}
		k := key{kind: kind, id: id}
		if _, exists := seen[k]; exists {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, proof.RelationshipRef{Kind: kind, ID: id})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func relationshipEdges(edges ...proof.RelationshipEdge) []proof.RelationshipEdge {
	type key struct {
		kind     string
		fromKind string
		fromID   string
		toKind   string
		toID     string
	}
	seen := map[key]struct{}{}
	out := make([]proof.RelationshipEdge, 0, len(edges))
	for _, edge := range edges {
		kind := strings.ToLower(strings.TrimSpace(edge.Kind))
		fromKind := strings.ToLower(strings.TrimSpace(edge.From.Kind))
		fromID := strings.TrimSpace(edge.From.ID)
		toKind := strings.ToLower(strings.TrimSpace(edge.To.Kind))
		toID := strings.TrimSpace(edge.To.ID)
		if kind == "" || fromKind == "" || fromID == "" || toKind == "" || toID == "" {
			continue
		}
		k := key{kind: kind, fromKind: fromKind, fromID: fromID, toKind: toKind, toID: toID}
		if _, exists := seen[k]; exists {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, proof.RelationshipEdge{
			Kind: kind,
			From: proof.RelationshipRef{Kind: fromKind, ID: fromID},
			To:   proof.RelationshipRef{Kind: toKind, ID: toID},
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].From.Kind != out[j].From.Kind {
			return out[i].From.Kind < out[j].From.Kind
		}
		if out[i].From.ID != out[j].From.ID {
			return out[i].From.ID < out[j].From.ID
		}
		if out[i].To.Kind != out[j].To.Kind {
			return out[i].To.Kind < out[j].To.Kind
		}
		return out[i].To.ID < out[j].To.ID
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func scopedID(prefix, value string) string {
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return ""
	}
	trimmedPrefix := strings.TrimSpace(prefix)
	if trimmedPrefix == "" {
		return trimmedValue
	}
	return trimmedPrefix + ":" + trimmedValue
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func agentInstanceIDForFinding(finding model.Finding) string {
	symbol := evidenceStringValue(finding, "symbol")
	startLine := 0
	endLine := 0
	if finding.LocationRange != nil {
		startLine = finding.LocationRange.StartLine
		endLine = finding.LocationRange.EndLine
	}
	return identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
}

func findingIdentityComponent(finding model.Finding) string {
	if strings.TrimSpace(finding.FindingType) != "agent_framework" {
		return ""
	}
	if !hasExplicitAgentInstanceMetadata(finding) {
		return ""
	}
	return agentInstanceIDForFinding(finding)
}

func hasExplicitAgentInstanceMetadata(finding model.Finding) bool {
	if evidenceStringValue(finding, "symbol") != "" {
		return true
	}
	if finding.LocationRange == nil {
		return false
	}
	return finding.LocationRange.StartLine > 0 || finding.LocationRange.EndLine > 0
}

func evidenceStringValue(finding model.Finding, key string) string {
	needle := strings.ToLower(strings.TrimSpace(key))
	for _, item := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(item.Key)) == needle {
			return strings.TrimSpace(item.Value)
		}
	}
	return ""
}

func evidenceListValue(finding model.Finding, key string) []string {
	needle := strings.ToLower(strings.TrimSpace(key))
	set := map[string]struct{}{}
	for _, item := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(item.Key)) != needle {
			continue
		}
		for _, part := range strings.Split(item.Value, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			set[trimmed] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func lifecycleEvidenceID(agentID, state string) string {
	agent := strings.TrimSpace(agentID)
	if agent == "" {
		return ""
	}
	return "lifecycle:" + agent + ":" + strings.TrimSpace(state)
}

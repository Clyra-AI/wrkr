package proofmap

import (
	"sort"
	"strconv"
	"strings"
	"time"

	proof "github.com/Clyra-AI/proof"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/score"
)

type MappedRecord struct {
	RecordType    string
	AgentID       string
	Timestamp     time.Time
	Event         map[string]any
	Metadata      map[string]any
	Relationship  *proof.Relationship
	ApprovedScope string
}

type SecurityVisibilityContext struct {
	Summary          agginventory.SecurityVisibilitySummary
	StatusByInstance map[string]string
}

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

		records = append(records, MappedRecord{
			RecordType:   "scan_finding",
			AgentID:      agentID,
			Timestamp:    canonicalTime(now),
			Event:        event,
			Metadata:     metadata,
			Relationship: buildFindingRelationship(representative, key, ruleIDs, agentID),
		})
	}
	return records
}

func MapRisk(report risk.Report, posture score.Result, profile profileeval.Result, visibility SecurityVisibilityContext, now time.Time) []MappedRecord {
	records := make([]MappedRecord, 0, len(report.Ranked)+len(report.AttackPaths)+len(report.ActionPaths)+1)
	for idx, item := range report.Ranked {
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
		records = append(records, MappedRecord{
			RecordType:   "risk_assessment",
			AgentID:      agentID,
			Timestamp:    canonicalTime(now),
			Event:        event,
			Relationship: buildFindingRiskRelationship(item, agentID),
			Metadata:     metadata,
		})
	}
	for idx, path := range report.AttackPaths {
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
		records = append(records, MappedRecord{
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
		})
	}
	for idx, path := range report.ActionPaths {
		event := map[string]any{
			"assessment_type":            "action_path_governance",
			"path_id":                    path.PathID,
			"org":                        path.Org,
			"repo":                       path.Repo,
			"tool_type":                  path.ToolType,
			"location":                   path.Location,
			"write_capable":              path.WriteCapable,
			"write_path_classes":         append([]string(nil), path.WritePathClasses...),
			"recommended_action":         path.RecommendedAction,
			"security_visibility_status": path.SecurityVisibilityStatus,
			"approval_gap_reasons":       append([]string(nil), path.ApprovalGapReasons...),
			"governance_controls":        append([]agginventory.GovernanceControlMapping(nil), path.GovernanceControls...),
			"credential_access":          path.CredentialAccess,
			"production_write":           path.ProductionWrite,
			"matched_production_targets": append([]string(nil), path.MatchedProductionTargets...),
		}
		records = append(records, MappedRecord{
			RecordType: "risk_assessment",
			AgentID:    path.AgentID,
			Timestamp:  canonicalTime(now),
			Event:      event,
			Metadata: map[string]any{
				"rank":              idx + 1,
				"canonical_finding": "action_path_governance",
				"action_path_id":    path.PathID,
			},
		})
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
	records = append(records, MappedRecord{
		RecordType:   "risk_assessment",
		Timestamp:    canonicalTime(now),
		Event:        postureEvent,
		Relationship: buildPostureRelationship(profile.ProfileName),
		Metadata: map[string]any{
			"canonical_finding": "posture_score",
			"profile_name":      profile.ProfileName,
		},
	})

	return records
}

func MapTransition(transition lifecycle.Transition, eventType string) MappedRecord {
	recordType := "decision"
	resolvedEventType := strings.TrimSpace(eventType)
	switch resolvedEventType {
	case "approval", "approval_recorded", "risk_accepted":
		recordType = "approval"
	case "owner_assigned", "evidence_attached", "least_privilege_verified", "rotation_evidence_attached", "deployment_gate_present", "production_access_classified", "proof_artifact_generated", "review_cadence_set":
		recordType = "evidence"
	}
	if resolvedEventType == "" {
		resolvedEventType = "lifecycle_transition"
	}

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
	return MappedRecord{
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
	}
}

func CanonicalFindingKey(finding model.Finding) string {
	if (finding.FindingType == "policy_violation" || finding.FindingType == "policy_check") && finding.RuleID == "WRKR-014" {
		return "skill_policy_conflict:" + canonicalOrg(finding.Org) + ":" + strings.TrimSpace(finding.Repo)
	}
	if finding.FindingType == "skill_policy_conflict" {
		return "skill_policy_conflict:" + canonicalOrg(finding.Org) + ":" + strings.TrimSpace(finding.Repo)
	}
	parts := []string{
		strings.TrimSpace(finding.FindingType),
		strings.TrimSpace(finding.RuleID),
		strings.TrimSpace(finding.ToolType),
		strings.TrimSpace(finding.Location),
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
	return findings[0]
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
		out[key] = value
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

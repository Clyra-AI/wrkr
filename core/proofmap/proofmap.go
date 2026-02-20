package proofmap

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
)

type MappedRecord struct {
	RecordType    string
	AgentID       string
	Timestamp     time.Time
	Event         map[string]any
	Metadata      map[string]any
	ApprovedScope string
}

func MapFindings(findings []model.Finding, profile *profileeval.Result, now time.Time) []MappedRecord {
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

		records = append(records, MappedRecord{
			RecordType: "scan_finding",
			AgentID:    agentIDForFinding(representative),
			Timestamp:  canonicalTime(now),
			Event:      event,
			Metadata:   metadata,
		})
	}
	return records
}

func MapRisk(report risk.Report, posture score.Result, profile profileeval.Result, now time.Time) []MappedRecord {
	records := make([]MappedRecord, 0, len(report.Ranked)+1)
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
		records = append(records, MappedRecord{
			RecordType: "risk_assessment",
			AgentID:    agentIDForFinding(item.Finding),
			Timestamp:  canonicalTime(now),
			Event:      event,
			Metadata: map[string]any{
				"rank":              idx + 1,
				"canonical_finding": item.CanonicalKey,
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
	}
	records = append(records, MappedRecord{
		RecordType: "risk_assessment",
		Timestamp:  canonicalTime(now),
		Event:      postureEvent,
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
	if resolvedEventType == "approval" {
		recordType = "approval"
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

	timestamp := time.Now().UTC().Truncate(time.Second)
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(transition.Timestamp)); err == nil {
		timestamp = parsed.UTC().Truncate(time.Second)
	}
	return MappedRecord{
		RecordType:    recordType,
		AgentID:       strings.TrimSpace(transition.AgentID),
		Timestamp:     timestamp,
		Event:         event,
		ApprovedScope: scope,
		Metadata: map[string]any{
			"transition_trigger": transition.Trigger,
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
	toolID := identity.ToolID(finding.ToolType, finding.Location)
	return identity.AgentID(toolID, canonicalOrg(finding.Org))
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

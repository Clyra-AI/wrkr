package model

import (
	"sort"
	"strings"
)

const (
	CheckResultPass = "pass"
	CheckResultFail = "fail"

	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"

	DiscoveryMethodStatic = "static"
)

// ParseError captures structured parsing failures for deterministic reporting.
type ParseError struct {
	Kind     string `json:"kind"`
	Format   string `json:"format"`
	Path     string `json:"path"`
	Detector string `json:"detector"`
	Message  string `json:"message"`
}

// Evidence is a deterministic key/value tuple attached to a finding.
type Evidence struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type LocationRange struct {
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`
}

type ExecutionRelationship struct {
	RelationshipID    string   `json:"relationship_id" yaml:"relationship_id"`
	Kind              string   `json:"kind" yaml:"kind"`
	Caller            string   `json:"caller" yaml:"caller"`
	Callee            string   `json:"callee" yaml:"callee"`
	Origin            string   `json:"origin" yaml:"origin"`
	ResolutionState   string   `json:"resolution_state" yaml:"resolution_state"`
	Confidence        string   `json:"confidence" yaml:"confidence"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	TruncationReasons []string `json:"truncation_reasons,omitempty" yaml:"truncation_reasons,omitempty"`
}

// Finding is the canonical detector/policy output contract.
type Finding struct {
	FindingType            string                  `json:"finding_type"`
	RuleID                 string                  `json:"rule_id,omitempty"`
	CheckResult            string                  `json:"check_result,omitempty"`
	PolicyOutcomeID        string                  `json:"policy_outcome_id,omitempty"`
	Severity               string                  `json:"severity"`
	DiscoveryMethod        string                  `json:"discovery_method"`
	Remediation            string                  `json:"remediation,omitempty"`
	ToolType               string                  `json:"tool_type"`
	Location               string                  `json:"location"`
	LocationRange          *LocationRange          `json:"location_range,omitempty"`
	Repo                   string                  `json:"repo,omitempty"`
	Org                    string                  `json:"org"`
	Detector               string                  `json:"detector,omitempty"`
	Permissions            []string                `json:"permissions,omitempty"`
	Autonomy               string                  `json:"autonomy,omitempty"`
	Evidence               []Evidence              `json:"evidence,omitempty"`
	ExecutionRelationships []ExecutionRelationship `json:"execution_relationships,omitempty"`
	ParseError             *ParseError             `json:"parse_error,omitempty"`
}

func NormalizeFinding(item Finding) Finding {
	item.FindingType = strings.TrimSpace(item.FindingType)
	item.RuleID = strings.TrimSpace(item.RuleID)
	item.CheckResult = strings.TrimSpace(item.CheckResult)
	item.PolicyOutcomeID = strings.TrimSpace(item.PolicyOutcomeID)
	item.Severity = normalizeSeverity(item.Severity)
	item.DiscoveryMethod = normalizeDiscoveryMethod(item.DiscoveryMethod)
	item.Remediation = strings.TrimSpace(item.Remediation)
	item.ToolType = strings.TrimSpace(item.ToolType)
	item.Location = strings.TrimSpace(item.Location)
	item.LocationRange = normalizeLocationRange(item.LocationRange)
	item.Repo = strings.TrimSpace(item.Repo)
	item.Org = strings.TrimSpace(item.Org)
	item.Detector = strings.TrimSpace(item.Detector)
	item.Autonomy = strings.TrimSpace(item.Autonomy)
	item.Permissions = normalizeStrings(item.Permissions)
	item.Evidence = normalizeEvidence(item.Evidence)
	item.ExecutionRelationships = NormalizeExecutionRelationships(item.ExecutionRelationships)
	if item.ParseError != nil {
		item.ParseError.Kind = strings.TrimSpace(item.ParseError.Kind)
		item.ParseError.Format = strings.TrimSpace(item.ParseError.Format)
		item.ParseError.Path = strings.TrimSpace(item.ParseError.Path)
		item.ParseError.Detector = strings.TrimSpace(item.ParseError.Detector)
		item.ParseError.Message = strings.TrimSpace(item.ParseError.Message)
	}
	return item
}

func NormalizeExecutionRelationships(in []ExecutionRelationship) []ExecutionRelationship {
	if len(in) == 0 {
		return nil
	}
	out := make([]ExecutionRelationship, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		item.RelationshipID = strings.TrimSpace(item.RelationshipID)
		item.Kind = strings.TrimSpace(item.Kind)
		item.Caller = strings.TrimSpace(item.Caller)
		item.Callee = strings.TrimSpace(item.Callee)
		item.Origin = strings.TrimSpace(item.Origin)
		item.ResolutionState = strings.TrimSpace(item.ResolutionState)
		item.Confidence = strings.TrimSpace(item.Confidence)
		item.EvidenceRefs = normalizeStrings(item.EvidenceRefs)
		item.TruncationReasons = normalizeStrings(item.TruncationReasons)
		if item.Kind == "" || item.Caller == "" || item.Callee == "" || item.ResolutionState == "" {
			continue
		}
		key := strings.Join([]string{item.RelationshipID, item.Kind, item.Caller, item.Callee, item.Origin, item.ResolutionState}, "|")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		left := strings.Join([]string{out[i].RelationshipID, out[i].Kind, out[i].Caller, out[i].Callee, out[i].ResolutionState}, "|")
		right := strings.Join([]string{out[j].RelationshipID, out[j].Kind, out[j].Caller, out[j].Callee, out[j].ResolutionState}, "|")
		return left < right
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func SortFindings(findings []Finding) {
	for i := range findings {
		findings[i] = NormalizeFinding(findings[i])
	}
	sort.Slice(findings, func(i, j int) bool {
		a := findings[i]
		b := findings[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		if a.FindingType != b.FindingType {
			return a.FindingType < b.FindingType
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.DiscoveryMethod != b.DiscoveryMethod {
			return a.DiscoveryMethod < b.DiscoveryMethod
		}
		if a.ToolType != b.ToolType {
			return a.ToolType < b.ToolType
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		aStart, aEnd := locationRangeBounds(a.LocationRange)
		bStart, bEnd := locationRangeBounds(b.LocationRange)
		if aStart != bStart {
			return aStart < bStart
		}
		if aEnd != bEnd {
			return aEnd < bEnd
		}
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		if a.Org != b.Org {
			return a.Org < b.Org
		}
		if a.Detector != b.Detector {
			return a.Detector < b.Detector
		}
		return strings.Join(a.Permissions, ",") < strings.Join(b.Permissions, ",")
	})
}

func normalizeSeverity(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func normalizeDiscoveryMethod(in string) string {
	trimmed := strings.ToLower(strings.TrimSpace(in))
	if trimmed == "" {
		return DiscoveryMethodStatic
	}
	return trimmed
}

func severityRank(severity string) int {
	switch normalizeSeverity(severity) {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}

func normalizeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeEvidence(in []Evidence) []Evidence {
	if len(in) == 0 {
		return nil
	}
	out := make([]Evidence, 0, len(in))
	for _, item := range in {
		k := strings.TrimSpace(item.Key)
		v := strings.TrimSpace(item.Value)
		if k == "" && v == "" {
			continue
		}
		out = append(out, Evidence{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key == out[j].Key {
			return out[i].Value < out[j].Value
		}
		return out[i].Key < out[j].Key
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeLocationRange(in *LocationRange) *LocationRange {
	if in == nil {
		return nil
	}
	start := in.StartLine
	end := in.EndLine
	if start < 0 {
		start = 0
	}
	if end < 0 {
		end = 0
	}
	if start == 0 && end == 0 {
		return nil
	}
	if start == 0 {
		start = end
	}
	if end == 0 {
		end = start
	}
	if end < start {
		start, end = end, start
	}
	return &LocationRange{StartLine: start, EndLine: end}
}

func locationRangeBounds(in *LocationRange) (int, int) {
	if in == nil {
		return 0, 0
	}
	return in.StartLine, in.EndLine
}

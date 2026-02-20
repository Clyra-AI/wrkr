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

// Finding is the canonical detector/policy output contract.
type Finding struct {
	FindingType string      `json:"finding_type"`
	RuleID      string      `json:"rule_id,omitempty"`
	CheckResult string      `json:"check_result,omitempty"`
	Severity    string      `json:"severity"`
	Remediation string      `json:"remediation,omitempty"`
	ToolType    string      `json:"tool_type"`
	Location    string      `json:"location"`
	Repo        string      `json:"repo,omitempty"`
	Org         string      `json:"org"`
	Detector    string      `json:"detector,omitempty"`
	Permissions []string    `json:"permissions,omitempty"`
	Autonomy    string      `json:"autonomy,omitempty"`
	Evidence    []Evidence  `json:"evidence,omitempty"`
	ParseError  *ParseError `json:"parse_error,omitempty"`
}

func NormalizeFinding(item Finding) Finding {
	item.FindingType = strings.TrimSpace(item.FindingType)
	item.RuleID = strings.TrimSpace(item.RuleID)
	item.CheckResult = strings.TrimSpace(item.CheckResult)
	item.Severity = normalizeSeverity(item.Severity)
	item.Remediation = strings.TrimSpace(item.Remediation)
	item.ToolType = strings.TrimSpace(item.ToolType)
	item.Location = strings.TrimSpace(item.Location)
	item.Repo = strings.TrimSpace(item.Repo)
	item.Org = strings.TrimSpace(item.Org)
	item.Detector = strings.TrimSpace(item.Detector)
	item.Autonomy = strings.TrimSpace(item.Autonomy)
	item.Permissions = normalizeStrings(item.Permissions)
	item.Evidence = normalizeEvidence(item.Evidence)
	if item.ParseError != nil {
		item.ParseError.Kind = strings.TrimSpace(item.ParseError.Kind)
		item.ParseError.Format = strings.TrimSpace(item.ParseError.Format)
		item.ParseError.Path = strings.TrimSpace(item.ParseError.Path)
		item.ParseError.Detector = strings.TrimSpace(item.ParseError.Detector)
		item.ParseError.Message = strings.TrimSpace(item.ParseError.Message)
	}
	return item
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
		if a.ToolType != b.ToolType {
			return a.ToolType < b.ToolType
		}
		if a.Location != b.Location {
			return a.Location < b.Location
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

package resolution

import (
	"path/filepath"
	"sort"
	"strings"
)

const (
	MatchConfidenceHigh      = "high"
	MatchConfidenceMedium    = "medium"
	MatchConfidenceLow       = "low"
	MatchConfidenceAmbiguous = "ambiguous"
)

type Selector struct {
	Repo              string   `json:"repo,omitempty" yaml:"repo,omitempty"`
	ToolType          string   `json:"tool_type,omitempty" yaml:"tool_type,omitempty"`
	Locations         []string `json:"locations,omitempty" yaml:"locations,omitempty"`
	ActionClasses     []string `json:"action_classes,omitempty" yaml:"action_classes,omitempty"`
	TargetClass       string   `json:"target_class,omitempty" yaml:"target_class,omitempty"`
	CredentialKinds   []string `json:"credential_kinds,omitempty" yaml:"credential_kinds,omitempty"`
	FindingKeys       []string `json:"finding_keys,omitempty" yaml:"finding_keys,omitempty"`
	EvidenceLocations []string `json:"evidence_locations,omitempty" yaml:"evidence_locations,omitempty"`
}

type Candidate struct {
	Org               string
	Repo              string
	ToolType          string
	Location          string
	ActionClasses     []string
	TargetClass       string
	CredentialKinds   []string
	FindingKeys       []string
	EvidenceLocations []string
}

type MatchResult struct {
	Matched         bool
	Confidence      string
	MismatchReasons []string
	Score           int
}

func NormalizePath(value string) string {
	normalized := filepath.ToSlash(strings.TrimSpace(value))
	normalized = strings.TrimPrefix(normalized, "./")
	normalized = strings.TrimPrefix(normalized, "/")
	return normalized
}

func NormalizeSelector(in Selector) Selector {
	out := in
	out.Repo = strings.TrimSpace(out.Repo)
	out.ToolType = strings.TrimSpace(out.ToolType)
	out.TargetClass = strings.TrimSpace(out.TargetClass)
	out.Locations = normalizePaths(out.Locations)
	out.ActionClasses = normalizeStrings(out.ActionClasses)
	out.CredentialKinds = normalizeStrings(out.CredentialKinds)
	out.FindingKeys = normalizeStrings(out.FindingKeys)
	out.EvidenceLocations = normalizePaths(out.EvidenceLocations)
	return out
}

func NormalizeCandidate(in Candidate) Candidate {
	out := in
	out.Org = strings.TrimSpace(out.Org)
	out.Repo = strings.TrimSpace(out.Repo)
	out.ToolType = strings.TrimSpace(out.ToolType)
	out.Location = NormalizePath(out.Location)
	out.ActionClasses = normalizeStrings(out.ActionClasses)
	out.TargetClass = strings.TrimSpace(out.TargetClass)
	out.CredentialKinds = normalizeStrings(out.CredentialKinds)
	out.FindingKeys = normalizeStrings(out.FindingKeys)
	out.EvidenceLocations = normalizePaths(out.EvidenceLocations)
	return out
}

func HasSelectorFields(in Selector) bool {
	normalized := NormalizeSelector(in)
	return normalized.Repo != "" ||
		normalized.ToolType != "" ||
		normalized.TargetClass != "" ||
		len(normalized.Locations) > 0 ||
		len(normalized.ActionClasses) > 0 ||
		len(normalized.CredentialKinds) > 0 ||
		len(normalized.FindingKeys) > 0 ||
		len(normalized.EvidenceLocations) > 0
}

func CloneSelector(in *Selector) *Selector {
	if in == nil {
		return nil
	}
	copyValue := NormalizeSelector(*in)
	return &copyValue
}

func Match(selector Selector, candidate Candidate) MatchResult {
	selector = NormalizeSelector(selector)
	candidate = NormalizeCandidate(candidate)
	if !HasSelectorFields(selector) {
		return MatchResult{MismatchReasons: []string{"selector:empty"}}
	}

	score := 0
	reasons := []string{}
	signals := 0

	if selector.Repo != "" {
		signals++
		if candidate.Repo != selector.Repo {
			reasons = append(reasons, "selector:repo_mismatch")
		} else {
			score += 2
		}
	}
	if selector.ToolType != "" {
		signals++
		if candidate.ToolType != selector.ToolType {
			reasons = append(reasons, "selector:tool_type_mismatch")
		} else {
			score++
		}
	}
	if len(selector.Locations) > 0 {
		signals++
		if !containsNormalizedPath(selector.Locations, candidate.Location) {
			reasons = append(reasons, "selector:location_mismatch")
		} else {
			score++
		}
	}
	if len(selector.ActionClasses) > 0 {
		signals++
		if !containsAll(candidate.ActionClasses, selector.ActionClasses) {
			reasons = append(reasons, "selector:action_class_mismatch")
		} else {
			score++
		}
	}
	if selector.TargetClass != "" {
		signals++
		if candidate.TargetClass != selector.TargetClass {
			reasons = append(reasons, "selector:target_class_mismatch")
		} else {
			score++
		}
	}
	if len(selector.CredentialKinds) > 0 {
		signals++
		if !hasOverlap(candidate.CredentialKinds, selector.CredentialKinds) {
			reasons = append(reasons, "selector:credential_kind_mismatch")
		} else {
			score++
		}
	}
	if len(selector.FindingKeys) > 0 {
		signals++
		if !hasOverlap(candidate.FindingKeys, selector.FindingKeys) {
			reasons = append(reasons, "selector:finding_key_mismatch")
		} else {
			score += 2
		}
	}
	if len(selector.EvidenceLocations) > 0 {
		signals++
		if !hasPathOverlap(candidate.EvidenceLocations, selector.EvidenceLocations) {
			reasons = append(reasons, "selector:evidence_location_mismatch")
		} else {
			score++
		}
	}

	if len(reasons) > 0 {
		return MatchResult{
			Matched:         false,
			Confidence:      "",
			MismatchReasons: normalizeStrings(reasons),
			Score:           score,
		}
	}

	confidence := MatchConfidenceLow
	switch {
	case score >= 6:
		confidence = MatchConfidenceHigh
	case score >= 4:
		confidence = MatchConfidenceMedium
	}
	return MatchResult{
		Matched:         signals > 0,
		Confidence:      confidence,
		MismatchReasons: nil,
		Score:           score,
	}
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := set[trimmed]; exists {
			continue
		}
		set[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizePaths(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := NormalizePath(value)
		if normalized == "" {
			continue
		}
		if _, exists := set[normalized]; exists {
			continue
		}
		set[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func containsAll(current []string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	set := map[string]struct{}{}
	for _, value := range current {
		set[strings.TrimSpace(value)] = struct{}{}
	}
	for _, value := range required {
		if _, ok := set[strings.TrimSpace(value)]; !ok {
			return false
		}
	}
	return true
}

func hasOverlap(current []string, expected []string) bool {
	if len(expected) == 0 {
		return true
	}
	set := map[string]struct{}{}
	for _, value := range current {
		set[strings.TrimSpace(value)] = struct{}{}
	}
	for _, value := range expected {
		if _, ok := set[strings.TrimSpace(value)]; ok {
			return true
		}
	}
	return false
}

func hasPathOverlap(current []string, expected []string) bool {
	if len(expected) == 0 {
		return true
	}
	normalizedCurrent := normalizePaths(current)
	for _, value := range normalizePaths(expected) {
		if containsNormalizedPath(normalizedCurrent, value) {
			return true
		}
	}
	return false
}

func containsNormalizedPath(current []string, expected string) bool {
	expected = NormalizePath(expected)
	for _, value := range current {
		if NormalizePath(value) == expected {
			return true
		}
	}
	return false
}

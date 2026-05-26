package evidencepolicy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	SourceTypeProviderExport    = "provider_export"
	SourceTypeGitHubTeamExport  = "github_team_export"
	SourceTypeBackstageExport   = "backstage_export"
	SourceTypeTicketExport      = "ticket_export"
	SourceTypeSignedDeclaration = "signed_declaration"
	SourceTypeCustomerOwnerMap  = "customer_owner_map"
	SourceTypeRepoPolicy        = "repo_policy"
	SourceTypePolicyConfig      = "policy_config"
	SourceTypeCodeowners        = "codeowners"
	SourceTypeCustomOwnerMap    = "custom_owner_mapping"
	SourceTypeServiceCatalog    = "service_catalog"
	SourceTypeBackstageCatalog  = "backstage_catalog"
	SourceTypeAppCatalog        = "app_catalog"
	SourceTypeGitHubMetadata    = "github_metadata"
	SourceTypeRepoFallback      = "repo_fallback"
	SourceTypeRuntime           = "runtime"
	SourceTypeUnknown           = "unknown"

	FreshnessStateFresh   = "fresh"
	FreshnessStateStale   = "stale"
	FreshnessStateExpired = "expired"
	FreshnessStateUnknown = "unknown"

	ConflictStateResolved  = "resolved"
	ConflictStateAmbiguous = "ambiguous"

	FieldOwner      = "owner"
	FieldApproval   = "approval"
	FieldConstraint = "constraint"
	FieldTarget     = "target_class"
	FieldPolicy     = "policy"
)

type Candidate struct {
	Field          string   `json:"field,omitempty"`
	Value          string   `json:"value,omitempty"`
	SourceType     string   `json:"source_type,omitempty"`
	Source         string   `json:"source,omitempty"`
	EvidenceRefs   []string `json:"evidence_refs,omitempty"`
	ObservedAt     string   `json:"observed_at,omitempty"`
	ValidUntil     string   `json:"valid_until,omitempty"`
	MaxAge         string   `json:"max_age,omitempty"`
	Issuer         string   `json:"issuer,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	FreshnessState string   `json:"freshness_state,omitempty"`
	Status         string   `json:"status,omitempty"`
	ReasonCodes    []string `json:"reason_codes,omitempty"`
}

type Decision struct {
	Field                  string      `json:"field"`
	SelectedValue          string      `json:"selected_value,omitempty"`
	SelectedSourceType     string      `json:"selected_source_type,omitempty"`
	SelectedSource         string      `json:"selected_source,omitempty"`
	SelectedEvidenceRefs   []string    `json:"selected_evidence_refs,omitempty"`
	SelectedObservedAt     string      `json:"selected_observed_at,omitempty"`
	SelectedValidUntil     string      `json:"selected_valid_until,omitempty"`
	SelectedMaxAge         string      `json:"selected_max_age,omitempty"`
	SelectedIssuer         string      `json:"selected_issuer,omitempty"`
	SelectedConfidence     string      `json:"selected_confidence,omitempty"`
	SelectedFreshnessState string      `json:"selected_freshness_state,omitempty"`
	SelectedStatus         string      `json:"selected_status,omitempty"`
	ConflictState          string      `json:"conflict_state,omitempty"`
	ReasonCodes            []string    `json:"reason_codes,omitempty"`
	ConflictReasonCodes    []string    `json:"conflict_reason_codes,omitempty"`
	RejectedCandidates     []Candidate `json:"rejected_candidates,omitempty"`
}

type Contradiction struct {
	Class             string   `json:"class"`
	ReasonCodes       []string `json:"reason_codes,omitempty"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
	ImpactedTarget    string   `json:"impacted_target_class,omitempty"`
	RecommendedAction string   `json:"recommended_action,omitempty"`
}

func NormalizeSourceType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SourceTypeProviderExport, SourceTypeGitHubTeamExport, SourceTypeBackstageExport,
		SourceTypeTicketExport, SourceTypeSignedDeclaration, SourceTypeCustomerOwnerMap,
		SourceTypeRepoPolicy, SourceTypePolicyConfig, SourceTypeCodeowners,
		SourceTypeCustomOwnerMap, SourceTypeServiceCatalog, SourceTypeBackstageCatalog,
		SourceTypeAppCatalog, SourceTypeGitHubMetadata, SourceTypeRepoFallback, SourceTypeRuntime:
		return strings.ToLower(strings.TrimSpace(value))
	default:
		if strings.TrimSpace(value) == "" {
			return SourceTypeUnknown
		}
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func SourcePrecedenceRank(sourceType string) int {
	switch NormalizeSourceType(sourceType) {
	case SourceTypeProviderExport, SourceTypeGitHubTeamExport, SourceTypeBackstageExport, SourceTypeTicketExport:
		return 0
	case SourceTypeSignedDeclaration, SourceTypeCustomerOwnerMap:
		return 1
	case SourceTypeRepoPolicy, SourceTypePolicyConfig, SourceTypeCodeowners, SourceTypeCustomOwnerMap:
		return 2
	case SourceTypeServiceCatalog, SourceTypeBackstageCatalog, SourceTypeAppCatalog:
		return 3
	case SourceTypeGitHubMetadata:
		return 4
	case SourceTypeRepoFallback:
		return 5
	case SourceTypeRuntime:
		return 6
	default:
		return 99
	}
}

func SourcePrecedenceKey(sourceType string) string {
	return fmt.Sprintf("%02d_%s", SourcePrecedenceRank(sourceType), NormalizeSourceType(sourceType))
}

func EvaluateFreshness(generatedAt time.Time, observedAt, validUntil, maxAge, status string) (string, []string, error) {
	observedAt = strings.TrimSpace(observedAt)
	validUntil = strings.TrimSpace(validUntil)
	maxAge = strings.TrimSpace(maxAge)
	status = strings.TrimSpace(status)
	reasons := []string{}

	var observed time.Time
	if observedAt != "" {
		parsedObserved, err := time.Parse(time.RFC3339, observedAt)
		if err != nil {
			return "", nil, fmt.Errorf("observed_at must be RFC3339: %w", err)
		}
		observed = parsedObserved.UTC()
	}

	var expiry time.Time
	switch {
	case validUntil != "":
		parsedValidUntil, err := time.Parse(time.RFC3339, validUntil)
		if err != nil {
			return "", nil, fmt.Errorf("valid_until must be RFC3339: %w", err)
		}
		expiry = parsedValidUntil.UTC()
		reasons = append(reasons, "freshness:valid_until_present")
	case maxAge != "" && !observed.IsZero():
		duration, err := time.ParseDuration(maxAge)
		if err != nil {
			return "", nil, fmt.Errorf("max_age must be a valid duration: %w", err)
		}
		expiry = observed.Add(duration)
		reasons = append(reasons, "freshness:max_age_present")
	case maxAge != "" && observed.IsZero():
		return "", nil, fmt.Errorf("max_age requires observed_at")
	}

	if !expiry.IsZero() && !observed.IsZero() && expiry.Before(observed) {
		return "", nil, fmt.Errorf("validity window precedes observed_at")
	}

	if status == "stale" {
		reasons = append(reasons, "freshness:status_stale")
	}

	if !expiry.IsZero() && !generatedAt.IsZero() {
		reference := generatedAt.UTC()
		if reference.After(expiry) {
			return FreshnessStateExpired, uniqueSorted(append(reasons, "freshness:expired")...), nil
		}
		if status == "stale" {
			return FreshnessStateStale, uniqueSorted(reasons...), nil
		}
		return FreshnessStateFresh, uniqueSorted(append(reasons, "freshness:fresh")...), nil
	}

	if status == "stale" {
		return FreshnessStateStale, uniqueSorted(reasons...), nil
	}
	return FreshnessStateUnknown, uniqueSorted(append(reasons, "freshness:unknown")...), nil
}

func ResolveDecision(candidates []Candidate, generatedAt time.Time) Decision {
	normalized := normalizeCandidates(candidates, generatedAt)
	if len(normalized) == 0 {
		return Decision{}
	}

	topRank := SourcePrecedenceRank(normalized[0].SourceType)
	top := make([]Candidate, 0, len(normalized))
	rejected := make([]Candidate, 0, len(normalized))
	for _, candidate := range normalized {
		if SourcePrecedenceRank(candidate.SourceType) == topRank {
			top = append(top, candidate)
			continue
		}
		rejected = append(rejected, candidate)
	}

	selected := top[0]
	field := strings.TrimSpace(selected.Field)
	reasons := []string{"precedence:selected:" + NormalizeSourceType(selected.SourceType)}
	conflictState := ""
	conflictReasons := []string{}

	distinctTopValues := map[string]struct{}{}
	for _, candidate := range top {
		distinctTopValues[candidate.Value] = struct{}{}
	}
	if len(distinctTopValues) > 1 {
		conflictState = ConflictStateAmbiguous
		conflictReasons = append(conflictReasons, "precedence:equal_precedence_conflict")
		reasons = append(reasons, "precedence:stable_tiebreak_applied")
	} else if len(top) > 1 {
		reasons = append(reasons, "precedence:equal_precedence_corroboration")
	}

	for _, candidate := range normalized[len(top):] {
		if strings.TrimSpace(candidate.Value) == strings.TrimSpace(selected.Value) {
			reasons = append(reasons, "precedence:lower_precedence_corroboration")
			continue
		}
		if conflictState == "" {
			conflictState = ConflictStateResolved
		}
		conflictReasons = append(conflictReasons, "precedence:lower_precedence_disagreement")
	}

	decision := Decision{
		Field:                  field,
		SelectedValue:          strings.TrimSpace(selected.Value),
		SelectedSourceType:     NormalizeSourceType(selected.SourceType),
		SelectedSource:         strings.TrimSpace(selected.Source),
		SelectedEvidenceRefs:   cloneStrings(selected.EvidenceRefs),
		SelectedObservedAt:     strings.TrimSpace(selected.ObservedAt),
		SelectedValidUntil:     strings.TrimSpace(selected.ValidUntil),
		SelectedMaxAge:         strings.TrimSpace(selected.MaxAge),
		SelectedIssuer:         strings.TrimSpace(selected.Issuer),
		SelectedConfidence:     strings.TrimSpace(selected.Confidence),
		SelectedFreshnessState: normalizeFreshnessState(selected.FreshnessState),
		SelectedStatus:         strings.TrimSpace(selected.Status),
		ConflictState:          conflictState,
		ReasonCodes:            uniqueSorted(reasons...),
		ConflictReasonCodes:    uniqueSorted(conflictReasons...),
		RejectedCandidates:     cloneCandidates(rejected),
	}

	if len(top) > 1 {
		for _, candidate := range top[1:] {
			decision.RejectedCandidates = append(decision.RejectedCandidates, candidate)
		}
		decision.RejectedCandidates = normalizeCandidates(decision.RejectedCandidates, generatedAt)
	}
	return decision
}

func normalizeCandidates(candidates []Candidate, generatedAt time.Time) []Candidate {
	out := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		normalized := candidate
		normalized.Field = strings.TrimSpace(normalized.Field)
		normalized.Value = strings.TrimSpace(normalized.Value)
		normalized.SourceType = NormalizeSourceType(normalized.SourceType)
		normalized.Source = strings.TrimSpace(normalized.Source)
		normalized.EvidenceRefs = uniqueSorted(normalized.EvidenceRefs...)
		normalized.ObservedAt = strings.TrimSpace(normalized.ObservedAt)
		normalized.ValidUntil = strings.TrimSpace(normalized.ValidUntil)
		normalized.MaxAge = strings.TrimSpace(normalized.MaxAge)
		normalized.Issuer = strings.TrimSpace(normalized.Issuer)
		normalized.Confidence = strings.TrimSpace(normalized.Confidence)
		normalized.Status = strings.TrimSpace(normalized.Status)
		if normalized.FreshnessState == "" {
			freshness, reasons, err := EvaluateFreshness(generatedAt, normalized.ObservedAt, normalized.ValidUntil, normalized.MaxAge, normalized.Status)
			if err == nil {
				normalized.FreshnessState = freshness
				normalized.ReasonCodes = uniqueSorted(append(normalized.ReasonCodes, reasons...)...)
			}
		} else {
			normalized.FreshnessState = normalizeFreshnessState(normalized.FreshnessState)
		}
		if normalized.Value == "" && len(normalized.EvidenceRefs) == 0 {
			continue
		}
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		if SourcePrecedenceRank(out[i].SourceType) != SourcePrecedenceRank(out[j].SourceType) {
			return SourcePrecedenceRank(out[i].SourceType) < SourcePrecedenceRank(out[j].SourceType)
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].ObservedAt != out[j].ObservedAt {
			return out[i].ObservedAt > out[j].ObservedAt
		}
		if joined := strings.Join(out[i].EvidenceRefs, "|"); joined != strings.Join(out[j].EvidenceRefs, "|") {
			return joined < strings.Join(out[j].EvidenceRefs, "|")
		}
		return filepath.ToSlash(out[i].Field) < filepath.ToSlash(out[j].Field)
	})
	return out
}

func normalizeFreshnessState(value string) string {
	switch strings.TrimSpace(value) {
	case FreshnessStateFresh:
		return FreshnessStateFresh
	case FreshnessStateStale:
		return FreshnessStateStale
	case FreshnessStateExpired:
		return FreshnessStateExpired
	default:
		return FreshnessStateUnknown
	}
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func cloneCandidates(values []Candidate) []Candidate {
	if len(values) == 0 {
		return nil
	}
	out := make([]Candidate, 0, len(values))
	for _, value := range values {
		item := value
		item.EvidenceRefs = cloneStrings(item.EvidenceRefs)
		item.ReasonCodes = cloneStrings(item.ReasonCodes)
		out = append(out, item)
	}
	return out
}

func uniqueSorted(values ...string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const DecisionPrecedentSchemaVersion = "v1"

type DecisionPrecedentBundle struct {
	SchemaVersion string                    `json:"schema_version"`
	GeneratedAt   string                    `json:"generated_at,omitempty"`
	Precedents    []DecisionPrecedentRecord `json:"precedents"`
}

type DecisionPrecedentRecord struct {
	PrecedentKey     string   `json:"precedent_key"`
	DecisionTraceRef string   `json:"decision_trace_ref,omitempty"`
	PriorDecision    string   `json:"prior_decision"`
	DecisionSource   string   `json:"decision_source,omitempty"`
	ObservedAt       string   `json:"observed_at,omitempty"`
	ExpiresAt        string   `json:"expires_at,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	EvidenceRefs     []string `json:"evidence_refs,omitempty"`
	ReasonCodes      []string `json:"reason_codes,omitempty"`
}

func LoadDecisionPrecedents(path string) (DecisionPrecedentBundle, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- caller provides an explicit local precedent sidecar path.
	if err != nil {
		return DecisionPrecedentBundle{}, fmt.Errorf("read decision precedents: %w", err)
	}
	var bundle DecisionPrecedentBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return DecisionPrecedentBundle{}, fmt.Errorf("parse decision precedents: %w", err)
	}
	return NormalizeDecisionPrecedents(bundle)
}

func NormalizeDecisionPrecedents(bundle DecisionPrecedentBundle) (DecisionPrecedentBundle, error) {
	if strings.TrimSpace(bundle.SchemaVersion) == "" {
		bundle.SchemaVersion = DecisionPrecedentSchemaVersion
	}
	if strings.TrimSpace(bundle.SchemaVersion) != DecisionPrecedentSchemaVersion {
		return DecisionPrecedentBundle{}, fmt.Errorf("unsupported decision precedents schema_version %q", bundle.SchemaVersion)
	}
	if strings.TrimSpace(bundle.GeneratedAt) != "" {
		if _, err := time.Parse(time.RFC3339, bundle.GeneratedAt); err != nil {
			return DecisionPrecedentBundle{}, fmt.Errorf("decision precedents generated_at must be RFC3339")
		}
	}
	items := make([]DecisionPrecedentRecord, 0, len(bundle.Precedents))
	seen := map[string]DecisionPrecedentRecord{}
	for _, item := range bundle.Precedents {
		normalized, err := normalizeDecisionPrecedentRecord(item)
		if err != nil {
			return DecisionPrecedentBundle{}, err
		}
		if existing, ok := seen[normalized.PrecedentKey]; ok {
			if existing.PriorDecision != normalized.PriorDecision || existing.DecisionTraceRef != normalized.DecisionTraceRef {
				return DecisionPrecedentBundle{}, fmt.Errorf("decision precedent %q has conflicting records", normalized.PrecedentKey)
			}
			continue
		}
		seen[normalized.PrecedentKey] = normalized
		items = append(items, normalized)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].PrecedentKey != items[j].PrecedentKey {
			return items[i].PrecedentKey < items[j].PrecedentKey
		}
		return items[i].DecisionTraceRef < items[j].DecisionTraceRef
	})
	bundle.Precedents = items
	return bundle, nil
}

func normalizeDecisionPrecedentRecord(item DecisionPrecedentRecord) (DecisionPrecedentRecord, error) {
	item.PrecedentKey = strings.TrimSpace(item.PrecedentKey)
	item.DecisionTraceRef = strings.TrimSpace(item.DecisionTraceRef)
	item.PriorDecision = strings.TrimSpace(item.PriorDecision)
	item.DecisionSource = strings.TrimSpace(item.DecisionSource)
	item.ObservedAt = strings.TrimSpace(item.ObservedAt)
	item.ExpiresAt = strings.TrimSpace(item.ExpiresAt)
	item.Confidence = normalizePrecedentConfidence(item.Confidence)
	item.EvidenceRefs = uniquePrecedentStrings(item.EvidenceRefs)
	item.ReasonCodes = uniquePrecedentStrings(item.ReasonCodes)
	if item.PrecedentKey == "" {
		return DecisionPrecedentRecord{}, fmt.Errorf("decision precedent key is required")
	}
	if item.PriorDecision == "" {
		return DecisionPrecedentRecord{}, fmt.Errorf("decision precedent prior_decision is required for %s", item.PrecedentKey)
	}
	if item.ObservedAt != "" {
		if _, err := time.Parse(time.RFC3339, item.ObservedAt); err != nil {
			return DecisionPrecedentRecord{}, fmt.Errorf("decision precedent observed_at must be RFC3339 for %s", item.PrecedentKey)
		}
	}
	if item.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, item.ExpiresAt); err != nil {
			return DecisionPrecedentRecord{}, fmt.Errorf("decision precedent expires_at must be RFC3339 for %s", item.PrecedentKey)
		}
	}
	return item, nil
}

func normalizePrecedentConfidence(value string) string {
	switch strings.TrimSpace(value) {
	case "high", "medium", "low":
		return strings.TrimSpace(value)
	default:
		return "medium"
	}
}

func uniquePrecedentStrings(values []string) []string {
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
		if _, ok := seen[trimmed]; ok {
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

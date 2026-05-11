package inventory

import (
	"sort"
	"strings"
)

const (
	EndpointSemanticRead               = "read"
	EndpointSemanticWrite              = "write"
	EndpointSemanticDelete             = "delete"
	EndpointSemanticDeploy             = "deploy"
	EndpointSemanticRefund             = "refund"
	EndpointSemanticPayment            = "payment"
	EndpointSemanticUserAdmin          = "user_admin"
	EndpointSemanticDataExport         = "data_export"
	EndpointSemanticProductionMutation = "production_mutation"
)

type MutableEndpointSemantic struct {
	Semantic     string   `json:"semantic" yaml:"semantic"`
	Confidence   string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Surface      string   `json:"surface,omitempty" yaml:"surface,omitempty"`
	Operation    string   `json:"operation,omitempty" yaml:"operation,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

func CloneMutableEndpointSemantics(in []MutableEndpointSemantic) []MutableEndpointSemantic {
	if len(in) == 0 {
		return nil
	}
	out := make([]MutableEndpointSemantic, 0, len(in))
	for _, item := range in {
		out = append(out, MutableEndpointSemantic{
			Semantic:     strings.TrimSpace(item.Semantic),
			Confidence:   strings.TrimSpace(item.Confidence),
			Surface:      strings.TrimSpace(item.Surface),
			Operation:    strings.TrimSpace(item.Operation),
			EvidenceRefs: mergeCredentialEvidenceBasis(item.EvidenceRefs),
		})
	}
	return out
}

func NormalizeMutableEndpointSemantics(in []MutableEndpointSemantic) []MutableEndpointSemantic {
	if len(in) == 0 {
		return nil
	}
	type key struct {
		semantic   string
		confidence string
		surface    string
		operation  string
	}
	merged := map[key]MutableEndpointSemantic{}
	for _, item := range in {
		normalized := MutableEndpointSemantic{
			Semantic:   strings.TrimSpace(item.Semantic),
			Confidence: strings.TrimSpace(item.Confidence),
			Surface:    strings.TrimSpace(item.Surface),
			Operation:  strings.TrimSpace(item.Operation),
		}
		if normalized.Semantic == "" {
			continue
		}
		normalized.EvidenceRefs = mergeCredentialEvidenceBasis(item.EvidenceRefs)
		k := key{
			semantic:   normalized.Semantic,
			confidence: normalized.Confidence,
			surface:    normalized.Surface,
			operation:  normalized.Operation,
		}
		current := merged[k]
		current.Semantic = normalized.Semantic
		current.Confidence = normalized.Confidence
		current.Surface = normalized.Surface
		current.Operation = normalized.Operation
		current.EvidenceRefs = mergeCredentialEvidenceBasis(append(current.EvidenceRefs, normalized.EvidenceRefs...))
		merged[k] = current
	}
	if len(merged) == 0 {
		return nil
	}
	out := make([]MutableEndpointSemantic, 0, len(merged))
	for _, item := range merged {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Semantic != out[j].Semantic {
			return out[i].Semantic < out[j].Semantic
		}
		if out[i].Surface != out[j].Surface {
			return out[i].Surface < out[j].Surface
		}
		if out[i].Operation != out[j].Operation {
			return out[i].Operation < out[j].Operation
		}
		return out[i].Confidence < out[j].Confidence
	})
	return out
}

func HasMutableEndpointSemantic(values []MutableEndpointSemantic, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, item := range values {
		if strings.TrimSpace(item.Semantic) == want {
			return true
		}
	}
	return false
}

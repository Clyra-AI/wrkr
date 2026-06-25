package attribution

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/resolution"
)

type ReviewDisposition struct {
	State         string
	Source        string
	Issuer        string
	Owner         string
	Rationale     string
	ObservedAt    string
	ValidUntil    string
	MaxAge        string
	Scope         string
	PathID        string
	ResolutionKey string
	FindingKey    string
	Selector      resolution.Selector
	EvidenceRefs  []string
}

func loadReviewDispositions(repoRoot string) []ReviewDisposition {
	doc, paths, err := config.LoadControlDeclarations(repoRoot)
	if err != nil || len(paths) == 0 || len(doc.ReviewDispositions) == 0 {
		return nil
	}
	out := make([]ReviewDisposition, 0, len(doc.ReviewDispositions))
	for _, item := range doc.ReviewDispositions {
		out = append(out, ReviewDisposition{
			State:         strings.TrimSpace(item.State),
			Source:        strings.TrimSpace(item.Source),
			Issuer:        firstNonEmptyMetadata(item.Issuer, doc.Issuer),
			Owner:         strings.TrimSpace(item.Owner),
			Rationale:     strings.TrimSpace(item.Rationale),
			ObservedAt:    strings.TrimSpace(item.ObservedAt),
			ValidUntil:    strings.TrimSpace(item.ValidUntil),
			MaxAge:        strings.TrimSpace(item.MaxAge),
			Scope:         strings.TrimSpace(item.Scope),
			PathID:        strings.TrimSpace(item.PathID),
			ResolutionKey: strings.TrimSpace(item.ResolutionKey),
			FindingKey:    strings.TrimSpace(item.FindingKey),
			Selector:      resolution.NormalizeSelector(item.Selector),
			EvidenceRefs:  normalizeStringList(item.EvidenceRefs),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

package report

import "github.com/Clyra-AI/wrkr/core/source"

func buildPublicSurfaceAssessment(manifestName string, items []source.PublicEvidence) *PublicSurfaceAssessment {
	if len(items) == 0 {
		return nil
	}
	sorted := source.SortPublicEvidence(items)
	out := &PublicSurfaceAssessment{
		ManifestName: manifestName,
		TotalSources: len(sorted),
	}
	for _, item := range sorted {
		entry := PublicSurfaceEntry{
			EntryID:            item.ID,
			SourceClass:        item.SourceClass,
			Title:              item.Title,
			PublicRef:          item.PublicRef,
			CapturePath:        item.CapturePath,
			CapturedAt:         item.CapturedAt,
			EvidenceLabel:      item.EvidenceLabel,
			Confidence:         item.Confidence,
			InferenceRationale: item.InferenceRationale,
			Claims:             append([]string(nil), item.Claims...),
		}
		out.Entries = append(out.Entries, entry)
		switch item.EvidenceLabel {
		case source.PublicEvidenceLabelObserved:
			out.LabelCounts.PublicObserved++
		case source.PublicEvidenceLabelInferred:
			out.LabelCounts.PublicInferred++
		case source.PublicEvidenceLabelUnsupportedClaim:
			out.LabelCounts.UnsupportedPublicClaim++
		case source.PublicEvidenceLabelPrivateEvidenceAbsent:
			out.LabelCounts.PrivateEvidenceAbsent++
		}
	}
	return out
}

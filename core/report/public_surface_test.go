package report

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildSummaryIncludesPublicSurfaceAssessment(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			Target: source.Target{Mode: source.TargetModePublicSurface, Value: "fixture"},
			PublicEvidence: []source.PublicEvidence{
				{
					ID:            "repo",
					SourceClass:   source.PublicSourceClassRepo,
					PublicRef:     "https://github.com/acme/platform",
					EvidenceLabel: source.PublicEvidenceLabelObserved,
					Confidence:    "high",
					Claims:        []string{"Public repo visible"},
				},
				{
					ID:                 "workflow",
					SourceClass:        source.PublicSourceClassWorkflow,
					PublicRef:          "https://github.com/acme/platform/actions/workflows/release.yml",
					EvidenceLabel:      source.PublicEvidenceLabelInferred,
					Confidence:         "medium",
					InferenceRationale: "Public workflow naming implies release automation.",
					Claims:             []string{"Release workflow likely exists"},
				},
			},
		},
		Template:     TemplatePublic,
		ShareProfile: ShareProfilePublic,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.PublicSurfaceAssessment == nil {
		t.Fatal("expected public-surface assessment in summary")
	}
	if summary.PublicSurfaceAssessment.TotalSources != 2 {
		t.Fatalf("expected two public sources, got %+v", summary.PublicSurfaceAssessment)
	}
	if summary.PublicSurfaceAssessment.LabelCounts.PublicObserved != 1 {
		t.Fatalf("expected one public observed source, got %+v", summary.PublicSurfaceAssessment.LabelCounts)
	}
	if summary.PublicSurfaceAssessment.LabelCounts.PublicInferred != 1 {
		t.Fatalf("expected one public inferred source, got %+v", summary.PublicSurfaceAssessment.LabelCounts)
	}
}

package report

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestFinalizeSummaryForSerializationAddsArtifactBudgetMetadata(t *testing.T) {
	t.Parallel()

	finalized := FinalizeSummaryForSerialization(Summary{
		ShareProfile: string(ShareProfileInternal),
		Sections:     []Section{{ID: "headline"}},
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{{PathID: "apc-1234"}},
		},
	})

	if finalized.ArtifactBudget == nil {
		t.Fatalf("expected artifact budget metadata, got %+v", finalized)
	}
	if finalized.ArtifactBudget.MaxActionPaths != defaultMaxActionPaths {
		t.Fatalf("expected max action paths %d, got %+v", defaultMaxActionPaths, finalized.ArtifactBudget)
	}
	if !finalized.AppendixAvailable {
		t.Fatalf("expected appendix availability, got %+v", finalized)
	}
	if !finalized.FocusedBundleAvailable {
		t.Fatalf("expected focused bundle availability, got %+v", finalized)
	}
	if finalized.FullExportAvailable {
		t.Fatalf("expected full export availability to remain false, got %+v", finalized)
	}
}

func TestBuildEvidenceBundleCarriesOutputMetadataAndSuppressionCounts(t *testing.T) {
	t.Parallel()

	bundle := BuildEvidenceBundle(Summary{
		ShareProfile:      string(ShareProfileCustomerRedacted),
		Sections:          []Section{{ID: "headline"}},
		SuppressedCounts:  &SuppressedCounts{ActionPaths: 3},
		AgentActionBOM:    &AgentActionBOM{Items: []AgentActionBOMItem{{PathID: "apc-1234"}}},
		AppendixAvailable: true,
	})

	if bundle.ArtifactBudget == nil {
		t.Fatalf("expected artifact budget metadata, got %+v", bundle)
	}
	if bundle.SuppressedCounts == nil || bundle.SuppressedCounts.ActionPaths != 3 {
		t.Fatalf("expected suppressed counts to carry through, got %+v", bundle.SuppressedCounts)
	}
	if !bundle.AppendixAvailable {
		t.Fatalf("expected appendix availability on evidence bundle, got %+v", bundle)
	}
	if !bundle.FocusedBundleAvailable {
		t.Fatalf("expected focused bundle availability on evidence bundle, got %+v", bundle)
	}
}

func TestValidateShareableArtifactsFailsClosedOnResidualSensitiveTokens(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		Findings: []source.Finding{{
			Repo:     "enterprise-001",
			Org:      "acme",
			Location: "/Users/example/private/repo/.github/workflows/release.yml",
		}},
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				OperationalOwner: "release-bot",
			}},
		},
	}

	err := ValidateShareableArtifacts(snapshot, Summary{
		ShareProfile: string(ShareProfileCustomerRedacted),
		Sections: []Section{{
			ID:    "headline",
			Facts: []string{"release-bot still appears here"},
		}},
	}, "release-bot", true)
	if err == nil {
		t.Fatal("expected residual redaction validation failure")
	}
	if !IsShareableSafetyError(err) {
		t.Fatalf("expected shareable safety error, got %T (%v)", err, err)
	}
}

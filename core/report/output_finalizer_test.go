package report

import (
	"fmt"
	"reflect"
	"strings"
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

func TestBuildEvidenceBundleCarriesCompactCompositionRefs(t *testing.T) {
	t.Parallel()

	bundle := BuildEvidenceBundle(Summary{
		ShareProfile: string(ShareProfileDesignPartner),
		ComposedActionPaths: []risk.ComposedActionPath{{
			CompositionID:              "cap-release-prod",
			ResolutionKey:              "rk-release-prod",
			PathIDs:                    []string{"apc-build", "apc-deploy"},
			WorkflowChainRefs:          []string{"workflow_chain:wfc-release"},
			ProposedActionContractRefs: []string{"pac-release-prod"},
		}},
	})

	if len(bundle.CompositionRefs) != 1 {
		t.Fatalf("expected one compact composition ref, got %+v", bundle.CompositionRefs)
	}
	ref := bundle.CompositionRefs[0]
	if ref.CompositionID != "cap-release-prod" || ref.ResolutionKey != "rk-release-prod" {
		t.Fatalf("expected stable composition identity refs, got %+v", ref)
	}
	if !reflect.DeepEqual(ref.PathIDs, []string{"apc-build", "apc-deploy"}) {
		t.Fatalf("expected path refs to survive without proof duplication, got %+v", ref)
	}
	if !reflect.DeepEqual(ref.ProposedActionContractRefs, []string{"pac-release-prod"}) {
		t.Fatalf("expected proposed contract refs, got %+v", ref)
	}
}

func TestBuildEvidenceBundleCarriesActionContractArtifactRefs(t *testing.T) {
	t.Parallel()
	contract := &risk.ProposedActionContract{
		ContractID: "pac-evidence", ContractFamilyID: "pacf-evidence", ContractContentDigest: "sha256:evidence", Revision: 2, SupersedesRef: "pac-prior",
		LifecycleObservations: risk.NormalizeProposedActionLifecycleObservations([]risk.ProposedActionLifecycleObservation{{
			Kind: risk.LifecycleObservationActivationReceipt, Producer: "gait", EvidenceState: risk.EvidenceStateVerified, FreshnessState: "fresh",
			EvidenceRefs:               []string{"runtime-record-1", "pac-evidence", "pacf-evidence", "paca-legacy-receipt"},
			ActionContractArtifactRefs: []string{"paca-gait-receipt"},
		}}),
	}
	bundle := BuildEvidenceBundle(Summary{ComposedActionPaths: []risk.ComposedActionPath{{CompositionID: "cap-evidence", ProposedActionContract: contract}}})
	if len(bundle.CompositionRefs) != 1 {
		t.Fatalf("expected one contract correlation, got %+v", bundle.CompositionRefs)
	}
	ref := bundle.CompositionRefs[0]
	if ref.ProposedActionContractID != contract.ContractID || ref.ContractFamilyID != contract.ContractFamilyID || ref.ContractRevision != 2 || ref.SupersedesRef != "pac-prior" {
		t.Fatalf("expected explicit immutable contract refs, got %+v", ref)
	}
	if !reflect.DeepEqual(ref.ActionContractArtifactRefs, []string{"paca-gait-receipt"}) || len(ref.LifecycleObservationRefs) != 1 {
		t.Fatalf("expected lifecycle artifact refs to stay separate from generic evidence refs, got %+v", ref)
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

func TestApplyShareableResidualRedactionDoesNotRewriteNumericTimestamps(t *testing.T) {
	t.Parallel()

	summary, err := ApplyShareableResidualRedaction(
		state.Snapshot{
			Findings: []source.Finding{{
				Repo: "2026",
				Org:  "acme",
			}},
		},
		Summary{
			ShareProfile: string(ShareProfileCustomerRedacted),
			GeneratedAt:  "2026-06-15T00:00:00Z",
			Sections:     []Section{{ID: "headline", Facts: []string{"ok"}}},
		},
	)
	if err != nil {
		t.Fatalf("apply residual redaction: %v", err)
	}
	if summary.GeneratedAt != "2026-06-15T00:00:00Z" {
		t.Fatalf("expected generated_at to remain unchanged, got %q", summary.GeneratedAt)
	}
}

func TestApplyShareableResidualRedactionPreservesUncappedWorkflowHighlightSource(t *testing.T) {
	t.Parallel()

	base := AgentActionBOMItem{
		Repo:                     "acme/private",
		Location:                 ".github/workflows/release.yml",
		ActionPathEligible:       true,
		ActionBindingState:       risk.ActionBindingStateBound,
		ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		TargetClass:              risk.TargetClassProductionImpacting,
		DelegationReadinessState: risk.DelegationReadinessReviewRequired,
	}
	items := make([]AgentActionBOMItem, 0, workflowHighlightLimit+1)
	for idx := 0; idx < workflowHighlightLimit; idx++ {
		item := base
		item.PathID = fmt.Sprintf("apc-duplicate-%d", idx+1)
		items = append(items, item)
	}
	distinct := base
	distinct.PathID = "apc-distinct"
	distinct.Location = ".github/workflows/deploy-prod.yml"
	items = append(items, distinct)

	highlights := BuildWorkflowHighlights(Summary{AgentActionBOM: &AgentActionBOM{Items: items}})
	if highlights == nil || len(highlights.Highlights) != workflowHighlightLimit {
		t.Fatalf("expected public highlights to be capped at %d, got %+v", workflowHighlightLimit, highlights)
	}
	summary := Summary{
		Template:           string(TemplateAgentActionBOM),
		ShareProfile:       string(ShareProfileCustomerRedacted),
		WorkflowHighlights: highlights,
		AgentActionBOM: &AgentActionBOM{
			Summary:          AgentActionBOMSummary{PrimaryView: &AgentActionBOMPrimaryView{PathID: "apc-duplicate-1"}},
			Items:            append([]AgentActionBOMItem(nil), items[:workflowHighlightLimit]...),
			focusSourceItems: items,
		},
	}

	redacted, err := ApplyShareableResidualRedaction(
		state.Snapshot{Findings: []source.Finding{{Repo: "acme/private"}}},
		summary,
	)
	if err != nil {
		t.Fatalf("apply residual redaction: %v", err)
	}
	if redacted.WorkflowHighlights == nil || len(redacted.WorkflowHighlights.sourceHighlights) != len(items) {
		t.Fatalf("expected uncapped workflow highlight source to survive residual redaction, got %+v", redacted.WorkflowHighlights)
	}
	if redacted.AgentActionBOM == nil || !focusedEvidenceContainsPathID(itemPathIDs(redacted.AgentActionBOM.focusSourceItems), "apc-distinct") {
		t.Fatalf("expected uncapped BOM source items to survive residual redaction, got %+v", redacted.AgentActionBOM)
	}
	for _, highlight := range redacted.WorkflowHighlights.sourceHighlights {
		if strings.Contains(highlight.Repo, "acme/private") {
			t.Fatalf("expected preserved source highlight repo to remain redacted, got %+v", highlight)
		}
	}
	markdown := RenderMarkdown(redacted)
	if !strings.Contains(markdown, "deploy-prod.yml") {
		t.Fatalf("expected compact top-action row from uncapped source after residual redaction, got:\n%s", markdown)
	}
}

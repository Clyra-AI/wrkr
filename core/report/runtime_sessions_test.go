package report

import (
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestRuntimeSessionSidecarFeedsRuntimeEvidencePacketsAndBOM(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	snapshot := state.Snapshot{
		Target: source.Target{Mode: "path"},
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:               "apc-runtime-1",
				AgentID:              "wrkr:codex-release:acme",
				Org:                  "acme",
				Repo:                 "acme/payments",
				ToolType:             "compiled_action",
				Location:             ".github/workflows/release.yml",
				ActionClasses:        []string{"deploy", "write"},
				WriteCapable:         true,
				CredentialAccess:     true,
				RecommendedAction:    "control",
				PolicyCoverageStatus: risk.PolicyCoverageStatusNone,
				IntroducedBy: &attribution.Result{
					Reference:   "pr/42",
					ChangedFile: "cmd/release.go",
				},
			}},
		},
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if err := ingest.SaveSessionBundle(ingest.DefaultSessionPath(statePath), ingest.SessionBundle{
		GeneratedAt: "2026-05-27T14:00:00Z",
		Sessions: []ingest.SessionRecord{{
			Provider:        ingest.SessionProviderCodex,
			SessionID:       "sess-1",
			AgentID:         "wrkr:codex-release:acme",
			Repo:            "acme/payments",
			Workflow:        ".github/workflows/release.yml",
			PullRequestRef:  "pr/42",
			ChangedFiles:    []string{"cmd/release.go"},
			Actions:         []string{"deploy", "write"},
			Approvals:       []string{"security"},
			PolicyDecisions: []string{"allow"},
			ProofRefs:       []string{"proof-1"},
			CompletedAt:     "2026-05-27T14:00:00Z",
		}},
	}); err != nil {
		t.Fatalf("save runtime sessions: %v", err)
	}

	runtimeSessions := buildSessionSummary(statePath, snapshot)
	if runtimeSessions == nil || runtimeSessions.MatchedSessions != 1 {
		t.Fatalf("expected matched runtime session summary, got %+v", runtimeSessions)
	}
	runtimeEvidence := buildRuntimeEvidenceSummary(statePath, snapshot)
	if runtimeEvidence == nil || runtimeEvidence.MatchedRecords == 0 {
		t.Fatalf("expected projected runtime evidence summary, got %+v", runtimeEvidence)
	}
	evidencePackets := buildEvidencePacketSummary(statePath, snapshot)
	if evidencePackets == nil || evidencePackets.MatchedPackets != 1 {
		t.Fatalf("expected projected evidence packets summary, got %+v", evidencePackets)
	}
	decoratedPaths := decorateBoundaryLabelsForReport(
		append([]risk.ActionPath(nil), snapshot.RiskReport.ActionPaths...),
		runtimeEvidenceByPath(runtimeEvidence),
		runtimeSessionsByPath(runtimeSessions),
		evidencePacketsByPath(evidencePackets),
	)
	if decoratedPaths[0].BoundaryLabel != BoundaryLabelApprovalCapable {
		t.Fatalf("expected approval_capable boundary label, got %+v", decoratedPaths[0])
	}
	graph := decorateControlPathGraphBoundary(risk.BuildControlPathGraph(decoratedPaths), decoratedPaths)
	if graph == nil || len(graph.Nodes) == 0 || graph.Nodes[0].BoundaryLabel != BoundaryLabelApprovalCapable {
		t.Fatalf("expected graph boundary label projection, got %+v", graph)
	}

	summary := Summary{
		GeneratedAt:      "2026-05-27T14:00:00Z",
		RuntimeSessions:  decorateSessionSummaryBoundary(runtimeSessions, decoratedPaths),
		RuntimeEvidence:  decorateRuntimeEvidenceSummaryBoundary(runtimeEvidence, decoratedPaths),
		EvidencePackets:  decorateEvidencePacketSummaryBoundary(evidencePackets, decoratedPaths),
		ActionPaths:      decoratedPaths,
		ControlPathGraph: graph,
	}
	bom := BuildAgentActionBOM(summary)
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	if bom.Items[0].RuntimeSessionStatus != ingest.CorrelationStatusMatched {
		t.Fatalf("expected matched runtime session status on BOM item, got %+v", bom.Items[0])
	}
	if len(bom.Items[0].ObservedSessionActions) == 0 || len(bom.Items[0].ObservedChangedFiles) == 0 {
		t.Fatalf("expected observed session actions and changed files on BOM item, got %+v", bom.Items[0])
	}
	if bom.Items[0].EvidencePacketStatus != ingest.CorrelationStatusMatched {
		t.Fatalf("expected matched evidence packet status on BOM item, got %+v", bom.Items[0])
	}
	if bom.Items[0].BoundaryLabel != BoundaryLabelApprovalCapable {
		t.Fatalf("expected approval_capable BOM boundary label, got %+v", bom.Items[0])
	}
}

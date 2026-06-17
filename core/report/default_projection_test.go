package report

import (
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildAgentActionBOMStripsEmbeddedCanonicalPayloadsByDefault(t *testing.T) {
	t.Parallel()

	semantics := []agginventory.MutableEndpointSemantic{{
		Semantic:     agginventory.EndpointSemanticDeploy,
		Confidence:   "high",
		Surface:      "workflow",
		Operation:    "deploy release",
		EvidenceRefs: []string{"deploy release"},
	}}
	authority := &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		AccessType:             agginventory.CredentialAccessTypeStanding,
		StandingAccess:         true,
	}
	binding := &agginventory.AuthorityBinding{
		Kind:         agginventory.AuthorityBindingSaaSToken,
		Provider:     "github",
		TargetSystem: "source_control",
		LikelyScope:  "repo_write",
		AccessLevel:  agginventory.AuthorityAccessWrite,
		Confidence:   "high",
	}

	bom := BuildAgentActionBOM(Summary{
		GeneratedAt: "2026-06-16T16:00:00Z",
		ActionPaths: []risk.ActionPath{{
			PathID:                      "apc-bom-default-canonical",
			Org:                         "acme",
			Repo:                        "acme/release",
			ToolType:                    "compiled_action",
			Location:                    ".github/workflows/release.yml",
			WriteCapable:                true,
			CredentialAccess:            true,
			ApprovalGap:                 true,
			ConfidenceLane:              risk.ConfidenceLaneConfirmedActionPath,
			ActionPathType:              risk.ActionPathTypeCICDWorkflow,
			TargetClass:                 risk.TargetClassReleaseAdjacent,
			ControlState:                risk.ControlStateApprovalNeeded,
			RiskZone:                    risk.RiskZoneRelease,
			ReviewBurden:                risk.ReviewBurdenHigh,
			MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
			MutableEndpointSemantics:    semantics,
			CredentialAuthorityRef:      agginventory.CanonicalCredentialAuthorityRef(authority),
			CredentialAuthority:         authority,
			AuthorityBindingRefs:        agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
			AuthorityBindings:           []*agginventory.AuthorityBinding{binding},
		}},
	})
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	item := bom.Items[0]
	if item.CredentialAuthorityRef == "" || len(item.AuthorityBindingRefs) == 0 || len(item.MutableEndpointSemanticRefs) == 0 {
		t.Fatalf("expected canonical refs on BOM item, got %+v", item)
	}
	if item.CredentialAuthority != nil || len(item.AuthorityBindings) > 0 || len(item.MutableEndpointSemantics) > 0 {
		t.Fatalf("expected BOM item to omit embedded canonical payload clones by default, got %+v", item)
	}
}

func TestBuildSummaryStripsDefaultCanonicalPayloadClonesBeforeFinalization(t *testing.T) {
	t.Parallel()

	semantics := []agginventory.MutableEndpointSemantic{{
		Semantic:     agginventory.EndpointSemanticDeploy,
		Confidence:   "high",
		Surface:      "workflow",
		Operation:    "deploy release",
		EvidenceRefs: []string{"deploy release"},
	}}
	authority := &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		AccessType:             agginventory.CredentialAccessTypeStanding,
		StandingAccess:         true,
	}
	binding := &agginventory.AuthorityBinding{
		Kind:         agginventory.AuthorityBindingSaaSToken,
		Provider:     "github",
		TargetSystem: "source_control",
		LikelyScope:  "repo_write",
		AccessLevel:  agginventory.AuthorityAccessWrite,
		Confidence:   "high",
	}

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                      "apc-summary-default-canonical",
					Org:                         "acme",
					Repo:                        "acme/release",
					ToolType:                    "compiled_action",
					Location:                    ".github/workflows/release.yml",
					WriteCapable:                true,
					CredentialAccess:            true,
					ApprovalGap:                 true,
					RecommendedAction:           "control",
					ConfidenceLane:              risk.ConfidenceLaneConfirmedActionPath,
					ActionPathType:              risk.ActionPathTypeCICDWorkflow,
					TargetClass:                 risk.TargetClassReleaseAdjacent,
					ControlState:                risk.ControlStateApprovalNeeded,
					RiskZone:                    risk.RiskZoneRelease,
					ReviewBurden:                risk.ReviewBurdenHigh,
					MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
					MutableEndpointSemantics:    semantics,
					CredentialAuthorityRef:      agginventory.CanonicalCredentialAuthorityRef(authority),
					CredentialAuthority:         authority,
					AuthorityBindingRefs:        agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
					AuthorityBindings:           []*agginventory.AuthorityBinding{binding},
				}},
			},
		},
		Template:     TemplateAgentActionBOM,
		ShareProfile: ShareProfileInternal,
		GeneratedAt:  time.Date(2026, 6, 16, 16, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if len(summary.ActionPaths) != 1 {
		t.Fatalf("expected one action path, got %+v", summary.ActionPaths)
	}
	if summary.ActionPaths[0].CredentialAuthorityRef == "" || len(summary.ActionPaths[0].AuthorityBindingRefs) == 0 || len(summary.ActionPaths[0].MutableEndpointSemanticRefs) == 0 {
		t.Fatalf("expected canonical refs on summary action path, got %+v", summary.ActionPaths[0])
	}
	if summary.ActionPaths[0].CredentialAuthority != nil || len(summary.ActionPaths[0].AuthorityBindings) > 0 || len(summary.ActionPaths[0].MutableEndpointSemantics) > 0 {
		t.Fatalf("expected summary action path to omit embedded canonical payload clones by default, got %+v", summary.ActionPaths[0])
	}
	if summary.AgentActionBOM == nil || len(summary.AgentActionBOM.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", summary.AgentActionBOM)
	}
	if summary.AgentActionBOM.Items[0].CredentialAuthority != nil || len(summary.AgentActionBOM.Items[0].AuthorityBindings) > 0 || len(summary.AgentActionBOM.Items[0].MutableEndpointSemantics) > 0 {
		t.Fatalf("expected summary BOM item to omit embedded canonical payload clones by default, got %+v", summary.AgentActionBOM.Items[0])
	}
	if summary.ControlBacklog == nil || len(summary.ControlBacklog.Items) != 1 {
		t.Fatalf("expected one backlog item, got %+v", summary.ControlBacklog)
	}
	if summary.ControlBacklog.Items[0].CredentialAuthority != nil || len(summary.ControlBacklog.Items[0].AuthorityBindings) > 0 {
		t.Fatalf("expected summary backlog item to omit embedded canonical payload clones by default, got %+v", summary.ControlBacklog.Items[0])
	}
	if summary.ControlPathGraph == nil || len(summary.ControlPathGraph.Nodes) == 0 {
		t.Fatalf("expected control path graph, got %+v", summary.ControlPathGraph)
	}
	for _, node := range summary.ControlPathGraph.Nodes {
		if node.CredentialAuthority != nil || len(node.AuthorityBindings) > 0 || len(node.MutableEndpointSemantics) > 0 {
			t.Fatalf("expected summary graph node to omit embedded canonical payload clones by default, got %+v", node)
		}
	}
}

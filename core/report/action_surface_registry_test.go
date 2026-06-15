package report

import (
	"fmt"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestActionSurfaceRegistryGroupsWorkflowPaths(t *testing.T) {
	t.Parallel()

	paths := []risk.ActionPath{
		{
			PathID:         "ap-1",
			ToolInstanceID: "workflow-release",
			Org:            "local",
			Repo:           "demo",
			ToolType:       "ci_agent",
			Location:       ".github/workflows/release.yml",
			Purpose:        "Release pipeline",
			ActionClasses:  []string{"deploy", "write"},
			ConfidenceLane: risk.ConfidenceLaneLikelyActionPath,
			CredentialAuthority: &agginventory.CredentialAuthority{
				CredentialPresent:              true,
				CredentialReferencedByWorkflow: true,
				CredentialUsableByPath:         true,
				StandingAccess:                 true,
				LikelyJIT:                      false,
			},
			MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{{
				Semantic:   agginventory.EndpointSemanticDeploy,
				Confidence: "high",
				Surface:    "route",
				Operation:  "POST /deploy",
			}},
		},
		{
			PathID:         "ap-2",
			ToolInstanceID: "workflow-release",
			Org:            "local",
			Repo:           "demo",
			ToolType:       "ci_agent",
			Location:       ".github/workflows/release.yml",
			Purpose:        "Release pipeline",
			ActionClasses:  []string{"write"},
			ConfidenceLane: risk.ConfidenceLaneLikelyActionPath,
			MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{{
				Semantic:   agginventory.EndpointSemanticPayment,
				Confidence: "high",
				Surface:    "openapi",
				Operation:  "POST /v1/payments",
			}},
		},
	}
	graph := risk.BuildControlPathGraph(paths)
	summary := Summary{
		ActionPaths:      paths,
		ControlPathGraph: graph,
	}
	summary.AgentActionBOM = BuildAgentActionBOM(summary)

	registry := BuildActionSurfaceRegistry(summary)
	if len(registry) != 1 {
		t.Fatalf("expected one grouped registry surface, got %+v", registry)
	}
	if registry[0].ActionPathCount != 2 {
		t.Fatalf("expected grouped registry action count=2, got %+v", registry[0])
	}
	if len(registry[0].PathIDs) != 2 {
		t.Fatalf("expected grouped registry to retain both path ids, got %+v", registry[0])
	}
	if registry[0].SurfaceType != "workflow" {
		t.Fatalf("expected workflow surface type, got %+v", registry[0])
	}
	if len(registry[0].MutableEndpointSemantics) != 2 {
		t.Fatalf("expected mutable endpoint semantics to aggregate across grouped paths, got %+v", registry[0])
	}
}

func TestActionSurfaceRegistrySortsFamilyOnlyGroupsWithoutPanicking(t *testing.T) {
	t.Parallel()

	paths := []risk.ActionPath{
		{
			PathID:         "ap-family",
			ToolFamilyID:   "wrkr:family-langchain:acme",
			Org:            "acme",
			Repo:           "demo",
			ToolType:       "agentlangchain",
			Location:       "agents/langchain.yaml",
			Purpose:        "LangChain agent",
			ActionClasses:  []string{"write"},
			ConfidenceLane: risk.ConfidenceLaneLikelyActionPath,
		},
		{
			PathID:         "ap-workflow",
			ToolInstanceID: "workflow-release",
			Org:            "acme",
			Repo:           "demo",
			ToolType:       "ci_agent",
			Location:       ".github/workflows/release.yml",
			Purpose:        "Release pipeline",
			ActionClasses:  []string{"deploy"},
			ConfidenceLane: risk.ConfidenceLaneLikelyActionPath,
		},
	}
	summary := Summary{
		ActionPaths:      paths,
		ControlPathGraph: risk.BuildControlPathGraph(paths),
	}
	summary.AgentActionBOM = BuildAgentActionBOM(summary)

	registry := BuildActionSurfaceRegistry(summary)
	if len(registry) != 2 {
		t.Fatalf("expected two registry entries, got %+v", registry)
	}
	if registry[0].Location != "agents/langchain.yaml" {
		t.Fatalf("expected family-only path to sort without panic and retain rank order, got %+v", registry)
	}
}

func TestActionSurfaceRegistryUsesBoundedEndpointProjection(t *testing.T) {
	t.Parallel()

	semantics := make([]agginventory.MutableEndpointSemantic, 0, 40)
	for idx := 0; idx < 40; idx++ {
		semantics = append(semantics, agginventory.MutableEndpointSemantic{
			Semantic:     agginventory.EndpointSemanticRefund,
			Confidence:   "high",
			Surface:      "openapi",
			Operation:    fmt.Sprintf("POST /v1/refunds/%03d/issue", idx),
			EvidenceRefs: []string{fmt.Sprintf("finding:%03d", idx)},
		})
	}
	path := risk.ProjectActionPath(risk.ActionPath{
		PathID:                      "ap-dense-registry",
		ToolInstanceID:              "workflow-release",
		Org:                         "acme",
		Repo:                        "demo",
		ToolType:                    "ci_agent",
		Location:                    ".github/workflows/release.yml",
		MutableEndpointSemantics:    semantics,
		MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
	})
	summary := Summary{
		ActionPaths:      []risk.ActionPath{path},
		ControlPathGraph: risk.BuildControlPathGraph([]risk.ActionPath{path}),
	}
	summary.AgentActionBOM = BuildAgentActionBOM(summary)

	registry := BuildActionSurfaceRegistry(summary)
	if len(registry) != 1 {
		t.Fatalf("expected one registry entry, got %+v", registry)
	}
	entry := registry[0]
	if entry.EndpointRefGroupID == "" || entry.EndpointRefCount != len(semantics) {
		t.Fatalf("expected grouped endpoint projection on registry entry, got %+v", entry)
	}
	if len(entry.MutableEndpointSemanticRefs) > 8 || len(entry.MutableEndpointSemantics) > 12 {
		t.Fatalf("expected bounded endpoint samples on registry entry, got %+v", entry)
	}
}

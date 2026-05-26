package report

import (
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestRenderMarkdownIncludesWave1AutonomyAndGovernedPathFields(t *testing.T) {
	t.Parallel()

	path := risk.ProjectActionPath(risk.ActionPath{
		PathID:                "apc-wave1-markdown",
		Org:                   "acme",
		Repo:                  "acme/payments",
		ToolType:              "ci_agent",
		Location:              ".github/workflows/deploy.yml",
		WriteCapable:          true,
		CredentialAccess:      true,
		ProductionWrite:       true,
		DeployWrite:           true,
		ApprovalEvidenceState: risk.EvidenceStateVerified,
		ProofEvidenceState:    risk.EvidenceStateVerified,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			StandingAccess:         true,
			AccessType:             agginventory.CredentialAccessTypeStanding,
		},
	})

	summary := Summary{
		GeneratedAt:  "2026-05-26T19:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: "internal",
		AgentActionBOM: BuildAgentActionBOM(Summary{
			GeneratedAt: "2026-05-26T19:00:00Z",
			ActionPaths: []risk.ActionPath{path},
		}),
	}

	markdown := RenderMarkdown(summary)
	for _, want := range []string{
		"Autonomy tiers:",
		"Delegation readiness:",
		"autonomy=prod or customer impacting",
		"readiness=blocked",
		"recommended_control=block standing credential",
		"governed_view=",
		"contract=",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("expected markdown to contain %q, got:\n%s", want, markdown)
		}
	}
}

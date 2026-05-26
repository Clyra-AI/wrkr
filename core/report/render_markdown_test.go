package report

import (
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

func TestContradictionMarkdownIsEvidenceScoped(t *testing.T) {
	t.Parallel()

	markdown := RenderMarkdown(Summary{
		GeneratedAt:  "2026-05-25T18:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID: "bom-1",
			Summary: AgentActionBOMSummary{
				TotalItems:         1,
				ControlFirstItems:  1,
				CoverageConfidence: "high",
			},
			Items: []AgentActionBOMItem{{
				Repo:                   "acme/release",
				Location:               ".github/workflows/release.yml",
				ConfidenceLane:         "confirmed_action_path",
				ActionPathType:         "ci_cd_workflow",
				ControlState:           "block_recommended",
				RiskZone:               "release",
				TargetClass:            "production_impacting",
				ReviewBurden:           "critical",
				ControlPriority:        "control_first",
				RiskTier:               "critical",
				ControlResolutionState: "contradictory_control",
				ApprovalEvidenceState:  "unknown",
				OwnerEvidenceState:     "unknown",
				ProofEvidenceState:     "unknown",
				RuntimeEvidenceState:   "unknown",
				Confidence:             "high",
				EvidenceStrength:       "high",
				Queue:                  "control_first",
				Remediation:            "Resolve contradictory evidence.",
				Contradictions: []evidencepolicy.Contradiction{{
					Class:       "non_prod_vs_credential",
					ReasonCodes: []string{"contradiction:non_prod_declared_with_production_credential"},
					EvidenceRefs: []string{
						"evidence://customer/declarations.yaml#non-prod",
						"credential:static_secret",
					},
				}},
			}},
		},
	})
	if !strings.Contains(markdown, "contradictions=") {
		t.Fatalf("expected contradiction summary in markdown, got %q", markdown)
	}
	if strings.Contains(markdown, "ghp_") {
		t.Fatalf("expected markdown to stay evidence-scoped, got %q", markdown)
	}
}

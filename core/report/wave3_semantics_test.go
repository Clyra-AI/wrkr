package report

import (
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildAgentActionBOMCountsTargetAndInstructionContext(t *testing.T) {
	t.Parallel()

	bom := BuildAgentActionBOM(Summary{
		GeneratedAt: "2026-06-15T12:00:00Z",
		ActionPaths: []risk.ActionPath{
			risk.ProjectActionPath(risk.ActionPath{
				PathID:             "apc-instruction",
				Org:                "acme",
				Repo:               "acme/app",
				ToolType:           "codex",
				Location:           ".codex/config.toml",
				ApprovalGap:        true,
				ApprovalGapReasons: []string{"approval_source_missing"},
				ActionClasses:      []string{"deploy"},
			}),
			risk.ProjectActionPath(risk.ActionPath{
				PathID:       "apc-target-context",
				Org:          "acme",
				Repo:         "acme/app",
				ToolType:     "openapi",
				Location:     "openapi/payments.yaml",
				WriteCapable: true,
			}),
		},
	})
	if bom == nil {
		t.Fatal("expected agent action bom")
	}
	if bom.Summary.EligibleActionPathItems != 1 || bom.Summary.TargetSurfaceContextItems != 1 || bom.Summary.InstructionControlItems != 0 {
		t.Fatalf("unexpected eligibility counts: %+v", bom.Summary)
	}
}

func TestRenderMarkdownIncludesTargetSurfaceContextSection(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-06-15T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: BuildAgentActionBOM(Summary{
			GeneratedAt: "2026-06-15T12:00:00Z",
			ActionPaths: []risk.ActionPath{
				risk.ProjectActionPath(risk.ActionPath{
					PathID:       "apc-target-context",
					Org:          "acme",
					Repo:         "acme/app",
					ToolType:     "openapi",
					Location:     "openapi/payments.yaml",
					WriteCapable: true,
				}),
				risk.ProjectActionPath(risk.ActionPath{
					PathID:             "apc-instruction",
					Org:                "acme",
					Repo:               "acme/app",
					ToolType:           "codex",
					Location:           ".codex/config.toml",
					ApprovalGap:        true,
					ApprovalGapReasons: []string{"approval_source_missing"},
					ActionClasses:      []string{"deploy"},
				}),
			},
		}),
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "## Target Surface Context") {
		t.Fatalf("expected target-surface markdown section, got %q", markdown)
	}
	if !strings.Contains(markdown, "target surface context") {
		t.Fatalf("expected target-surface wording, got %q", markdown)
	}
}

func TestRenderMarkdownIncludesContextSectionsWithoutPrimaryView(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-06-15T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: BuildAgentActionBOM(Summary{
			GeneratedAt: "2026-06-15T12:00:00Z",
			ActionPaths: []risk.ActionPath{
				risk.ProjectActionPath(risk.ActionPath{
					PathID:       "apc-target-context",
					Org:          "acme",
					Repo:         "acme/app",
					ToolType:     "openapi",
					Location:     "openapi/payments.yaml",
					WriteCapable: true,
				}),
			},
		}),
	}

	if summary.AgentActionBOM == nil || summary.AgentActionBOM.Summary.PrimaryView != nil {
		t.Fatalf("expected no primary view for target-context-only BOM, got %+v", summary.AgentActionBOM)
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "## Empty-State Assessment") {
		t.Fatalf("expected empty-state section, got %q", markdown)
	}
	if !strings.Contains(markdown, "## Target Surface Context") {
		t.Fatalf("expected target-surface context section in empty-state report, got %q", markdown)
	}
}

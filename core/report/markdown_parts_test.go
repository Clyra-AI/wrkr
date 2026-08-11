package report

import (
	"strings"
	"testing"
)

func TestRenderMarkdownPartsSeparatesBuyerLeadAndAppendix(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-08-11T00:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileCustomerRedacted),
		AgentActionBOM: &AgentActionBOM{
			Summary: AgentActionBOMSummary{EmptyStateStatus: "eligible", CoverageConfidence: "complete"},
		},
	}
	lead, appendix := RenderMarkdownParts(summary)
	if strings.Contains(lead, markdownAppendixBoundary) || !strings.Contains(lead, "companion appendix") {
		t.Fatalf("expected bounded buyer lead, got %q", lead)
	}
	if !strings.Contains(appendix, "# Wrkr Diagnostic Appendix") || !strings.Contains(appendix, markdownAppendixBoundary) {
		t.Fatalf("expected companion appendix, got %q", appendix)
	}
}

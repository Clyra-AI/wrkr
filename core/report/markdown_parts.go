package report

import "strings"

const markdownAppendixBoundary = "## Report Context Appendix"

// RenderMarkdownParts keeps the buyer brief usable while preserving the complete
// diagnostic report as a companion artifact.
func RenderMarkdownParts(summary Summary) (string, string) {
	full := RenderMarkdown(summary)
	if summary.Template != string(TemplateAgentActionBOM) && summary.Template != string(TemplateDesignPartnerSummary) {
		return full, ""
	}
	boundary := strings.Index(full, markdownAppendixBoundary)
	if boundary < 0 {
		lead := strings.TrimRight(full, "\n") + "\n\n- Detailed diagnostics are available in the companion appendix artifact.\n"
		return lead, "# Wrkr Diagnostic Appendix\n\n- No additional diagnostic appendix sections were produced for this assessment.\n"
	}
	lead := strings.TrimRight(full[:boundary], "\n") + "\n\n- Detailed diagnostics are available in the companion appendix artifact.\n"
	appendix := "# Wrkr Diagnostic Appendix\n\n" + strings.TrimLeft(full[boundary:], "\n")
	return lead, appendix
}

package report

import (
	"fmt"
	"strings"
)

func RenderMarkdown(summary Summary) string {
	var builder strings.Builder
	builder.WriteString("# Wrkr Deterministic Report\n\n")
	builder.WriteString(fmt.Sprintf("- Generated at: %s\n", summary.GeneratedAt))
	builder.WriteString(fmt.Sprintf("- Template: %s\n", summary.Template))
	builder.WriteString(fmt.Sprintf("- Share profile: %s\n\n", summary.ShareProfile))

	for _, section := range summary.Sections {
		builder.WriteString(fmt.Sprintf("## %s (%s)\n\n", section.Title, section.ID))
		for _, fact := range section.Facts {
			builder.WriteString(fmt.Sprintf("- %s\n", strings.TrimSpace(fact)))
		}
		builder.WriteString("\n")
		builder.WriteString(fmt.Sprintf("Impact: %s\n", strings.TrimSpace(section.Impact)))
		builder.WriteString(fmt.Sprintf("Action: %s\n", strings.TrimSpace(section.Action)))
		builder.WriteString(fmt.Sprintf("Proof: chain=%s head=%s records=%d\n\n", section.Proof.ChainPath, section.Proof.HeadHash, section.Proof.RecordCount))
	}

	if builder.Len() == 0 {
		return ""
	}
	if !strings.HasSuffix(builder.String(), "\n") {
		builder.WriteString("\n")
	}
	return builder.String()
}

func MarkdownLines(markdown string) []string {
	raw := strings.Split(markdown, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "### ")
		trimmed = strings.TrimPrefix(trimmed, "## ")
		trimmed = strings.TrimPrefix(trimmed, "# ")
		trimmed = strings.TrimPrefix(trimmed, "- ")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == "" {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

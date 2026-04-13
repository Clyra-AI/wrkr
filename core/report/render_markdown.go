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

	if summary.AssessmentSummary != nil {
		builder.WriteString("## Assessment Summary\n\n")
		builder.WriteString("- Scope: static posture from saved scan state only; no runtime observation or enforcement\n")
		builder.WriteString(fmt.Sprintf("- Governable paths: %d\n", summary.AssessmentSummary.GovernablePathCount))
		builder.WriteString(fmt.Sprintf("- Write-capable paths: %d\n", summary.AssessmentSummary.WriteCapablePathCount))
		builder.WriteString(fmt.Sprintf("- Production-target-backed paths: %d\n", summary.AssessmentSummary.ProductionBackedPathCount))
		if summary.AssessmentSummary.TopPathToControlFirst != nil {
			builder.WriteString(fmt.Sprintf("- Top path to control first: %s %s (%s%s)\n",
				summary.AssessmentSummary.TopPathToControlFirst.Repo,
				summary.AssessmentSummary.TopPathToControlFirst.Location,
				summary.AssessmentSummary.TopPathToControlFirst.RecommendedAction,
				renderTriggerClassSuffix(summary.AssessmentSummary.TopPathToControlFirst.WorkflowTriggerClass),
			))
		}
		if summary.AssessmentSummary.TopExecutionIdentityBacked != nil {
			builder.WriteString(fmt.Sprintf("- Top identity-backed path: %s %s%s\n",
				summary.AssessmentSummary.TopExecutionIdentityBacked.Repo,
				summary.AssessmentSummary.TopExecutionIdentityBacked.Location,
				renderTriggerClassSuffix(summary.AssessmentSummary.TopExecutionIdentityBacked.WorkflowTriggerClass),
			))
		}
		if summary.AssessmentSummary.OwnerlessExposure != nil {
			builder.WriteString(fmt.Sprintf("- Ownerless exposure: explicit=%d inferred=%d unresolved=%d conflict=%d\n",
				summary.AssessmentSummary.OwnerlessExposure.ExplicitOwnerPaths,
				summary.AssessmentSummary.OwnerlessExposure.InferredOwnerPaths,
				summary.AssessmentSummary.OwnerlessExposure.UnresolvedOwnerPaths,
				summary.AssessmentSummary.OwnerlessExposure.ConflictOwnerPaths,
			))
		}
		if summary.AssessmentSummary.IdentityExposureSummary != nil {
			builder.WriteString(fmt.Sprintf("- Identity exposure: total=%d write-backed=%d deploy-backed=%d unresolved-owner=%d unknown-correlation=%d\n",
				summary.AssessmentSummary.IdentityExposureSummary.TotalNonHumanIdentitiesObserved,
				summary.AssessmentSummary.IdentityExposureSummary.IdentitiesBackingWriteCapablePaths,
				summary.AssessmentSummary.IdentityExposureSummary.IdentitiesBackingDeployCapablePaths,
				summary.AssessmentSummary.IdentityExposureSummary.IdentitiesWithUnresolvedOwnership,
				summary.AssessmentSummary.IdentityExposureSummary.IdentitiesWithUnknownExecutionLinked,
			))
		}
		if summary.AssessmentSummary.IdentityToReviewFirst != nil {
			builder.WriteString(fmt.Sprintf("- Identity to review first: %s (%s)\n",
				summary.AssessmentSummary.IdentityToReviewFirst.ExecutionIdentity,
				summary.AssessmentSummary.IdentityToReviewFirst.ExecutionIdentityType,
			))
		}
		if summary.AssessmentSummary.IdentityToRevokeFirst != nil {
			builder.WriteString(fmt.Sprintf("- Identity to revoke first: %s (%s)\n",
				summary.AssessmentSummary.IdentityToRevokeFirst.ExecutionIdentity,
				summary.AssessmentSummary.IdentityToRevokeFirst.ExecutionIdentityType,
			))
		}
		if summary.AssessmentSummary.ProofChainPath != "" {
			builder.WriteString(fmt.Sprintf("- Proof chain: %s\n", summary.AssessmentSummary.ProofChainPath))
		}
		if len(summary.ExposureGroups) > 0 {
			builder.WriteString(fmt.Sprintf("- Exposure groups: %d\n", len(summary.ExposureGroups)))
		}
		builder.WriteString("\n")
	}

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

func renderTriggerClassSuffix(triggerClass string) string {
	if strings.TrimSpace(triggerClass) == "" {
		return ""
	}
	return ", trigger=" + strings.TrimSpace(triggerClass)
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

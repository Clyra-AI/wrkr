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

	if summary.AgentActionBOM != nil && summary.Template == string(TemplateAgentActionBOM) {
		builder.WriteString("## Agent Action BOM\n\n")
		builder.WriteString(fmt.Sprintf("- BOM id: %s\n", summary.AgentActionBOM.BOMID))
		if summary.ScanScope != nil {
			builder.WriteString(fmt.Sprintf("- Scanned scope: %s mode=%s repos=%d targets=%d boundary=%s\n",
				summary.ScanScope.ScopeLabel,
				summary.ScanScope.Mode,
				summary.ScanScope.RepoCount,
				summary.ScanScope.TargetCount,
				summary.ScanScope.SourceBoundary,
			))
		}
		if summary.SourcePrivacy != nil {
			builder.WriteString(fmt.Sprintf("- Source privacy: retention=%s retained=%t raw_source_in_artifacts=%t serialized_locations=%s cleanup_status=%s zero_data_exfiltration_default=true\n",
				summary.SourcePrivacy.RetentionMode,
				summary.SourcePrivacy.MaterializedSourceRetained,
				summary.SourcePrivacy.RawSourceInArtifacts,
				summary.SourcePrivacy.SerializedLocations,
				summary.SourcePrivacy.CleanupStatus,
			))
		}
		if summary.OperationalExposure != nil {
			builder.WriteString(fmt.Sprintf("- Operational exposure: grade=%s driver=%s paths=%d\n",
				summary.OperationalExposure.Grade,
				summary.OperationalExposure.Driver,
				summary.OperationalExposure.PathCount,
			))
		}
		if summary.GovernanceReadiness != nil {
			builder.WriteString(fmt.Sprintf("- Governance readiness: grade=%s driver=%s paths=%d\n",
				summary.GovernanceReadiness.Grade,
				summary.GovernanceReadiness.Driver,
				summary.GovernanceReadiness.PathCount,
			))
		}
		builder.WriteString(fmt.Sprintf("- Coverage confidence: %s\n", summary.AgentActionBOM.Summary.CoverageConfidence))
		builder.WriteString(fmt.Sprintf("- Governable paths: total=%d control_first=%d standing_credentials=%d missing_approval=%d missing_policy=%d missing_proof=%d\n",
			summary.AgentActionBOM.Summary.TotalItems,
			summary.AgentActionBOM.Summary.ControlFirstItems,
			summary.AgentActionBOM.Summary.StaticCredentialItems,
			summary.AgentActionBOM.Summary.MissingApprovalItems,
			summary.AgentActionBOM.Summary.MissingPolicyItems,
			summary.AgentActionBOM.Summary.MissingProofItems,
		))
		if summary.ShareProfileMetadata != nil && summary.ShareProfileMetadata.RedactionApplied {
			builder.WriteString(fmt.Sprintf("- Share redaction: version=%s policy=%s\n",
				summary.ShareProfileMetadata.RedactionVersion,
				strings.Join(summary.ShareProfileMetadata.PolicySummary, " | "),
			))
		}
		builder.WriteString("\n")

		if len(summary.AgentActionBOM.Items) == 0 || summary.AgentActionBOM.Summary.ControlFirstItems == 0 {
			builder.WriteString("## Positive Empty State\n\n")
			builder.WriteString(fmt.Sprintf("- No high-risk governable BOM items were emitted. Coverage confidence is %s, so treat this as a clean buyer-facing empty state only when the reported coverage matches your scan intent.\n\n", summary.AgentActionBOM.Summary.CoverageConfidence))
		} else {
			builder.WriteString("## Top Governable Paths\n\n")
			limit := len(summary.AgentActionBOM.Items)
			if limit > 8 {
				limit = 8
			}
			for idx := 0; idx < limit; idx++ {
				item := summary.AgentActionBOM.Items[idx]
				builder.WriteString(fmt.Sprintf("- %s %s state=%s zone=%s review=%s priority=%s tier=%s confidence=%s evidence=%s queue=%s remediation=%s\n",
					item.Repo,
					item.Location,
					item.ControlState,
					item.RiskZone,
					item.ReviewBurden,
					item.ControlPriority,
					item.RiskTier,
					item.Confidence,
					item.EvidenceStrength,
					item.Queue,
					item.Remediation,
				))
			}
			builder.WriteString("\n")
		}
	}

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

	if summary.ScanQuality != nil && len(summary.ScanQuality.Detectors) > 0 {
		builder.WriteString("## Scan Quality\n\n")
		builder.WriteString(fmt.Sprintf("- Mode: %s\n", summary.ScanQuality.Mode))
		for _, detector := range summary.ScanQuality.Detectors {
			builder.WriteString(fmt.Sprintf("- %s status=%s attempted=%d parsed=%d partial=%d suppressed=%d failures=%d reasons=%s\n",
				detector.Detector,
				detector.Status,
				detector.AttemptedFiles,
				detector.ParsedFiles,
				detector.PartialParses,
				detector.SuppressedFiles,
				detector.ParseFailures,
				strings.Join(detector.CoverageReasons, ","),
			))
		}
		builder.WriteString("\n")
	}

	if summary.AgentActionBOM != nil && summary.Template == string(TemplateAgentActionBOM) {
		builder.WriteString("## BOM Items\n\n")
		limit := len(summary.AgentActionBOM.Items)
		if limit > 10 {
			limit = 10
		}
		for idx := 0; idx < limit; idx++ {
			item := summary.AgentActionBOM.Items[idx]
			builder.WriteString(fmt.Sprintf("- %s %s owner=%s state=%s zone=%s review=%s queue=%s priority=%s tier=%s confidence=%s evidence=%s policy=%s proof=%s runtime=%s remediation=%s\n",
				item.Repo,
				item.Location,
				item.Owner,
				item.ControlState,
				item.RiskZone,
				item.ReviewBurden,
				item.Queue,
				item.ControlPriority,
				item.RiskTier,
				item.Confidence,
				item.EvidenceStrength,
				item.PolicyStatus,
				item.ProofCoverage,
				item.RuntimeEvidenceStatus,
				item.Remediation,
			))
			if item.GaitCoverage != nil {
				builder.WriteString(fmt.Sprintf("  gait=policy:%s approval:%s jit:%s freeze:%s kill:%s outcome:%s proof:%s\n",
					item.GaitCoverage.PolicyDecision.Status,
					item.GaitCoverage.Approval.Status,
					item.GaitCoverage.JITCredential.Status,
					item.GaitCoverage.FreezeWindow.Status,
					item.GaitCoverage.KillSwitch.Status,
					item.GaitCoverage.ActionOutcome.Status,
					item.GaitCoverage.ProofVerification.Status,
				))
			}
			if strings.TrimSpace(item.ExclusionReason) != "" {
				builder.WriteString(fmt.Sprintf("  exclusion=%s\n", item.ExclusionReason))
			}
		}
		builder.WriteString("\n")
	}

	if summary.ControlBacklog != nil && len(summary.ControlBacklog.Items) > 0 {
		builder.WriteString("## Control Backlog\n\n")
		limit := len(summary.ControlBacklog.Items)
		if limit > 10 {
			limit = 10
		}
		for idx := 0; idx < limit; idx++ {
			item := summary.ControlBacklog.Items[idx]
			builder.WriteString(fmt.Sprintf("- %s %s owner=%s queue=%s visibility=%s action=%s sla=%s closure=%s remediation=%s\n",
				item.Repo,
				item.Path,
				item.Owner,
				item.Queue,
				item.FindingVisibility,
				item.RecommendedAction,
				item.SLA,
				item.ClosureCriteria,
				item.Remediation,
			))
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

package report

import (
	"fmt"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func RenderMarkdown(summary Summary) string {
	if summary.Template == string(TemplateDesignPartnerSummary) {
		return renderDesignPartnerMarkdown(summary)
	}

	var builder strings.Builder
	builder.WriteString("# Wrkr Deterministic Report\n\n")
	builder.WriteString(fmt.Sprintf("- Generated at: %s\n", summary.GeneratedAt))
	builder.WriteString(fmt.Sprintf("- Template: %s\n", summary.Template))
	builder.WriteString(fmt.Sprintf("- Share profile: %s\n\n", summary.ShareProfile))

	if summary.AgentActionBOM != nil && summary.Template == string(TemplateAgentActionBOM) {
		builder.WriteString("## Agent Action BOM\n\n")
		builder.WriteString(fmt.Sprintf("- BOM id: %s\n", summary.AgentActionBOM.BOMID))
		if summary.AgentActionBOM.Summary.PrimaryView != nil {
			builder.WriteString("\n")
			renderPrimaryWorkflowBOMSection(&builder, summary.AgentActionBOM.Summary.PrimaryView)
		}
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
		if summary.EvidenceCompleteness != nil {
			builder.WriteString(fmt.Sprintf("- Evidence completeness: average=%d label=%s low_evidence_paths=%d reduced_coverage_paths=%d\n",
				summary.EvidenceCompleteness.AverageTotalScore,
				risk.BuyerEvidenceCompletenessSummaryLabel(summary.EvidenceCompleteness),
				summary.EvidenceCompleteness.LowEvidencePathCount,
				summary.EvidenceCompleteness.ReducedCoveragePathCount,
			))
		}
		builder.WriteString(fmt.Sprintf("- Coverage confidence: %s\n", summary.AgentActionBOM.Summary.CoverageConfidence))
		if summary.AgentActionBOM.Summary.ScanCoverage != nil {
			builder.WriteString(fmt.Sprintf("- Scan coverage: reduced_detectors=%d parse_failures=%d suppressed_generated_files=%d blocked_detectors=%d unsupported_declarations=%d impact=%s\n",
				summary.AgentActionBOM.Summary.ScanCoverage.ReducedDetectorCount,
				summary.AgentActionBOM.Summary.ScanCoverage.ParseFailureCount,
				summary.AgentActionBOM.Summary.ScanCoverage.SuppressedGeneratedFileCount,
				summary.AgentActionBOM.Summary.ScanCoverage.BlockedDetectorCount,
				summary.AgentActionBOM.Summary.ScanCoverage.UnsupportedDeclarationCount,
				firstNonEmptyValue(strings.TrimSpace(summary.AgentActionBOM.Summary.ScanCoverage.ImpactStatement), "Coverage metadata was unavailable."),
			))
		}
		builder.WriteString(fmt.Sprintf("- Governable paths: total=%d control_first=%d standing_credentials=%d approval_evidence_unknown=%d control_evidence_unknown=%d proof_evidence_unknown=%d\n",
			summary.AgentActionBOM.Summary.TotalItems,
			summary.AgentActionBOM.Summary.ControlFirstItems,
			summary.AgentActionBOM.Summary.StandingPrivilegeItems,
			summary.AgentActionBOM.Summary.ApprovalEvidenceUnknownItems,
			summary.AgentActionBOM.Summary.ControlEvidenceUnknownItems,
			summary.AgentActionBOM.Summary.ProofEvidenceUnknownItems,
		))
		builder.WriteString(fmt.Sprintf("- Autonomy tiers: safe_metadata=%d low_risk_internal=%d owner_review_app_code=%d sensitive_code_or_infra=%d prod_or_customer_impacting=%d\n",
			summary.AgentActionBOM.Summary.AutonomyTiers.Tier0SafeMetadata,
			summary.AgentActionBOM.Summary.AutonomyTiers.Tier1LowRiskInternal,
			summary.AgentActionBOM.Summary.AutonomyTiers.Tier2AppCodeOwnerReview,
			summary.AgentActionBOM.Summary.AutonomyTiers.Tier3SensitiveCodeOrInfra,
			summary.AgentActionBOM.Summary.AutonomyTiers.Tier4ProdPrivilegedCustomerImpact,
		))
		builder.WriteString(fmt.Sprintf("- Delegation readiness: safe_to_delegate=%d review_required=%d approval_required=%d proof_required=%d ready_for_control=%d blocked=%d blocked_by_contradiction=%d\n",
			summary.AgentActionBOM.Summary.DelegationReadiness.SafeToDelegate,
			summary.AgentActionBOM.Summary.DelegationReadiness.ReviewRequired,
			summary.AgentActionBOM.Summary.DelegationReadiness.ApprovalRequired,
			summary.AgentActionBOM.Summary.DelegationReadiness.ProofRequired,
			summary.AgentActionBOM.Summary.DelegationReadiness.ReadyForControl,
			summary.AgentActionBOM.Summary.DelegationReadiness.Blocked,
			summary.AgentActionBOM.Summary.DelegationReadiness.BlockedByContradict,
		))
		if summary.ShareProfileMetadata != nil && summary.ShareProfileMetadata.RedactionApplied {
			builder.WriteString(fmt.Sprintf("- Share redaction: version=%s policy=%s\n",
				summary.ShareProfileMetadata.RedactionVersion,
				strings.Join(summary.ShareProfileMetadata.PolicySummary, " | "),
			))
		}
		builder.WriteString("\n")
		if summary.RecentPRReview != nil {
			builder.WriteString("## Recent PR Review Appendix\n\n")
			builder.WriteString(fmt.Sprintf("- Mode: %s limit=%d total_candidates=%d\n",
				summary.RecentPRReview.Mode,
				summary.RecentPRReview.Limit,
				summary.RecentPRReview.TotalCandidates,
			))
			for _, item := range summary.RecentPRReview.Ranked {
				builder.WriteString(fmt.Sprintf("- rank=%d ref=%s repo=%s workflow=%s autonomy=%s readiness=%s control=%s target=%s contradictions=%t checks=%d approvals=%d deployments=%d focus_path=%s proof_refs=%s packet_refs=%s missing_evidence=%s\n",
					item.Rank,
					firstNonEmptyValue(item.Reference, item.ReviewID),
					item.Repo,
					item.Workflow,
					risk.BuyerAutonomyTierShortLabel(item.AutonomyTier),
					risk.BuyerDelegationReadinessLabel(item.DelegationReadinessState),
					risk.BuyerRecommendedControlLabel(item.RecommendedControl),
					item.TargetClass,
					item.Contradiction,
					item.CheckCount,
					item.ApprovalCount,
					item.DeploymentCount,
					item.FocusBOMPathID,
					strings.Join(item.ProofRefs, ", "),
					strings.Join(item.EvidencePacketRefs, ", "),
					strings.Join(item.MissingEvidence, ", "),
				))
			}
			builder.WriteString("\n")
		}

		emptyStateStatus := strings.TrimSpace(summary.AgentActionBOM.Summary.EmptyStateStatus)
		emptyStateReasons := summary.AgentActionBOM.Summary.EmptyStateReasons
		if summary.AgentActionBOM.Summary.PrimaryView == nil || len(summary.AgentActionBOM.Items) == 0 || (emptyStateStatus != "" && emptyStateStatus != "not_eligible") {
			builder.WriteString("## Empty-State Assessment\n\n")
			reasons := "none"
			if len(emptyStateReasons) > 0 {
				reasons = strings.Join(emptyStateReasons, ", ")
			}
			builder.WriteString(fmt.Sprintf("- status=%s coverage_confidence=%s reasons=%s\n\n",
				firstNonEmptyValue(emptyStateStatus, "eligible"),
				summary.AgentActionBOM.Summary.CoverageConfidence,
				reasons,
			))
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
		if compact := scanquality.BuildCompactCoverageSummary(summary.ScanQuality); compact.CoverageConfidence != "" {
			builder.WriteString(fmt.Sprintf("- Coverage summary: confidence=%s reduced_detectors=%d parse_failures=%d suppressed_generated_files=%d blocked_detectors=%d unsupported_declarations=%d impact=%s\n",
				compact.CoverageConfidence,
				compact.ReducedDetectorCount,
				compact.ParseFailureCount,
				compact.SuppressedGeneratedFileCount,
				compact.BlockedDetectorCount,
				compact.UnsupportedDeclarationCount,
				firstNonEmptyValue(strings.TrimSpace(compact.ImpactStatement), "Coverage metadata was unavailable."),
			))
		}
		for _, claim := range summary.ScanQuality.AbsenceClaims {
			if strings.TrimSpace(claim.Surface) == "" {
				continue
			}
			reasons := "none"
			if len(claim.Reasons) > 0 {
				reasons = strings.Join(claim.Reasons, ",")
			}
			builder.WriteString(fmt.Sprintf("- %s absence_status=%s reasons=%s impact=%s\n",
				claim.Surface,
				claim.Status,
				reasons,
				firstNonEmptyValue(strings.TrimSpace(claim.Impact), "none"),
			))
		}
		builder.WriteString("\n")
	}

	if summary.AgentActionBOM != nil && summary.Template == string(TemplateAgentActionBOM) {
		builder.WriteString("## Workflow BOM Appendix\n\n")
		limit := len(summary.AgentActionBOM.Items)
		if limit > 10 {
			limit = 10
		}
		for idx := 0; idx < limit; idx++ {
			item := summary.AgentActionBOM.Items[idx]
			builder.WriteString(fmt.Sprintf("- %s repo=%s location=%s owner=%s boundary=%s lane=%s type=%s state=%s zone=%s target=%s review=%s queue=%s priority=%s tier=%s autonomy=%s readiness=%s recommended_control=%s control=%s approval=%s proof=%s runtime=%s session=%s confidence=%s evidence=%s completeness=%s(%d) policy=%s remediation=%s\n",
				markdownActionPathLabel(item.ConfidenceLane, item.ActionPathType),
				item.Repo,
				item.Location,
				item.Owner,
				firstNonEmptyValue(item.BoundaryLabel, BoundaryLabelReportOnly),
				item.ConfidenceLane,
				item.ActionPathType,
				item.ControlState,
				item.RiskZone,
				item.TargetClass,
				item.ReviewBurden,
				item.Queue,
				item.ControlPriority,
				item.RiskTier,
				risk.BuyerAutonomyTierShortLabel(item.AutonomyTier),
				risk.BuyerDelegationReadinessLabel(item.DelegationReadinessState),
				risk.BuyerRecommendedControlLabel(item.RecommendedControl),
				risk.BuyerControlResolutionLabel(item.ControlResolutionState),
				risk.BuyerEvidenceStateLabel("approval", item.ApprovalEvidenceState),
				risk.BuyerEvidenceStateLabel("proof", item.ProofEvidenceState),
				markdownBOMRuntimeEvidenceLabel(item),
				firstNonEmptyValue(item.RuntimeSessionStatus, "not_collected"),
				item.Confidence,
				item.EvidenceStrength,
				risk.BuyerEvidenceCompletenessLabel(item.EvidenceCompleteness),
				markdownCompletenessScore(item.EvidenceCompleteness),
				item.PolicyStatus,
				item.Remediation,
			))
			if len(item.RiskClassificationValidationReasons) > 0 {
				builder.WriteString(fmt.Sprintf("  classification_validation=%s\n", strings.Join(item.RiskClassificationValidationReasons, ", ")))
			}
			if item.TodayPath != nil || item.RecommendedGovernedPath != nil {
				builder.WriteString(fmt.Sprintf("  governed_view=%s\n", markdownGovernedPathViews(item.TodayPath, item.RecommendedGovernedPath)))
			}
			if item.RecommendedActionContract != nil {
				builder.WriteString(fmt.Sprintf("  contract=%s\n", markdownActionContract(item.RecommendedActionContract)))
			}
			if len(item.ClosureRequirements) > 0 {
				builder.WriteString(fmt.Sprintf("  closure_requirements=%s\n", markdownClosureRequirements(item.ClosureRequirements)))
			}
			if len(item.Contradictions) > 0 {
				builder.WriteString(fmt.Sprintf("  contradictions=%s\n", markdownContradictions(item.Contradictions)))
			}
			if item.GovernanceDisposition != nil {
				builder.WriteString(fmt.Sprintf("  governance=%s status=%s scope=%s expires=%s reason=%s\n",
					item.GovernanceDisposition.Kind,
					item.GovernanceDisposition.Status,
					item.GovernanceDisposition.Scope,
					item.GovernanceDisposition.ExpiresAt,
					item.GovernanceDisposition.Reason,
				))
			}
			if item.LifecycleQueue != nil {
				builder.WriteString(fmt.Sprintf("  lifecycle_queue=%s severity=%s credential_status=%s closure=%s\n",
					item.LifecycleQueue.ReasonCode,
					item.LifecycleQueue.Severity,
					item.LifecycleQueue.CredentialStatus,
					item.LifecycleQueue.ClosureCriteria,
				))
			}
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
			if item.EvidenceCompleteness != nil {
				builder.WriteString(fmt.Sprintf("  completeness=%s(%d)\n",
					risk.BuyerEvidenceCompletenessLabel(item.EvidenceCompleteness),
					markdownCompletenessScore(item.EvidenceCompleteness),
				))
			}
			if len(item.ClosureRequirements) > 0 {
				builder.WriteString(fmt.Sprintf("  closure_requirements=%s\n", markdownClosureRequirements(item.ClosureRequirements)))
			}
			if item.GovernanceDisposition != nil {
				builder.WriteString(fmt.Sprintf("  governance=%s status=%s scope=%s expires=%s reason=%s\n",
					item.GovernanceDisposition.Kind,
					item.GovernanceDisposition.Status,
					item.GovernanceDisposition.Scope,
					item.GovernanceDisposition.ExpiresAt,
					item.GovernanceDisposition.Reason,
				))
			}
			if item.LifecycleQueue != nil {
				builder.WriteString(fmt.Sprintf("  lifecycle_queue=%s severity=%s credential_status=%s closure=%s\n",
					item.LifecycleQueue.ReasonCode,
					item.LifecycleQueue.Severity,
					item.LifecycleQueue.CredentialStatus,
					item.LifecycleQueue.ClosureCriteria,
				))
			}
		}
		builder.WriteString("\n")
	}

	if summary.ScanQuality != nil && len(summary.ScanQuality.Detectors) > 0 {
		builder.WriteString("## Scan Quality Appendix\n\n")
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

func markdownContradictions(items []evidencepolicy.Contradiction) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		label := strings.TrimSpace(item.Class)
		if len(item.ReasonCodes) > 0 {
			label = label + ":" + strings.Join(item.ReasonCodes, ",")
		}
		parts = append(parts, strings.Trim(label, ":"))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " | ")
}

func markdownClosureRequirements(items []risk.ClosureRequirement) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		label := strings.TrimSpace(item.ID)
		if guidance := strings.TrimSpace(item.Guidance); guidance != "" {
			if label != "" {
				label += ":"
			}
			label += guidance
		}
		if label != "" {
			parts = append(parts, label)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " | ")
}

func markdownCompletenessScore(completeness *risk.EvidenceCompleteness) int {
	if completeness == nil {
		return 0
	}
	return completeness.TotalScore
}

func renderTriggerClassSuffix(triggerClass string) string {
	if strings.TrimSpace(triggerClass) == "" {
		return ""
	}
	return ", trigger=" + strings.TrimSpace(triggerClass)
}

func markdownBOMRuntimeEvidenceLabel(item AgentActionBOMItem) string {
	return risk.BuyerRuntimeEvidenceLabel(item.RuntimeEvidenceState, item.RuntimeEvidenceAbsenceStatus, item.GaitCoverage)
}

func markdownActionPathLabel(lane string, actionPathType string) string {
	switch strings.TrimSpace(actionPathType) {
	case risk.ActionPathTypeAIAssistedWorkflow:
		switch strings.TrimSpace(lane) {
		case risk.ConfidenceLaneLikelyActionPath:
			return "likely AI-assisted workflow"
		case risk.ConfidenceLaneConfirmedActionPath:
			return "confirmed AI-assisted workflow"
		}
	case risk.ActionPathTypeAgentFramework:
		switch strings.TrimSpace(lane) {
		case risk.ConfidenceLaneLikelyActionPath:
			return "likely agent framework"
		case risk.ConfidenceLaneConfirmedActionPath:
			return "confirmed agent framework"
		}
	case risk.ActionPathTypeAutomationBot:
		switch strings.TrimSpace(lane) {
		case risk.ConfidenceLaneLikelyActionPath:
			return "likely automation bot"
		case risk.ConfidenceLaneConfirmedActionPath:
			return "confirmed automation bot"
		}
	}
	switch strings.TrimSpace(lane) {
	case "confirmed_action_path":
		return "confirmed action path"
	case "semantic_review_candidate":
		return "review candidate"
	case "context_only":
		return "context-only evidence"
	case "likely_action_path":
		return "likely action path"
	default:
		return "action-path evidence"
	}
}

func renderPrimaryWorkflowBOMSection(builder *strings.Builder, view *AgentActionBOMPrimaryView) {
	if builder == nil || view == nil {
		return
	}
	builder.WriteString("## Primary Workflow BOM\n\n")
	fmt.Fprintf(builder, "- Selected path: %s selection=%s boundary=%s autonomy=%s readiness=%s recommended_control=%s proof=%s\n",
		view.PathID,
		view.SelectionReason,
		firstNonEmptyValue(view.BoundaryLabel, BoundaryLabelReportOnly),
		risk.BuyerAutonomyTierShortLabel(view.AutonomyTier),
		risk.BuyerDelegationReadinessLabel(view.DelegationReadinessState),
		risk.BuyerRecommendedControlLabel(view.RecommendedControl),
		risk.BuyerEvidenceStateLabel("proof", view.ProofEvidenceState),
	)
	fmt.Fprintf(builder, "- Path map: %s -> %s -> %s -> %s -> %s -> %s\n",
		firstNonEmptyValue(view.PathMap.Tool, "unknown_tool"),
		firstNonEmptyValue(view.PathMap.RepoPR, "unknown_repo"),
		firstNonEmptyValue(view.PathMap.Workflow, "unknown_workflow"),
		firstNonEmptyValue(view.PathMap.Credential, "unknown_credential"),
		firstNonEmptyValue(view.PathMap.Action, "unknown_action"),
		firstNonEmptyValue(view.PathMap.Target, "unknown_target"),
	)
	fmt.Fprintf(builder, "- Control resolution: control=%s approval=%s owner=%s runtime=%s target=%s credential=%s completeness=%s(%d)\n",
		risk.BuyerControlResolutionLabel(view.ControlResolutionState),
		risk.BuyerEvidenceStateLabel("approval", view.ApprovalEvidenceState),
		risk.BuyerEvidenceStateLabel("owner", view.OwnerEvidenceState),
		risk.BuyerEvidenceStateLabel("runtime", view.RuntimeEvidenceState),
		risk.BuyerEvidenceStateLabel("target", view.TargetEvidenceState),
		risk.BuyerEvidenceStateLabel("credential", view.CredentialEvidenceState),
		markdownPrimaryViewEvidenceCompleteness(view),
		view.EvidenceCompletenessScore,
	)
	if len(view.UnresolvedEvidence) > 0 {
		fmt.Fprintf(builder, "- Unresolved evidence: %s\n", strings.Join(view.UnresolvedEvidence, ", "))
	}
	if view.TodayPath != nil || view.RecommendedGovernedPath != nil {
		fmt.Fprintf(builder, "- Governed path: %s\n", markdownGovernedPathViews(view.TodayPath, view.RecommendedGovernedPath))
	}
	if view.RecommendedActionContract != nil {
		fmt.Fprintf(builder, "- Draft contract: %s\n", markdownActionContract(view.RecommendedActionContract))
	}
	if len(view.AppendixRefs) > 0 {
		fmt.Fprintf(builder, "- Appendix refs: %s\n", strings.Join(view.AppendixRefs, ", "))
	}
	builder.WriteString("\n")
}

func markdownPrimaryViewEvidenceCompleteness(view *AgentActionBOMPrimaryView) string {
	switch strings.TrimSpace(view.EvidenceCompletenessLabel) {
	case risk.EvidenceCompletenessStrong:
		return "strong evidence coverage"
	case risk.EvidenceCompletenessPartial:
		return "partial evidence coverage"
	case risk.EvidenceCompletenessInsufficient:
		return "insufficient evidence coverage"
	default:
		return "evidence coverage unavailable"
	}
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

func renderDesignPartnerMarkdown(summary Summary) string {
	var builder strings.Builder
	builder.WriteString("# Wrkr Design Partner Summary\n\n")
	builder.WriteString(fmt.Sprintf("- Generated at: %s\n", summary.GeneratedAt))
	builder.WriteString(fmt.Sprintf("- Template: %s\n", summary.Template))
	builder.WriteString(fmt.Sprintf("- Share profile: %s\n", summary.ShareProfile))
	builder.WriteString("- Boundary: static posture from saved scan state only; no live runtime observation, endpoint probing, or control-layer enforcement\n")
	if summary.ScanScope != nil {
		builder.WriteString(fmt.Sprintf("- Scan scope: %s mode=%s repos=%d targets=%d\n",
			summary.ScanScope.ScopeLabel,
			summary.ScanScope.Mode,
			summary.ScanScope.RepoCount,
			summary.ScanScope.TargetCount,
		))
	}
	if summary.ShareProfileMetadata != nil && summary.ShareProfileMetadata.RedactionApplied {
		builder.WriteString(fmt.Sprintf("- Share redaction: version=%s fields=%s\n",
			summary.ShareProfileMetadata.RedactionVersion,
			strings.Join(summary.ShareProfileMetadata.SelectedFields, ", "),
		))
	}
	builder.WriteString("\n")

	items := designPartnerItems(summary)
	builder.WriteString("## Top Validated Findings\n\n")
	if len(items) == 0 {
		builder.WriteString("- No validated action paths were available. Remaining evidence is context-only or still needs stronger execution linkage before buyer-facing confirmation.\n\n")
	} else {
		for idx, item := range items {
			builder.WriteString(fmt.Sprintf("%d. %s in %s\n", idx+1, firstNonEmptyValue(item.Repo, "unknown-repo"), firstNonEmptyValue(item.Location, "unknown-location")))
			builder.WriteString(fmt.Sprintf("Problem: %s\n", designPartnerProblem(item)))
			builder.WriteString(fmt.Sprintf("Likely explanation: %s\n", designPartnerExplanation(item)))
			builder.WriteString(fmt.Sprintf("Threat: %s\n", designPartnerThreat(item)))
			builder.WriteString(fmt.Sprintf("Recommended control: %s\n", firstNonEmptyValue(item.Remediation, item.RecommendedNextAction, "review and add path-specific proof before approval")))
			builder.WriteString(fmt.Sprintf("Confidence lane: %s\n", markdownActionPathLabel(item.ConfidenceLane, item.ActionPathType)))
			builder.WriteString(fmt.Sprintf("Proof gap: %s\n", designPartnerProofGap(item)))
			builder.WriteString(fmt.Sprintf("Credential authority: %s\n", designPartnerCredentialAuthority(item)))
			builder.WriteString(fmt.Sprintf("High-stakes: %s\n", designPartnerHighStakes(item)))
			builder.WriteString(fmt.Sprintf("Mutable endpoint: %s\n", designPartnerMutableEndpoint(item)))
			builder.WriteString(fmt.Sprintf("Production context: %s\n", designPartnerProductionContext(item)))
			builder.WriteString(fmt.Sprintf("Owner: %s\n", firstNonEmptyValue(item.Owner, "owner not confirmed")))
			builder.WriteString(fmt.Sprintf("Purpose: %s\n", firstNonEmptyValue(item.Purpose, "purpose not confirmed")))
			builder.WriteString(fmt.Sprintf("Lineage: %s\n\n", designPartnerLineage(item)))
		}
	}

	if len(summary.ActionSurfaceRegistry) > 0 {
		builder.WriteString("## Registry Highlights\n\n")
		limit := len(summary.ActionSurfaceRegistry)
		if limit > 5 {
			limit = 5
		}
		for idx := 0; idx < limit; idx++ {
			entry := summary.ActionSurfaceRegistry[idx]
			builder.WriteString(fmt.Sprintf("- %s surface=%s owner=%s purpose=%s confidence=%s remediation=%s\n",
				firstNonEmptyValue(entry.Label, entry.ToolType, entry.RegistryID),
				firstNonEmptyValue(entry.SurfaceType, "surface"),
				firstNonEmptyValue(entry.Owner, "owner not confirmed"),
				firstNonEmptyValue(entry.Purpose, "purpose not confirmed"),
				firstNonEmptyValue(entry.ConfidenceLane, "unknown"),
				firstNonEmptyValue(entry.Remediation, "review linked path controls"),
			))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Known Limits\n\n")
	builder.WriteString("- This summary reflects declared code, workflow, MCP, route, and evidence artifacts only.\n")
	builder.WriteString("- Runtime control, live endpoint reachability, and Gait enforcement are not claimed unless explicit runtime evidence is attached.\n")
	builder.WriteString("- Semantic prompt or instruction findings stay labeled as review candidates until executable linkage, permissions, and authority are proven.\n")
	builder.WriteString("\n")
	return builder.String()
}

func designPartnerItems(summary Summary) []AgentActionBOMItem {
	if summary.AgentActionBOM == nil || len(summary.AgentActionBOM.Items) == 0 {
		return nil
	}
	filtered := make([]AgentActionBOMItem, 0, len(summary.AgentActionBOM.Items))
	for _, item := range summary.AgentActionBOM.Items {
		if strings.TrimSpace(item.ConfidenceLane) == "context_only" {
			continue
		}
		filtered = append(filtered, item)
	}
	if len(filtered) == 0 {
		return nil
	}
	if len(filtered) > 10 {
		filtered = filtered[:10]
	}
	return filtered
}

func designPartnerProblem(item AgentActionBOMItem) string {
	switch {
	case item.StandingPrivilege && item.CredentialAuthority != nil && item.CredentialAuthority.StandingAccess:
		return "A standing credential can drive this path without enough compensating proof or gating."
	case item.ProductionWrite || item.ControlState == "block_recommended":
		return "This path can change production-adjacent state and is missing enough governance evidence."
	case len(item.MutableEndpointSemantics) > 0:
		return "The path reaches declared mutable actions that need tighter approval, proof, or scope."
	case item.ApprovalGap:
		return "The path is operationally meaningful, but approval evidence is not yet linked or complete."
	case item.Owner == "":
		return "The path is governable, but ownership is not yet explicit."
	default:
		return "This path remains one of the highest static action surfaces to review before wider buyer trust claims."
	}
}

func designPartnerExplanation(item AgentActionBOMItem) string {
	parts := []string{}
	if purpose := strings.TrimSpace(item.Purpose); purpose != "" {
		parts = append(parts, fmt.Sprintf("purpose=%s", purpose))
	}
	if source := strings.TrimSpace(item.PurposeSource); source != "" {
		parts = append(parts, fmt.Sprintf("purpose_source=%s", source))
	}
	if version := strings.TrimSpace(item.Version); version != "" {
		parts = append(parts, fmt.Sprintf("version=%s", version))
	}
	if versionSource := strings.TrimSpace(item.VersionSource); versionSource != "" {
		parts = append(parts, fmt.Sprintf("version_source=%s", versionSource))
	}
	if configSource := strings.TrimSpace(item.ConfigSource); configSource != "" {
		parts = append(parts, fmt.Sprintf("config=%s", configSource))
	}
	if len(parts) == 0 {
		return "Wrkr found a deterministic static binding for this action path, but the underlying config metadata is still sparse."
	}
	return strings.Join(parts, ", ")
}

func designPartnerThreat(item AgentActionBOMItem) string {
	parts := []string{
		fmt.Sprintf("risk_zone=%s", firstNonEmptyValue(item.RiskZone, "unknown")),
		fmt.Sprintf("risk_tier=%s", firstNonEmptyValue(item.RiskTier, "unknown")),
	}
	if status := strings.TrimSpace(item.ProductionTargetStatus); status != "" {
		parts = append(parts, "production_target_status="+status)
	}
	if len(item.MutableEndpointSemantics) > 0 {
		semantics := make([]string, 0, len(item.MutableEndpointSemantics))
		for _, semantic := range item.MutableEndpointSemantics {
			if strings.TrimSpace(semantic.Semantic) == "" {
				continue
			}
			semantics = append(semantics, strings.TrimSpace(semantic.Semantic))
		}
		if len(semantics) > 0 {
			parts = append(parts, "mutable_endpoint="+strings.Join(semantics, ","))
		}
	}
	return strings.Join(parts, ", ")
}

func designPartnerProofGap(item AgentActionBOMItem) string {
	parts := []string{
		"proof=" + risk.BuyerEvidenceStateLabel("proof", item.ProofEvidenceState),
		"policy=" + firstNonEmptyValue(item.PolicyStatus, "none"),
		"runtime=" + markdownBOMRuntimeEvidenceLabel(item),
	}
	if item.ApprovalGap {
		parts = append(parts, "approval="+risk.BuyerEvidenceStateLabel("approval", item.ApprovalEvidenceState))
	}
	return strings.Join(parts, ", ")
}

func designPartnerCredentialAuthority(item AgentActionBOMItem) string {
	if item.CredentialAuthority == nil {
		if item.CredentialAccess {
			return "credential access is present, but normalized authority details are incomplete"
		}
		return "no credential authority was linked to this path"
	}
	parts := []string{}
	if kind := strings.TrimSpace(item.CredentialAuthority.CredentialKind); kind != "" {
		parts = append(parts, "kind="+kind)
	}
	if source := strings.TrimSpace(item.CredentialAuthority.CredentialSource); source != "" {
		parts = append(parts, "source="+source)
	}
	if accessType := strings.TrimSpace(item.CredentialAuthority.AccessType); accessType != "" {
		parts = append(parts, "access="+accessType)
	}
	if rotation := strings.TrimSpace(item.CredentialAuthority.RotationEvidenceStatus); rotation != "" {
		parts = append(parts, "rotation="+rotation)
	}
	if len(parts) == 0 {
		return "credential authority is present"
	}
	return strings.Join(parts, ", ")
}

func designPartnerMutableEndpoint(item AgentActionBOMItem) string {
	if len(item.MutableEndpointSemantics) == 0 {
		return "no declared mutable endpoint semantics were linked to this path"
	}
	parts := make([]string, 0, len(item.MutableEndpointSemantics))
	for _, semantic := range item.MutableEndpointSemantics {
		label := firstNonEmptyValue(strings.TrimSpace(semantic.Semantic), strings.TrimSpace(semantic.Operation), "declared_mutation")
		if confidence := strings.TrimSpace(semantic.Confidence); confidence != "" {
			label += "@" + confidence
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}

func designPartnerHighStakes(item AgentActionBOMItem) string {
	if len(item.HighStakesPresets) == 0 {
		return "no high-stakes preset was projected for this path"
	}
	parts := make([]string, 0, len(item.HighStakesPresets))
	for _, preset := range item.HighStakesPresets {
		label := strings.TrimSpace(preset.Preset)
		if label == "" {
			continue
		}
		if len(preset.ReasonCodes) > 0 {
			label += " (" + strings.Join(preset.ReasonCodes, ",") + ")"
		}
		parts = append(parts, label)
	}
	if len(parts) == 0 {
		return "no high-stakes preset was projected for this path"
	}
	return strings.Join(parts, "; ")
}

func designPartnerProductionContext(item AgentActionBOMItem) string {
	if item.ProductionContext == nil {
		return "no production-data context was projected for this path"
	}
	parts := []string{
		"status=" + firstNonEmptyValue(item.ProductionContext.Status, "unknown"),
		"surface=" + firstNonEmptyValue(item.ProductionContext.SurfaceLabel, "unknown"),
		"credential=" + firstNonEmptyValue(item.ProductionContext.CredentialMode, "unknown"),
		"target=" + firstNonEmptyValue(item.ProductionContext.TargetClass, "unknown"),
	}
	if strings.TrimSpace(item.ProductionContext.DeploymentStatus) != "" {
		parts = append(parts, "deployment="+strings.TrimSpace(item.ProductionContext.DeploymentStatus))
	}
	if len(item.ProductionContext.MutableEndpointOperations) > 0 {
		parts = append(parts, "operations="+strings.Join(item.ProductionContext.MutableEndpointOperations, ","))
	}
	return strings.Join(parts, ", ")
}

func markdownGovernedPathViews(today *risk.GovernedPathView, recommended *risk.GovernedPathView) string {
	parts := []string{}
	if today != nil {
		parts = append(parts, fmt.Sprintf("today=%s", strings.TrimSpace(today.Summary)))
	}
	if recommended != nil {
		parts = append(parts, fmt.Sprintf("recommended=%s", strings.TrimSpace(recommended.Summary)))
	}
	return strings.Join(parts, " | ")
}

func markdownActionContract(contract *risk.RecommendedActionContract) string {
	if contract == nil {
		return ""
	}
	return fmt.Sprintf("%s; readiness=%s; authority=%s; proof=%s",
		risk.BuyerActionContractReadinessLabel(contract.ContractReadinessState),
		risk.BuyerDelegationReadinessLabel(contract.DelegationReadinessState),
		firstNonEmptyValue(contract.RequiredAuthority, "not specified"),
		firstNonEmptyValue(contract.RequiredProof, "not specified"),
	)
}

func designPartnerLineage(item AgentActionBOMItem) string {
	if item.ActionLineage == nil || len(item.ActionLineage.Segments) == 0 {
		return "lineage not available"
	}
	parts := make([]string, 0, len(item.ActionLineage.Segments))
	for _, segment := range item.ActionLineage.Segments {
		label := firstNonEmptyValue(strings.TrimSpace(segment.Label), strings.TrimSpace(segment.Kind), "segment")
		if strings.TrimSpace(segment.Status) == "missing" {
			label += " (missing)"
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, " -> ")
}

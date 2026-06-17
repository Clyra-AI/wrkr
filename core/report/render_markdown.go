package report

import (
	"fmt"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	templatespkg "github.com/Clyra-AI/wrkr/core/report/templates"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func RenderMarkdown(summary Summary) string {
	if summary.Template == string(TemplateDesignPartnerSummary) {
		return renderDesignPartnerMarkdown(summary)
	}
	isAgentActionBOMTemplate := summary.Template == string(TemplateAgentActionBOM)

	var builder strings.Builder
	builder.WriteString("# Wrkr Deterministic Report\n\n")
	builder.WriteString(fmt.Sprintf("- Generated at: %s\n", summary.GeneratedAt))
	builder.WriteString(fmt.Sprintf("- Template: %s\n", summary.Template))
	builder.WriteString(fmt.Sprintf("- Share profile: %s\n\n", summary.ShareProfile))
	renderExecutiveRollupSection(&builder, templatespkg.Resolve(summary.Template).ExecutiveRollupTitle, resolveExecutiveRollup(summary))

	agentActionBOMLeadHandledEmptyState := false
	if summary.AgentActionBOM != nil && isAgentActionBOMTemplate {
		if summary.RecentPRReview != nil {
			renderRecentPRReviewWorkflowSection(&builder, summary)
		}
		agentActionBOMLeadHandledEmptyState = renderAgentActionBOMLeadSection(&builder, summary)
		renderAgentActionBOMContextAppendix(&builder, summary)

		emptyStateStatus := strings.TrimSpace(summary.AgentActionBOM.Summary.EmptyStateStatus)
		emptyStateReasons := summary.AgentActionBOM.Summary.EmptyStateReasons
		if !agentActionBOMLeadHandledEmptyState && (summary.AgentActionBOM.Summary.PrimaryView == nil || len(summary.AgentActionBOM.Items) == 0 || (emptyStateStatus != "" && emptyStateStatus != "not_eligible")) {
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

	if summary.FocusView != nil {
		renderFocusViewSection(&builder, summary.FocusView)
	}

	if summary.PublicSurfaceAssessment != nil {
		renderPublicSurfaceAssessmentSection(&builder, summary.PublicSurfaceAssessment)
	}

	if summary.WorkflowHighlights != nil {
		if isAgentActionBOMTemplate {
			renderWorkflowHighlightsSectionWithTitle(&builder, "Workflow Chain Appendix", summary.WorkflowHighlights)
		} else {
			renderWorkflowHighlightsSection(&builder, summary.WorkflowHighlights)
		}
	}

	if summary.AssessmentSummary != nil {
		title := "Assessment Summary"
		if isAgentActionBOMTemplate {
			title = "Assessment Appendix"
		}
		builder.WriteString("## " + title + "\n\n")
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

	if len(summary.PolicyOutcomes) > 0 {
		title := "Policy Outcomes"
		if isAgentActionBOMTemplate {
			title = "Policy Outcomes Appendix"
		}
		builder.WriteString("## " + title + "\n\n")
		for _, item := range summary.PolicyOutcomes {
			repoScope := "no repo examples recorded"
			if len(item.TopRepoRefs) > 0 {
				repoScope = strings.Join(item.TopRepoRefs, ", ")
				if item.SuppressedCount > 0 {
					repoScope += fmt.Sprintf(", plus %d more", item.SuppressedCount)
				}
			}
			builder.WriteString(fmt.Sprintf("- Rule %s is %s across %d occurrence(s) in %d repo(s): %s.\n",
				firstNonEmptyValue(item.RuleID, item.OutcomeID),
				firstNonEmptyValue(item.CheckResult, "observed"),
				item.OccurrenceCount,
				item.AffectedRepoCount,
				repoScope,
			))
		}
		builder.WriteString("\n")
	}

	if summary.ScanQuality != nil && len(summary.ScanQuality.Detectors) > 0 {
		title := "Scan Quality"
		if isAgentActionBOMTemplate {
			title = "Scan Quality Appendix"
		}
		builder.WriteString("## " + title + "\n\n")
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

	if summary.AgentActionBOM != nil && isAgentActionBOMTemplate {
		builder.WriteString("## Workflow BOM Appendix\n\n")
		limit := len(summary.AgentActionBOM.Items)
		if limit > 10 {
			limit = 10
		}
		for idx := 0; idx < limit; idx++ {
			item := summary.AgentActionBOM.Items[idx]
			builder.WriteString(fmt.Sprintf("- %s repo=%s location=%s owner=%s boundary=%s lane=%s type=%s state=%s zone=%s target=%s review=%s queue=%s priority=%s tier=%s autonomy=%s readiness=%s recommended_control=%s control=%s approval=%s proof=%s runtime=%s session=%s confidence=%s evidence=%s completeness=%s(%d) policy=%s remediation=%s\n",
				markdownActionPathLabel(item.ConfidenceLane, item.ActionPathType, bomItemEligible(item), bomItemBindingState(item)),
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
			if item.AgenticDeliverySystemChange != nil {
				builder.WriteString(fmt.Sprintf("  agentic_change=%s\n", markdownAgenticDeliveryChange(item.AgenticDeliverySystemChange)))
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
			if len(item.DecisionTraceRefs) > 0 {
				builder.WriteString(fmt.Sprintf("  decision_traces=%s\n", strings.Join(item.DecisionTraceRefs, ", ")))
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
		title := "Scan Quality Appendix"
		if isAgentActionBOMTemplate {
			title = "Detector Diagnostics Appendix"
		}
		builder.WriteString("## " + title + "\n\n")
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
	markdown, _ := ApplyMarkdownBudget(builder.String())
	return markdown
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

func markdownActionPathLabel(lane string, actionPathType string, eligible bool, bindingState string) string {
	if !eligible {
		switch strings.TrimSpace(actionPathType) {
		case risk.ActionPathTypeAgentInstruction:
			return "instruction control surface"
		case risk.ActionPathTypeDependencyOnlySignal:
			return "dependency-only context"
		default:
			if strings.TrimSpace(bindingState) == risk.ActionBindingStateUnboundContext {
				return "target surface context"
			}
		}
	}
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
	case risk.ActionPathTypeAgentInstruction:
		if strings.TrimSpace(lane) == risk.ConfidenceLaneSemanticReviewCandidate {
			return "review candidate instruction surface"
		}
		return "agent instruction surface"
	case risk.ActionPathTypeDependencyOnlySignal:
		return "dependency-only signal"
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

func renderPublicSurfaceAssessmentSection(builder *strings.Builder, assessment *PublicSurfaceAssessment) {
	if builder == nil || assessment == nil {
		return
	}
	builder.WriteString("## Public-Surface Assessment\n\n")
	if assessment.ManifestName != "" {
		fmt.Fprintf(builder, "- Manifest: %s\n", assessment.ManifestName)
	}
	fmt.Fprintf(builder, "- Sources: %d\n", assessment.TotalSources)
	fmt.Fprintf(builder, "- Label counts: public_observed=%d public_inferred=%d unsupported_public_claim=%d private_evidence_absent=%d\n",
		assessment.LabelCounts.PublicObserved,
		assessment.LabelCounts.PublicInferred,
		assessment.LabelCounts.UnsupportedPublicClaim,
		assessment.LabelCounts.PrivateEvidenceAbsent,
	)
	builder.WriteString("- This section uses only explicit public evidence and inferred public context; it does not verify private runtime, approval, credential, or control state without private evidence.\n")
	for _, entry := range assessment.Entries {
		fmt.Fprintf(builder, "- %s source=%s ref=%s confidence=%s\n",
			risk.BuyerPublicEvidenceLabel(entry.EvidenceLabel),
			entry.SourceClass,
			entry.PublicRef,
			firstNonEmptyValue(entry.Confidence, "unknown"),
		)
		if entry.Title != "" {
			fmt.Fprintf(builder, "  title=%s\n", entry.Title)
		}
		if entry.CapturePath != "" {
			fmt.Fprintf(builder, "  capture_path=%s\n", entry.CapturePath)
		}
		if entry.CapturedAt != "" {
			fmt.Fprintf(builder, "  captured_at=%s\n", entry.CapturedAt)
		}
		if entry.InferenceRationale != "" {
			fmt.Fprintf(builder, "  rationale=%s\n", entry.InferenceRationale)
		}
		if len(entry.Claims) > 0 {
			fmt.Fprintf(builder, "  claims=%s\n", strings.Join(entry.Claims, " | "))
		}
	}
	builder.WriteString("\n")
}

func renderAgentActionBOMLeadSection(builder *strings.Builder, summary Summary) bool {
	if builder == nil || summary.AgentActionBOM == nil {
		return false
	}
	bom := summary.AgentActionBOM
	builder.WriteString("## Agent Action BOM\n\n")
	fmt.Fprintf(builder, "- BOM id: %s\n", bom.BOMID)
	fmt.Fprintf(builder, "- Lead summary: %d governable paths, %d control-first, %d blocked, %d review required, coverage %s.\n",
		bom.Summary.TotalItems,
		bom.Summary.ControlFirstItems,
		bom.Summary.DelegationReadiness.Blocked,
		bom.Summary.DelegationReadiness.ReviewRequired,
		firstNonEmptyValue(strings.TrimSpace(bom.Summary.CoverageConfidence), scanquality.AbsenceStatusNotScanned),
	)
	renderBuyerDiagnosticCards(builder, summary)
	builder.WriteString("\n")

	emptyStateStatus := strings.TrimSpace(bom.Summary.EmptyStateStatus)
	emptyStateReasons := bom.Summary.EmptyStateReasons
	if bom.Summary.PrimaryView == nil || len(bom.Items) == 0 || (emptyStateStatus != "" && emptyStateStatus != "not_eligible") {
		builder.WriteString("## Empty-State Assessment\n\n")
		reasons := "none"
		if len(emptyStateReasons) > 0 {
			reasons = strings.Join(emptyStateReasons, ", ")
		}
		fmt.Fprintf(builder, "- status=%s coverage_confidence=%s reasons=%s\n\n",
			firstNonEmptyValue(emptyStateStatus, "eligible"),
			bom.Summary.CoverageConfidence,
			reasons,
		)
		renderSurfaceContextSection(builder, "Target Surface Context", targetSurfaceContextItems(bom.Items))
		renderSurfaceContextSection(builder, "Instruction Control Surfaces", instructionControlSurfaceItems(bom.Items))
		return true
	}

	renderPrimaryWorkflowBOMSection(builder, bom.Summary.PrimaryView)
	renderCompactTopActionPathsSection(builder, summary.WorkflowHighlights)
	renderSurfaceContextSection(builder, "Target Surface Context", targetSurfaceContextItems(bom.Items))
	renderSurfaceContextSection(builder, "Instruction Control Surfaces", instructionControlSurfaceItems(bom.Items))
	return false
}

type buyerDiagnosticCard struct {
	Inspect            string
	Why                string
	EvidenceFound      string
	EvidenceUnresolved string
	RecommendedAction  string
}

func renderBuyerDiagnosticCards(builder *strings.Builder, summary Summary) {
	if builder == nil {
		return
	}
	cards := buildBuyerDiagnosticCards(summary)
	for idx, card := range cards {
		prefix := "Inspect first"
		if idx > 0 {
			prefix = "Inspect next"
		}
		fmt.Fprintf(builder, "- %s: %s. Why: %s. Evidence found: %s. Evidence unresolved: %s. Recommended action: %s.\n",
			prefix,
			card.Inspect,
			firstNonEmptyValue(card.Why, "This remains one of the highest-signal governable paths in the scan."),
			firstNonEmptyValue(card.EvidenceFound, "evidence summary unavailable"),
			firstNonEmptyValue(card.EvidenceUnresolved, "none"),
			firstNonEmptyValue(card.RecommendedAction, "review this path before expanding scope"),
		)
	}
}

func buildBuyerDiagnosticCards(summary Summary) []buyerDiagnosticCard {
	if summary.AgentActionBOM == nil || summary.AgentActionBOM.Summary.PrimaryView == nil {
		return nil
	}
	itemsByPath := map[string]AgentActionBOMItem{}
	for _, item := range summary.AgentActionBOM.Items {
		itemsByPath[strings.TrimSpace(item.PathID)] = item
	}

	cards := make([]buyerDiagnosticCard, 0, 2)
	primaryView := summary.AgentActionBOM.Summary.PrimaryView
	primaryPathID := strings.TrimSpace(primaryView.PathID)
	seen := map[string]struct{}{}
	if primaryItem, ok := itemsByPath[primaryPathID]; ok {
		cards = append(cards, diagnosticCardFromItem(primaryView, primaryItem))
		seen[primaryPathID] = struct{}{}
	} else {
		cards = append(cards, diagnosticCardFromPrimaryView(primaryView))
	}

	if summary.WorkflowHighlights == nil {
		return cards
	}
	for _, highlight := range summary.WorkflowHighlights.Highlights {
		pathID := strings.TrimSpace(highlight.PathID)
		if pathID == "" {
			continue
		}
		if _, ok := seen[pathID]; ok {
			continue
		}
		item, ok := itemsByPath[pathID]
		if !ok {
			continue
		}
		cards = append(cards, diagnosticCardFromHighlight(highlight, item))
		if len(cards) >= 2 {
			break
		}
	}
	return cards
}

func diagnosticCardFromPrimaryView(view *AgentActionBOMPrimaryView) buyerDiagnosticCard {
	if view == nil {
		return buyerDiagnosticCard{}
	}
	return buyerDiagnosticCard{
		Inspect:            fmt.Sprintf("%s in %s via %s", firstNonEmptyValue(view.PathMap.Tool, "unknown tool"), firstNonEmptyValue(view.PathMap.RepoPR, "unknown repo"), firstNonEmptyValue(view.PathMap.Workflow, "unknown workflow")),
		Why:                fmt.Sprintf("%s path with %s posture", humanizeEnum(firstNonEmptyValue(view.PathMap.Target, "unknown")), humanizeEnum(firstNonEmptyValue(view.DelegationReadinessState, "unknown"))),
		EvidenceFound:      fmt.Sprintf("control=%s approval=%s proof=%s runtime=%s", risk.BuyerControlResolutionLabel(view.ControlResolutionState), risk.BuyerEvidenceStateLabel("approval", view.ApprovalEvidenceState), risk.BuyerEvidenceStateLabel("proof", view.ProofEvidenceState), risk.BuyerEvidenceStateLabel("runtime", view.RuntimeEvidenceState)),
		EvidenceUnresolved: strings.Join(view.UnresolvedEvidence, ", "),
		RecommendedAction:  strings.Join(view.RecommendedNextActions, " | "),
	}
}

func diagnosticCardFromItem(view *AgentActionBOMPrimaryView, item AgentActionBOMItem) buyerDiagnosticCard {
	card := diagnosticCardFromPrimaryView(view)
	if authority := workflowAuthoritySummary(item); authority != "" {
		card.Why = fmt.Sprintf("%s with %s", firstNonEmptyValue(card.Why, "High-signal governable path"), authority)
	}
	return card
}

func diagnosticCardFromHighlight(highlight WorkflowHighlight, item AgentActionBOMItem) buyerDiagnosticCard {
	unresolved := primaryViewUnresolvedEvidence(item)
	return buyerDiagnosticCard{
		Inspect:            fmt.Sprintf("%s in %s via %s", firstNonEmptyValue(highlight.PathType, "workflow path"), firstNonEmptyValue(highlight.Repo, "unknown repo"), firstNonEmptyValue(highlight.Workflow, "unknown workflow")),
		Why:                fmt.Sprintf("%s path with %s and %s", humanizeEnum(firstNonEmptyValue(highlight.TargetClass, "unknown")), humanizeEnum(firstNonEmptyValue(highlight.DelegationReadiness, "unknown")), firstNonEmptyValue(highlight.Authority, "limited authority context")),
		EvidenceFound:      fmt.Sprintf("%s; approval=%s; proof=%s; runtime=%s", firstNonEmptyValue(highlight.EvidenceSummary, "evidence summary unavailable"), firstNonEmptyValue(highlight.ApprovalPath, "unknown"), firstNonEmptyValue(highlight.ProofStatus, "unknown"), firstNonEmptyValue(highlight.RuntimeStatus, "unknown")),
		EvidenceUnresolved: firstNonEmptyValue(strings.Join(unresolved, ", "), "none"),
		RecommendedAction:  firstNonEmptyValue(highlight.Recommendation, workflowRecommendation(item), "review this workflow path"),
	}
}

func renderRecentPRReviewWorkflowSection(builder *strings.Builder, summary Summary) {
	if builder == nil || summary.RecentPRReview == nil {
		return
	}
	builder.WriteString("## Recent PR Review Workflow\n\n")
	fmt.Fprintf(builder, "- Mode: %s limit=%d total_candidates=%d\n",
		summary.RecentPRReview.Mode,
		summary.RecentPRReview.Limit,
		summary.RecentPRReview.TotalCandidates,
	)
	itemsByPath := map[string]AgentActionBOMItem{}
	if summary.AgentActionBOM != nil {
		for _, item := range summary.AgentActionBOM.Items {
			itemsByPath[strings.TrimSpace(item.PathID)] = item
		}
	}
	for _, item := range summary.RecentPRReview.Ranked {
		pathItem, ok := itemsByPath[strings.TrimSpace(item.PathID)]
		detail := recentPRReviewDetail(item, ok, pathItem)
		fmt.Fprintf(builder, "- #%d %s in %s via %s. Change: %s. Authority: %s. Blast radius: %s. Control resolution: %s. Unresolved evidence: %s. Draft action contract: %s. Focus drilldown: %s.\n",
			item.Rank,
			firstNonEmptyValue(item.Reference, item.ReviewID),
			firstNonEmptyValue(item.Repo, "unknown repo"),
			firstNonEmptyValue(item.Workflow, "unknown workflow"),
			firstNonEmptyValue(detail.Change, item.Workflow),
			firstNonEmptyValue(detail.Authority, "authority evidence not yet linked"),
			firstNonEmptyValue(detail.BlastRadius, humanizeEnum(firstNonEmptyValue(item.TargetClass, "unknown"))),
			firstNonEmptyValue(detail.ControlResolution, risk.BuyerRecommendedControlLabel(item.RecommendedControl)),
			firstNonEmptyValue(detail.UnresolvedEvidence, strings.Join(item.MissingEvidence, ", ")),
			firstNonEmptyValue(detail.ActionContract, "attach path-specific approval and proof evidence"),
			firstNonEmptyValue(item.FocusBOMPathID, "not_available"),
		)
	}
	builder.WriteString("\n")
}

type recentPRReviewWorkflowDetail struct {
	Change             string
	Authority          string
	BlastRadius        string
	ControlResolution  string
	UnresolvedEvidence string
	ActionContract     string
}

func recentPRReviewDetail(reviewItem RecentPRReviewItem, hasPathItem bool, pathItem AgentActionBOMItem) recentPRReviewWorkflowDetail {
	detail := recentPRReviewWorkflowDetail{}
	if !hasPathItem {
		detail.UnresolvedEvidence = strings.Join(reviewItem.MissingEvidence, ", ")
		return detail
	}
	if pathItem.AgenticDeliverySystemChange != nil {
		detail.Change = strings.TrimSpace(pathItem.AgenticDeliverySystemChange.ChangedArtifact)
	}
	detail.Authority = workflowAuthoritySummary(pathItem)
	detail.BlastRadius = workflowBlastRadiusSummary(pathItem)
	detail.ControlResolution = risk.BuyerControlResolutionLabel(pathItem.ControlResolutionState)
	unresolved := uniqueSortedStrings(append(primaryViewUnresolvedEvidence(pathItem), reviewItem.MissingEvidence...))
	detail.UnresolvedEvidence = strings.Join(unresolved, ", ")
	if pathItem.RecommendedActionContract != nil {
		detail.ActionContract = markdownActionContract(pathItem.RecommendedActionContract)
	} else {
		detail.ActionContract = firstSentence(pathItem.Remediation)
	}
	return detail
}

func renderAgentActionBOMContextAppendix(builder *strings.Builder, summary Summary) {
	if builder == nil || summary.AgentActionBOM == nil {
		return
	}
	builder.WriteString("## Report Context Appendix\n\n")
	if summary.ScanScope != nil {
		fmt.Fprintf(builder, "- Scanned scope: %s mode=%s repos=%d targets=%d boundary=%s\n",
			summary.ScanScope.ScopeLabel,
			summary.ScanScope.Mode,
			summary.ScanScope.RepoCount,
			summary.ScanScope.TargetCount,
			summary.ScanScope.SourceBoundary,
		)
	}
	if summary.SourcePrivacy != nil {
		fmt.Fprintf(builder, "- Source privacy: retention=%s retained=%t raw_source_in_artifacts=%t serialized_locations=%s cleanup_status=%s zero_data_exfiltration_default=true\n",
			summary.SourcePrivacy.RetentionMode,
			summary.SourcePrivacy.MaterializedSourceRetained,
			summary.SourcePrivacy.RawSourceInArtifacts,
			summary.SourcePrivacy.SerializedLocations,
			summary.SourcePrivacy.CleanupStatus,
		)
	}
	if summary.OperationalExposure != nil {
		fmt.Fprintf(builder, "- Operational exposure: grade=%s driver=%s paths=%d\n",
			summary.OperationalExposure.Grade,
			summary.OperationalExposure.Driver,
			summary.OperationalExposure.PathCount,
		)
	}
	if summary.GovernanceReadiness != nil {
		fmt.Fprintf(builder, "- Governance readiness: grade=%s driver=%s paths=%d\n",
			summary.GovernanceReadiness.Grade,
			summary.GovernanceReadiness.Driver,
			summary.GovernanceReadiness.PathCount,
		)
	}
	if summary.EvidenceCompleteness != nil {
		fmt.Fprintf(builder, "- Evidence completeness: average=%d label=%s low_evidence_paths=%d reduced_coverage_paths=%d\n",
			summary.EvidenceCompleteness.AverageTotalScore,
			risk.BuyerEvidenceCompletenessSummaryLabel(summary.EvidenceCompleteness),
			summary.EvidenceCompleteness.LowEvidencePathCount,
			summary.EvidenceCompleteness.ReducedCoveragePathCount,
		)
	}
	renderRepeatUsageSignals(builder, summary.AgentActionBOM.Summary.RepeatUsageSignals)
	fmt.Fprintf(builder, "- Coverage confidence: %s\n", summary.AgentActionBOM.Summary.CoverageConfidence)
	if summary.AgentActionBOM.Summary.ScanCoverage != nil {
		fmt.Fprintf(builder, "- Scan coverage: reduced_detectors=%d parse_failures=%d suppressed_generated_files=%d blocked_detectors=%d unsupported_declarations=%d impact=%s\n",
			summary.AgentActionBOM.Summary.ScanCoverage.ReducedDetectorCount,
			summary.AgentActionBOM.Summary.ScanCoverage.ParseFailureCount,
			summary.AgentActionBOM.Summary.ScanCoverage.SuppressedGeneratedFileCount,
			summary.AgentActionBOM.Summary.ScanCoverage.BlockedDetectorCount,
			summary.AgentActionBOM.Summary.ScanCoverage.UnsupportedDeclarationCount,
			firstNonEmptyValue(strings.TrimSpace(summary.AgentActionBOM.Summary.ScanCoverage.ImpactStatement), "Coverage metadata was unavailable."),
		)
	}
	fmt.Fprintf(builder, "- Governable paths: total=%d control_first=%d standing_credentials=%d approval_evidence_unknown=%d control_evidence_unknown=%d proof_evidence_unknown=%d\n",
		summary.AgentActionBOM.Summary.TotalItems,
		summary.AgentActionBOM.Summary.ControlFirstItems,
		summary.AgentActionBOM.Summary.StandingPrivilegeItems,
		summary.AgentActionBOM.Summary.ApprovalEvidenceUnknownItems,
		summary.AgentActionBOM.Summary.ControlEvidenceUnknownItems,
		summary.AgentActionBOM.Summary.ProofEvidenceUnknownItems,
	)
	fmt.Fprintf(builder, "- Eligibility split: eligible=%d target_surface_context=%d instruction_control_surfaces=%d\n",
		summary.AgentActionBOM.Summary.EligibleActionPathItems,
		summary.AgentActionBOM.Summary.TargetSurfaceContextItems,
		summary.AgentActionBOM.Summary.InstructionControlItems,
	)
	fmt.Fprintf(builder, "- Autonomy tiers: safe_metadata=%d low_risk_internal=%d owner_review_app_code=%d sensitive_code_or_infra=%d prod_or_customer_impacting=%d\n",
		summary.AgentActionBOM.Summary.AutonomyTiers.Tier0SafeMetadata,
		summary.AgentActionBOM.Summary.AutonomyTiers.Tier1LowRiskInternal,
		summary.AgentActionBOM.Summary.AutonomyTiers.Tier2AppCodeOwnerReview,
		summary.AgentActionBOM.Summary.AutonomyTiers.Tier3SensitiveCodeOrInfra,
		summary.AgentActionBOM.Summary.AutonomyTiers.Tier4ProdPrivilegedCustomerImpact,
	)
	fmt.Fprintf(builder, "- Delegation readiness: safe_to_delegate=%d review_required=%d approval_required=%d proof_required=%d ready_for_control=%d blocked=%d blocked_by_contradiction=%d\n",
		summary.AgentActionBOM.Summary.DelegationReadiness.SafeToDelegate,
		summary.AgentActionBOM.Summary.DelegationReadiness.ReviewRequired,
		summary.AgentActionBOM.Summary.DelegationReadiness.ApprovalRequired,
		summary.AgentActionBOM.Summary.DelegationReadiness.ProofRequired,
		summary.AgentActionBOM.Summary.DelegationReadiness.ReadyForControl,
		summary.AgentActionBOM.Summary.DelegationReadiness.Blocked,
		summary.AgentActionBOM.Summary.DelegationReadiness.BlockedByContradict,
	)
	if summary.AgentActionBOM.Summary.DriftReview != nil {
		fmt.Fprintf(builder, "- Drift review: detected=%t reasons=%d categories=%d comparison_status=%s\n",
			summary.AgentActionBOM.Summary.DriftReview.DriftDetected,
			summary.AgentActionBOM.Summary.DriftReview.ReasonCount,
			summary.AgentActionBOM.Summary.DriftReview.DriftCategoryCount,
			firstNonEmptyValue(strings.TrimSpace(summary.AgentActionBOM.Summary.DriftReview.ComparisonStatus), "not_requested"),
		)
	}
	if summary.ShareProfileMetadata != nil && summary.ShareProfileMetadata.RedactionApplied {
		fmt.Fprintf(builder, "- Share redaction: version=%s policy=%s\n",
			summary.ShareProfileMetadata.RedactionVersion,
			strings.Join(summary.ShareProfileMetadata.PolicySummary, " | "),
		)
	}
	builder.WriteString("\n")
}

func renderPrimaryWorkflowBOMSection(builder *strings.Builder, view *AgentActionBOMPrimaryView) {
	if builder == nil || view == nil {
		return
	}
	builder.WriteString("## Primary Workflow BOM\n\n")
	fmt.Fprintf(builder, "- Selection: %s inside the %s boundary.\n",
		humanizeEnum(view.SelectionReason),
		humanizeEnum(firstNonEmptyValue(view.BoundaryLabel, BoundaryLabelReportOnly)),
	)
	fmt.Fprintf(builder, "- Workflow: %s in %s via %s.\n",
		firstNonEmptyValue(view.PathMap.Tool, "unknown tool"),
		firstNonEmptyValue(view.PathMap.RepoPR, "unknown repo"),
		firstNonEmptyValue(view.PathMap.Workflow, "unknown workflow"),
	)
	fmt.Fprintf(builder, "- Authority and target: %s can %s against %s.\n",
		firstNonEmptyValue(view.PathMap.Credential, "no visible credential"),
		firstNonEmptyValue(view.PathMap.Action, "unknown action"),
		firstNonEmptyValue(view.PathMap.Target, "unknown target"),
	)
	fmt.Fprintf(builder, "- Posture: risk=%s autonomy=%s readiness=%s recommended_control=%s.\n",
		firstNonEmptyValue(strings.TrimSpace(view.RiskTier), "unknown"),
		risk.BuyerAutonomyTierShortLabel(view.AutonomyTier),
		risk.BuyerDelegationReadinessLabel(view.DelegationReadinessState),
		risk.BuyerRecommendedControlLabel(view.RecommendedControl),
	)
	fmt.Fprintf(builder, "- Control coverage: control=%s approval=%s owner=%s proof=%s runtime=%s target=%s credential=%s evidence=%s(%d).\n",
		risk.BuyerControlResolutionLabel(view.ControlResolutionState),
		risk.BuyerEvidenceStateLabel("approval", view.ApprovalEvidenceState),
		risk.BuyerEvidenceStateLabel("owner", view.OwnerEvidenceState),
		risk.BuyerEvidenceStateLabel("proof", view.ProofEvidenceState),
		risk.BuyerEvidenceStateLabel("runtime", view.RuntimeEvidenceState),
		risk.BuyerEvidenceStateLabel("target", view.TargetEvidenceState),
		risk.BuyerEvidenceStateLabel("credential", view.CredentialEvidenceState),
		markdownPrimaryViewEvidenceCompleteness(view),
		view.EvidenceCompletenessScore,
	)
	if len(view.UnresolvedEvidence) > 0 {
		fmt.Fprintf(builder, "- Unresolved evidence: %s.\n", strings.Join(view.UnresolvedEvidence, ", "))
	}
	if strings.TrimSpace(view.CoverageStatus) != "" {
		fmt.Fprintf(builder, "- Coverage status: %s.\n", humanizeEnum(view.CoverageStatus))
	}
	if strings.TrimSpace(view.CoverageImpact) != "" && strings.TrimSpace(view.CoverageStatus) != scanquality.CoverageConfidenceComplete {
		fmt.Fprintf(builder, "- Coverage note: %s\n", strings.TrimSpace(view.CoverageImpact))
	}
	if len(view.RecommendedNextActions) > 0 {
		fmt.Fprintf(builder, "- Next actions: %s.\n", strings.Join(view.RecommendedNextActions, " | "))
	}
	builder.WriteString("\n")
}

func renderCompactTopActionPathsSection(builder *strings.Builder, highlights *WorkflowHighlights) {
	if builder == nil || highlights == nil || len(highlights.Highlights) == 0 {
		return
	}
	builder.WriteString("## Top Action Paths\n\n")
	for _, item := range compactWorkflowHighlightGroups(highlights.Highlights) {
		fmt.Fprintf(builder, "- %s %s path in %s via %s: %s",
			risk.BuyerDelegationReadinessLabel(item.Highlight.DelegationReadiness),
			humanizeEnum(firstNonEmptyValue(item.Highlight.TargetClass, "unknown")),
			firstNonEmptyValue(item.Highlight.Repo, "unknown repo"),
			firstNonEmptyValue(item.Highlight.Workflow, "unknown workflow"),
			firstNonEmptyValue(item.Highlight.Recommendation, "review this workflow path"),
		)
		if item.DuplicateCount > 1 {
			fmt.Fprintf(builder, " (%d similar paths)", item.DuplicateCount)
		}
		builder.WriteString(".\n")
	}
	builder.WriteString("\n")
}

func renderSurfaceContextSection(builder *strings.Builder, title string, items []AgentActionBOMItem) {
	if builder == nil || len(items) == 0 {
		return
	}
	builder.WriteString("## " + title + "\n\n")
	for _, item := range items {
		fmt.Fprintf(builder, "- %s in %s via %s: binding=%s target=%s owner=%s next=%s.\n",
			markdownActionPathLabel(item.ConfidenceLane, item.ActionPathType, bomItemEligible(item), bomItemBindingState(item)),
			firstNonEmptyValue(item.Repo, "unknown repo"),
			firstNonEmptyValue(item.Location, "unknown surface"),
			humanizeEnum(firstNonEmptyValue(bomItemBindingState(item), risk.ActionBindingStateUnboundContext)),
			humanizeEnum(firstNonEmptyValue(item.TargetClass, "unknown")),
			firstNonEmptyValue(item.Owner, "owner not confirmed"),
			firstNonEmptyValue(item.Remediation, item.RecommendedNextAction, "correlate this surface before promoting it"),
		)
	}
	builder.WriteString("\n")
}

func targetSurfaceContextItems(items []AgentActionBOMItem) []AgentActionBOMItem {
	out := make([]AgentActionBOMItem, 0, len(items))
	for _, item := range items {
		if bomItemEligible(item) || strings.TrimSpace(item.ExclusionReason) != "" {
			continue
		}
		if bomItemBindingState(item) != risk.ActionBindingStateUnboundContext {
			continue
		}
		if item.ActionPathType == risk.ActionPathTypeAgentInstruction {
			continue
		}
		out = append(out, item)
	}
	return out
}

func instructionControlSurfaceItems(items []AgentActionBOMItem) []AgentActionBOMItem {
	out := make([]AgentActionBOMItem, 0, len(items))
	for _, item := range items {
		if bomItemEligible(item) || strings.TrimSpace(item.ExclusionReason) != "" {
			continue
		}
		if bomItemBindingState(item) != risk.ActionBindingStateUnboundContext {
			continue
		}
		if item.ActionPathType != risk.ActionPathTypeAgentInstruction {
			continue
		}
		out = append(out, item)
	}
	return out
}

type compactWorkflowHighlight struct {
	Highlight      WorkflowHighlight
	DuplicateCount int
}

func compactWorkflowHighlightGroups(highlights []WorkflowHighlight) []compactWorkflowHighlight {
	grouped := make([]compactWorkflowHighlight, 0, len(highlights))
	indexByKey := map[string]int{}
	for _, item := range highlights {
		key := strings.Join([]string{
			strings.TrimSpace(item.Repo),
			strings.TrimSpace(item.Workflow),
			strings.TrimSpace(item.TargetClass),
			strings.TrimSpace(item.DelegationReadiness),
			strings.TrimSpace(item.Recommendation),
		}, "|")
		if idx, ok := indexByKey[key]; ok {
			grouped[idx].DuplicateCount++
			continue
		}
		indexByKey[key] = len(grouped)
		grouped = append(grouped, compactWorkflowHighlight{
			Highlight:      item,
			DuplicateCount: 1,
		})
	}
	if len(grouped) > defaultBOMLeadTopPaths {
		grouped = append([]compactWorkflowHighlight(nil), grouped[:defaultBOMLeadTopPaths]...)
	}
	return grouped
}

func humanizeEnum(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	return value
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

func renderExecutiveRollupSection(builder *strings.Builder, title string, rollup *controlbacklog.ExecutiveRollup) {
	if builder == nil || rollup == nil || rollup.TotalGroups == 0 {
		return
	}
	if strings.TrimSpace(title) == "" {
		title = "Executive rollup"
	}
	builder.WriteString("## " + title + "\n\n")
	fmt.Fprintf(builder, "- total_groups=%d total_paths=%d\n", rollup.TotalGroups, rollup.TotalPaths)
	for _, group := range rollup.Groups {
		fmt.Fprintf(builder, "- group=%s count=%d severity=%s priority=%s closure=%s evidence=%s owner=%s repo_cluster=%s contradictions=%s examples=%s\n",
			group.GroupID,
			group.Count,
			group.HighestSeverity,
			group.HighestPriority,
			group.Dimensions.ClosureAction,
			group.Dimensions.EvidenceState,
			group.Dimensions.OwnerState,
			group.Dimensions.RepoCluster,
			group.Dimensions.ContradictionState,
			strings.Join(group.TopExampleRefs, ", "),
		)
		if strings.TrimSpace(group.ClosureRecommendation) != "" {
			fmt.Fprintf(builder, "  recommendation=%s\n", group.ClosureRecommendation)
		}
		if len(group.Rationale) > 0 {
			fmt.Fprintf(builder, "  rationale=%s\n", strings.Join(group.Rationale, " | "))
		}
	}
	builder.WriteString("\n")
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
	renderRepeatUsageSignals(&builder, summary.RepeatUsageSignals)
	builder.WriteString("\n")

	if summary.FocusView != nil {
		renderFocusViewSection(&builder, summary.FocusView)
	}

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
			builder.WriteString(fmt.Sprintf("Confidence lane: %s\n", markdownActionPathLabel(item.ConfidenceLane, item.ActionPathType, bomItemEligible(item), bomItemBindingState(item))))
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
		if !bomItemEligible(item) {
			continue
		}
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

func renderRepeatUsageSignals(builder *strings.Builder, signals *RepeatUsageSignals) {
	if builder == nil || signals == nil {
		return
	}
	if signals.Status == repeatUsageStatusFirstRun &&
		!signals.BaselinePresent &&
		signals.AssessRuns == 0 &&
		signals.RegressArtifacts == 0 &&
		signals.DriftArtifacts == 0 &&
		signals.EvidenceExports == 0 &&
		signals.TicketExports == 0 &&
		signals.ActionContractExports == 0 {
		return
	}
	_, _ = fmt.Fprintf(builder, "- Repeat-use signals: status=%s baseline_present=%t assess_runs=%d regress_artifacts=%d drift_artifacts=%d evidence_exports=%d ticket_exports=%d action_contract_exports=%d\n",
		firstNonEmptyValue(strings.TrimSpace(signals.Status), repeatUsageStatusFirstRun),
		signals.BaselinePresent,
		signals.AssessRuns,
		signals.RegressArtifacts,
		signals.DriftArtifacts,
		signals.EvidenceExports,
		signals.TicketExports,
		signals.ActionContractExports,
	)
}

func designPartnerProblem(item AgentActionBOMItem) string {
	switch {
	case item.StandingPrivilege:
		return "A standing credential can drive this path without enough compensating proof or gating."
	case item.ProductionWrite || item.ControlState == "block_recommended":
		return "This path can change production-adjacent state and is missing enough governance evidence."
	case itemHasMutableEndpointProjection(item):
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
	if summary := itemMutableEndpointThreatSummary(item); summary != "" {
		parts = append(parts, "mutable_endpoint="+summary)
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
		if item.CredentialProvenance != nil {
			parts := []string{}
			if kind := strings.TrimSpace(item.CredentialProvenance.CredentialKind); kind != "" {
				parts = append(parts, "kind="+kind)
			}
			if source := strings.TrimSpace(item.CredentialProvenance.Type); source != "" {
				parts = append(parts, "source="+source)
			}
			if scope := strings.TrimSpace(item.CredentialProvenance.Scope); scope != "" {
				parts = append(parts, "scope="+scope)
			}
			if item.CredentialProvenance.StandingAccess {
				parts = append(parts, "access=standing")
			}
			if len(parts) > 0 {
				return strings.Join(parts, ", ")
			}
		}
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
	if !itemHasMutableEndpointProjection(item) {
		return "no declared mutable endpoint semantics were linked to this path"
	}
	if summary := itemGroupedMutableEndpointSummary(item); summary != "" {
		return summary
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

func itemHasMutableEndpointProjection(item AgentActionBOMItem) bool {
	return len(item.MutableEndpointSemantics) > 0 || item.EndpointRefCount > 0
}

func itemMutableEndpointThreatSummary(item AgentActionBOMItem) string {
	labels := itemMutableEndpointClassLabels(item, 3)
	if len(labels) > 0 {
		return strings.Join(labels, ",")
	}
	if item.EndpointRefCount > 0 {
		return fmt.Sprintf("grouped_refs=%d", item.EndpointRefCount)
	}
	return ""
}

func itemGroupedMutableEndpointSummary(item AgentActionBOMItem) string {
	classes := itemMutableEndpointClassLabels(item, 4)
	parts := []string{}
	if item.EndpointRefCount > 0 {
		parts = append(parts, fmt.Sprintf("%d grouped endpoint semantics", item.EndpointRefCount))
	}
	if len(item.EndpointRouteGroups) > 0 {
		parts = append(parts, fmt.Sprintf("%d route groups", len(item.EndpointRouteGroups)))
	}
	if len(classes) > 0 {
		parts = append(parts, strings.Join(classes, ", "))
	}
	if len(item.EndpointRefSamples) > 0 {
		samples := make([]string, 0, len(item.EndpointRefSamples))
		for _, sample := range item.EndpointRefSamples {
			label := firstNonEmptyValue(strings.TrimSpace(sample.Operation), strings.Join(sample.Semantics, ","), strings.TrimSpace(sample.RefID))
			if label == "" {
				continue
			}
			samples = append(samples, label)
		}
		if len(samples) > 0 {
			parts = append(parts, "samples="+strings.Join(samples, " | "))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ")
}

func itemMutableEndpointClassLabels(item AgentActionBOMItem, limit int) []string {
	if limit <= 0 {
		limit = 3
	}
	if len(item.MutableEndpointSemantics) > 0 {
		labels := make([]string, 0, len(item.MutableEndpointSemantics))
		for _, semantic := range item.MutableEndpointSemantics {
			if trimmed := strings.TrimSpace(semantic.Semantic); trimmed != "" {
				labels = append(labels, trimmed)
			}
		}
		labels = uniqueSortedStrings(labels)
		if len(labels) > limit {
			labels = labels[:limit]
		}
		return labels
	}
	if len(item.EndpointOperationCounts) == 0 {
		return nil
	}
	out := make([]string, 0, minInt(limit, len(item.EndpointOperationCounts)))
	for idx, count := range item.EndpointOperationCounts {
		if idx >= limit {
			break
		}
		label := strings.TrimSpace(count.Class)
		if label == "" {
			continue
		}
		if count.Count > 0 {
			label = fmt.Sprintf("%s x%d", label, count.Count)
		}
		out = append(out, label)
	}
	return out
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

func markdownAgenticDeliveryChange(change *risk.AgenticDeliverySystemChange) string {
	if change == nil {
		return ""
	}
	parts := []string{
		"surface=" + firstNonEmptyValue(strings.TrimSpace(change.SurfaceType), "unknown"),
		"artifact=" + firstNonEmptyValue(strings.TrimSpace(change.ChangedArtifact), "unknown"),
		"impact=" + firstNonEmptyValue(strings.TrimSpace(change.AuthorityImpact), "none"),
		"review=" + firstNonEmptyValue(strings.TrimSpace(change.ReviewState), "review_unknown"),
		"credential=" + firstNonEmptyValue(strings.TrimSpace(change.CredentialReach), "no_visible_credential"),
	}
	if len(change.ReachableTools) > 0 {
		parts = append(parts, "reachable_tools="+strings.Join(change.ReachableTools, ","))
	}
	if len(change.ReachableTargets) > 0 {
		parts = append(parts, "targets="+strings.Join(change.ReachableTargets, ","))
	}
	if strings.TrimSpace(change.RecommendedControl) != "" {
		parts = append(parts, "recommended_control="+strings.TrimSpace(change.RecommendedControl))
	}
	return strings.Join(parts, " ")
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

func renderFocusViewSection(builder *strings.Builder, focus *FocusView) {
	if builder == nil || focus == nil {
		return
	}
	builder.WriteString("## Focus View\n\n")
	fmt.Fprintf(builder, "- Preset: %s\n", focus.Preset)
	fmt.Fprintf(builder, "- Title: %s\n", focus.Title)
	fmt.Fprintf(builder, "- Matching paths: %d\n", focus.MatchingPaths)
	fmt.Fprintf(builder, "- Matching workflow chains: %d\n", focus.MatchingWorkflowChains)
	fmt.Fprintf(builder, "- Matching backlog items: %d\n", focus.MatchingBacklogItems)
	if focus.EmptyStateStatus != "" {
		fmt.Fprintf(builder, "- Empty state: %s\n", focus.EmptyStateStatus)
	}
	if focus.EmptyStateMessage != "" {
		fmt.Fprintf(builder, "- Empty state detail: %s\n", focus.EmptyStateMessage)
	}
	for _, action := range focus.RecommendedNextActions {
		if strings.TrimSpace(action) == "" {
			continue
		}
		fmt.Fprintf(builder, "- Next action: %s\n", strings.TrimSpace(action))
	}
	if len(focus.Highlights) == 0 {
		builder.WriteString("\n")
		return
	}
	builder.WriteString("\n")
	for _, item := range focus.Highlights {
		renderWorkflowHighlightLine(builder, item)
	}
	builder.WriteString("\n")
}

func renderWorkflowHighlightsSection(builder *strings.Builder, highlights *WorkflowHighlights) {
	renderWorkflowHighlightsSectionWithTitle(builder, "Workflow Chain Highlights", highlights)
}

func renderWorkflowHighlightsSectionWithTitle(builder *strings.Builder, title string, highlights *WorkflowHighlights) {
	if builder == nil || highlights == nil {
		return
	}
	if strings.TrimSpace(title) == "" {
		title = "Workflow Chain Highlights"
	}
	builder.WriteString("## " + title + "\n\n")
	fmt.Fprintf(builder, "- Total buyer-facing workflow paths: %d\n", highlights.TotalItems)
	builder.WriteString("\n")
	for _, item := range highlights.Highlights {
		renderWorkflowHighlightLine(builder, item)
	}
	builder.WriteString("\n")
}

func renderWorkflowHighlightLine(builder *strings.Builder, item WorkflowHighlight) {
	if builder == nil {
		return
	}
	fmt.Fprintf(builder, "- path=%s repo=%s workflow=%s type=%s target=%s autonomy=%s readiness=%s authority=%s blast_radius=%s approval=%s proof=%s runtime=%s session=%s boundary=%s recommendation=%s\n",
		firstNonEmptyValue(item.PathID, "unknown-path"),
		firstNonEmptyValue(item.Repo, "unknown-repo"),
		firstNonEmptyValue(item.Workflow, "unknown-workflow"),
		firstNonEmptyValue(item.PathType, "unknown"),
		firstNonEmptyValue(item.TargetClass, "unknown"),
		risk.BuyerAutonomyTierShortLabel(item.AutonomyTier),
		risk.BuyerDelegationReadinessLabel(item.DelegationReadiness),
		firstNonEmptyValue(item.Authority, "none"),
		firstNonEmptyValue(item.BlastRadius, "unknown"),
		firstNonEmptyValue(item.ApprovalPath, "approval evidence not found"),
		firstNonEmptyValue(item.ProofStatus, "path-specific proof not found"),
		firstNonEmptyValue(item.RuntimeStatus, "runtime evidence not collected"),
		firstNonEmptyValue(item.RuntimeSessionStatus, "not_collected"),
		firstNonEmptyValue(item.BoundaryLabel, BoundaryLabelReportOnly),
		firstNonEmptyValue(item.Recommendation, "review this workflow path"),
	)
	fmt.Fprintf(builder, "  evidence=%s\n", firstNonEmptyValue(item.EvidenceSummary, "evidence summary unavailable"))
	fmt.Fprintf(builder, "  explanation=%s\n", firstNonEmptyValue(item.Explanation, "workflow explanation unavailable"))
}

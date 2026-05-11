package report

import (
	"fmt"
	"strings"
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
			summary.AgentActionBOM.Summary.StandingPrivilegeItems,
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

		emptyStateStatus := strings.TrimSpace(summary.AgentActionBOM.Summary.EmptyStateStatus)
		emptyStateReasons := summary.AgentActionBOM.Summary.EmptyStateReasons
		if len(summary.AgentActionBOM.Items) == 0 || (emptyStateStatus != "" && emptyStateStatus != "not_eligible") {
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
		} else {
			builder.WriteString("## Top Governable Paths\n\n")
			limit := len(summary.AgentActionBOM.Items)
			if limit > 8 {
				limit = 8
			}
			for idx := 0; idx < limit; idx++ {
				item := summary.AgentActionBOM.Items[idx]
				builder.WriteString(fmt.Sprintf("- %s repo=%s location=%s lane=%s state=%s zone=%s review=%s priority=%s tier=%s confidence=%s evidence=%s queue=%s remediation=%s\n",
					markdownActionPathLabel(item.ConfidenceLane),
					item.Repo,
					item.Location,
					item.ConfidenceLane,
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
			builder.WriteString(fmt.Sprintf("- %s repo=%s location=%s owner=%s lane=%s state=%s zone=%s review=%s queue=%s priority=%s tier=%s confidence=%s evidence=%s policy=%s proof=%s runtime=%s remediation=%s\n",
				markdownActionPathLabel(item.ConfidenceLane),
				item.Repo,
				item.Location,
				item.Owner,
				item.ConfidenceLane,
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

func markdownActionPathLabel(lane string) string {
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
			builder.WriteString(fmt.Sprintf("Confidence lane: %s\n", markdownActionPathLabel(item.ConfidenceLane)))
			builder.WriteString(fmt.Sprintf("Proof gap: %s\n", designPartnerProofGap(item)))
			builder.WriteString(fmt.Sprintf("Credential authority: %s\n", designPartnerCredentialAuthority(item)))
			builder.WriteString(fmt.Sprintf("Mutable endpoint: %s\n", designPartnerMutableEndpoint(item)))
			builder.WriteString(fmt.Sprintf("Owner: %s\n", firstNonEmptyValue(item.Owner, "owner not confirmed")))
			builder.WriteString(fmt.Sprintf("Purpose: %s\n", firstNonEmptyValue(item.Purpose, "purpose not confirmed")))
			builder.WriteString(fmt.Sprintf("Lineage: %s\n\n", designPartnerLineage(item)))
		}
	}

	if summary.ActionSurfaceRegistry != nil && len(summary.ActionSurfaceRegistry) > 0 {
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
		return "The path is operationally meaningful, but recorded approval is missing or incomplete."
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
		"proof=" + firstNonEmptyValue(item.ProofCoverage, "missing"),
		"policy=" + firstNonEmptyValue(item.PolicyStatus, "none"),
		"runtime=" + firstNonEmptyValue(item.RuntimeEvidenceStatus, "unmatched"),
	}
	if item.ApprovalGap {
		parts = append(parts, "approval=missing")
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

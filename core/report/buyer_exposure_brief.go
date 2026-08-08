package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const buyerExposureBriefLimit = 3

type buyerExposureBrief struct {
	Confirmed            []buyerExposureGroup
	Candidates           []buyerExposureGroup
	SuppressedConfirmed  int
	SuppressedCandidates int
}

type buyerExposureGroup struct {
	Outcome      string
	Primary      AgentActionBOMItem
	RelatedCount int
}

func buildBuyerExposureBrief(summary Summary) buyerExposureBrief {
	if summary.AgentActionBOM == nil {
		return buyerExposureBrief{}
	}

	items := eligibleWorkflowHighlightSourceItems(summary.AgentActionBOM)
	confirmed := groupBuyerExposureItems(items, true)
	candidates := groupBuyerExposureItems(items, false)

	brief := buyerExposureBrief{}
	brief.Confirmed, brief.SuppressedConfirmed = limitBuyerExposureGroups(confirmed, buyerExposureBriefLimit)
	brief.Candidates, brief.SuppressedCandidates = limitBuyerExposureGroups(candidates, buyerExposureBriefLimit)
	return brief
}

func groupBuyerExposureItems(items []AgentActionBOMItem, confirmed bool) []buyerExposureGroup {
	groups := make([]buyerExposureGroup, 0, len(items))
	indexByKey := map[string]int{}
	for _, item := range items {
		if buyerExposureConfirmed(item) != confirmed {
			continue
		}
		outcome := buyerExposureOutcome(item)
		key := strings.Join([]string{outcome, buyerExposureControlFamily(item)}, "\x00")
		if idx, ok := indexByKey[key]; ok {
			groups[idx].RelatedCount++
			if buyerExposureItemLess(item, groups[idx].Primary) {
				groups[idx].Primary = item
			}
			continue
		}
		indexByKey[key] = len(groups)
		groups = append(groups, buyerExposureGroup{Outcome: outcome, Primary: item, RelatedCount: 1})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		left := buyerExposurePriority(groups[i].Primary)
		right := buyerExposurePriority(groups[j].Primary)
		if left != right {
			return left > right
		}
		if groups[i].Outcome != groups[j].Outcome {
			return groups[i].Outcome < groups[j].Outcome
		}
		if groups[i].Primary.Repo != groups[j].Primary.Repo {
			return groups[i].Primary.Repo < groups[j].Primary.Repo
		}
		return groups[i].Primary.Location < groups[j].Primary.Location
	})
	return groups
}

func buyerExposureControlFamily(item AgentActionBOMItem) string {
	return strings.TrimSpace(item.RecommendedControl)
}

func limitBuyerExposureGroups(groups []buyerExposureGroup, limit int) ([]buyerExposureGroup, int) {
	if limit <= 0 || len(groups) <= limit {
		return groups, 0
	}
	return append([]buyerExposureGroup(nil), groups[:limit]...), len(groups) - limit
}

func buyerExposureConfirmed(item AgentActionBOMItem) bool {
	return bomItemPromotableActionPath(item) &&
		strings.TrimSpace(item.ConfidenceLane) == risk.ConfidenceLaneConfirmedActionPath &&
		bomItemBindingState(item) == risk.ActionBindingStateBound
}

func buyerExposureItemLess(left AgentActionBOMItem, right AgentActionBOMItem) bool {
	leftPriority := buyerExposurePriority(left)
	rightPriority := buyerExposurePriority(right)
	if leftPriority != rightPriority {
		return leftPriority > rightPriority
	}
	if left.Repo != right.Repo {
		return left.Repo < right.Repo
	}
	return left.Location < right.Location
}

func buyerExposurePriority(item AgentActionBOMItem) int {
	priority := 0
	if item.StandingPrivilege {
		priority += 100
	}
	switch strings.TrimSpace(item.DelegationReadinessState) {
	case risk.DelegationReadinessBlocked, risk.DelegationReadinessBlockedByContradiction:
		priority += 80
	case risk.DelegationReadinessApprovalRequired, risk.DelegationReadinessProofRequired:
		priority += 50
	case risk.DelegationReadinessReviewRequired:
		priority += 30
	}
	switch strings.TrimSpace(item.ControlPriority) {
	case risk.ControlPriorityControlFirst:
		priority += 40
	}
	switch strings.TrimSpace(item.RiskTier) {
	case risk.RiskTierCritical:
		priority += 30
	case risk.RiskTierHigh:
		priority += 20
	case risk.RiskTierMedium:
		priority += 10
	}
	return priority
}

func buyerExposureOutcome(item AgentActionBOMItem) string {
	if buyerExposureHasAction(item, "deploy", "release", "publish") {
		if item.CredentialAccess || item.StandingPrivilege {
			return "Credential to deploy or release"
		}
		return "Workflow mutation to deploy or release"
	}
	if buyerExposureHasAction(item, "egress", "network", "export") {
		return "Credential or workflow to external egress"
	}
	if itemHasMutableEndpointProjection(item) || buyerExposureHasAction(item, "write", "merge", "delete", "refund") {
		return "Workflow mutation to consequential data or state"
	}
	if item.CredentialAccess || item.StandingPrivilege {
		return "Credential to consequential action"
	}
	return "Workflow to consequential action"
}

func buyerExposureHasAction(item AgentActionBOMItem, wants ...string) bool {
	for _, action := range item.ActionClasses {
		for _, want := range wants {
			if strings.EqualFold(strings.TrimSpace(action), want) {
				return true
			}
		}
	}
	return false
}

func renderBuyerExposureBrief(builder *strings.Builder, summary Summary) buyerExposureBrief {
	brief := buildBuyerExposureBrief(summary)
	if builder == nil {
		return brief
	}

	builder.WriteString("## Confirmed Exposures\n\n")
	renderBuyerCoverageQualification(builder, summary)
	if len(brief.Confirmed) == 0 {
		builder.WriteString("- No configuration-backed exposure met the confirmation threshold in this scan. Inferred candidates are listed separately for validation.\n\n")
	} else {
		for idx, group := range brief.Confirmed {
			renderBuyerExposureGroup(builder, idx+1, group, false)
		}
		if brief.SuppressedConfirmed > 0 {
			fmt.Fprintf(builder, "- %d additional confirmed outcome group(s) are retained in the report JSON.\n", brief.SuppressedConfirmed)
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## Validate Next\n\n")
	if len(brief.Candidates) == 0 {
		builder.WriteString("- No inferred action-path candidates require validation before the next review.\n\n")
	} else {
		for _, group := range brief.Candidates {
			renderBuyerExposureGroup(builder, 0, group, true)
		}
		if brief.SuppressedCandidates > 0 {
			fmt.Fprintf(builder, "- %d additional candidate outcome group(s) are retained in the report JSON.\n", brief.SuppressedCandidates)
		}
		builder.WriteString("\n")
	}
	return brief
}

func renderBuyerCoverageQualification(builder *strings.Builder, summary Summary) {
	if builder == nil || summary.AgentActionBOM == nil {
		return
	}
	coverage := strings.TrimSpace(summary.AgentActionBOM.Summary.CoverageConfidence)
	if coverage == "" {
		return
	}
	if coverage == "reduced" {
		builder.WriteString("- Scan quality: reduced coverage. Positive static observations remain visible; this scan cannot support an absence-of-exposure or safe-control conclusion.\n")
		return
	}
	fmt.Fprintf(builder, "- Scan quality: %s coverage for the scanned source. Findings remain static observations, not runtime-control verification.\n", humanizeEnum(coverage))
}

func renderBuyerExposureGroup(builder *strings.Builder, number int, group buyerExposureGroup, candidate bool) {
	if builder == nil {
		return
	}
	item := group.Primary
	prefix := ""
	if candidate {
		prefix = "Candidate: "
	} else if number > 0 {
		prefix = fmt.Sprintf("%d. ", number)
	}
	fmt.Fprintf(builder, "%s%s\n", prefix, group.Outcome)
	fmt.Fprintf(builder, "   Workflow: %s. Credential reference: %s. Target: %s. Likely owner: %s.\n",
		buyerExposureWorkflow(item),
		buyerExposureCredential(item),
		buyerExposureTarget(item),
		buyerExposureOwner(item),
	)
	if candidate {
		builder.WriteString("   Relationship: inferred from static source correlation; validate the executable binding before treating this as confirmed.\n")
	} else {
		builder.WriteString("   Relationship: confirmed static configuration-backed action path.\n")
	}
	fmt.Fprintf(builder, "   Evidence: repository configuration observed in this scan (freshness: current scan); %s.\n", buyerExposureEvidenceSummary(item))
	fmt.Fprintf(builder, "   Required control: %s. Closure evidence: %s.\n", buyerExposureControl(item), buyerExposureClosureEvidence(item))
	if group.RelatedCount > 1 {
		fmt.Fprintf(builder, "   Related paths collapsed: %d.\n", group.RelatedCount-1)
	}
}

func buyerExposureWorkflow(item AgentActionBOMItem) string {
	return firstNonEmptyValue(strings.TrimSpace(item.Location), "workflow location not observed")
}

func buyerExposureCredential(item AgentActionBOMItem) string {
	if item.CredentialAuthority != nil && strings.TrimSpace(item.CredentialAuthority.CredentialKind) != "" {
		return humanizeAuthorityText(item.CredentialAuthority.CredentialKind)
	}
	if item.CredentialProvenance != nil && strings.TrimSpace(item.CredentialProvenance.CredentialKind) != "" {
		return humanizeAuthorityText(item.CredentialProvenance.CredentialKind)
	}
	if authority := strings.TrimSpace(workflowAuthoritySummary(item)); authority != "" {
		return humanizeAuthorityText(authority)
	}
	if item.CredentialAccess {
		return "credential reference observed; authority details unresolved"
	}
	return "no credential reference observed"
}

func buyerExposureTarget(item AgentActionBOMItem) string {
	return humanizeEnum(firstNonEmptyValue(strings.TrimSpace(item.TargetClass), "target not classified"))
}

func buyerExposureOwner(item AgentActionBOMItem) string {
	return firstNonEmptyValue(strings.TrimSpace(item.Owner), strings.TrimSpace(item.ReviewOwner), "owner not yet resolved")
}

func buyerExposureControl(item AgentActionBOMItem) string {
	if control := strings.TrimSpace(item.RecommendedControl); control != "" {
		return risk.BuyerRecommendedControlLabel(control)
	}
	return firstNonEmptyValue(
		firstSentence(strings.TrimSpace(item.Remediation)),
		"review the exact workflow, authority, and target before wider rollout",
	)
}

func buyerExposureClosureEvidence(item AgentActionBOMItem) string {
	if len(item.ClosureActions) > 0 {
		return markdownClosureActions(item.ClosureActions)
	}
	if item.RecommendedActionContract != nil && strings.TrimSpace(item.RecommendedActionContract.RequiredProof) != "" {
		return strings.TrimSpace(item.RecommendedActionContract.RequiredProof)
	}
	if item.ApprovalGap || strings.TrimSpace(item.ApprovalEvidenceState) == risk.EvidenceStateUnknown {
		return "import path-specific approval or branch-protection evidence"
	}
	if strings.TrimSpace(item.ProofEvidenceState) == risk.EvidenceStateUnknown {
		return "attach path-specific proof or verification evidence"
	}
	return "record the control decision and rerun the scan"
}

func buyerExposureEvidenceSummary(item AgentActionBOMItem) string {
	fields := []string{
		buyerExposureEvidenceField(item, evidencepolicy.FieldApproval, "approval", item.ApprovalEvidenceState),
		buyerExposureEvidenceField(item, evidencepolicy.FieldOwner, "owner", item.OwnerEvidenceState),
		buyerExposureEvidenceField(item, evidencepolicy.FieldTarget, "target", item.TargetEvidenceState),
		buyerExposureEvidenceField(item, "proof", "proof", item.ProofEvidenceState),
	}
	return strings.Join(fields, "; ")
}

func buyerExposureEvidenceField(item AgentActionBOMItem, decisionField string, label string, state string) string {
	decision, found := buyerExposureDecision(item, decisionField)
	if found {
		if strings.TrimSpace(state) == "" || strings.TrimSpace(state) == risk.EvidenceStateUnknown {
			if strings.TrimSpace(decision.SelectedStatus) == "unmatched" {
				return fmt.Sprintf("%s: not observed in this scan or imported evidence (source: %s; freshness: %s; evidence match: unmatched)",
					label,
					buyerEvidenceSourceLabel(decision),
					buyerEvidenceFreshnessLabel(decision.SelectedFreshnessState),
				)
			}
			return fmt.Sprintf("%s: observed from %s (freshness: %s)", label, buyerEvidenceSourceLabel(decision), buyerEvidenceFreshnessLabel(decision.SelectedFreshnessState))
		}
		value := buyerExposureDecisionState(label, state)
		return fmt.Sprintf("%s: %s (source: %s; freshness: %s)", label, value, buyerEvidenceSourceLabel(decision), buyerEvidenceFreshnessLabel(decision.SelectedFreshnessState))
	}
	if strings.TrimSpace(state) == "" || strings.TrimSpace(state) == risk.EvidenceStateUnknown {
		return fmt.Sprintf("%s: not observed in this scan or imported evidence (source: none; freshness: unknown)", label)
	}
	return fmt.Sprintf("%s: %s (source: scan-derived classification; freshness: current scan)", label, buyerExposureDecisionState(label, state))
}

func buyerExposureDecision(item AgentActionBOMItem, field string) (evidencepolicy.Decision, bool) {
	field = strings.TrimSpace(field)
	for _, decision := range item.EvidenceDecisions {
		if strings.TrimSpace(decision.Field) == field {
			return decision, true
		}
	}
	return evidencepolicy.Decision{}, false
}

func buyerExposureDecisionState(kind string, state string) string {
	if strings.TrimSpace(state) == "" || strings.TrimSpace(state) == risk.EvidenceStateUnknown {
		return "not observed in this scan or imported evidence"
	}
	return buyerLeadEvidenceTextLabel(risk.BuyerEvidenceStateLabel(kind, state))
}

func buyerEvidenceSourceLabel(decision evidencepolicy.Decision) string {
	switch evidencepolicy.NormalizeSourceType(decision.SelectedSourceType) {
	case evidencepolicy.SourceTypeProviderExport:
		return "provider export"
	case evidencepolicy.SourceTypeGitHubTeamExport:
		return "GitHub team export"
	case evidencepolicy.SourceTypeBackstageExport:
		return "Backstage export"
	case evidencepolicy.SourceTypeTicketExport:
		return "ticket export"
	case evidencepolicy.SourceTypeSignedDeclaration:
		return "signed declaration"
	case evidencepolicy.SourceTypeCustomerOwnerMap:
		return "customer owner map"
	case evidencepolicy.SourceTypeRepoPolicy:
		return "repository policy"
	case evidencepolicy.SourceTypePolicyConfig:
		return "policy configuration"
	case evidencepolicy.SourceTypeCodeowners:
		return "CODEOWNERS"
	case evidencepolicy.SourceTypeCustomOwnerMap:
		return "custom owner mapping"
	case evidencepolicy.SourceTypeServiceCatalog:
		return "service catalog"
	case evidencepolicy.SourceTypeBackstageCatalog:
		return "Backstage catalog"
	case evidencepolicy.SourceTypeAppCatalog:
		return "application catalog"
	case evidencepolicy.SourceTypeGitHubMetadata:
		return "GitHub metadata"
	case evidencepolicy.SourceTypeRepoFallback:
		return "repository metadata"
	case evidencepolicy.SourceTypeRuntime:
		return "runtime evidence"
	default:
		return "imported evidence"
	}
}

func buyerEvidenceFreshnessLabel(value string) string {
	return humanizeEnum(firstNonEmptyValue(strings.TrimSpace(value), evidencepolicy.FreshnessStateUnknown))
}

func renderInternalRemediationBrief(builder *strings.Builder, brief buyerExposureBrief) {
	if builder == nil || len(brief.Confirmed) == 0 {
		return
	}
	builder.WriteString("## Internal Remediation Brief\n\n")
	for idx, group := range brief.Confirmed {
		item := group.Primary
		fmt.Fprintf(builder, "%d. %s\n", idx+1, group.Outcome)
		fmt.Fprintf(builder, "   Repository: %s. Workflow: %s. Credential reference: %s. Target: %s. Likely owner: %s.\n",
			firstNonEmptyValue(strings.TrimSpace(item.Repo), "repository not observed"),
			buyerExposureWorkflow(item),
			buyerExposureCredential(item),
			buyerExposureTarget(item),
			buyerExposureOwner(item),
		)
		fmt.Fprintf(builder, "   Required control: %s. Closure evidence: %s.\n", buyerExposureControl(item), buyerExposureClosureEvidence(item))
	}
	builder.WriteString("\n")
}

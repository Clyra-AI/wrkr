package risk

import (
	"sort"
	"strings"
)

const (
	ClosureActionImportPRReviewEvidence     = "import_pr_review_evidence"
	ClosureActionImportBranchProtection     = "import_branch_protection"
	ClosureActionImportEnvironmentApproval  = "import_environment_approval"
	ClosureActionDeclareRepoOwner           = "declare_repo_owner"
	ClosureActionDeclareNonProductionTarget = "declare_non_production_target"
	ClosureActionDeclareApprovedCredential  = "declare_approved_credential_use"
	ClosureActionAttachPolicyOrProof        = "attach_policy_or_proof_reference"
	ClosureActionReduceStandingCredential   = "reduce_standing_credential"
	ClosureActionAcceptRiskWithExpiry       = "accept_risk_with_expiry"
	ClosureActionMarkNotApplicable          = "mark_not_applicable"
	ClosureActionMarkFalsePositive          = "mark_false_positive"
	ClosureActionRequestRuntimeEvidence     = "request_runtime_evidence"
	ClosureActionDeclareControlled          = "declare_controlled"
	ClosureActionConfirmReviewedPath        = "confirm_reviewed_path"
)

const (
	ClosureActionDeclarationKindNone              = ""
	ClosureActionDeclarationKindOwner             = "owner"
	ClosureActionDeclarationKindTarget            = "target"
	ClosureActionDeclarationKindReviewDisposition = "review_disposition"
)

type ClosureAction struct {
	ID                     string `json:"id"`
	ActionType             string `json:"action_type"`
	Title                  string `json:"title"`
	Guidance               string `json:"guidance,omitempty"`
	DeclarationKind        string `json:"declaration_kind,omitempty"`
	ReviewDispositionState string `json:"review_disposition_state,omitempty"`
	ProviderEvidenceClass  string `json:"provider_evidence_class,omitempty"`
}

func CloneClosureActions(in []ClosureAction) []ClosureAction {
	if len(in) == 0 {
		return nil
	}
	out := make([]ClosureAction, 0, len(in))
	for _, item := range in {
		out = append(out, item)
	}
	return out
}

func BuildClosureActionsForPath(raw ActionPath) []ClosureAction {
	path := ProjectActionPath(raw)
	if strings.TrimSpace(path.PathID) == "" && strings.TrimSpace(path.ResolutionKey) == "" {
		return nil
	}

	actions := []ClosureAction{}
	seen := map[string]struct{}{}
	add := func(action ClosureAction) {
		action.ActionType = strings.TrimSpace(action.ActionType)
		action.Title = strings.TrimSpace(action.Title)
		action.Guidance = strings.TrimSpace(action.Guidance)
		action.DeclarationKind = strings.TrimSpace(action.DeclarationKind)
		action.ReviewDispositionState = strings.TrimSpace(action.ReviewDispositionState)
		action.ProviderEvidenceClass = strings.TrimSpace(action.ProviderEvidenceClass)
		if action.ActionType == "" || action.Title == "" {
			return
		}
		if action.ID == "" {
			action.ID = closureActionID(path, action)
		}
		if _, ok := seen[action.ID]; ok {
			return
		}
		seen[action.ID] = struct{}{}
		actions = append(actions, action)
	}

	switch normalizeEvidenceState(path.OwnerEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		add(ClosureAction{
			ActionType:      ClosureActionDeclareRepoOwner,
			Title:           "Declare repo owner",
			Guidance:        pathOwnerClosureGuidance(path),
			DeclarationKind: ClosureActionDeclarationKindOwner,
		})
	}

	if nonProductionDeclarationCandidate(path) {
		add(ClosureAction{
			ActionType:      ClosureActionDeclareNonProductionTarget,
			Title:           "Declare non-production target",
			Guidance:        "Record this path as non-production in control declarations so future reruns keep the target scope explicit.",
			DeclarationKind: ClosureActionDeclarationKindTarget,
		})
	}

	if needsGovernedCIImports(path) {
		add(ClosureAction{
			ActionType:            ClosureActionImportPRReviewEvidence,
			Title:                 "Import PR review evidence",
			Guidance:              "Import local PR or MR review evidence for this exact CI path before treating it as governed.",
			ProviderEvidenceClass: "pr_review",
		})
		add(ClosureAction{
			ActionType:            ClosureActionImportBranchProtection,
			Title:                 "Import branch protection",
			Guidance:              "Import branch-protection or required-check evidence for this exact CI path before treating it as governed.",
			ProviderEvidenceClass: "branch_protection",
		})
		if pathTargetsProtectedEnvironment(path) {
			add(ClosureAction{
				ActionType:            ClosureActionImportEnvironmentApproval,
				Title:                 "Import environment approval",
				Guidance:              "Import environment approval or deployment-gate evidence for this exact release or production path.",
				ProviderEvidenceClass: "environment_approval",
			})
		}
	}

	if needsPolicyOrProofReference(path) {
		add(ClosureAction{
			ActionType: ClosureActionAttachPolicyOrProof,
			Title:      "Attach policy or proof reference",
			Guidance:   firstNonEmptyString(pathPolicyClosureGuidance(path), pathProofClosureGuidance(path)),
		})
	}

	if standingCredentialWithBroadAuthority(path) {
		add(ClosureAction{
			ActionType: ClosureActionReduceStandingCredential,
			Title:      "Reduce standing credential scope",
			Guidance:   "Replace standing credential use with JIT, brokered, or narrower repo-scoped authority for this exact path.",
		})
	} else if path.CredentialAccess && pathHasUnknownCredentialAuthority(path) {
		add(ClosureAction{
			ActionType:             ClosureActionDeclareApprovedCredential,
			Title:                  "Declare approved credential use",
			Guidance:               "Record the approved credential purpose, owner, scope, and expiry once authority correlation is complete.",
			DeclarationKind:        ClosureActionDeclarationKindReviewDisposition,
			ReviewDispositionState: ReviewLifecycleStateDeclaredControlled,
		})
	}

	if runtimeEvidenceNeeded(path) {
		add(ClosureAction{
			ActionType:             ClosureActionRequestRuntimeEvidence,
			Title:                  "Request runtime evidence",
			Guidance:               pathRuntimeClosureGuidance(path),
			DeclarationKind:        ClosureActionDeclarationKindReviewDisposition,
			ReviewDispositionState: ReviewLifecycleStateNeedsRuntimeEvidence,
		})
	}

	if reviewDispositionCandidate(path) {
		if controlledDeclarationCandidate(path) {
			add(ClosureAction{
				ActionType:             ClosureActionDeclareControlled,
				Title:                  "Declare controlled path",
				Guidance:               "Record the reviewed control context, owner, rationale, and evidence refs so future scans move this path into the resolved appendix.",
				DeclarationKind:        ClosureActionDeclarationKindReviewDisposition,
				ReviewDispositionState: ReviewLifecycleStateDeclaredControlled,
			})
		}
		add(ClosureAction{
			ActionType:             ClosureActionAcceptRiskWithExpiry,
			Title:                  "Accept risk with expiry",
			Guidance:               "Record an accepted-risk decision with owner, rationale, scope, and expiry so future scans keep the path visible but out of primary unresolved output.",
			DeclarationKind:        ClosureActionDeclarationKindReviewDisposition,
			ReviewDispositionState: ReviewLifecycleStateAcceptedRisk,
		})
		if notApplicableDeclarationCandidate(path) {
			add(ClosureAction{
				ActionType:             ClosureActionMarkNotApplicable,
				Title:                  "Mark not applicable",
				Guidance:               "Record why this path is not applicable so future scans keep the audit context without escalating it as unresolved.",
				DeclarationKind:        ClosureActionDeclarationKindReviewDisposition,
				ReviewDispositionState: ReviewLifecycleStateNotApplicable,
			})
		}
		add(ClosureAction{
			ActionType:             ClosureActionMarkFalsePositive,
			Title:                  "Mark false positive",
			Guidance:               "Record the false-positive rationale and evidence refs so future scans keep the audit context without re-opening the same path.",
			DeclarationKind:        ClosureActionDeclarationKindReviewDisposition,
			ReviewDispositionState: ReviewLifecycleStateFalsePositive,
		})
		if confirmReviewCandidate(path) {
			add(ClosureAction{
				ActionType:             ClosureActionConfirmReviewedPath,
				Title:                  "Confirm reviewed path",
				Guidance:               "Record that this path was reviewed and matched to the intended workflow or surface before adding stronger control declarations.",
				DeclarationKind:        ClosureActionDeclarationKindReviewDisposition,
				ReviewDispositionState: ReviewLifecycleStateConfirmed,
			})
		}
	}

	if len(actions) == 0 {
		add(ClosureAction{
			ActionType: ClosureActionConfirmReviewedPath,
			Title:      "Confirm reviewed path",
			Guidance:   "Record the operator review context for this path so future reruns can keep the same audit thread.",
		})
	}

	sort.Slice(actions, func(i, j int) bool {
		left := closureActionPriority(actions[i].ActionType)
		right := closureActionPriority(actions[j].ActionType)
		if left != right {
			return left < right
		}
		if actions[i].Title != actions[j].Title {
			return actions[i].Title < actions[j].Title
		}
		return actions[i].ID < actions[j].ID
	})

	return actions
}

func closureActionID(path ActionPath, action ClosureAction) string {
	parts := []string{
		strings.TrimSpace(path.PathID),
		strings.TrimSpace(path.ResolutionKey),
		strings.TrimSpace(action.ActionType),
		strings.TrimSpace(action.ReviewDispositionState),
		strings.TrimSpace(action.ProviderEvidenceClass),
	}
	return strings.Join(parts, "|")
}

func closureActionPriority(actionType string) int {
	switch strings.TrimSpace(actionType) {
	case ClosureActionImportPRReviewEvidence:
		return 10
	case ClosureActionImportBranchProtection:
		return 11
	case ClosureActionImportEnvironmentApproval:
		return 12
	case ClosureActionDeclareRepoOwner:
		return 20
	case ClosureActionDeclareNonProductionTarget:
		return 21
	case ClosureActionDeclareApprovedCredential:
		return 22
	case ClosureActionAttachPolicyOrProof:
		return 30
	case ClosureActionReduceStandingCredential:
		return 31
	case ClosureActionRequestRuntimeEvidence:
		return 32
	case ClosureActionDeclareControlled:
		return 40
	case ClosureActionAcceptRiskWithExpiry:
		return 41
	case ClosureActionMarkNotApplicable:
		return 42
	case ClosureActionMarkFalsePositive:
		return 43
	case ClosureActionConfirmReviewedPath:
		return 44
	default:
		return 100
	}
}

func needsGovernedCIImports(path ActionPath) bool {
	if !pathIsWorkflowSurface(path) && !pathIsReleaseWorkflowSurface(path) {
		return false
	}
	if standingCredentialWithBroadAuthority(path) || pathHasUnknownCredentialAuthority(path) {
		return false
	}
	switch normalizeEvidenceState(path.ApprovalEvidenceState) {
	case EvidenceStateVerified:
		return false
	default:
		return path.CredentialAccess || path.ProductionWrite || strings.TrimSpace(path.CIFlowClass) == CIFlowClassStandardGovernedCI
	}
}

func needsPolicyOrProofReference(path ActionPath) bool {
	if strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusNone {
		return true
	}
	switch normalizeEvidenceState(path.ProofEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		return true
	default:
		return len(path.PolicyMissingReasons) > 0
	}
}

func runtimeEvidenceNeeded(path ActionPath) bool {
	switch RuntimeEvidenceAbsenceStatus(path) {
	case RuntimeEvidenceAbsenceMissingRequired, RuntimeEvidenceAbsenceMissingForClaim, RuntimeEvidenceAbsenceNotCollected:
		return true
	default:
		return false
	}
}

func reviewDispositionCandidate(path ActionPath) bool {
	switch strings.TrimSpace(path.ReviewLifecycleState) {
	case ReviewLifecycleStateDeclaredControlled,
		ReviewLifecycleStateCoveredByImportedControl,
		ReviewLifecycleStateAcceptedRisk,
		ReviewLifecycleStateNotApplicable,
		ReviewLifecycleStateFalsePositive:
		return false
	}
	return path.ActionPathEligible || strings.TrimSpace(path.ControlPriority) == ControlPriorityControlFirst
}

func controlledDeclarationCandidate(path ActionPath) bool {
	switch strings.TrimSpace(path.ControlResolutionState) {
	case ControlResolutionStateDetectedControl, ControlResolutionStateDeclaredControl, ControlResolutionStateExternalControlReference:
		return true
	}
	return normalizeEvidenceState(path.ApprovalEvidenceState) == EvidenceStateVerified ||
		normalizeEvidenceState(path.OwnerEvidenceState) == EvidenceStateVerified ||
		len(path.ControlEvidenceRefs) > 0
}

func notApplicableDeclarationCandidate(path ActionPath) bool {
	if strings.TrimSpace(path.TargetClass) == TargetClassInternalTooling {
		return true
	}
	return nonProductionDeclarationCandidate(path) || actionPathDependencyOnly(path) || pathTargetsCorrelationContext(path)
}

func nonProductionDeclarationCandidate(path ActionPath) bool {
	if path.ProductionWrite || len(path.MatchedProductionTargets) > 0 {
		return false
	}
	switch strings.TrimSpace(path.TargetClass) {
	case TargetClassDeveloperProductivity, TargetClassTestDemoSandbox, TargetClassInternalTooling:
		return true
	default:
		return false
	}
}

func confirmReviewCandidate(path ActionPath) bool {
	switch strings.TrimSpace(path.ConfidenceLane) {
	case ConfidenceLaneLikelyActionPath, ConfidenceLaneSemanticReviewCandidate:
		return true
	default:
		return pathTargetsCorrelationContext(path)
	}
}

func pathTargetsProtectedEnvironment(path ActionPath) bool {
	if path.ProductionWrite || len(path.MatchedProductionTargets) > 0 {
		return true
	}
	switch strings.TrimSpace(path.TargetClass) {
	case TargetClassProductionImpacting, TargetClassReleaseAdjacent:
		return true
	default:
		return pathIsReleaseWorkflowSurface(path)
	}
}

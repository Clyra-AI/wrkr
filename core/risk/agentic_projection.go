package risk

import (
	"fmt"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

const (
	AutonomyTier0SafeMetadata                 = "tier_0_safe_metadata"
	AutonomyTier1LowRiskInternal              = "tier_1_low_risk_internal"
	AutonomyTier2AppCodeOwnerReview           = "tier_2_app_code_owner_review"
	AutonomyTier3SensitiveCodeOrInfra         = "tier_3_sensitive_code_or_infra"
	AutonomyTier4ProdPrivilegedCustomerImpact = "tier_4_prod_privileged_or_customer_impacting"
	DelegationReadinessSafeToDelegate         = "safe_to_delegate"
	DelegationReadinessReviewRequired         = "review_required"
	DelegationReadinessApprovalRequired       = "approval_required"
	DelegationReadinessProofRequired          = "proof_required"
	DelegationReadinessReadyForControl        = "ready_for_control"
	DelegationReadinessBlocked                = "blocked"
	DelegationReadinessBlockedByContradiction = "blocked_by_contradiction"
	RecommendedControlAllow                   = "allow"
	RecommendedControlOwnerReview             = "owner_review"
	RecommendedControlSecurityReview          = "security_review"
	RecommendedControlApprovalRequired        = "approval_required"
	RecommendedControlJITCredentialRequired   = "jit_credential_required" // #nosec G101 -- deterministic control enum label, not credential material.
	RecommendedControlProofRequired           = "proof_required"
	RecommendedControlBlockStandingCredential = "block_standing_credential"
	RecommendedControlBlock                   = "block"
	ActionContractReadinessDraft              = "draft"
	ActionContractReadinessNeedsOwner         = "needs_owner"
	ActionContractReadinessNeedsApproval      = "needs_approval_evidence"
	ActionContractReadinessReadyForReportOnly = "ready_for_report_only"
	ActionContractReadinessReadyForControl    = "ready_for_control"
	ActionContractReadinessBlockedContradict  = "blocked_by_contradiction"
	GovernedPathLabelToday                    = "today_path"
	GovernedPathLabelRecommended              = "recommended_governed_path"
)

type AutonomyTierCounts struct {
	Tier0SafeMetadata                 int `json:"tier_0_safe_metadata"`
	Tier1LowRiskInternal              int `json:"tier_1_low_risk_internal"`
	Tier2AppCodeOwnerReview           int `json:"tier_2_app_code_owner_review"`
	Tier3SensitiveCodeOrInfra         int `json:"tier_3_sensitive_code_or_infra"`
	Tier4ProdPrivilegedCustomerImpact int `json:"tier_4_prod_privileged_or_customer_impacting"`
}

type DelegationReadinessCounts struct {
	SafeToDelegate      int `json:"safe_to_delegate"`
	ReviewRequired      int `json:"review_required"`
	ApprovalRequired    int `json:"approval_required"`
	ProofRequired       int `json:"proof_required"`
	ReadyForControl     int `json:"ready_for_control"`
	Blocked             int `json:"blocked"`
	BlockedByContradict int `json:"blocked_by_contradiction"`
}

type RecommendedControlCounts struct {
	Allow                   int `json:"allow"`
	OwnerReview             int `json:"owner_review"`
	SecurityReview          int `json:"security_review"`
	ApprovalRequired        int `json:"approval_required"`
	JITCredentialRequired   int `json:"jit_credential_required"`
	ProofRequired           int `json:"proof_required"`
	BlockStandingCredential int `json:"block_standing_credential"`
	Block                   int `json:"block"`
}

type RecommendedActionContract struct {
	PathSummary              string   `json:"path_summary,omitempty"`
	AllowedAction            string   `json:"allowed_action,omitempty"`
	RequiredAuthority        string   `json:"required_authority,omitempty"`
	RequiredReview           string   `json:"required_review,omitempty"`
	RequiredApproval         string   `json:"required_approval,omitempty"`
	RequiredProof            string   `json:"required_proof,omitempty"`
	AllowedAutonomyTier      string   `json:"allowed_autonomy_tier,omitempty"`
	ValidationStep           string   `json:"validation_step,omitempty"`
	DefaultPosture           string   `json:"default_posture,omitempty"`
	DelegationReadinessState string   `json:"delegation_readiness_state,omitempty"`
	ApprovalEvidenceState    string   `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState       string   `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState       string   `json:"proof_evidence_state,omitempty"`
	OutcomeEvidenceState     string   `json:"outcome_evidence_state,omitempty"`
	ContractReadinessState   string   `json:"contract_readiness_state,omitempty"`
	ReportOnly               bool     `json:"report_only,omitempty"`
	ReasonCodes              []string `json:"reason_codes,omitempty"`
}

type GovernedPathView struct {
	Label                    string   `json:"label,omitempty"`
	Summary                  string   `json:"summary,omitempty"`
	AutonomyTier             string   `json:"autonomy_tier,omitempty"`
	DelegationReadinessState string   `json:"delegation_readiness_state,omitempty"`
	RecommendedControl       string   `json:"recommended_control,omitempty"`
	CredentialMode           string   `json:"credential_mode,omitempty"`
	ApprovalEvidenceState    string   `json:"approval_evidence_state,omitempty"`
	ProofEvidenceState       string   `json:"proof_evidence_state,omitempty"`
	OutcomeEvidenceState     string   `json:"outcome_evidence_state,omitempty"`
	PathType                 string   `json:"path_type,omitempty"`
	TargetClass              string   `json:"target_class,omitempty"`
	ReasonCodes              []string `json:"reason_codes,omitempty"`
}

func CloneRecommendedActionContract(in *RecommendedActionContract) *RecommendedActionContract {
	if in == nil {
		return nil
	}
	out := *in
	out.ReasonCodes = append([]string(nil), in.ReasonCodes...)
	return &out
}

func CloneGovernedPathView(in *GovernedPathView) *GovernedPathView {
	if in == nil {
		return nil
	}
	out := *in
	out.ReasonCodes = append([]string(nil), in.ReasonCodes...)
	return &out
}

func ValidAutonomyTier(value string) bool {
	switch strings.TrimSpace(value) {
	case AutonomyTier0SafeMetadata,
		AutonomyTier1LowRiskInternal,
		AutonomyTier2AppCodeOwnerReview,
		AutonomyTier3SensitiveCodeOrInfra,
		AutonomyTier4ProdPrivilegedCustomerImpact:
		return true
	default:
		return false
	}
}

func ValidDelegationReadinessState(value string) bool {
	switch strings.TrimSpace(value) {
	case DelegationReadinessSafeToDelegate,
		DelegationReadinessReviewRequired,
		DelegationReadinessApprovalRequired,
		DelegationReadinessProofRequired,
		DelegationReadinessReadyForControl,
		DelegationReadinessBlocked,
		DelegationReadinessBlockedByContradiction:
		return true
	default:
		return false
	}
}

func ValidRecommendedControl(value string) bool {
	switch strings.TrimSpace(value) {
	case RecommendedControlAllow,
		RecommendedControlOwnerReview,
		RecommendedControlSecurityReview,
		RecommendedControlApprovalRequired,
		RecommendedControlJITCredentialRequired,
		RecommendedControlProofRequired,
		RecommendedControlBlockStandingCredential,
		RecommendedControlBlock:
		return true
	default:
		return false
	}
}

func ValidActionContractReadinessState(value string) bool {
	switch strings.TrimSpace(value) {
	case ActionContractReadinessDraft,
		ActionContractReadinessNeedsOwner,
		ActionContractReadinessNeedsApproval,
		ActionContractReadinessReadyForReportOnly,
		ActionContractReadinessReadyForControl,
		ActionContractReadinessBlockedContradict:
		return true
	default:
		return false
	}
}

func populateAgenticProjection(path ActionPath) ActionPath {
	out := path
	out.RiskClassificationValidationReasons, out.RiskClassificationValidationRefs = deriveRiskClassificationValidation(out)
	out.AutonomyTier, out.AutonomyTierReasons, out.AutonomyTierEvidenceRefs = deriveAutonomyTier(out)
	out.DelegationReadinessState, out.DelegationReadinessReasons, out.RecommendedControl, out.RecommendedControlReasons = deriveDelegationProjection(out)
	out.RecommendedActionContract = buildRecommendedActionContract(out)
	out.TodayPath = buildTodayPathView(out)
	out.RecommendedGovernedPath = buildRecommendedGovernedPathView(out)
	return out
}

func deriveAutonomyTier(path ActionPath) (string, []string, []string) {
	reasons := []string{}
	refs := []string{}
	addReason := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}
	addRefs := func(values ...string) {
		refs = append(refs, values...)
	}

	var tier string
	switch {
	case len(path.Contradictions) > 0 || hasClassificationReason(path, "classification:broad_credential_low_risk") || hasClassificationReason(path, "classification:missing_deploy_proof"):
		tier = AutonomyTier4ProdPrivilegedCustomerImpact
		addReason("tier:contradiction_or_prod_authority")
	case path.ProductionWrite ||
		pathHasExplicitProductionImpact(path) ||
		len(path.MatchedProductionTargets) > 0 ||
		normalizeTargetClass(path.TargetClass) == TargetClassProductionImpacting ||
		pathHasHighImpactMutableEndpoint(path) ||
		pathHasSensitiveDataEndpoint(path) ||
		standingCredentialWithBroadAuthority(path):
		tier = AutonomyTier4ProdPrivilegedCustomerImpact
		addReason("tier:production_or_customer_impact")
	case sensitiveInfraSurface(path) ||
		hasClassificationReason(path, "classification:low_risk_sensitive_path") ||
		hasClassificationReason(path, "classification:missing_security_check"):
		tier = AutonomyTier3SensitiveCodeOrInfra
		addReason("tier:sensitive_code_or_infra")
	case path.WriteCapable ||
		path.PullRequestWrite ||
		path.MergeExecute ||
		normalizeTargetClass(path.TargetClass) == TargetClassInternalTooling ||
		normalizeTargetClass(path.TargetClass) == TargetClassDeveloperProductivity ||
		path.PathContext != nil && path.PathContext.Kind == agginventory.PathContextRuntimeSource:
		tier = AutonomyTier2AppCodeOwnerReview
		addReason("tier:app_code_owner_review")
	case pathIsSafeMetadataOnly(path):
		tier = AutonomyTier0SafeMetadata
		addReason("tier:safe_metadata_only")
	default:
		tier = AutonomyTier1LowRiskInternal
		addReason("tier:low_risk_internal")
	}

	if strings.TrimSpace(tier) == AutonomyTier0SafeMetadata &&
		pathIsLowEvidence(path) &&
		(path.WriteCapable || path.CredentialAccess || path.DeployWrite || path.ProductionWrite || path.ApprovalGap) {
		tier = AutonomyTier1LowRiskInternal
		addReason("tier:evidence_gap_promotes_internal_review")
	}
	if len(path.RiskClassificationValidationReasons) > 0 && autonomyTierRank(AutonomyTier3SensitiveCodeOrInfra) < autonomyTierRank(tier) {
		tier = AutonomyTier3SensitiveCodeOrInfra
		addReason("tier:risk_classification_validation")
	}
	if actionPathHasContradictoryControlEvidence(path) && autonomyTierRank(AutonomyTier4ProdPrivilegedCustomerImpact) < autonomyTierRank(tier) {
		tier = AutonomyTier4ProdPrivilegedCustomerImpact
		addReason("tier:contradictory_evidence")
	}

	switch tier {
	case AutonomyTier4ProdPrivilegedCustomerImpact:
		addRefs(path.TargetClassEvidenceRefs...)
		addRefs(path.PolicyEvidenceRefs...)
		addRefs(path.ControlEvidenceRefs...)
		if path.CredentialAuthority != nil {
			addRefs(path.CredentialAuthority.ReasonCodes...)
		}
		if path.CredentialProvenance != nil {
			addRefs(path.CredentialProvenance.EvidenceBasis...)
		}
	case AutonomyTier3SensitiveCodeOrInfra:
		addRefs(path.TargetClassEvidenceRefs...)
		addRefs(path.ActionPathTypeEvidenceRefs...)
		addRefs(path.ControlEvidenceRefs...)
	case AutonomyTier2AppCodeOwnerReview:
		addRefs(path.TargetClassEvidenceRefs...)
		addRefs(path.OwnershipEvidence...)
	case AutonomyTier1LowRiskInternal, AutonomyTier0SafeMetadata:
		addRefs(path.ActionPathTypeEvidenceRefs...)
		addRefs(path.TargetClassEvidenceRefs...)
	}
	addRefs(path.RiskClassificationValidationRefs...)
	return tier, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
}

func deriveDelegationProjection(path ActionPath) (string, []string, string, []string) {
	readinessReasons := []string{}
	controlReasons := []string{}
	addReadiness := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			readinessReasons = append(readinessReasons, strings.TrimSpace(reason))
		}
	}
	addControl := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			controlReasons = append(controlReasons, strings.TrimSpace(reason))
		}
	}

	switch {
	case len(path.Contradictions) > 0 || actionPathHasContradictoryControlEvidence(path) || normalizeEvidenceState(path.TargetEvidenceState) == EvidenceStateContradictory:
		addReadiness("readiness:contradictory_path")
		addControl("recommended_control:block")
		return DelegationReadinessBlockedByContradiction, dedupeSortedStrings(readinessReasons), RecommendedControlBlock, dedupeSortedStrings(controlReasons)
	case standingCredentialWithBroadAuthority(path) && path.AutonomyTier == AutonomyTier4ProdPrivilegedCustomerImpact:
		addReadiness("readiness:standing_credential_block")
		addControl("recommended_control:block_standing_credential")
		return DelegationReadinessBlocked, dedupeSortedStrings(readinessReasons), RecommendedControlBlockStandingCredential, dedupeSortedStrings(controlReasons)
	case path.AutonomyTier == AutonomyTier0SafeMetadata && !pathIsLowEvidence(path):
		addReadiness("readiness:safe_metadata")
		addControl("recommended_control:allow")
		return DelegationReadinessSafeToDelegate, dedupeSortedStrings(readinessReasons), RecommendedControlAllow, dedupeSortedStrings(controlReasons)
	case path.AutonomyTier == AutonomyTier1LowRiskInternal && !pathNeedsOwnerReview(path) && !pathNeedsApproval(path) && !pathNeedsProof(path):
		addReadiness("readiness:low_risk_internal")
		addControl("recommended_control:allow")
		return DelegationReadinessSafeToDelegate, dedupeSortedStrings(readinessReasons), RecommendedControlAllow, dedupeSortedStrings(controlReasons)
	case pathNeedsOwnerReview(path):
		addReadiness("readiness:owner_review_needed")
		if path.AutonomyTier == AutonomyTier3SensitiveCodeOrInfra || path.AutonomyTier == AutonomyTier4ProdPrivilegedCustomerImpact {
			addControl("recommended_control:security_review")
			return DelegationReadinessReviewRequired, dedupeSortedStrings(readinessReasons), RecommendedControlSecurityReview, dedupeSortedStrings(controlReasons)
		}
		addControl("recommended_control:owner_review")
		return DelegationReadinessReviewRequired, dedupeSortedStrings(readinessReasons), RecommendedControlOwnerReview, dedupeSortedStrings(controlReasons)
	case pathNeedsApproval(path):
		addReadiness("readiness:approval_evidence_needed")
		addControl("recommended_control:approval_required")
		return DelegationReadinessApprovalRequired, dedupeSortedStrings(readinessReasons), RecommendedControlApprovalRequired, dedupeSortedStrings(controlReasons)
	case pathNeedsProof(path):
		addReadiness("readiness:path_proof_needed")
		if path.CredentialAccess && !likelyJITCredential(path) && (path.AutonomyTier == AutonomyTier3SensitiveCodeOrInfra || path.AutonomyTier == AutonomyTier4ProdPrivilegedCustomerImpact) {
			addControl("recommended_control:jit_credential_required")
			return DelegationReadinessProofRequired, dedupeSortedStrings(readinessReasons), RecommendedControlJITCredentialRequired, dedupeSortedStrings(controlReasons)
		}
		addControl("recommended_control:proof_required")
		return DelegationReadinessProofRequired, dedupeSortedStrings(readinessReasons), RecommendedControlProofRequired, dedupeSortedStrings(controlReasons)
	default:
		addReadiness("readiness:governable_with_controls")
		addControl("recommended_control:allow")
		return DelegationReadinessReadyForControl, dedupeSortedStrings(readinessReasons), RecommendedControlAllow, dedupeSortedStrings(controlReasons)
	}
}

func deriveRiskClassificationValidation(path ActionPath) ([]string, []string) {
	if !pathCarriesLowRiskClaim(path) {
		return nil, nil
	}
	reasons := []string{}
	refs := []string{}
	addReason := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}
	addRefs := func(values ...string) {
		refs = append(refs, values...)
	}

	if sensitiveInfraSurface(path) || path.AutonomyTier == AutonomyTier3SensitiveCodeOrInfra || path.AutonomyTier == AutonomyTier4ProdPrivilegedCustomerImpact {
		addReason("classification:low_risk_sensitive_path")
	}
	if pathHasMeaningfulGovernedSurface(path) && (pathNeedsOwnerReview(path) || pathNeedsApproval(path)) {
		addReason("classification:missing_owner_review")
	}
	if workflowOrToolingControlSurface(path) && (strings.TrimSpace(path.ControlResolutionState) == ControlResolutionStateNoVisibleControl || strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusNone || len(path.PolicyMissingReasons) > 0) {
		addReason("classification:missing_security_check")
	}
	if (path.DeployWrite || path.ProductionWrite || len(path.MatchedProductionTargets) > 0) && pathNeedsProof(path) {
		addReason("classification:missing_deploy_proof")
	}
	if standingCredentialWithBroadAuthority(path) {
		addReason("classification:broad_credential_low_risk")
	}
	if len(reasons) == 0 {
		return nil, nil
	}

	addRefs(path.TargetClassEvidenceRefs...)
	addRefs(path.PolicyEvidenceRefs...)
	addRefs(path.ControlEvidenceRefs...)
	addRefs(path.ConstraintEvidenceRefs...)
	addRefs(path.OwnershipEvidence...)
	if path.CredentialAuthority != nil {
		addRefs(path.CredentialAuthority.ReasonCodes...)
	}
	if path.CredentialProvenance != nil {
		addRefs(path.CredentialProvenance.EvidenceBasis...)
	}
	return dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
}

func buildRecommendedActionContract(path ActionPath) *RecommendedActionContract {
	if strings.TrimSpace(path.ControlPriority) != ControlPriorityControlFirst &&
		path.AutonomyTier != AutonomyTier3SensitiveCodeOrInfra &&
		path.AutonomyTier != AutonomyTier4ProdPrivilegedCustomerImpact &&
		path.DelegationReadinessState == DelegationReadinessSafeToDelegate {
		return nil
	}

	contract := &RecommendedActionContract{
		PathSummary:              fmt.Sprintf("%s path for %s", BuyerAutonomyTierShortLabel(path.AutonomyTier), firstNonEmptyString(strings.TrimSpace(path.TargetClass), "unknown target")),
		AllowedAction:            strings.TrimSpace(path.RecommendedControl),
		RequiredAuthority:        requiredAuthorityForPath(path),
		RequiredReview:           requiredReviewForPath(path),
		RequiredApproval:         requiredApprovalForPath(path),
		RequiredProof:            requiredProofForPath(path),
		AllowedAutonomyTier:      strings.TrimSpace(path.AutonomyTier),
		ValidationStep:           validationStepForPath(path),
		DefaultPosture:           defaultPostureForPath(path),
		DelegationReadinessState: strings.TrimSpace(path.DelegationReadinessState),
		ApprovalEvidenceState:    normalizeEvidenceState(path.ApprovalEvidenceState),
		OwnerEvidenceState:       normalizeEvidenceState(path.OwnerEvidenceState),
		ProofEvidenceState:       normalizeEvidenceState(path.ProofEvidenceState),
		OutcomeEvidenceState:     outcomeEvidenceState(path),
		ContractReadinessState:   deriveContractReadiness(path),
		ReportOnly:               true,
		ReasonCodes:              dedupeSortedStrings(append(append([]string(nil), path.DelegationReadinessReasons...), path.RiskClassificationValidationReasons...)),
	}
	return contract
}

func buildTodayPathView(path ActionPath) *GovernedPathView {
	if !pathNeedsGovernedPathView(path) {
		return nil
	}
	return &GovernedPathView{
		Label:                    GovernedPathLabelToday,
		Summary:                  fmt.Sprintf("Today this path is %s using %s with %s and %s.", BuyerAutonomyTierShortLabel(path.AutonomyTier), credentialModeForPath(path), BuyerEvidenceStateLabel("approval", path.ApprovalEvidenceState), BuyerEvidenceStateLabel("proof", path.ProofEvidenceState)),
		AutonomyTier:             strings.TrimSpace(path.AutonomyTier),
		DelegationReadinessState: strings.TrimSpace(path.DelegationReadinessState),
		RecommendedControl:       strings.TrimSpace(path.RecommendedControl),
		CredentialMode:           credentialModeForPath(path),
		ApprovalEvidenceState:    normalizeEvidenceState(path.ApprovalEvidenceState),
		ProofEvidenceState:       normalizeEvidenceState(path.ProofEvidenceState),
		OutcomeEvidenceState:     outcomeEvidenceState(path),
		PathType:                 strings.TrimSpace(path.ActionPathType),
		TargetClass:              strings.TrimSpace(path.TargetClass),
		ReasonCodes:              dedupeSortedStrings(append(append([]string(nil), path.AutonomyTierReasons...), path.RiskClassificationValidationReasons...)),
	}
}

func buildRecommendedGovernedPathView(path ActionPath) *GovernedPathView {
	if !pathNeedsGovernedPathView(path) {
		return nil
	}
	return &GovernedPathView{
		Label:                    GovernedPathLabelRecommended,
		Summary:                  fmt.Sprintf("Recommended governed path uses %s, requires %s, and leaves this path %s.", BuyerRecommendedControlLabel(path.RecommendedControl), governanceEvidenceSummary(path), BuyerDelegationReadinessLabel(path.DelegationReadinessState)),
		AutonomyTier:             strings.TrimSpace(path.AutonomyTier),
		DelegationReadinessState: strings.TrimSpace(path.DelegationReadinessState),
		RecommendedControl:       strings.TrimSpace(path.RecommendedControl),
		CredentialMode:           recommendedCredentialModeForPath(path),
		ApprovalEvidenceState:    normalizeEvidenceState(path.ApprovalEvidenceState),
		ProofEvidenceState:       normalizeEvidenceState(path.ProofEvidenceState),
		OutcomeEvidenceState:     outcomeEvidenceState(path),
		PathType:                 strings.TrimSpace(path.ActionPathType),
		TargetClass:              strings.TrimSpace(path.TargetClass),
		ReasonCodes:              dedupeSortedStrings(append(append([]string(nil), path.RecommendedControlReasons...), path.DelegationReadinessReasons...)),
	}
}

func pathNeedsGovernedPathView(path ActionPath) bool {
	if strings.TrimSpace(path.ControlPriority) == ControlPriorityControlFirst {
		return true
	}
	switch strings.TrimSpace(path.AutonomyTier) {
	case AutonomyTier3SensitiveCodeOrInfra, AutonomyTier4ProdPrivilegedCustomerImpact:
		return true
	}
	switch strings.TrimSpace(path.DelegationReadinessState) {
	case DelegationReadinessReviewRequired, DelegationReadinessApprovalRequired, DelegationReadinessProofRequired, DelegationReadinessBlocked, DelegationReadinessBlockedByContradiction:
		return true
	}
	return false
}

func pathIsSafeMetadataOnly(path ActionPath) bool {
	if path.WriteCapable || path.CredentialAccess || path.PullRequestWrite || path.MergeExecute || path.DeployWrite || path.ProductionWrite || pathHasAnyMutableEndpoint(path) {
		return false
	}
	if path.PathContext == nil {
		return confidenceLaneForPath(path) == ConfidenceLaneContextOnly
	}
	switch strings.TrimSpace(path.PathContext.Kind) {
	case agginventory.PathContextDocs, agginventory.PathContextExample, agginventory.PathContextUnitTest, agginventory.PathContextGeneratedCode, agginventory.PathContextPackageCache:
		return true
	default:
		return confidenceLaneForPath(path) == ConfidenceLaneContextOnly
	}
}

func pathIsLowEvidence(path ActionPath) bool {
	if pathIsSafeMetadataOnly(path) && !pathHasMeaningfulGovernedSurface(path) {
		return false
	}
	switch normalizeEvidenceState(path.OwnerEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		return true
	}
	switch normalizeEvidenceState(path.ApprovalEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		return true
	}
	switch normalizeEvidenceState(path.ProofEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		return true
	}
	return len(path.RiskClassificationValidationReasons) > 0
}

func pathCarriesLowRiskClaim(path ActionPath) bool {
	if strings.TrimSpace(path.RiskTier) == RiskTierLow {
		return true
	}
	if strings.TrimSpace(path.ControlPriority) == ControlPriorityInventoryHygiene {
		return true
	}
	return strings.TrimSpace(path.ReviewBurden) == ReviewBurdenLow
}

func pathNeedsOwnerReview(path ActionPath) bool {
	if len(path.RiskClassificationValidationReasons) > 0 {
		return true
	}
	switch normalizeEvidenceState(path.OwnerEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		return true
	}
	return path.AutonomyTier == AutonomyTier2AppCodeOwnerReview
}

func pathNeedsApproval(path ActionPath) bool {
	if path.ApprovalGap {
		return true
	}
	switch normalizeEvidenceState(path.ApprovalEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		return path.AutonomyTier != AutonomyTier0SafeMetadata
	default:
		return false
	}
}

func pathHasMeaningfulGovernedSurface(path ActionPath) bool {
	return path.WriteCapable ||
		path.CredentialAccess ||
		path.PullRequestWrite ||
		path.MergeExecute ||
		path.DeployWrite ||
		path.ProductionWrite ||
		len(path.MatchedProductionTargets) > 0 ||
		pathHasAnyMutableEndpoint(path) ||
		sensitiveInfraSurface(path)
}

func pathNeedsProof(path ActionPath) bool {
	if len(path.RiskClassificationValidationReasons) > 0 {
		return true
	}
	if actionPathMissingProof(path) {
		return true
	}
	switch RuntimeEvidenceAbsenceStatus(path) {
	case RuntimeEvidenceAbsenceMissingRequired, RuntimeEvidenceAbsenceMissingForClaim:
		return true
	default:
		return false
	}
}

func standingCredentialWithBroadAuthority(path ActionPath) bool {
	if path.CredentialAuthority != nil && path.CredentialAuthority.StandingAccess {
		switch strings.TrimSpace(path.CredentialAuthority.AccessType) {
		case agginventory.CredentialAccessTypeStanding, agginventory.CredentialAccessTypeUnknown, "":
			return true
		}
	}
	return path.CredentialProvenance != nil && path.CredentialProvenance.StandingAccess
}

func sensitiveInfraSurface(path ActionPath) bool {
	location := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path.Location), "\\", "/"))
	if strings.Contains(location, ".github/workflows") ||
		strings.Contains(location, "jenkinsfile") ||
		strings.Contains(location, "terraform") ||
		strings.Contains(location, ".tf") ||
		strings.Contains(location, "cloudformation") ||
		strings.Contains(location, "helm") ||
		strings.Contains(location, "k8s") ||
		strings.Contains(location, "kubernetes") ||
		strings.Contains(location, "auth") ||
		strings.Contains(location, "identity") ||
		strings.Contains(location, "payment") ||
		strings.Contains(location, "publish") ||
		strings.Contains(location, ".mcp") ||
		strings.Contains(location, "agents.md") ||
		strings.Contains(location, "claude.md") ||
		strings.Contains(location, ".cursorrules") {
		return true
	}
	switch strings.TrimSpace(path.RiskZone) {
	case RiskZoneCICD, RiskZoneIAC, RiskZoneRelease, RiskZoneCredential, RiskZoneProductionData, RiskZoneExternalEgress:
		return true
	}
	if path.PathContext != nil && strings.TrimSpace(path.PathContext.Kind) == agginventory.PathContextDeployableSource {
		return true
	}
	return path.CredentialAccess || path.DeployWrite || pathHasAnyMutableEndpoint(path)
}

func workflowOrToolingControlSurface(path ActionPath) bool {
	location := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path.Location), "\\", "/"))
	return strings.Contains(location, ".github/workflows") ||
		strings.Contains(location, "jenkinsfile") ||
		strings.Contains(location, ".mcp") ||
		strings.Contains(location, "agents.md") ||
		strings.Contains(location, "claude.md") ||
		strings.Contains(location, ".cursorrules")
}

func hasClassificationReason(path ActionPath, reason string) bool {
	for _, item := range path.RiskClassificationValidationReasons {
		if strings.TrimSpace(item) == strings.TrimSpace(reason) {
			return true
		}
	}
	return false
}

func requiredAuthorityForPath(path ActionPath) string {
	switch {
	case standingCredentialWithBroadAuthority(path):
		return "replace standing credential with repo-scoped JIT or brokered authority"
	case path.CredentialAccess:
		return "use workload or brokered authority scoped to this exact path"
	case path.AutonomyTier == AutonomyTier4ProdPrivilegedCustomerImpact:
		return "require production-scoped owner and deploy authority"
	default:
		return "require explicit owner-scoped authority for this path"
	}
}

func requiredReviewForPath(path ActionPath) string {
	switch strings.TrimSpace(path.RecommendedControl) {
	case RecommendedControlSecurityReview:
		return "security review for sensitive code, infra, or production-bearing changes"
	case RecommendedControlOwnerReview:
		return "owner review for app-code or internal workflow changes"
	default:
		return "review per existing local governance policy"
	}
}

func requiredApprovalForPath(path ActionPath) string {
	if pathNeedsApproval(path) {
		return "record explicit owner approval with scope and expiry"
	}
	if strings.TrimSpace(path.DelegationReadinessState) == DelegationReadinessReadyForControl {
		return "approval evidence already present or path does not require separate approval"
	}
	return "approval only when the path changes production or privileged authority"
}

func requiredProofForPath(path ActionPath) string {
	if pathNeedsProof(path) {
		return "attach path-specific proof and runtime or policy evidence"
	}
	return "keep path-specific proof linked as the path evolves"
}

func validationStepForPath(path ActionPath) string {
	switch strings.TrimSpace(path.RecommendedControl) {
	case RecommendedControlBlockStandingCredential:
		return "replace standing credential, attach proof, and rerun the scan"
	case RecommendedControlApprovalRequired:
		return "attach owner approval evidence and rerun the scan"
	case RecommendedControlProofRequired, RecommendedControlJITCredentialRequired:
		return "attach proof or JIT credential evidence and rerun the scan"
	case RecommendedControlSecurityReview:
		return "complete security review, attach control evidence, and rerun the scan"
	case RecommendedControlOwnerReview:
		return "complete owner review and rerun the scan"
	default:
		return "rerun the scan and confirm the path stays byte-stable"
	}
}

func defaultPostureForPath(path ActionPath) string {
	switch strings.TrimSpace(path.RecommendedControl) {
	case RecommendedControlAllow:
		return "allow after deterministic local validation"
	case RecommendedControlOwnerReview, RecommendedControlSecurityReview:
		return "review before delegation"
	case RecommendedControlApprovalRequired:
		return "approval before delegation"
	case RecommendedControlProofRequired, RecommendedControlJITCredentialRequired:
		return "proof before delegation"
	default:
		return "block until contradictory or broad authority evidence is resolved"
	}
}

func deriveContractReadiness(path ActionPath) string {
	switch {
	case len(path.Contradictions) > 0 || actionPathHasContradictoryControlEvidence(path):
		return ActionContractReadinessBlockedContradict
	case normalizeEvidenceState(path.OwnerEvidenceState) == EvidenceStateUnknown || normalizeEvidenceState(path.OwnerEvidenceState) == EvidenceStateInferred:
		return ActionContractReadinessNeedsOwner
	case normalizeEvidenceState(path.ApprovalEvidenceState) == EvidenceStateUnknown || normalizeEvidenceState(path.ApprovalEvidenceState) == EvidenceStateInferred:
		return ActionContractReadinessNeedsApproval
	case pathNeedsProof(path):
		return ActionContractReadinessReadyForReportOnly
	case strings.TrimSpace(path.DelegationReadinessState) == DelegationReadinessReadyForControl || strings.TrimSpace(path.DelegationReadinessState) == DelegationReadinessSafeToDelegate:
		return ActionContractReadinessReadyForControl
	default:
		return ActionContractReadinessDraft
	}
}

func outcomeEvidenceState(path ActionPath) string {
	if state := normalizeEvidenceState(path.RuntimeEvidenceState); state != "" {
		return state
	}
	return normalizeEvidenceState(path.ProofEvidenceState)
}

func credentialModeForPath(path ActionPath) string {
	switch {
	case standingCredentialWithBroadAuthority(path):
		return "standing credential"
	case likelyJITCredential(path):
		return "jit credential"
	case path.CredentialAccess:
		return "scoped credential"
	default:
		return "no credential evidence"
	}
}

func recommendedCredentialModeForPath(path ActionPath) string {
	if strings.TrimSpace(path.RecommendedControl) == RecommendedControlBlockStandingCredential || strings.TrimSpace(path.RecommendedControl) == RecommendedControlJITCredentialRequired {
		return "jit or brokered credential"
	}
	return credentialModeForPath(path)
}

func governanceEvidenceSummary(path ActionPath) string {
	parts := []string{}
	switch strings.TrimSpace(path.RecommendedControl) {
	case RecommendedControlApprovalRequired:
		parts = append(parts, "owner approval")
	case RecommendedControlProofRequired:
		parts = append(parts, "path-specific proof")
	case RecommendedControlJITCredentialRequired:
		parts = append(parts, "jit credential proof")
	case RecommendedControlOwnerReview:
		parts = append(parts, "owner review")
	case RecommendedControlSecurityReview:
		parts = append(parts, "security review")
	case RecommendedControlBlockStandingCredential, RecommendedControlBlock:
		parts = append(parts, "blocking control")
	default:
		parts = append(parts, "local validation")
	}
	if pathNeedsProof(path) {
		parts = append(parts, "proof evidence")
	}
	if pathNeedsApproval(path) {
		parts = append(parts, "approval evidence")
	}
	return strings.Join(dedupeSortedStrings(parts), ", ")
}

func autonomyTierRank(value string) int {
	switch strings.TrimSpace(value) {
	case AutonomyTier4ProdPrivilegedCustomerImpact:
		return 0
	case AutonomyTier3SensitiveCodeOrInfra:
		return 1
	case AutonomyTier2AppCodeOwnerReview:
		return 2
	case AutonomyTier1LowRiskInternal:
		return 3
	default:
		return 4
	}
}

func delegationReadinessRank(value string) int {
	switch strings.TrimSpace(value) {
	case DelegationReadinessBlockedByContradiction:
		return 0
	case DelegationReadinessBlocked:
		return 1
	case DelegationReadinessProofRequired:
		return 2
	case DelegationReadinessApprovalRequired:
		return 3
	case DelegationReadinessReviewRequired:
		return 4
	case DelegationReadinessReadyForControl:
		return 5
	default:
		return 6
	}
}

func IncrementAutonomyTierCounts(counts *AutonomyTierCounts, tier string) {
	switch strings.TrimSpace(tier) {
	case AutonomyTier0SafeMetadata:
		counts.Tier0SafeMetadata++
	case AutonomyTier1LowRiskInternal:
		counts.Tier1LowRiskInternal++
	case AutonomyTier2AppCodeOwnerReview:
		counts.Tier2AppCodeOwnerReview++
	case AutonomyTier3SensitiveCodeOrInfra:
		counts.Tier3SensitiveCodeOrInfra++
	case AutonomyTier4ProdPrivilegedCustomerImpact:
		counts.Tier4ProdPrivilegedCustomerImpact++
	}
}

func IncrementDelegationReadinessCounts(counts *DelegationReadinessCounts, state string) {
	switch strings.TrimSpace(state) {
	case DelegationReadinessSafeToDelegate:
		counts.SafeToDelegate++
	case DelegationReadinessReviewRequired:
		counts.ReviewRequired++
	case DelegationReadinessApprovalRequired:
		counts.ApprovalRequired++
	case DelegationReadinessProofRequired:
		counts.ProofRequired++
	case DelegationReadinessReadyForControl:
		counts.ReadyForControl++
	case DelegationReadinessBlocked:
		counts.Blocked++
	case DelegationReadinessBlockedByContradiction:
		counts.BlockedByContradict++
	}
}

func IncrementRecommendedControlCounts(counts *RecommendedControlCounts, value string) {
	switch strings.TrimSpace(value) {
	case RecommendedControlAllow:
		counts.Allow++
	case RecommendedControlOwnerReview:
		counts.OwnerReview++
	case RecommendedControlSecurityReview:
		counts.SecurityReview++
	case RecommendedControlApprovalRequired:
		counts.ApprovalRequired++
	case RecommendedControlJITCredentialRequired:
		counts.JITCredentialRequired++
	case RecommendedControlProofRequired:
		counts.ProofRequired++
	case RecommendedControlBlockStandingCredential:
		counts.BlockStandingCredential++
	case RecommendedControlBlock:
		counts.Block++
	}
}

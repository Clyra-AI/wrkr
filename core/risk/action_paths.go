package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/owners"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

const actionPathIDPrefix = "apc-"

type ActionPathSummary struct {
	TotalPaths                   int      `json:"total_paths"`
	WriteCapablePaths            int      `json:"write_capable_paths"`
	CredentialAccessPaths        int      `json:"credential_access_paths"`
	StandingPrivilegePaths       int      `json:"standing_privilege_paths"`
	ProductionTargetBackedPaths  int      `json:"production_target_backed_paths"`
	ControlFirstPaths            int      `json:"control_first_paths"`
	GovernFirstPaths             int      `json:"govern_first_paths"`
	MissingApprovalPaths         int      `json:"missing_approval_paths"`
	MissingPolicyPaths           int      `json:"missing_policy_paths"`
	MissingProofPaths            int      `json:"missing_proof_paths"`
	UnresolvedOwnerPaths         int      `json:"unresolved_owner_paths"`
	HighReviewBurdenPaths        int      `json:"high_review_burden_paths"`
	ConfirmedActionPaths         int      `json:"confirmed_action_paths"`
	LikelyActionPaths            int      `json:"likely_action_paths"`
	SemanticReviewCandidatePaths int      `json:"semantic_review_candidate_paths"`
	ContextOnlyPaths             int      `json:"context_only_paths"`
	EmptyStateStatus             string   `json:"empty_state_status,omitempty"`
	EmptyStateReasons            []string `json:"empty_state_reasons,omitempty"`
}

type ActionPath struct {
	PathID                     string                                  `json:"path_id"`
	Org                        string                                  `json:"org"`
	Repo                       string                                  `json:"repo"`
	AgentID                    string                                  `json:"agent_id,omitempty"`
	ToolFamilyID               string                                  `json:"tool_family_id,omitempty"`
	ToolInstanceID             string                                  `json:"tool_instance_id,omitempty"`
	ToolType                   string                                  `json:"tool_type"`
	Location                   string                                  `json:"location,omitempty"`
	LocationRange              *model.LocationRange                    `json:"location_range,omitempty"`
	Purpose                    string                                  `json:"purpose,omitempty"`
	PurposeSource              string                                  `json:"purpose_source,omitempty"`
	PurposeConfidence          string                                  `json:"purpose_confidence,omitempty"`
	Version                    string                                  `json:"version,omitempty"`
	VersionSource              string                                  `json:"version_source,omitempty"`
	ConfigFingerprint          string                                  `json:"config_fingerprint,omitempty"`
	ConfigSource               string                                  `json:"config_source,omitempty"`
	WriteCapable               bool                                    `json:"write_capable"`
	OperationalOwner           string                                  `json:"operational_owner,omitempty"`
	OwnerSource                string                                  `json:"owner_source,omitempty"`
	OwnershipStatus            string                                  `json:"ownership_status,omitempty"`
	OwnershipState             string                                  `json:"ownership_state,omitempty"`
	OwnershipConfidence        float64                                 `json:"ownership_confidence,omitempty"`
	OwnershipEvidence          []string                                `json:"ownership_evidence_basis,omitempty"`
	OwnershipConflicts         []string                                `json:"ownership_conflicts,omitempty"`
	ApprovalGapReasons         []string                                `json:"approval_gap_reasons,omitempty"`
	WritePathClasses           []string                                `json:"write_path_classes,omitempty"`
	ActionClasses              []string                                `json:"action_classes,omitempty"`
	ActionReasons              []string                                `json:"action_reasons,omitempty"`
	PullRequestWrite           bool                                    `json:"pull_request_write,omitempty"`
	MergeExecute               bool                                    `json:"merge_execute,omitempty"`
	DeployWrite                bool                                    `json:"deploy_write,omitempty"`
	DeliveryChainStatus        string                                  `json:"delivery_chain_status,omitempty"`
	ProductionTargetStatus     string                                  `json:"production_target_status,omitempty"`
	ProductionWrite            bool                                    `json:"production_write"`
	ApprovalGap                bool                                    `json:"approval_gap"`
	SecurityVisibilityStatus   string                                  `json:"security_visibility_status,omitempty"`
	CredentialAccess           bool                                    `json:"credential_access"`
	Credentials                []*agginventory.CredentialProvenance    `json:"credentials,omitempty"`
	CredentialProvenance       *agginventory.CredentialProvenance      `json:"credential_provenance,omitempty"`
	CredentialAuthority        *agginventory.CredentialAuthority       `json:"credential_authority,omitempty"`
	PathContext                *agginventory.PathContext               `json:"path_context,omitempty"`
	TrustDepth                 *agginventory.TrustDepth                `json:"trust_depth,omitempty"`
	DeploymentStatus           string                                  `json:"deployment_status,omitempty"`
	WorkflowTriggerClass       string                                  `json:"workflow_trigger_class,omitempty"`
	ExecutionIdentity          string                                  `json:"execution_identity,omitempty"`
	ExecutionIdentityType      string                                  `json:"execution_identity_type,omitempty"`
	ExecutionIdentitySource    string                                  `json:"execution_identity_source,omitempty"`
	ExecutionIdentityStatus    string                                  `json:"execution_identity_status,omitempty"`
	ExecutionIdentityRationale string                                  `json:"execution_identity_rationale,omitempty"`
	BusinessStateSurface       string                                  `json:"business_state_surface,omitempty"`
	SharedExecutionIdentity    bool                                    `json:"shared_execution_identity,omitempty"`
	StandingPrivilege          bool                                    `json:"standing_privilege,omitempty"`
	StandingPrivilegeReasons   []string                                `json:"standing_privilege_reasons,omitempty"`
	ControlState               string                                  `json:"control_state,omitempty"`
	ControlStateReasons        []string                                `json:"control_state_reasons,omitempty"`
	RiskZone                   string                                  `json:"risk_zone,omitempty"`
	RiskZoneReasons            []string                                `json:"risk_zone_reasons,omitempty"`
	ReviewBurden               string                                  `json:"review_burden,omitempty"`
	ReviewBurdenReasons        []string                                `json:"review_burden_reasons,omitempty"`
	ConfidenceLane             string                                  `json:"confidence_lane,omitempty"`
	ConfidenceLaneReasons      []string                                `json:"confidence_lane_reasons,omitempty"`
	PolicyCoverageStatus       string                                  `json:"policy_coverage_status,omitempty"`
	PolicyRefs                 []string                                `json:"policy_refs,omitempty"`
	PolicyMissingReasons       []string                                `json:"policy_missing_reasons,omitempty"`
	PolicyStatusReasons        []string                                `json:"policy_status_reasons,omitempty"`
	PolicyConfidence           string                                  `json:"policy_confidence,omitempty"`
	PolicyEvidenceRefs         []string                                `json:"policy_evidence_refs,omitempty"`
	GaitCoverage               *GaitCoverage                           `json:"gait_coverage,omitempty"`
	IntroducedBy               *attribution.Result                     `json:"introduced_by,omitempty"`
	InventoryRisk              string                                  `json:"inventory_risk,omitempty"`
	ControlPriority            string                                  `json:"control_priority,omitempty"`
	RiskTier                   string                                  `json:"risk_tier,omitempty"`
	AttackPathScore            float64                                 `json:"attack_path_score"`
	RiskScore                  float64                                 `json:"risk_score"`
	RecommendedAction          string                                  `json:"recommended_action"`
	AttackPathRefs             []string                                `json:"attack_path_refs,omitempty"`
	SourceFindingKeys          []string                                `json:"source_finding_keys,omitempty"`
	MatchedProductionTargets   []string                                `json:"matched_production_targets,omitempty"`
	GovernanceControls         []agginventory.GovernanceControlMapping `json:"governance_controls,omitempty"`
	ActionLineage              *ActionLineage                          `json:"action_lineage,omitempty"`
}

type ActionPathToControlFirst struct {
	Summary ActionPathSummary `json:"summary"`
	Path    ActionPath        `json:"path"`
}

func BuildActionPaths(attackPaths []riskattack.ScoredPath, inventory *agginventory.Inventory) ([]ActionPath, *ActionPathToControlFirst) {
	if inventory == nil || len(inventory.AgentPrivilegeMap) == 0 {
		return nil, nil
	}

	attackScoreByRepo := map[string]float64{}
	for _, path := range attackPaths {
		key := repoKey(path.Org, path.Repo)
		if path.PathScore > attackScoreByRepo[key] {
			attackScoreByRepo[key] = path.PathScore
		}
	}

	paths := make([]ActionPath, 0, len(inventory.AgentPrivilegeMap))
	pathIndexByKey := map[string]int{}
	for _, entry := range inventory.AgentPrivilegeMap {
		if !shouldIncludeActionPath(entry) {
			continue
		}
		key := actionPathIdentityKey(entry)
		path := buildActionPath(entry, attackScoreByRepo, inventory.NonHumanIdentities)
		if idx, ok := pathIndexByKey[key]; ok {
			paths[idx] = mergeActionPath(paths[idx], path)
			continue
		}
		pathIndexByKey[key] = len(paths)
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil, nil
	}
	paths = DecorateActionPaths(paths)
	paths = LinkAttackPaths(paths, attackPaths)
	paths = applyLinkedAttackPathScores(paths, attackPaths)
	paths = ProjectActionPaths(paths)

	summary := summarizeActionPaths(paths)
	choice := &ActionPathToControlFirst{
		Summary: summary,
		Path:    paths[0],
	}
	return paths, choice
}

func buildActionPath(
	entry agginventory.AgentPrivilegeMapEntry,
	attackScoreByRepo map[string]float64,
	identities []agginventory.NonHumanIdentity,
) ActionPath {
	executionIdentity, executionIdentityType, executionIdentitySource, executionIdentityStatus, executionIdentityRationale := correlateExecutionIdentity(entry, identities)
	credentials := agginventory.NormalizeCredentialProvenances(entry.Credentials)
	provenance := agginventory.CredentialRollup(credentials, entry.CredentialProvenance)
	authority := agginventory.NormalizeCredentialAuthority(entry.CredentialAuthority)
	if len(credentials) == 0 && provenance != nil {
		credentials = agginventory.NormalizeCredentialProvenances([]*agginventory.CredentialProvenance{provenance})
	}
	standingPrivilege, standingReasons := agginventory.StandingPrivilegeFromProvenance(provenance)
	if authorityStanding, authorityReasons := agginventory.StandingPrivilegeFromAuthority(authority); authorityStanding {
		standingPrivilege = true
		standingReasons = dedupeSortedStrings(append(standingReasons, authorityReasons...))
	}
	path := ActionPath{
		PathID:                     actionPathID(entry),
		Org:                        strings.TrimSpace(entry.Org),
		Repo:                       firstRepoFromEntry(entry),
		AgentID:                    strings.TrimSpace(entry.AgentID),
		ToolFamilyID:               strings.TrimSpace(entry.ToolFamilyID),
		ToolInstanceID:             strings.TrimSpace(entry.ToolInstanceID),
		ToolType:                   actionPathToolType(entry),
		Location:                   strings.TrimSpace(entry.Location),
		LocationRange:              cloneLocationRange(entry.LocationRange),
		Purpose:                    strings.TrimSpace(entry.Purpose),
		PurposeSource:              strings.TrimSpace(entry.PurposeSource),
		PurposeConfidence:          strings.TrimSpace(entry.PurposeConfidence),
		Version:                    strings.TrimSpace(entry.Version),
		VersionSource:              strings.TrimSpace(entry.VersionSource),
		ConfigFingerprint:          strings.TrimSpace(entry.ConfigFingerprint),
		ConfigSource:               strings.TrimSpace(entry.ConfigSource),
		WriteCapable:               entry.WriteCapable,
		OperationalOwner:           strings.TrimSpace(entry.OperationalOwner),
		OwnerSource:                strings.TrimSpace(entry.OwnerSource),
		OwnershipStatus:            strings.TrimSpace(entry.OwnershipStatus),
		OwnershipState:             strings.TrimSpace(entry.OwnershipState),
		OwnershipConfidence:        entry.OwnershipConfidence,
		OwnershipEvidence:          dedupeSortedStrings(entry.OwnershipEvidence),
		OwnershipConflicts:         dedupeSortedStrings(entry.OwnershipConflicts),
		ApprovalGapReasons:         dedupeSortedStrings(entry.ApprovalGapReasons),
		WritePathClasses:           dedupeSortedStrings(entry.WritePathClasses),
		ActionClasses:              dedupeSortedStrings(entry.ActionClasses),
		ActionReasons:              dedupeSortedStrings(entry.ActionReasons),
		PullRequestWrite:           entry.PullRequestWrite,
		MergeExecute:               entry.MergeExecute,
		DeployWrite:                entry.DeployWrite,
		DeliveryChainStatus:        strings.TrimSpace(entry.DeliveryChainStatus),
		ProductionTargetStatus:     strings.TrimSpace(entry.ProductionTargetStatus),
		ProductionWrite:            entry.ProductionWrite,
		ApprovalGap:                actionPathApprovalGap(entry.ApprovalClassification, entry.ApprovalGapReasons),
		SecurityVisibilityStatus:   strings.TrimSpace(entry.SecurityVisibilityStatus),
		CredentialAccess:           entry.CredentialAccess,
		Credentials:                agginventory.CloneCredentialProvenances(credentials),
		CredentialProvenance:       agginventory.CloneCredentialProvenance(provenance),
		CredentialAuthority:        agginventory.CloneCredentialAuthority(authority),
		PathContext:                firstPathContext(entry.PathContext, entry.Location),
		TrustDepth:                 agginventory.CloneTrustDepth(entry.TrustDepth),
		DeploymentStatus:           strings.TrimSpace(entry.DeploymentStatus),
		WorkflowTriggerClass:       strings.TrimSpace(entry.WorkflowTriggerClass),
		ExecutionIdentity:          executionIdentity,
		ExecutionIdentityType:      executionIdentityType,
		ExecutionIdentitySource:    executionIdentitySource,
		ExecutionIdentityStatus:    executionIdentityStatus,
		ExecutionIdentityRationale: executionIdentityRationale,
		BusinessStateSurface:       classifyBusinessStateSurface(entry),
		AttackPathScore:            attackScoreByRepo[repoKey(entry.Org, firstRepoFromEntry(entry))],
		RiskScore:                  actionPathRiskScore(entry.RiskScore, provenance),
		StandingPrivilege:          entry.StandingPrivilege || standingPrivilege,
		StandingPrivilegeReasons:   dedupeSortedStrings(append(append([]string(nil), entry.StandingPrivilegeReasons...), standingReasons...)),
		PolicyCoverageStatus:       PolicyCoverageStatusNone,
		MatchedProductionTargets:   dedupeSortedStrings(entry.MatchedProductionTargets),
		GovernanceControls:         append([]agginventory.GovernanceControlMapping(nil), entry.GovernanceControls...),
	}
	return path
}

func shouldIncludeActionPath(entry agginventory.AgentPrivilegeMapEntry) bool {
	return entry.WriteCapable ||
		entry.CredentialAccess ||
		entry.ProductionWrite ||
		entry.PullRequestWrite ||
		entry.MergeExecute ||
		entry.DeployWrite ||
		actionPathHasCriticalTrustGap(agginventory.NormalizeTrustDepth(entry.TrustDepth)) ||
		actionPathApprovalGap(entry.ApprovalClassification, entry.ApprovalGapReasons)
}

func actionPathApprovalGap(status string, reasons []string) bool {
	if len(reasons) > 0 {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "unknown", "unapproved":
		return true
	default:
		return false
	}
}

func actionPriority(action string) int {
	switch strings.TrimSpace(action) {
	case "control":
		return 0
	case "approval":
		return 1
	case "proof":
		return 2
	case "inventory":
		return 3
	default:
		return 99
	}
}

func firstRepoFromEntry(entry agginventory.AgentPrivilegeMapEntry) string {
	if len(entry.Repos) == 0 {
		return ""
	}
	repos := append([]string(nil), entry.Repos...)
	sort.Strings(repos)
	return repos[0]
}

func actionPathToolType(entry agginventory.AgentPrivilegeMapEntry) string {
	if strings.TrimSpace(entry.Framework) != "" {
		return strings.TrimSpace(entry.Framework)
	}
	return strings.TrimSpace(entry.ToolType)
}

func actionPathID(entry agginventory.AgentPrivilegeMapEntry) string {
	return hashActionPathIdentity(actionPathIdentityKey(entry))
}

func actionPathIdentityKey(entry agginventory.AgentPrivilegeMapEntry) string {
	parts := []string{
		strings.TrimSpace(entry.Org),
		strings.Join(dedupeSortedStrings(entry.Repos), ","),
		strings.TrimSpace(entry.AgentID),
		strings.TrimSpace(entry.AgentInstanceID),
		strings.TrimSpace(entry.ToolID),
		actionPathToolType(entry),
		strings.TrimSpace(entry.Symbol),
		strings.TrimSpace(entry.Location),
		locationRangeKey(entry.LocationRange),
	}
	return strings.Join(parts, "|")
}

func hashActionPathIdentity(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return actionPathIDPrefix + hex.EncodeToString(sum[:6])
}

func locationRangeKey(locationRange *model.LocationRange) string {
	if locationRange == nil {
		return ""
	}
	return strconv.Itoa(locationRange.StartLine) + ":" + strconv.Itoa(locationRange.EndLine)
}

func cloneLocationRange(locationRange *model.LocationRange) *model.LocationRange {
	if locationRange == nil {
		return nil
	}
	return &model.LocationRange{
		StartLine: locationRange.StartLine,
		EndLine:   locationRange.EndLine,
	}
}

func mergeActionPath(current, incoming ActionPath) ActionPath {
	merged := current
	merged.WriteCapable = current.WriteCapable || incoming.WriteCapable
	merged.PullRequestWrite = current.PullRequestWrite || incoming.PullRequestWrite
	merged.MergeExecute = current.MergeExecute || incoming.MergeExecute
	merged.DeployWrite = current.DeployWrite || incoming.DeployWrite
	merged.ProductionWrite = current.ProductionWrite || incoming.ProductionWrite
	merged.ApprovalGap = current.ApprovalGap || incoming.ApprovalGap
	merged.CredentialAccess = current.CredentialAccess || incoming.CredentialAccess
	merged.Credentials = mergeCredentials(current.Credentials, incoming.Credentials)
	merged.CredentialProvenance = agginventory.CredentialRollup(merged.Credentials, mergeCredentialProvenance(current.CredentialProvenance, incoming.CredentialProvenance))
	merged.CredentialAuthority = mergeCredentialAuthority(current.CredentialAuthority, incoming.CredentialAuthority)
	merged.PathContext = mergePathContext(current.PathContext, incoming.PathContext)
	merged.TrustDepth = agginventory.MergeTrustDepth(current.TrustDepth, incoming.TrustDepth)
	merged.DeliveryChainStatus = actionPathDeliveryChainStatus(merged.PullRequestWrite, merged.MergeExecute, merged.DeployWrite)
	merged.AttackPathScore = maxFloat64(current.AttackPathScore, incoming.AttackPathScore)
	merged.RiskScore = maxFloat64(current.RiskScore, incoming.RiskScore)
	merged.ApprovalGapReasons = dedupeSortedStrings(append(append([]string(nil), current.ApprovalGapReasons...), incoming.ApprovalGapReasons...))
	merged.WritePathClasses = dedupeSortedStrings(append(append([]string(nil), current.WritePathClasses...), incoming.WritePathClasses...))
	merged.ActionClasses = dedupeSortedStrings(append(append([]string(nil), current.ActionClasses...), incoming.ActionClasses...))
	merged.ActionReasons = dedupeSortedStrings(append(append([]string(nil), current.ActionReasons...), incoming.ActionReasons...))
	merged.MatchedProductionTargets = dedupeSortedStrings(append(append([]string(nil), current.MatchedProductionTargets...), incoming.MatchedProductionTargets...))
	merged.ProductionTargetStatus = mergeProductionTargetStatus(current.ProductionTargetStatus, incoming.ProductionTargetStatus)
	merged.SecurityVisibilityStatus = mergeSecurityVisibilityStatus(current.SecurityVisibilityStatus, incoming.SecurityVisibilityStatus)
	merged.DeploymentStatus = mergeDeploymentStatus(current.DeploymentStatus, incoming.DeploymentStatus)
	merged.WorkflowTriggerClass = mergeWorkflowTriggerClass(current.WorkflowTriggerClass, incoming.WorkflowTriggerClass)
	merged.LocationRange = mergeLocationRange(current.LocationRange, incoming.LocationRange)
	merged.OperationalOwner, merged.OwnerSource, merged.OwnershipStatus = mergeOperationalOwner(current, incoming)
	merged.OwnershipState = mergeOwnershipState(current, incoming)
	merged.OwnershipConfidence = mergeOwnershipConfidence(current, incoming)
	merged.OwnershipEvidence = dedupeSortedStrings(append(append([]string(nil), current.OwnershipEvidence...), incoming.OwnershipEvidence...))
	merged.OwnershipConflicts = dedupeSortedStrings(append(append([]string(nil), current.OwnershipConflicts...), incoming.OwnershipConflicts...))
	merged.ExecutionIdentity, merged.ExecutionIdentityType, merged.ExecutionIdentitySource, merged.ExecutionIdentityStatus, merged.ExecutionIdentityRationale = mergeExecutionIdentity(current, incoming)
	merged.BusinessStateSurface = mergeBusinessStateSurface(current.BusinessStateSurface, incoming.BusinessStateSurface)
	merged.ToolFamilyID = firstNonEmptyString(current.ToolFamilyID, incoming.ToolFamilyID)
	merged.ToolInstanceID = firstNonEmptyString(current.ToolInstanceID, incoming.ToolInstanceID)
	merged.Purpose, merged.PurposeSource, merged.PurposeConfidence = mergePurposeMetadata(current, incoming)
	merged.Version = firstNonEmptyString(current.Version, incoming.Version)
	merged.VersionSource = chooseMetadataSource(current.VersionSource, incoming.VersionSource, current.Version, incoming.Version)
	merged.ConfigFingerprint = firstNonEmptyString(current.ConfigFingerprint, incoming.ConfigFingerprint)
	merged.ConfigSource = firstNonEmptyString(current.ConfigSource, incoming.ConfigSource)
	merged.StandingPrivilege = current.StandingPrivilege || incoming.StandingPrivilege
	merged.StandingPrivilegeReasons = dedupeSortedStrings(append(append([]string(nil), current.StandingPrivilegeReasons...), incoming.StandingPrivilegeReasons...))
	merged.ControlState = firstNonEmptyString(current.ControlState, incoming.ControlState)
	merged.ControlStateReasons = dedupeSortedStrings(append(append([]string(nil), current.ControlStateReasons...), incoming.ControlStateReasons...))
	merged.RiskZone = firstNonEmptyString(current.RiskZone, incoming.RiskZone)
	merged.RiskZoneReasons = dedupeSortedStrings(append(append([]string(nil), current.RiskZoneReasons...), incoming.RiskZoneReasons...))
	merged.ReviewBurden = firstNonEmptyString(current.ReviewBurden, incoming.ReviewBurden)
	merged.ReviewBurdenReasons = dedupeSortedStrings(append(append([]string(nil), current.ReviewBurdenReasons...), incoming.ReviewBurdenReasons...))
	merged.PolicyCoverageStatus = choosePolicyCoverageStatus(current.PolicyCoverageStatus, incoming.PolicyCoverageStatus)
	merged.PolicyRefs = dedupeSortedStrings(append(append([]string(nil), current.PolicyRefs...), incoming.PolicyRefs...))
	merged.PolicyMissingReasons = dedupeSortedStrings(append(append([]string(nil), current.PolicyMissingReasons...), incoming.PolicyMissingReasons...))
	merged.PolicyStatusReasons = dedupeSortedStrings(append(append([]string(nil), current.PolicyStatusReasons...), incoming.PolicyStatusReasons...))
	merged.PolicyConfidence = choosePolicyConfidence(current.PolicyConfidence, incoming.PolicyConfidence)
	merged.PolicyEvidenceRefs = dedupeSortedStrings(append(append([]string(nil), current.PolicyEvidenceRefs...), incoming.PolicyEvidenceRefs...))
	merged.GaitCoverage = MergeGaitCoverage(current.GaitCoverage, incoming.GaitCoverage)
	merged.IntroducedBy = attribution.Merge(current.IntroducedBy, incoming.IntroducedBy)
	merged.GovernanceControls = mergeGovernanceControls(current.GovernanceControls, incoming.GovernanceControls)
	merged.AttackPathRefs = dedupeSortedStrings(append(append([]string(nil), current.AttackPathRefs...), incoming.AttackPathRefs...))
	merged.SourceFindingKeys = dedupeSortedStrings(append(append([]string(nil), current.SourceFindingKeys...), incoming.SourceFindingKeys...))
	merged.ActionLineage = CloneActionLineage(firstNonNilLineage(current.ActionLineage, incoming.ActionLineage))
	return merged
}

func summarizeActionPaths(paths []ActionPath) ActionPathSummary {
	return SummarizeActionPaths(paths, ActionPathSummaryOptions{})
}

func actionPathHasCriticalTrustGap(depth *agginventory.TrustDepth) bool {
	normalized := agginventory.NormalizeTrustDepth(depth)
	if normalized == nil {
		return false
	}
	if normalized.Exposure == agginventory.TrustExposurePublic && normalized.GatewayCoverage == agginventory.TrustCoverageUnprotected {
		return true
	}
	if normalized.DelegationModel == agginventory.TrustDelegationAgent && normalized.PolicyBinding != agginventory.TrustPolicyDeclared {
		return true
	}
	for _, gap := range normalized.TrustGaps {
		switch strings.TrimSpace(gap) {
		case "public_exposure", "gateway_unprotected", "delegation_without_policy":
			return true
		}
	}
	return false
}

func ApplyGovernFirstProfile(profileName string, paths []ActionPath) ([]ActionPath, *ActionPathToControlFirst) {
	if len(paths) == 0 {
		return nil, nil
	}
	filtered := append([]ActionPath(nil), paths...)
	if strings.EqualFold(strings.TrimSpace(profileName), "assessment") {
		filtered = make([]ActionPath, 0, len(paths))
		for _, path := range paths {
			if assessmentSuppressesPath(path) {
				continue
			}
			filtered = append(filtered, path)
		}
	}
	filtered = ProjectActionPaths(filtered)
	return filtered, buildActionPathChoice(filtered)
}

func buildActionPathChoice(paths []ActionPath) *ActionPathToControlFirst {
	if len(paths) == 0 {
		return nil
	}
	return &ActionPathToControlFirst{
		Summary: summarizeActionPaths(paths),
		Path:    paths[0],
	}
}

func BuildActionPathChoice(paths []ActionPath) *ActionPathToControlFirst {
	return buildActionPathChoice(paths)
}

func BuildControlPathGraph(paths []ActionPath) *aggattack.ControlPathGraph {
	if len(paths) == 0 {
		return nil
	}
	inputs := make([]aggattack.ControlPathInput, 0, len(paths))
	for _, path := range paths {
		inputs = append(inputs, aggattack.ControlPathInput{
			PathID:                   strings.TrimSpace(path.PathID),
			AgentID:                  strings.TrimSpace(path.AgentID),
			Org:                      strings.TrimSpace(path.Org),
			Repo:                     strings.TrimSpace(path.Repo),
			ToolType:                 strings.TrimSpace(path.ToolType),
			Location:                 strings.TrimSpace(path.Location),
			Purpose:                  strings.TrimSpace(path.Purpose),
			PurposeSource:            strings.TrimSpace(path.PurposeSource),
			PurposeConfidence:        strings.TrimSpace(path.PurposeConfidence),
			Version:                  strings.TrimSpace(path.Version),
			VersionSource:            strings.TrimSpace(path.VersionSource),
			ConfigFingerprint:        strings.TrimSpace(path.ConfigFingerprint),
			ConfigSource:             strings.TrimSpace(path.ConfigSource),
			ExecutionIdentity:        strings.TrimSpace(path.ExecutionIdentity),
			ExecutionIdentityType:    strings.TrimSpace(path.ExecutionIdentityType),
			ExecutionIdentitySource:  strings.TrimSpace(path.ExecutionIdentitySource),
			ExecutionIdentityStatus:  strings.TrimSpace(path.ExecutionIdentityStatus),
			CredentialAccess:         path.CredentialAccess,
			CredentialProvenance:     agginventory.CloneCredentialProvenance(path.CredentialProvenance),
			CredentialAuthority:      agginventory.CloneCredentialAuthority(path.CredentialAuthority),
			GovernanceControls:       append([]agginventory.GovernanceControlMapping(nil), path.GovernanceControls...),
			MatchedProductionTargets: dedupeSortedStrings(path.MatchedProductionTargets),
			WritePathClasses:         dedupeSortedStrings(path.WritePathClasses),
			PullRequestWrite:         path.PullRequestWrite,
			MergeExecute:             path.MergeExecute,
			DeployWrite:              path.DeployWrite,
			ProductionWrite:          path.ProductionWrite,
			ApprovalGap:              path.ApprovalGap,
			AttackPathRefs:           dedupeSortedStrings(path.AttackPathRefs),
			SourceFindingKeys:        dedupeSortedStrings(path.SourceFindingKeys),
		})
	}
	return aggattack.BuildControlPathGraph(inputs)
}

func dedupeSortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func actionPathRiskScore(base float64, provenance *agginventory.CredentialProvenance) float64 {
	score := base
	if score <= 0 {
		return score
	}
	normalized := agginventory.NormalizeCredentialProvenance(provenance)
	if normalized == nil {
		return score
	}
	score = score * normalized.RiskMultiplier
	if score > 10 {
		score = 10
	}
	return score
}

func mergeCredentialProvenance(current, incoming *agginventory.CredentialProvenance) *agginventory.CredentialProvenance {
	current = agginventory.NormalizeCredentialProvenance(current)
	incoming = agginventory.NormalizeCredentialProvenance(incoming)
	switch {
	case current == nil:
		return agginventory.CloneCredentialProvenance(incoming)
	case incoming == nil:
		return agginventory.CloneCredentialProvenance(current)
	case current.Type == incoming.Type && current.Subject == incoming.Subject && current.Scope == incoming.Scope:
		merged := agginventory.CloneCredentialProvenance(current)
		merged.EvidenceBasis = dedupeSortedStrings(append(append([]string(nil), current.EvidenceBasis...), incoming.EvidenceBasis...))
		merged.RiskMultiplier = maxFloat64(current.RiskMultiplier, incoming.RiskMultiplier)
		if credentialConfidencePriority(incoming.Confidence) > credentialConfidencePriority(current.Confidence) {
			merged.Confidence = incoming.Confidence
		}
		return agginventory.NormalizeCredentialProvenance(merged)
	default:
		merged := &agginventory.CredentialProvenance{
			Type:           agginventory.CredentialProvenanceUnknown,
			Scope:          agginventory.CredentialScopeUnknown,
			Confidence:     "low",
			EvidenceBasis:  dedupeSortedStrings(append(append([]string(nil), current.EvidenceBasis...), incoming.EvidenceBasis...)),
			RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceUnknown),
		}
		merged.EvidenceBasis = dedupeSortedStrings(append(merged.EvidenceBasis,
			"conflict:"+current.Type,
			"conflict:"+incoming.Type,
		))
		return agginventory.NormalizeCredentialProvenance(merged)
	}
}

func mergeCredentials(current, incoming []*agginventory.CredentialProvenance) []*agginventory.CredentialProvenance {
	combined := append(agginventory.CloneCredentialProvenances(current), agginventory.CloneCredentialProvenances(incoming)...)
	return agginventory.NormalizeCredentialProvenances(combined)
}

func mergeCredentialAuthority(current, incoming *agginventory.CredentialAuthority) *agginventory.CredentialAuthority {
	current = agginventory.NormalizeCredentialAuthority(current)
	incoming = agginventory.NormalizeCredentialAuthority(incoming)
	switch {
	case current == nil:
		return agginventory.CloneCredentialAuthority(incoming)
	case incoming == nil:
		return agginventory.CloneCredentialAuthority(current)
	default:
		merged := agginventory.CloneCredentialAuthority(current)
		merged.CredentialPresent = current.CredentialPresent || incoming.CredentialPresent
		merged.CredentialReferencedByWorkflow = current.CredentialReferencedByWorkflow || incoming.CredentialReferencedByWorkflow
		merged.CredentialUsableByPath = current.CredentialUsableByPath || incoming.CredentialUsableByPath
		merged.CredentialKind = firstNonEmptyString(current.CredentialKind, incoming.CredentialKind)
		merged.AccessType = firstNonEmptyString(current.AccessType, incoming.AccessType)
		merged.StandingAccess = current.StandingAccess || incoming.StandingAccess
		merged.LikelyJIT = current.LikelyJIT || incoming.LikelyJIT
		merged.RotationEvidenceStatus = chooseMetadataSource(current.RotationEvidenceStatus, incoming.RotationEvidenceStatus, current.RotationEvidenceStatus, incoming.RotationEvidenceStatus)
		merged.CredentialSource = firstNonEmptyString(current.CredentialSource, incoming.CredentialSource)
		if credentialConfidencePriority(incoming.Confidence) > credentialConfidencePriority(current.Confidence) {
			merged.Confidence = incoming.Confidence
		}
		merged.ReasonCodes = dedupeSortedStrings(append(append([]string(nil), current.ReasonCodes...), incoming.ReasonCodes...))
		return agginventory.NormalizeCredentialAuthority(merged)
	}
}

func mergePathContext(current, incoming *agginventory.PathContext) *agginventory.PathContext {
	if current == nil {
		return agginventory.ClonePathContext(incoming)
	}
	if incoming == nil {
		return agginventory.ClonePathContext(current)
	}
	if current.Kind == incoming.Kind {
		merged := agginventory.ClonePathContext(current)
		merged.Reasons = dedupeSortedStrings(append(append([]string(nil), current.Reasons...), incoming.Reasons...))
		if contextConfidencePriority(incoming.Confidence) > contextConfidencePriority(current.Confidence) {
			merged.Confidence = incoming.Confidence
		}
		return merged
	}
	if contextConfidencePriority(incoming.Confidence) > contextConfidencePriority(current.Confidence) {
		return agginventory.ClonePathContext(incoming)
	}
	return agginventory.ClonePathContext(current)
}

func mergePurposeMetadata(current, incoming ActionPath) (string, string, string) {
	if strings.TrimSpace(current.Purpose) == "" {
		return strings.TrimSpace(incoming.Purpose), strings.TrimSpace(incoming.PurposeSource), strings.TrimSpace(incoming.PurposeConfidence)
	}
	if strings.TrimSpace(incoming.Purpose) == "" {
		return strings.TrimSpace(current.Purpose), strings.TrimSpace(current.PurposeSource), strings.TrimSpace(current.PurposeConfidence)
	}
	if strings.EqualFold(strings.TrimSpace(current.Purpose), strings.TrimSpace(incoming.Purpose)) {
		if contextConfidencePriority(incoming.PurposeConfidence) > contextConfidencePriority(current.PurposeConfidence) {
			return strings.TrimSpace(incoming.Purpose), strings.TrimSpace(incoming.PurposeSource), strings.TrimSpace(incoming.PurposeConfidence)
		}
		return strings.TrimSpace(current.Purpose), strings.TrimSpace(current.PurposeSource), strings.TrimSpace(current.PurposeConfidence)
	}
	if contextConfidencePriority(incoming.PurposeConfidence) > contextConfidencePriority(current.PurposeConfidence) {
		return strings.TrimSpace(incoming.Purpose), strings.TrimSpace(incoming.PurposeSource), strings.TrimSpace(incoming.PurposeConfidence)
	}
	return strings.TrimSpace(current.Purpose), strings.TrimSpace(current.PurposeSource), strings.TrimSpace(current.PurposeConfidence)
}

func chooseMetadataSource(currentSource, incomingSource, currentValue, incomingValue string) string {
	currentSource = strings.TrimSpace(currentSource)
	incomingSource = strings.TrimSpace(incomingSource)
	currentValue = strings.TrimSpace(currentValue)
	incomingValue = strings.TrimSpace(incomingValue)
	switch {
	case currentValue == "":
		return incomingSource
	case incomingValue == "":
		return currentSource
	case strings.EqualFold(currentValue, incomingValue):
		return firstNonEmptyString(currentSource, incomingSource)
	default:
		return firstNonEmptyString(currentSource, incomingSource)
	}
}

func firstNonNilLineage(values ...*ActionLineage) *ActionLineage {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func firstPathContext(context *agginventory.PathContext, location string) *agginventory.PathContext {
	if context != nil {
		return agginventory.ClonePathContext(context)
	}
	return agginventory.ClassifyPathContext(location)
}

func contextConfidencePriority(value string) int {
	switch strings.TrimSpace(value) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func credentialProvenancePriority(provenance *agginventory.CredentialProvenance) int {
	normalized := agginventory.NormalizeCredentialProvenance(provenance)
	if normalized == nil {
		return 0
	}
	switch normalized.CredentialKind {
	case agginventory.CredentialKindCloudAdminKey:
		return 7
	case agginventory.CredentialKindGitHubPAT, agginventory.CredentialKindUnknownDurable:
		return 6
	case agginventory.CredentialKindInheritedHuman:
		return 5
	case agginventory.CredentialKindGitHubWorkflowToken:
		return 3
	case agginventory.CredentialKindGitHubAppKey, agginventory.CredentialKindDeployKey, agginventory.CredentialKindCloudAccessKey, agginventory.CredentialKindStaticSecret:
		return 4
	case agginventory.CredentialKindDelegatedOAuth:
		return 2
	case agginventory.CredentialKindOIDCWorkloadID, agginventory.CredentialKindJITCredential:
		return 1
	default:
		switch normalized.Type {
		case agginventory.CredentialProvenanceUnknown:
			return 5
		case agginventory.CredentialProvenanceInheritedHuman:
			return 4
		case agginventory.CredentialProvenanceStaticSecret:
			return 3
		case agginventory.CredentialProvenanceOAuthDelegation:
			return 2
		case agginventory.CredentialProvenanceWorkloadIdentity, agginventory.CredentialProvenanceJIT:
			return 1
		default:
			return 0
		}
	}
}

func credentialAuthorityPriority(authority *agginventory.CredentialAuthority, provenance *agginventory.CredentialProvenance) int {
	normalized := agginventory.NormalizeCredentialAuthority(authority)
	if normalized == nil {
		return credentialProvenancePriority(provenance)
	}
	switch normalized.CredentialKind {
	case agginventory.CredentialKindCloudAdminKey:
		return 7
	case agginventory.CredentialKindGitHubPAT, agginventory.CredentialKindUnknownDurable:
		return 6
	case agginventory.CredentialKindInheritedHuman:
		return 5
	case agginventory.CredentialKindGitHubAppKey, agginventory.CredentialKindDeployKey, agginventory.CredentialKindCloudAccessKey, agginventory.CredentialKindStaticSecret:
		return 4
	case agginventory.CredentialKindGitHubWorkflowToken:
		return 3
	case agginventory.CredentialKindDelegatedOAuth:
		return 2
	case agginventory.CredentialKindOIDCWorkloadID, agginventory.CredentialKindJITCredential:
		return 1
	default:
		return credentialProvenancePriority(provenance)
	}
}

func credentialConfidencePriority(value string) int {
	switch strings.TrimSpace(value) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func actionPathDeliveryChainStatus(pullRequestWrite, mergeExecute, deployWrite bool) string {
	switch {
	case pullRequestWrite && mergeExecute && deployWrite:
		return "pr_merge_deploy"
	case mergeExecute && deployWrite:
		return "merge_deploy"
	case pullRequestWrite && mergeExecute:
		return "pr_merge"
	case deployWrite:
		return "deploy_only"
	case pullRequestWrite:
		return "pr_only"
	case mergeExecute:
		return "merge_only"
	default:
		return "none"
	}
}

func assessmentSuppressesPath(path ActionPath) bool {
	for _, value := range []string{path.Repo, path.Location} {
		if value == "" {
			continue
		}
		for _, segment := range assessmentSegments(value) {
			if assessmentSuppressionToken(segment) {
				return true
			}
		}
	}
	return false
}

func assessmentSegments(value string) []string {
	raw := strings.ToLower(strings.TrimSpace(value))
	if raw == "" {
		return nil
	}

	segments := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	seen := map[string]struct{}{}
	out := make([]string, 0, len(segments)*4)
	for _, segment := range segments {
		for _, candidate := range assessmentSegmentCandidates(segment) {
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			out = append(out, candidate)
		}
	}
	return out
}

func assessmentSegmentCandidates(segment string) []string {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return nil
	}

	candidates := []string{segment}
	trimmed := strings.Trim(segment, " ._-")
	if trimmed != "" && trimmed != segment {
		candidates = append(candidates, trimmed)
	}
	if trimmed != "" {
		parts := strings.FieldsFunc(trimmed, func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		})
		for _, part := range parts {
			if part == "" || part == trimmed {
				continue
			}
			candidates = append(candidates, part)
		}
		if dot := strings.LastIndex(trimmed, "."); dot > 0 {
			base := trimmed[:dot]
			if base != "" && base != trimmed {
				candidates = append(candidates, base)
			}
		}
	}
	return candidates
}

func assessmentSuppressionToken(value string) bool {
	switch value {
	case "examples", "example", "sample", "samples", "demo", "tests", "test", "testdata", "fixtures", "vendor", "node_modules", ".venv", "venv", "generated", "__generated__":
		return true
	default:
		return false
	}
}

func mergeProductionTargetStatus(current, incoming string) string {
	switch {
	case strings.TrimSpace(current) == agginventory.ProductionTargetsStatusInvalid || strings.TrimSpace(incoming) == agginventory.ProductionTargetsStatusInvalid:
		return agginventory.ProductionTargetsStatusInvalid
	case strings.TrimSpace(current) == agginventory.ProductionTargetsStatusConfigured || strings.TrimSpace(incoming) == agginventory.ProductionTargetsStatusConfigured:
		return agginventory.ProductionTargetsStatusConfigured
	case strings.TrimSpace(current) != "":
		return strings.TrimSpace(current)
	default:
		return strings.TrimSpace(incoming)
	}
}

func mergeSecurityVisibilityStatus(current, incoming string) string {
	if securityVisibilityPriority(incoming) < securityVisibilityPriority(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func securityVisibilityPriority(status string) int {
	switch strings.TrimSpace(status) {
	case agginventory.SecurityVisibilityUnknownToSecurity:
		return 0
	case agginventory.SecurityVisibilityRevoked:
		return 1
	case agginventory.SecurityVisibilityDeprecated:
		return 2
	case agginventory.SecurityVisibilityNeedsReview:
		return 3
	case agginventory.SecurityVisibilityAcceptedRisk:
		return 4
	case agginventory.SecurityVisibilityKnownUnapproved:
		return 5
	case agginventory.SecurityVisibilityApproved, agginventory.SecurityVisibilityKnownApproved:
		return 6
	case "":
		return 7
	default:
		return 8
	}
}

func mergeDeploymentStatus(current, incoming string) string {
	currentNormalized := strings.TrimSpace(current)
	incomingNormalized := strings.TrimSpace(incoming)
	switch {
	case strings.EqualFold(currentNormalized, "deployed") || strings.EqualFold(incomingNormalized, "deployed"):
		return "deployed"
	case currentNormalized == "" || strings.EqualFold(currentNormalized, "unknown"):
		return incomingNormalized
	case incomingNormalized == "" || strings.EqualFold(incomingNormalized, "unknown"):
		return currentNormalized
	case currentNormalized <= incomingNormalized:
		return currentNormalized
	default:
		return incomingNormalized
	}
}

func mergeOperationalOwner(current, incoming ActionPath) (string, string, string) {
	currentPriority := ownershipPriority(current.OwnershipStatus)
	incomingPriority := ownershipPriority(incoming.OwnershipStatus)
	switch {
	case incomingPriority < currentPriority:
		return incoming.OperationalOwner, incoming.OwnerSource, incoming.OwnershipStatus
	case currentPriority < incomingPriority:
		return current.OperationalOwner, current.OwnerSource, current.OwnershipStatus
	default:
		return canonicalString(current.OperationalOwner, incoming.OperationalOwner),
			canonicalString(current.OwnerSource, incoming.OwnerSource),
			canonicalString(current.OwnershipStatus, incoming.OwnershipStatus)
	}
}

func mergeOwnershipState(current, incoming ActionPath) string {
	if strings.TrimSpace(current.OwnerSource) == owners.OwnerSourceConflict || strings.TrimSpace(incoming.OwnerSource) == owners.OwnerSourceConflict {
		return owners.OwnershipStateConflicting
	}
	if ownershipStatePriority(incoming.OwnershipState) < ownershipStatePriority(current.OwnershipState) {
		return strings.TrimSpace(incoming.OwnershipState)
	}
	if ownershipStatePriority(current.OwnershipState) < ownershipStatePriority(incoming.OwnershipState) {
		return strings.TrimSpace(current.OwnershipState)
	}
	return canonicalString(current.OwnershipState, incoming.OwnershipState)
}

func mergeOwnershipConfidence(current, incoming ActionPath) float64 {
	if strings.TrimSpace(current.OwnerSource) == owners.OwnerSourceConflict || strings.TrimSpace(incoming.OwnerSource) == owners.OwnerSourceConflict {
		return minNonZeroFloat64(current.OwnershipConfidence, incoming.OwnershipConfidence, 0.2)
	}
	if current.OwnershipConfidence == 0 {
		return incoming.OwnershipConfidence
	}
	if incoming.OwnershipConfidence == 0 {
		return current.OwnershipConfidence
	}
	if incoming.OwnershipConfidence < current.OwnershipConfidence {
		return incoming.OwnershipConfidence
	}
	return current.OwnershipConfidence
}

func ownershipPriority(status string) int {
	switch strings.TrimSpace(status) {
	case "explicit":
		return 0
	case "inferred":
		return 1
	case "unresolved":
		return 2
	case "":
		return 3
	default:
		return 4
	}
}

func ownershipStatePriority(state string) int {
	switch strings.TrimSpace(state) {
	case owners.OwnershipStateExplicit:
		return 0
	case owners.OwnershipStateInferred:
		return 1
	case owners.OwnershipStateConflicting:
		return 2
	case owners.OwnershipStateMissing:
		return 3
	case "":
		return 4
	default:
		return 5
	}
}

func minNonZeroFloat64(values ...float64) float64 {
	min := 0.0
	for _, value := range values {
		if value == 0 {
			continue
		}
		if min == 0 || value < min {
			min = value
		}
	}
	return min
}

func governFirstPriorityScore(path ActionPath) int {
	score := 0
	if path.ProductionWrite {
		score += 15
	}
	if path.DeployWrite {
		score += 10
	}
	if path.MergeExecute {
		score += 8
	}
	if path.PullRequestWrite {
		score += 6
	}
	if path.WriteCapable {
		score += 5
	}
	if path.CredentialAccess {
		score += 4
	}
	score += credentialAuthorityPriority(path.CredentialAuthority, path.CredentialProvenance)
	if path.StandingPrivilege {
		score += 6
	}
	if path.ApprovalGap {
		score += 4
	}
	if strings.TrimSpace(path.SecurityVisibilityStatus) == agginventory.SecurityVisibilityUnknownToSecurity {
		score += 4
	}
	switch strings.TrimSpace(path.ExecutionIdentityStatus) {
	case "known":
		score += 3
	case "ambiguous", "unknown", "":
		score += 2
	}
	switch strings.TrimSpace(path.OwnershipStatus) {
	case owners.OwnershipStatusUnresolved:
		score += 3
	case owners.OwnershipStatusInferred:
		score += 1
	}
	if strings.TrimSpace(path.OwnerSource) == owners.OwnerSourceConflict {
		score += 4
	}
	switch strings.TrimSpace(path.WorkflowTriggerClass) {
	case "deploy_pipeline":
		score += 5
	case "scheduled":
		score += 3
	case "workflow_dispatch":
		score += 1
	}
	if actionPathHighImpact(path) {
		score += 4
	}
	return score
}

func workflowTriggerPriority(triggerClass string) int {
	switch strings.TrimSpace(triggerClass) {
	case "deploy_pipeline":
		return 0
	case "scheduled":
		return 1
	case "workflow_dispatch":
		return 2
	case "":
		return 3
	default:
		return 4
	}
}

func mergeWorkflowTriggerClass(current, incoming string) string {
	if workflowTriggerPriority(incoming) < workflowTriggerPriority(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func mergeExecutionIdentity(current, incoming ActionPath) (string, string, string, string, string) {
	currentStatus := strings.TrimSpace(current.ExecutionIdentityStatus)
	incomingStatus := strings.TrimSpace(incoming.ExecutionIdentityStatus)
	switch {
	case currentStatus == "ambiguous" || incomingStatus == "ambiguous":
		return "", "ambiguous", "", "ambiguous", "multiple non-human identity candidates matched this path"
	case currentStatus == "known" && incomingStatus == "known":
		if current.ExecutionIdentity == incoming.ExecutionIdentity &&
			current.ExecutionIdentityType == incoming.ExecutionIdentityType &&
			current.ExecutionIdentitySource == incoming.ExecutionIdentitySource {
			return current.ExecutionIdentity, current.ExecutionIdentityType, current.ExecutionIdentitySource, "known", current.ExecutionIdentityRationale
		}
		return "", "ambiguous", "", "ambiguous", "multiple non-human identity candidates matched this path"
	case currentStatus == "known":
		return current.ExecutionIdentity, current.ExecutionIdentityType, current.ExecutionIdentitySource, currentStatus, current.ExecutionIdentityRationale
	case incomingStatus == "known":
		return incoming.ExecutionIdentity, incoming.ExecutionIdentityType, incoming.ExecutionIdentitySource, incomingStatus, incoming.ExecutionIdentityRationale
	case currentStatus == "":
		return incoming.ExecutionIdentity, incoming.ExecutionIdentityType, incoming.ExecutionIdentitySource, incomingStatus, incoming.ExecutionIdentityRationale
	default:
		return current.ExecutionIdentity, current.ExecutionIdentityType, current.ExecutionIdentitySource, currentStatus, current.ExecutionIdentityRationale
	}
}

func mergeLocationRange(current, incoming *model.LocationRange) *model.LocationRange {
	switch {
	case current == nil:
		return cloneLocationRange(incoming)
	case incoming == nil:
		return cloneLocationRange(current)
	default:
		return cloneLocationRange(current)
	}
}

func canonicalString(current, incoming string) string {
	current = strings.TrimSpace(current)
	incoming = strings.TrimSpace(incoming)
	switch {
	case current == "":
		return incoming
	case incoming == "":
		return current
	case current <= incoming:
		return current
	default:
		return incoming
	}
}

func maxFloat64(current, incoming float64) float64 {
	if incoming > current {
		return incoming
	}
	return current
}

func correlateExecutionIdentity(entry agginventory.AgentPrivilegeMapEntry, identities []agginventory.NonHumanIdentity) (string, string, string, string, string) {
	if len(identities) == 0 {
		return "", "", "", "unknown", "no static non-human identity evidence matched this path"
	}
	matches := make([]agginventory.NonHumanIdentity, 0)
	repoScopedMatches := make([]agginventory.NonHumanIdentity, 0)
	for _, identity := range identities {
		if strings.TrimSpace(identity.Org) != strings.TrimSpace(entry.Org) {
			continue
		}
		if !entryContainsRepo(entry, identity.Repo) {
			continue
		}
		repoScopedMatches = append(repoScopedMatches, identity)
		if strings.TrimSpace(identity.Location) != strings.TrimSpace(entry.Location) {
			continue
		}
		matches = append(matches, identity)
	}
	if len(matches) == 0 {
		return correlateRepoScopedIdentity(repoScopedMatches)
	}
	if len(matches) == 1 {
		if strings.TrimSpace(matches[0].IdentityType) == "unknown" {
			return "", "unknown", strings.TrimSpace(matches[0].Source), "unknown", "static identity evidence stayed ambiguous for this path"
		}
		return strings.TrimSpace(matches[0].Subject), strings.TrimSpace(matches[0].IdentityType), strings.TrimSpace(matches[0].Source), "known", "static workflow identity evidence matched this path"
	}
	unique := map[string]agginventory.NonHumanIdentity{}
	for _, item := range matches {
		key := strings.Join([]string{item.IdentityType, item.Subject, item.Source}, "|")
		unique[key] = item
	}
	if len(unique) == 1 {
		for _, item := range unique {
			if strings.TrimSpace(item.IdentityType) == "unknown" {
				return "", "unknown", strings.TrimSpace(item.Source), "unknown", "static identity evidence stayed ambiguous for this path"
			}
			return strings.TrimSpace(item.Subject), strings.TrimSpace(item.IdentityType), strings.TrimSpace(item.Source), "known", "static workflow identity evidence matched this path"
		}
	}
	return "", "ambiguous", "", "ambiguous", fmt.Sprintf("%d non-human identity candidates matched this path", len(unique))
}

func mergeGovernanceControls(current, incoming []agginventory.GovernanceControlMapping) []agginventory.GovernanceControlMapping {
	byControl := map[string]agginventory.GovernanceControlMapping{}
	for _, item := range append(append([]agginventory.GovernanceControlMapping(nil), current...), incoming...) {
		control := strings.TrimSpace(item.Control)
		if control == "" {
			continue
		}
		existing, ok := byControl[control]
		if !ok || governanceControlStatusPriority(item.Status) < governanceControlStatusPriority(existing.Status) {
			item.Evidence = dedupeSortedStrings(item.Evidence)
			item.Gaps = dedupeSortedStrings(item.Gaps)
			byControl[control] = item
			continue
		}
		if governanceControlStatusPriority(item.Status) == governanceControlStatusPriority(existing.Status) {
			existing.Evidence = dedupeSortedStrings(append(existing.Evidence, item.Evidence...))
			existing.Gaps = dedupeSortedStrings(append(existing.Gaps, item.Gaps...))
			byControl[control] = existing
		}
	}
	out := make([]agginventory.GovernanceControlMapping, 0, len(byControl))
	for _, item := range byControl {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Control < out[j].Control
	})
	return out
}

func governanceControlStatusPriority(status string) int {
	switch strings.TrimSpace(status) {
	case agginventory.ControlStatusGap:
		return 0
	case agginventory.ControlStatusSatisfied:
		return 1
	case agginventory.ControlStatusNotApplicable:
		return 2
	default:
		return 3
	}
}

func correlateRepoScopedIdentity(matches []agginventory.NonHumanIdentity) (string, string, string, string, string) {
	if len(matches) == 0 {
		return "", "", "", "unknown", "no static non-human identity evidence matched this path"
	}
	unique := map[string]agginventory.NonHumanIdentity{}
	for _, item := range matches {
		key := strings.Join([]string{item.IdentityType, item.Subject, item.Source}, "|")
		unique[key] = item
	}
	if len(unique) == 1 {
		for _, item := range unique {
			if strings.TrimSpace(item.IdentityType) == "unknown" {
				return "", "unknown", strings.TrimSpace(item.Source), "unknown", "repo-scoped static identity evidence stayed ambiguous for this path"
			}
			return strings.TrimSpace(item.Subject), strings.TrimSpace(item.IdentityType), strings.TrimSpace(item.Source), "known", "repo-scoped static workflow identity evidence matched this path"
		}
	}
	return "", "ambiguous", "", "ambiguous", fmt.Sprintf("%d repo-scoped non-human identity candidates matched this path", len(unique))
}

func entryContainsRepo(entry agginventory.AgentPrivilegeMapEntry, repo string) bool {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return false
	}
	for _, candidate := range entry.Repos {
		if strings.TrimSpace(candidate) == repo {
			return true
		}
	}
	return firstRepoFromEntry(entry) == repo
}

func classifyBusinessStateSurface(entry agginventory.AgentPrivilegeMapEntry) string {
	permissions := normalizeGovernFirstTokens(entry.Permissions)
	boundTools := normalizeGovernFirstTokens(entry.BoundTools)
	dataClass := strings.TrimSpace(entry.DataClass)

	switch {
	case hasGovernFirstPrefix(permissions, "mcp.admin") || hasGovernFirstToken(permissions, "admin"):
		return "admin_api"
	case hasGovernFirstToken(permissions, "db.write") || strings.EqualFold(dataClass, "database"):
		return "db"
	case entry.DeployWrite || entry.ProductionWrite || hasGovernFirstToken(permissions, "deploy.write"):
		return "deploy"
	case hasTicketingSurface(permissions, boundTools):
		return "ticketing"
	case hasSaaSWriteSurface(permissions, boundTools):
		return "saas_write"
	case entry.MergeExecute:
		return "workflow_control"
	case hasGovernFirstToken(permissions, "repo.write"), hasGovernFirstToken(permissions, "pull_request.write"), hasGovernFirstToken(permissions, "iac.write"):
		return "code"
	default:
		return "code"
	}
}

func mergeBusinessStateSurface(current, incoming string) string {
	if businessStateSurfacePriority(incoming) < businessStateSurfacePriority(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func businessStateSurfacePriority(surface string) int {
	switch strings.TrimSpace(surface) {
	case "admin_api":
		return 0
	case "db":
		return 1
	case "deploy":
		return 2
	case "ticketing":
		return 3
	case "saas_write":
		return 4
	case "workflow_control":
		return 5
	case "code":
		return 6
	case "":
		return 7
	default:
		return 8
	}
}

func normalizeGovernFirstTokens(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return dedupeSortedStrings(out)
}

func hasGovernFirstToken(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func hasGovernFirstPrefix(values []string, prefix string) bool {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	for _, value := range values {
		if strings.HasPrefix(strings.TrimSpace(value), prefix) {
			return true
		}
	}
	return false
}

func hasTicketingSurface(permissions, boundTools []string) bool {
	for _, values := range [][]string{permissions, boundTools} {
		for _, value := range values {
			switch {
			case strings.Contains(value, "ticket.write"),
				strings.Contains(value, "jira"),
				strings.Contains(value, "linear"),
				strings.Contains(value, "issue.write"):
				return true
			}
		}
	}
	return false
}

func hasSaaSWriteSurface(permissions, boundTools []string) bool {
	for _, values := range [][]string{permissions, boundTools} {
		for _, value := range values {
			switch {
			case strings.HasPrefix(value, "mcp.write"),
				strings.HasPrefix(value, "crm."),
				strings.HasPrefix(value, "saas."),
				strings.HasSuffix(value, ".write") && !strings.HasPrefix(value, "repo.") && !strings.HasPrefix(value, "pull_request.") && !strings.HasPrefix(value, "deploy.") && !strings.HasPrefix(value, "db.") && !strings.HasPrefix(value, "ticket.") && !strings.HasPrefix(value, "iac."):
				return true
			}
		}
	}
	return false
}

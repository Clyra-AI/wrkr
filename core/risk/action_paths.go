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
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/owners"
	"github.com/Clyra-AI/wrkr/core/resolution"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

const actionPathIDPrefix = "apc-"

type ActionPathSummary struct {
	TotalPaths                   int                       `json:"total_paths"`
	WriteCapablePaths            int                       `json:"write_capable_paths"`
	CredentialAccessPaths        int                       `json:"credential_access_paths"`
	StandingPrivilegePaths       int                       `json:"standing_privilege_paths"`
	ProductionTargetBackedPaths  int                       `json:"production_target_backed_paths"`
	ControlFirstPaths            int                       `json:"control_first_paths"`
	GovernFirstPaths             int                       `json:"govern_first_paths"`
	DetectedControlPaths         int                       `json:"detected_control_paths,omitempty"`
	DeclaredControlPaths         int                       `json:"declared_control_paths,omitempty"`
	ExternalControlPaths         int                       `json:"external_control_reference_paths,omitempty"`
	ContradictoryControlPaths    int                       `json:"contradictory_control_paths,omitempty"`
	ControlEvidenceUnknownPaths  int                       `json:"control_evidence_unknown_paths,omitempty"`
	ApprovalEvidenceUnknownPaths int                       `json:"approval_evidence_unknown_paths,omitempty"`
	OwnerEvidenceUnknownPaths    int                       `json:"owner_evidence_unknown_paths,omitempty"`
	ProofEvidenceUnknownPaths    int                       `json:"proof_evidence_unknown_paths,omitempty"`
	MissingApprovalPaths         int                       `json:"missing_approval_paths"`
	MissingPolicyPaths           int                       `json:"missing_policy_paths"`
	MissingProofPaths            int                       `json:"missing_proof_paths"`
	UnresolvedOwnerPaths         int                       `json:"unresolved_owner_paths"`
	HighReviewBurdenPaths        int                       `json:"high_review_burden_paths"`
	ConfirmedActionPaths         int                       `json:"confirmed_action_paths"`
	LikelyActionPaths            int                       `json:"likely_action_paths"`
	SemanticReviewCandidatePaths int                       `json:"semantic_review_candidate_paths"`
	ContextOnlyPaths             int                       `json:"context_only_paths"`
	AutonomyTiers                AutonomyTierCounts        `json:"autonomy_tiers"`
	DelegationReadiness          DelegationReadinessCounts `json:"delegation_readiness"`
	RecommendedControls          RecommendedControlCounts  `json:"recommended_controls"`
	EmptyStateStatus             string                    `json:"empty_state_status,omitempty"`
	EmptyStateReasons            []string                  `json:"empty_state_reasons,omitempty"`
}

type ReviewAuditContext struct {
	LifecycleState string   `json:"lifecycle_state,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	Source         string   `json:"source,omitempty"`
	Rationale      string   `json:"rationale,omitempty"`
	ObservedAt     string   `json:"observed_at,omitempty"`
	ValidUntil     string   `json:"valid_until,omitempty"`
	Scope          string   `json:"scope,omitempty"`
	EvidenceRefs   []string `json:"evidence_refs,omitempty"`
	ReasonCodes    []string `json:"reason_codes,omitempty"`
}

type ActionPath struct {
	PathID                     string                         `json:"path_id"`
	Org                        string                         `json:"org"`
	Repo                       string                         `json:"repo"`
	AgentID                    string                         `json:"agent_id,omitempty"`
	ToolFamilyID               string                         `json:"tool_family_id,omitempty"`
	ToolInstanceID             string                         `json:"tool_instance_id,omitempty"`
	ToolType                   string                         `json:"tool_type"`
	Location                   string                         `json:"location,omitempty"`
	LocationRange              *model.LocationRange           `json:"location_range,omitempty"`
	Purpose                    string                         `json:"purpose,omitempty"`
	PurposeSource              string                         `json:"purpose_source,omitempty"`
	PurposeConfidence          string                         `json:"purpose_confidence,omitempty"`
	Version                    string                         `json:"version,omitempty"`
	VersionSource              string                         `json:"version_source,omitempty"`
	ConfigFingerprint          string                         `json:"config_fingerprint,omitempty"`
	ConfigSource               string                         `json:"config_source,omitempty"`
	AutonomyLevel              string                         `json:"autonomy_level,omitempty"`
	WriteCapable               bool                           `json:"write_capable"`
	OperationalOwner           string                         `json:"operational_owner,omitempty"`
	OwnerSource                string                         `json:"owner_source,omitempty"`
	OwnershipStatus            string                         `json:"ownership_status,omitempty"`
	OwnershipState             string                         `json:"ownership_state,omitempty"`
	OwnershipConfidence        float64                        `json:"ownership_confidence,omitempty"`
	OwnershipEvidence          []string                       `json:"ownership_evidence_basis,omitempty"`
	OwnershipConflicts         []string                       `json:"ownership_conflicts,omitempty"`
	EvidenceDecisions          []evidencepolicy.Decision      `json:"evidence_decisions,omitempty"`
	Contradictions             []evidencepolicy.Contradiction `json:"contradictions,omitempty"`
	ControlResolutionState     string                         `json:"control_resolution_state,omitempty"`
	BoundaryLabel              string                         `json:"boundary_label,omitempty"`
	ControlResolutionReasons   []string                       `json:"control_resolution_reasons,omitempty"`
	ResolutionKey              string                         `json:"resolution_key,omitempty"`
	ResolutionSelector         *resolution.Selector           `json:"resolution_selector,omitempty"`
	ResolutionMatchConfidence  string                         `json:"resolution_match_confidence,omitempty"`
	ResolutionMismatchReasons  []string                       `json:"resolution_mismatch_reasons,omitempty"`
	ControlEvidenceRefs        []string                       `json:"control_evidence_refs,omitempty"`
	ConstraintEvidenceClasses  []string                       `json:"constraint_evidence_classes,omitempty"`
	ConstraintEvidenceRefs     []string                       `json:"constraint_evidence_refs,omitempty"`
	ConstraintEvidenceStatus   string                         `json:"constraint_evidence_status,omitempty"`
	ApprovalEvidenceState      string                         `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState         string                         `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState         string                         `json:"proof_evidence_state,omitempty"`
	RuntimeEvidenceState       string                         `json:"runtime_evidence_state,omitempty"`
	TargetEvidenceState        string                         `json:"target_evidence_state,omitempty"`
	CredentialEvidenceState    string                         `json:"credential_evidence_state,omitempty"`
	TargetClass                string                         `json:"target_class,omitempty"`
	TargetClassReasons         []string                       `json:"target_class_reasons,omitempty"`
	TargetClassEvidenceRefs    []string                       `json:"target_class_evidence_refs,omitempty"`
	ActionPathEligible         bool                           `json:"action_path_eligible,omitempty"`
	ActionBindingState         string                         `json:"action_binding_state,omitempty"`
	ActionPathType             string                         `json:"action_path_type,omitempty"`
	ActionPathTypeReasons      []string                       `json:"action_path_type_reasons,omitempty"`
	ActionPathTypeEvidenceRefs []string                       `json:"action_path_type_evidence_refs,omitempty"`
	CIFlowClass                string                         `json:"ci_flow_class,omitempty"`
	CIFlowReasons              []string                       `json:"ci_flow_reasons,omitempty"`
	ApprovalGapReasons         []string                       `json:"approval_gap_reasons,omitempty"`
	WritePathClasses           []string                       `json:"write_path_classes,omitempty"`
	ActionClasses              []string                       `json:"action_classes,omitempty"`
	ActionReasons              []string                       `json:"action_reasons,omitempty"`
	OccurrenceCount            int                            `json:"occurrence_count,omitempty"`
	OccurrenceRefs             []string                       `json:"occurrence_refs,omitempty"`
	agginventory.EndpointRefGroupProjection
	MutableEndpointSemanticRefs         []string                                `json:"mutable_endpoint_semantic_refs,omitempty"`
	MutableEndpointSemantics            []agginventory.MutableEndpointSemantic  `json:"mutable_endpoint_semantics,omitempty"`
	PullRequestWrite                    bool                                    `json:"pull_request_write,omitempty"`
	MergeExecute                        bool                                    `json:"merge_execute,omitempty"`
	DeployWrite                         bool                                    `json:"deploy_write,omitempty"`
	DeliveryChainStatus                 string                                  `json:"delivery_chain_status,omitempty"`
	ProductionTargetStatus              string                                  `json:"production_target_status,omitempty"`
	ProductionWrite                     bool                                    `json:"production_write"`
	ApprovalGap                         bool                                    `json:"approval_gap"`
	SecurityVisibilityStatus            string                                  `json:"security_visibility_status,omitempty"`
	CredentialAccess                    bool                                    `json:"credential_access"`
	Credentials                         []*agginventory.CredentialProvenance    `json:"credentials,omitempty"`
	CredentialProvenance                *agginventory.CredentialProvenance      `json:"credential_provenance,omitempty"`
	CredentialAuthorityRef              string                                  `json:"credential_authority_ref,omitempty"`
	CredentialAuthority                 *agginventory.CredentialAuthority       `json:"credential_authority,omitempty"`
	AuthorityBindingRefs                []string                                `json:"authority_binding_refs,omitempty"`
	AuthorityBindings                   []*agginventory.AuthorityBinding        `json:"authority_bindings,omitempty"`
	PathContext                         *agginventory.PathContext               `json:"path_context,omitempty"`
	TrustDepth                          *agginventory.TrustDepth                `json:"trust_depth,omitempty"`
	DeploymentStatus                    string                                  `json:"deployment_status,omitempty"`
	WorkflowTriggerClass                string                                  `json:"workflow_trigger_class,omitempty"`
	ExecutionIdentity                   string                                  `json:"execution_identity,omitempty"`
	ExecutionIdentityType               string                                  `json:"execution_identity_type,omitempty"`
	ExecutionIdentitySource             string                                  `json:"execution_identity_source,omitempty"`
	ExecutionIdentityStatus             string                                  `json:"execution_identity_status,omitempty"`
	ExecutionIdentityRationale          string                                  `json:"execution_identity_rationale,omitempty"`
	BusinessStateSurface                string                                  `json:"business_state_surface,omitempty"`
	SharedExecutionIdentity             bool                                    `json:"shared_execution_identity,omitempty"`
	StandingPrivilege                   bool                                    `json:"standing_privilege,omitempty"`
	StandingPrivilegeReasons            []string                                `json:"standing_privilege_reasons,omitempty"`
	ControlState                        string                                  `json:"control_state,omitempty"`
	ControlStateReasons                 []string                                `json:"control_state_reasons,omitempty"`
	RiskZone                            string                                  `json:"risk_zone,omitempty"`
	RiskZoneReasons                     []string                                `json:"risk_zone_reasons,omitempty"`
	ReviewBurden                        string                                  `json:"review_burden,omitempty"`
	ReviewBurdenReasons                 []string                                `json:"review_burden_reasons,omitempty"`
	ConfidenceLane                      string                                  `json:"confidence_lane,omitempty"`
	ConfidenceLaneReasons               []string                                `json:"confidence_lane_reasons,omitempty"`
	ReviewLifecycleState                string                                  `json:"review_lifecycle_state,omitempty"`
	ReviewLifecycleReasons              []string                                `json:"review_lifecycle_reasons,omitempty"`
	ReviewRationale                     string                                  `json:"review_rationale,omitempty"`
	ReviewOwner                         string                                  `json:"review_owner,omitempty"`
	ReviewSource                        string                                  `json:"review_source,omitempty"`
	ReviewObservedAt                    string                                  `json:"review_observed_at,omitempty"`
	ReviewValidUntil                    string                                  `json:"review_valid_until,omitempty"`
	ReviewScope                         string                                  `json:"review_scope,omitempty"`
	ReviewEvidenceRefs                  []string                                `json:"-"`
	ReviewAuditContext                  *ReviewAuditContext                     `json:"review_audit_context,omitempty"`
	ResolvedVisibility                  string                                  `json:"resolved_visibility,omitempty"`
	ResolvedAppendixRefs                []string                                `json:"resolved_appendix_refs,omitempty"`
	PreviousReviewLifecycleState        string                                  `json:"previous_review_lifecycle_state,omitempty"`
	ReopenState                         string                                  `json:"reopen_state,omitempty"`
	ReopenReasons                       []string                                `json:"reopen_reasons,omitempty"`
	ReopenEvidenceRefs                  []string                                `json:"reopen_evidence_refs,omitempty"`
	PolicyCoverageStatus                string                                  `json:"policy_coverage_status,omitempty"`
	PolicyRefs                          []string                                `json:"policy_refs,omitempty"`
	PolicyMissingReasons                []string                                `json:"policy_missing_reasons,omitempty"`
	PolicyStatusReasons                 []string                                `json:"policy_status_reasons,omitempty"`
	PolicyConfidence                    string                                  `json:"policy_confidence,omitempty"`
	PolicyEvidenceRefs                  []string                                `json:"policy_evidence_refs,omitempty"`
	GaitCoverage                        *GaitCoverage                           `json:"gait_coverage,omitempty"`
	IntroducedBy                        *attribution.Result                     `json:"introduced_by,omitempty"`
	InventoryRisk                       string                                  `json:"inventory_risk,omitempty"`
	ControlPriority                     string                                  `json:"control_priority,omitempty"`
	RiskTier                            string                                  `json:"risk_tier,omitempty"`
	AutonomyTier                        string                                  `json:"autonomy_tier,omitempty"`
	AutonomyTierReasons                 []string                                `json:"autonomy_tier_reasons,omitempty"`
	AutonomyTierEvidenceRefs            []string                                `json:"autonomy_tier_evidence_refs,omitempty"`
	DelegationReadinessState            string                                  `json:"delegation_readiness_state,omitempty"`
	DelegationReadinessReasons          []string                                `json:"delegation_readiness_reasons,omitempty"`
	RecommendedControl                  string                                  `json:"recommended_control,omitempty"`
	RecommendedControlReasons           []string                                `json:"recommended_control_reasons,omitempty"`
	RiskClassificationValidationReasons []string                                `json:"risk_classification_validation_reasons,omitempty"`
	RiskClassificationValidationRefs    []string                                `json:"risk_classification_validation_refs,omitempty"`
	RecommendedActionContract           *RecommendedActionContract              `json:"recommended_action_contract,omitempty"`
	TodayPath                           *GovernedPathView                       `json:"today_path,omitempty"`
	RecommendedGovernedPath             *GovernedPathView                       `json:"recommended_governed_path,omitempty"`
	AgenticDeliverySystemChange         *AgenticDeliverySystemChange            `json:"agentic_delivery_system_change,omitempty"`
	RuntimeContextEvidenceState         string                                  `json:"runtime_context_evidence_state,omitempty"`
	RuntimeProvider                     string                                  `json:"runtime_provider,omitempty"`
	RuntimeHost                         string                                  `json:"runtime_host,omitempty"`
	RuntimeKind                         string                                  `json:"runtime_kind,omitempty"`
	ModelProvider                       string                                  `json:"model_provider,omitempty"`
	ModelVersion                        string                                  `json:"model_version,omitempty"`
	ExecutionEnvironment                string                                  `json:"execution_environment,omitempty"`
	StateRetentionEvidenceState         string                                  `json:"state_retention_evidence_state,omitempty"`
	StateRetentionStatus                string                                  `json:"state_retention_status,omitempty"`
	RetainedStateTypes                  []string                                `json:"retained_state_types,omitempty"`
	StateLocationRefs                   []string                                `json:"state_location_refs,omitempty"`
	StateDigestRefs                     []string                                `json:"state_digest_refs,omitempty"`
	AgentIdentity                       *AgentIdentity                          `json:"agent_identity,omitempty"`
	DecisionPrecedent                   *DecisionPrecedent                      `json:"decision_precedent,omitempty"`
	DeliveryControlContext              *DeliveryControlContext                 `json:"delivery_control_context,omitempty"`
	DeliveryHarnesses                   []string                                `json:"delivery_harnesses,omitempty"`
	ResolverRefs                        []string                                `json:"resolver_refs,omitempty"`
	EvalConfigRefs                      []string                                `json:"eval_config_refs,omitempty"`
	DryRunRequired                      bool                                    `json:"dry_run_required,omitempty"`
	SandboxGates                        []string                                `json:"sandbox_gates,omitempty"`
	TestGates                           []string                                `json:"test_gates,omitempty"`
	ValidationRequirements              []string                                `json:"validation_requirements,omitempty"`
	HighStakesPresets                   []HighStakesPreset                      `json:"high_stakes_presets,omitempty"`
	ProductionContext                   *ProductionContext                      `json:"production_context,omitempty"`
	EvidencePacketStatus                string                                  `json:"evidence_packet_status,omitempty"`
	EvidencePacketResult                string                                  `json:"evidence_packet_result,omitempty"`
	EvidencePacketMissingEvidenceState  string                                  `json:"evidence_packet_missing_evidence_state,omitempty"`
	EvidencePacketRefs                  []string                                `json:"evidence_packet_refs,omitempty"`
	AttackPathScore                     float64                                 `json:"attack_path_score"`
	RiskScore                           float64                                 `json:"risk_score"`
	RecommendedAction                   string                                  `json:"recommended_action"`
	AttackPathRefs                      []string                                `json:"attack_path_refs,omitempty"`
	SourceFindingKeys                   []string                                `json:"source_finding_keys,omitempty"`
	WorkflowChainRefs                   []string                                `json:"workflow_chain_refs,omitempty"`
	DecisionTraceRefs                   []string                                `json:"decision_trace_refs,omitempty"`
	CompositionIDs                      []string                                `json:"composition_ids,omitempty"`
	ProposedActionContractRefs          []string                                `json:"proposed_action_contract_refs,omitempty"`
	MatchedProductionTargets            []string                                `json:"matched_production_targets,omitempty"`
	GovernanceControls                  []agginventory.GovernanceControlMapping `json:"governance_controls,omitempty"`
	ClosureRequirements                 []ClosureRequirement                    `json:"closure_requirements,omitempty"`
	EvidenceCompleteness                *EvidenceCompleteness                   `json:"evidence_completeness,omitempty"`
	ActionLineage                       *ActionLineage                          `json:"action_lineage,omitempty"`
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
	paths = finalizeActionPathEndpointProjections(paths)
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
		PathID:                      actionPathID(entry),
		Org:                         strings.TrimSpace(entry.Org),
		Repo:                        firstRepoFromEntry(entry),
		AgentID:                     strings.TrimSpace(entry.AgentID),
		ToolFamilyID:                strings.TrimSpace(entry.ToolFamilyID),
		ToolInstanceID:              strings.TrimSpace(entry.ToolInstanceID),
		ToolType:                    actionPathToolType(entry),
		Location:                    strings.TrimSpace(entry.Location),
		LocationRange:               cloneLocationRange(entry.LocationRange),
		Purpose:                     strings.TrimSpace(entry.Purpose),
		PurposeSource:               strings.TrimSpace(entry.PurposeSource),
		PurposeConfidence:           strings.TrimSpace(entry.PurposeConfidence),
		Version:                     strings.TrimSpace(entry.Version),
		VersionSource:               strings.TrimSpace(entry.VersionSource),
		ConfigFingerprint:           strings.TrimSpace(entry.ConfigFingerprint),
		ConfigSource:                strings.TrimSpace(entry.ConfigSource),
		AutonomyLevel:               strings.TrimSpace(entry.AutonomyLevel),
		DeliveryHarnesses:           dedupeSortedStrings(entry.DeliveryHarnesses),
		ResolverRefs:                dedupeSortedStrings(entry.ResolverRefs),
		EvalConfigRefs:              dedupeSortedStrings(entry.EvalConfigRefs),
		DryRunRequired:              entry.DryRunRequired,
		SandboxGates:                dedupeSortedStrings(entry.SandboxGates),
		TestGates:                   dedupeSortedStrings(entry.TestGates),
		ValidationRequirements:      dedupeSortedStrings(entry.ValidationRequirements),
		WriteCapable:                entry.WriteCapable,
		OperationalOwner:            strings.TrimSpace(entry.OperationalOwner),
		OwnerSource:                 strings.TrimSpace(entry.OwnerSource),
		OwnershipStatus:             strings.TrimSpace(entry.OwnershipStatus),
		OwnershipState:              strings.TrimSpace(entry.OwnershipState),
		OwnershipConfidence:         entry.OwnershipConfidence,
		OwnershipEvidence:           dedupeSortedStrings(entry.OwnershipEvidence),
		OwnershipConflicts:          dedupeSortedStrings(entry.OwnershipConflicts),
		EvidenceDecisions:           ownershipDecisionSlice(entry.OwnershipDecision),
		ApprovalGapReasons:          dedupeSortedStrings(entry.ApprovalGapReasons),
		WritePathClasses:            dedupeSortedStrings(entry.WritePathClasses),
		ActionClasses:               dedupeSortedStrings(entry.ActionClasses),
		ActionReasons:               dedupeSortedStrings(entry.ActionReasons),
		OccurrenceCount:             1,
		OccurrenceRefs:              []string{actionPathOccurrenceRef(entry)},
		EndpointRefGroupProjection:  agginventory.BuildMutableEndpointGroupProjection(entry.MutableEndpointSemanticRefs, entry.MutableEndpointSemantics),
		MutableEndpointSemanticRefs: append([]string(nil), entry.MutableEndpointSemanticRefs...),
		MutableEndpointSemantics:    agginventory.CloneMutableEndpointSemantics(entry.MutableEndpointSemantics),
		PullRequestWrite:            entry.PullRequestWrite,
		MergeExecute:                entry.MergeExecute,
		DeployWrite:                 entry.DeployWrite,
		DeliveryChainStatus:         strings.TrimSpace(entry.DeliveryChainStatus),
		ProductionTargetStatus:      strings.TrimSpace(entry.ProductionTargetStatus),
		ProductionWrite:             entry.ProductionWrite,
		ApprovalGap:                 actionPathApprovalGap(entry.ApprovalClassification, entry.ApprovalGapReasons),
		SecurityVisibilityStatus:    strings.TrimSpace(entry.SecurityVisibilityStatus),
		CredentialAccess:            entry.CredentialAccess,
		Credentials:                 agginventory.CloneCredentialProvenances(credentials),
		CredentialProvenance:        agginventory.CloneCredentialProvenance(provenance),
		CredentialAuthorityRef:      strings.TrimSpace(entry.CredentialAuthorityRef),
		CredentialAuthority:         agginventory.CloneCredentialAuthority(authority),
		AuthorityBindingRefs:        append([]string(nil), entry.AuthorityBindingRefs...),
		AuthorityBindings:           agginventory.CloneAuthorityBindings(entry.AuthorityBindings),
		PathContext:                 firstPathContext(entry.PathContext, entry.Location),
		TrustDepth:                  agginventory.CloneTrustDepth(entry.TrustDepth),
		DeploymentStatus:            strings.TrimSpace(entry.DeploymentStatus),
		WorkflowTriggerClass:        strings.TrimSpace(entry.WorkflowTriggerClass),
		ExecutionIdentity:           executionIdentity,
		ExecutionIdentityType:       executionIdentityType,
		ExecutionIdentitySource:     executionIdentitySource,
		ExecutionIdentityStatus:     executionIdentityStatus,
		ExecutionIdentityRationale:  executionIdentityRationale,
		BusinessStateSurface:        classifyBusinessStateSurface(entry),
		AttackPathScore:             attackScoreByRepo[repoKey(entry.Org, firstRepoFromEntry(entry))],
		RiskScore:                   actionPathRiskScore(entry.RiskScore, provenance),
		StandingPrivilege:           entry.StandingPrivilege || standingPrivilege,
		StandingPrivilegeReasons:    dedupeSortedStrings(append(append([]string(nil), entry.StandingPrivilegeReasons...), standingReasons...)),
		PolicyCoverageStatus:        PolicyCoverageStatusNone,
		MatchedProductionTargets:    dedupeSortedStrings(entry.MatchedProductionTargets),
		GovernanceControls:          append([]agginventory.GovernanceControlMapping(nil), entry.GovernanceControls...),
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
		len(entry.MutableEndpointSemantics) > 0 ||
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

func actionPathOccurrenceRef(entry agginventory.AgentPrivilegeMapEntry) string {
	parts := []string{
		strings.TrimSpace(entry.Org),
		strings.Join(dedupeSortedStrings(entry.Repos), ","),
		strings.TrimSpace(entry.Location),
		locationRangeKey(entry.LocationRange),
		strings.TrimSpace(entry.ToolType),
		strings.TrimSpace(entry.ToolID),
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
	merged.CredentialAuthorityRef = firstNonEmptyString(current.CredentialAuthorityRef, incoming.CredentialAuthorityRef)
	merged.CredentialAuthority = mergeCredentialAuthority(current.CredentialAuthority, incoming.CredentialAuthority)
	merged.AuthorityBindingRefs = dedupeSortedStrings(append(append([]string(nil), current.AuthorityBindingRefs...), incoming.AuthorityBindingRefs...))
	merged.AuthorityBindings = agginventory.NormalizeAuthorityBindings(append(agginventory.CloneAuthorityBindings(current.AuthorityBindings), agginventory.CloneAuthorityBindings(incoming.AuthorityBindings)...))
	merged.PathContext = mergePathContext(current.PathContext, incoming.PathContext)
	merged.TrustDepth = agginventory.MergeTrustDepth(current.TrustDepth, incoming.TrustDepth)
	merged.DeliveryChainStatus = actionPathDeliveryChainStatus(merged.PullRequestWrite, merged.MergeExecute, merged.DeployWrite)
	merged.AttackPathScore = maxFloat64(current.AttackPathScore, incoming.AttackPathScore)
	merged.RiskScore = maxFloat64(current.RiskScore, incoming.RiskScore)
	merged.ApprovalGapReasons = dedupeSortedStrings(append(append([]string(nil), current.ApprovalGapReasons...), incoming.ApprovalGapReasons...))
	merged.WritePathClasses = dedupeSortedStrings(append(append([]string(nil), current.WritePathClasses...), incoming.WritePathClasses...))
	merged.ActionClasses = dedupeSortedStrings(append(append([]string(nil), current.ActionClasses...), incoming.ActionClasses...))
	merged.ActionReasons = dedupeSortedStrings(append(append([]string(nil), current.ActionReasons...), incoming.ActionReasons...))
	merged.OccurrenceRefs = dedupeSortedStrings(append(append([]string(nil), current.OccurrenceRefs...), incoming.OccurrenceRefs...))
	merged.OccurrenceCount = len(merged.OccurrenceRefs)
	if merged.OccurrenceCount == 0 {
		merged.OccurrenceCount = maxInt(current.OccurrenceCount, incoming.OccurrenceCount)
		if merged.OccurrenceCount == 0 {
			merged.OccurrenceCount = 1
		}
	}
	merged.MutableEndpointSemanticRefs = dedupeSortedStrings(append(append([]string(nil), current.MutableEndpointSemanticRefs...), incoming.MutableEndpointSemanticRefs...))
	merged.MutableEndpointSemantics = append(append([]agginventory.MutableEndpointSemantic(nil), current.MutableEndpointSemantics...), incoming.MutableEndpointSemantics...)
	merged.EndpointRefGroupProjection = mergeEndpointRefGroupProjection(current.EndpointRefGroupProjection, incoming.EndpointRefGroupProjection)
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
	merged.EvidenceDecisions = mergeEvidenceDecisions(current.EvidenceDecisions, incoming.EvidenceDecisions)
	merged.Contradictions = mergeContradictions(current.Contradictions, incoming.Contradictions)
	merged.ControlResolutionState = chooseControlResolutionState(current.ControlResolutionState, incoming.ControlResolutionState)
	merged.ControlResolutionReasons = dedupeSortedStrings(append(append([]string(nil), current.ControlResolutionReasons...), incoming.ControlResolutionReasons...))
	merged.ControlEvidenceRefs = dedupeSortedStrings(append(append([]string(nil), current.ControlEvidenceRefs...), incoming.ControlEvidenceRefs...))
	merged.ConstraintEvidenceClasses = dedupeSortedStrings(append(append([]string(nil), current.ConstraintEvidenceClasses...), incoming.ConstraintEvidenceClasses...))
	merged.ConstraintEvidenceRefs = dedupeSortedStrings(append(append([]string(nil), current.ConstraintEvidenceRefs...), incoming.ConstraintEvidenceRefs...))
	merged.ConstraintEvidenceStatus = mergeConstraintEvidenceStatus(current.ConstraintEvidenceStatus, incoming.ConstraintEvidenceStatus)
	merged.ApprovalEvidenceState = chooseEvidenceState(current.ApprovalEvidenceState, incoming.ApprovalEvidenceState)
	merged.OwnerEvidenceState = chooseEvidenceState(current.OwnerEvidenceState, incoming.OwnerEvidenceState)
	merged.ProofEvidenceState = chooseEvidenceState(current.ProofEvidenceState, incoming.ProofEvidenceState)
	merged.RuntimeEvidenceState = chooseEvidenceState(current.RuntimeEvidenceState, incoming.RuntimeEvidenceState)
	merged.TargetEvidenceState = chooseEvidenceState(current.TargetEvidenceState, incoming.TargetEvidenceState)
	merged.CredentialEvidenceState = chooseEvidenceState(current.CredentialEvidenceState, incoming.CredentialEvidenceState)
	merged.TargetClass = chooseTargetClass(current.TargetClass, incoming.TargetClass)
	merged.TargetClassReasons = dedupeSortedStrings(append(append([]string(nil), current.TargetClassReasons...), incoming.TargetClassReasons...))
	merged.TargetClassEvidenceRefs = dedupeSortedStrings(append(append([]string(nil), current.TargetClassEvidenceRefs...), incoming.TargetClassEvidenceRefs...))
	merged.ActionPathEligible = current.ActionPathEligible || incoming.ActionPathEligible
	merged.ActionBindingState = mergeActionBindingState(current.ActionBindingState, incoming.ActionBindingState)
	merged.ActionPathType = chooseActionPathType(current.ActionPathType, incoming.ActionPathType)
	merged.ActionPathTypeReasons = dedupeSortedStrings(append(append([]string(nil), current.ActionPathTypeReasons...), incoming.ActionPathTypeReasons...))
	merged.ActionPathTypeEvidenceRefs = dedupeSortedStrings(append(append([]string(nil), current.ActionPathTypeEvidenceRefs...), incoming.ActionPathTypeEvidenceRefs...))
	merged.CIFlowClass = firstNonEmptyString(current.CIFlowClass, incoming.CIFlowClass)
	merged.CIFlowReasons = dedupeSortedStrings(append(append([]string(nil), current.CIFlowReasons...), incoming.CIFlowReasons...))
	merged.ExecutionIdentity, merged.ExecutionIdentityType, merged.ExecutionIdentitySource, merged.ExecutionIdentityStatus, merged.ExecutionIdentityRationale = mergeExecutionIdentity(current, incoming)
	merged.BusinessStateSurface = mergeBusinessStateSurface(current.BusinessStateSurface, incoming.BusinessStateSurface)
	merged.ToolFamilyID = firstNonEmptyString(current.ToolFamilyID, incoming.ToolFamilyID)
	merged.ToolInstanceID = firstNonEmptyString(current.ToolInstanceID, incoming.ToolInstanceID)
	merged.Purpose, merged.PurposeSource, merged.PurposeConfidence = mergePurposeMetadata(current, incoming)
	merged.Version = firstNonEmptyString(current.Version, incoming.Version)
	merged.VersionSource = chooseMetadataSource(current.VersionSource, incoming.VersionSource, current.Version, incoming.Version)
	merged.ConfigFingerprint = firstNonEmptyString(current.ConfigFingerprint, incoming.ConfigFingerprint)
	merged.ConfigSource = firstNonEmptyString(current.ConfigSource, incoming.ConfigSource)
	merged.AutonomyLevel = chooseAutonomyLevel(current.AutonomyLevel, incoming.AutonomyLevel)
	merged.DeliveryHarnesses = dedupeSortedStrings(append(append([]string(nil), current.DeliveryHarnesses...), incoming.DeliveryHarnesses...))
	merged.ResolverRefs = dedupeSortedStrings(append(append([]string(nil), current.ResolverRefs...), incoming.ResolverRefs...))
	merged.EvalConfigRefs = dedupeSortedStrings(append(append([]string(nil), current.EvalConfigRefs...), incoming.EvalConfigRefs...))
	merged.DryRunRequired = current.DryRunRequired || incoming.DryRunRequired
	merged.SandboxGates = dedupeSortedStrings(append(append([]string(nil), current.SandboxGates...), incoming.SandboxGates...))
	merged.TestGates = dedupeSortedStrings(append(append([]string(nil), current.TestGates...), incoming.TestGates...))
	merged.ValidationRequirements = dedupeSortedStrings(append(append([]string(nil), current.ValidationRequirements...), incoming.ValidationRequirements...))
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
	merged.AgenticDeliverySystemChange = CloneAgenticDeliverySystemChange(firstNonNilAgenticDeliverySystemChange(current.AgenticDeliverySystemChange, incoming.AgenticDeliverySystemChange))
	merged.RuntimeContextEvidenceState = runtimeContextEvidenceStateFromValues(current.RuntimeContextEvidenceState, incoming.RuntimeContextEvidenceState)
	merged.RuntimeProvider = firstNonEmptyString(current.RuntimeProvider, incoming.RuntimeProvider)
	merged.RuntimeHost = firstNonEmptyString(current.RuntimeHost, incoming.RuntimeHost)
	merged.RuntimeKind = firstNonEmptyString(current.RuntimeKind, incoming.RuntimeKind)
	merged.ModelProvider = firstNonEmptyString(current.ModelProvider, incoming.ModelProvider)
	merged.ModelVersion = firstNonEmptyString(current.ModelVersion, incoming.ModelVersion)
	merged.ExecutionEnvironment = firstNonEmptyString(current.ExecutionEnvironment, incoming.ExecutionEnvironment)
	merged.StateRetentionEvidenceState = runtimeContextEvidenceStateFromValues(current.StateRetentionEvidenceState, incoming.StateRetentionEvidenceState)
	merged.StateRetentionStatus = firstNonEmptyString(current.StateRetentionStatus, incoming.StateRetentionStatus)
	merged.RetainedStateTypes = dedupeSortedStrings(append(append([]string(nil), current.RetainedStateTypes...), incoming.RetainedStateTypes...))
	merged.StateLocationRefs = dedupeSortedStrings(append(append([]string(nil), current.StateLocationRefs...), incoming.StateLocationRefs...))
	merged.StateDigestRefs = dedupeSortedStrings(append(append([]string(nil), current.StateDigestRefs...), incoming.StateDigestRefs...))
	merged.AgentIdentity = CloneAgentIdentity(firstNonNilAgentIdentity(current.AgentIdentity, incoming.AgentIdentity))
	merged.DecisionPrecedent = CloneDecisionPrecedent(firstNonNilDecisionPrecedent(current.DecisionPrecedent, incoming.DecisionPrecedent))
	merged.DeliveryControlContext = CloneDeliveryControlContext(mergeDeliveryControlContext(current.DeliveryControlContext, incoming.DeliveryControlContext))
	merged.GovernanceControls = mergeGovernanceControls(current.GovernanceControls, incoming.GovernanceControls)
	merged.ClosureRequirements = CloneClosureRequirements(firstNonEmptyClosureRequirements(current.ClosureRequirements, incoming.ClosureRequirements))
	merged.EvidenceCompleteness = firstNonNilEvidenceCompleteness(current.EvidenceCompleteness, incoming.EvidenceCompleteness)
	merged.AttackPathRefs = dedupeSortedStrings(append(append([]string(nil), current.AttackPathRefs...), incoming.AttackPathRefs...))
	merged.SourceFindingKeys = dedupeSortedStrings(append(append([]string(nil), current.SourceFindingKeys...), incoming.SourceFindingKeys...))
	merged.WorkflowChainRefs = dedupeSortedStrings(append(append([]string(nil), current.WorkflowChainRefs...), incoming.WorkflowChainRefs...))
	merged.DecisionTraceRefs = dedupeSortedStrings(append(append([]string(nil), current.DecisionTraceRefs...), incoming.DecisionTraceRefs...))
	merged.ActionLineage = CloneActionLineage(firstNonNilLineage(current.ActionLineage, incoming.ActionLineage))
	return merged
}

func finalizeActionPathEndpointProjections(paths []ActionPath) []ActionPath {
	for idx := range paths {
		paths[idx].MutableEndpointSemanticRefs = dedupeSortedStrings(paths[idx].MutableEndpointSemanticRefs)
		paths[idx].MutableEndpointSemantics = agginventory.NormalizeMutableEndpointSemantics(paths[idx].MutableEndpointSemantics)
		paths[idx].EndpointRefGroupProjection = agginventory.BuildMutableEndpointGroupProjection(paths[idx].MutableEndpointSemanticRefs, paths[idx].MutableEndpointSemantics)
	}
	return paths
}

func mergeEndpointRefGroupProjection(current, incoming agginventory.EndpointRefGroupProjection) agginventory.EndpointRefGroupProjection {
	if current.EndpointRefCount >= incoming.EndpointRefCount {
		return current
	}
	return incoming
}

func summarizeActionPaths(paths []ActionPath) ActionPathSummary {
	return SummarizeActionPaths(paths, ActionPathSummaryOptions{})
}

func mergeActionBindingState(current, incoming string) string {
	current = strings.TrimSpace(current)
	incoming = strings.TrimSpace(incoming)
	switch {
	case !ValidActionBindingState(current):
		return incoming
	case !ValidActionBindingState(incoming):
		return current
	case current == incoming:
		return current
	case actionBindingRank(incoming) < actionBindingRank(current):
		return incoming
	default:
		return current
	}
}

func chooseAutonomyLevel(current, incoming string) string {
	current = strings.TrimSpace(current)
	incoming = strings.TrimSpace(incoming)
	if autonomyRank(incoming) > autonomyRank(current) {
		return incoming
	}
	return current
}

func actionBindingRank(value string) int {
	switch strings.TrimSpace(value) {
	case ActionBindingStateBound:
		return 0
	case ActionBindingStatePartiallyBound:
		return 1
	case ActionBindingStateUnboundContext:
		return 2
	case ActionBindingStateContradictory:
		return 3
	default:
		return 99
	}
}

func firstNonNilAgenticDeliverySystemChange(current, incoming *AgenticDeliverySystemChange) *AgenticDeliverySystemChange {
	switch {
	case current == nil:
		return incoming
	case incoming == nil:
		return current
	case agenticDeliverySystemChangeRank(incoming) > agenticDeliverySystemChangeRank(current):
		return incoming
	default:
		return current
	}
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
			PathID:                      strings.TrimSpace(path.PathID),
			AgentID:                     strings.TrimSpace(path.AgentID),
			Org:                         strings.TrimSpace(path.Org),
			Repo:                        strings.TrimSpace(path.Repo),
			ToolType:                    strings.TrimSpace(path.ToolType),
			Location:                    strings.TrimSpace(path.Location),
			Purpose:                     strings.TrimSpace(path.Purpose),
			PurposeSource:               strings.TrimSpace(path.PurposeSource),
			PurposeConfidence:           strings.TrimSpace(path.PurposeConfidence),
			Version:                     strings.TrimSpace(path.Version),
			VersionSource:               strings.TrimSpace(path.VersionSource),
			ConfigFingerprint:           strings.TrimSpace(path.ConfigFingerprint),
			ConfigSource:                strings.TrimSpace(path.ConfigSource),
			ExecutionIdentity:           strings.TrimSpace(path.ExecutionIdentity),
			ExecutionIdentityType:       strings.TrimSpace(path.ExecutionIdentityType),
			ExecutionIdentitySource:     strings.TrimSpace(path.ExecutionIdentitySource),
			ExecutionIdentityStatus:     strings.TrimSpace(path.ExecutionIdentityStatus),
			CredentialAccess:            path.CredentialAccess,
			CredentialProvenance:        agginventory.CloneCredentialProvenance(path.CredentialProvenance),
			CredentialAuthorityRef:      strings.TrimSpace(path.CredentialAuthorityRef),
			CredentialAuthority:         agginventory.CloneCredentialAuthority(path.CredentialAuthority),
			AuthorityBindingRefs:        dedupeSortedStrings(path.AuthorityBindingRefs),
			AuthorityBindings:           agginventory.CloneAuthorityBindings(path.AuthorityBindings),
			EndpointRefGroupProjection:  agginventory.BackfillMutableEndpointGroupProjection(path.EndpointRefGroupProjection, path.MutableEndpointSemanticRefs, path.MutableEndpointSemantics),
			MutableEndpointSemanticRefs: dedupeSortedStrings(path.MutableEndpointSemanticRefs),
			MutableEndpointSemantics:    agginventory.CloneMutableEndpointSemantics(path.MutableEndpointSemantics),
			GovernanceControls:          append([]agginventory.GovernanceControlMapping(nil), path.GovernanceControls...),
			MatchedProductionTargets:    dedupeSortedStrings(path.MatchedProductionTargets),
			WritePathClasses:            dedupeSortedStrings(path.WritePathClasses),
			PullRequestWrite:            path.PullRequestWrite,
			MergeExecute:                path.MergeExecute,
			DeployWrite:                 path.DeployWrite,
			ProductionWrite:             path.ProductionWrite,
			ApprovalGap:                 path.ApprovalGap,
			IntroducedBy:                path.IntroducedBy,
			PolicyRefs:                  dedupeSortedStrings(path.PolicyRefs),
			ControlResolutionState:      strings.TrimSpace(path.ControlResolutionState),
			AutonomyTier:                strings.TrimSpace(path.AutonomyTier),
			DelegationReadinessState:    strings.TrimSpace(path.DelegationReadinessState),
			ApprovalEvidenceState:       strings.TrimSpace(path.ApprovalEvidenceState),
			ProofEvidenceState:          strings.TrimSpace(path.ProofEvidenceState),
			RuntimeEvidenceState:        strings.TrimSpace(path.RuntimeEvidenceState),
			TargetEvidenceState:         strings.TrimSpace(path.TargetEvidenceState),
			EvidenceCompletenessLabel:   evidenceCompletenessProjectionLabel(path.EvidenceCompleteness),
			AttackPathRefs:              dedupeSortedStrings(path.AttackPathRefs),
			SourceFindingKeys:           dedupeSortedStrings(path.SourceFindingKeys),
		})
	}
	return aggattack.BuildControlPathGraph(inputs)
}

func evidenceCompletenessProjectionLabel(in *EvidenceCompleteness) string {
	if in == nil {
		return ""
	}
	return strings.TrimSpace(in.Label)
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

func ownershipDecisionSlice(decision *evidencepolicy.Decision) []evidencepolicy.Decision {
	if decision == nil {
		return nil
	}
	return []evidencepolicy.Decision{cloneEvidenceDecision(*decision)}
}

func mergeEvidenceDecisions(current, incoming []evidencepolicy.Decision) []evidencepolicy.Decision {
	if len(current) == 0 && len(incoming) == 0 {
		return nil
	}
	byField := map[string]evidencepolicy.Decision{}
	for _, item := range append(append([]evidencepolicy.Decision(nil), current...), incoming...) {
		field := strings.TrimSpace(item.Field)
		if field == "" {
			continue
		}
		byField[field] = cloneEvidenceDecision(item)
	}
	out := make([]evidencepolicy.Decision, 0, len(byField))
	for _, item := range byField {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func mergeContradictions(current, incoming []evidencepolicy.Contradiction) []evidencepolicy.Contradiction {
	if len(current) == 0 && len(incoming) == 0 {
		return nil
	}
	seen := map[string]evidencepolicy.Contradiction{}
	for _, item := range append(append([]evidencepolicy.Contradiction(nil), current...), incoming...) {
		key := strings.Join([]string{
			strings.TrimSpace(item.Class),
			strings.TrimSpace(item.ImpactedTarget),
			strings.Join(dedupeSortedStrings(item.ReasonCodes), "|"),
		}, "|")
		seen[key] = cloneContradiction(item)
	}
	out := make([]evidencepolicy.Contradiction, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].ImpactedTarget < out[j].ImpactedTarget
	})
	return out
}

func cloneEvidenceDecision(in evidencepolicy.Decision) evidencepolicy.Decision {
	out := in
	out.SelectedEvidenceRefs = dedupeSortedStrings(append([]string(nil), in.SelectedEvidenceRefs...))
	out.ReasonCodes = dedupeSortedStrings(append([]string(nil), in.ReasonCodes...))
	out.ConflictReasonCodes = dedupeSortedStrings(append([]string(nil), in.ConflictReasonCodes...))
	if len(in.RejectedCandidates) > 0 {
		out.RejectedCandidates = make([]evidencepolicy.Candidate, 0, len(in.RejectedCandidates))
		for _, item := range in.RejectedCandidates {
			copyItem := item
			copyItem.EvidenceRefs = dedupeSortedStrings(append([]string(nil), item.EvidenceRefs...))
			copyItem.ReasonCodes = dedupeSortedStrings(append([]string(nil), item.ReasonCodes...))
			out.RejectedCandidates = append(out.RejectedCandidates, copyItem)
		}
	}
	return out
}

func cloneContradiction(in evidencepolicy.Contradiction) evidencepolicy.Contradiction {
	out := in
	out.ReasonCodes = dedupeSortedStrings(append([]string(nil), in.ReasonCodes...))
	out.EvidenceRefs = dedupeSortedStrings(append([]string(nil), in.EvidenceRefs...))
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
		merged.TargetSystem = firstNonEmptyString(current.TargetSystem, incoming.TargetSystem)
		merged.LikelyScope = firstNonEmptyString(current.LikelyScope, incoming.LikelyScope)
		if credentialConfidencePriority(incoming.ScopeConfidence) > credentialConfidencePriority(current.ScopeConfidence) {
			merged.ScopeConfidence = incoming.ScopeConfidence
		}
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
		merged.TargetSystem = firstNonEmptyString(current.TargetSystem, incoming.TargetSystem)
		merged.LikelyScope = firstNonEmptyString(current.LikelyScope, incoming.LikelyScope)
		if credentialConfidencePriority(incoming.ScopeConfidence) > credentialConfidencePriority(current.ScopeConfidence) {
			merged.ScopeConfidence = incoming.ScopeConfidence
		}
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

func firstNonEmptyClosureRequirements(values ...[]ClosureRequirement) []ClosureRequirement {
	for _, value := range values {
		if len(value) > 0 {
			return value
		}
	}
	return nil
}

func firstNonNilEvidenceCompleteness(values ...*EvidenceCompleteness) *EvidenceCompleteness {
	for _, value := range values {
		if value != nil {
			return CloneEvidenceCompleteness(value)
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
	out := make([]string, 0, len(segments))
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

func mergeConstraintEvidenceStatus(current, incoming string) string {
	switch strings.TrimSpace(current) {
	case "conflict":
		return "conflict"
	case "stale":
		if strings.TrimSpace(incoming) == "conflict" {
			return "conflict"
		}
		return "stale"
	case "unmatched":
		switch strings.TrimSpace(incoming) {
		case "conflict", "stale", "matched":
			return strings.TrimSpace(incoming)
		default:
			return "unmatched"
		}
	}
	switch strings.TrimSpace(incoming) {
	case "conflict":
		return "conflict"
	case "stale":
		return "stale"
	case "matched":
		return "matched"
	case "unmatched":
		return "unmatched"
	default:
		return firstNonEmptyString(current, incoming)
	}
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
	score += pathMutableEndpointPriority(path)
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

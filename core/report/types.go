package report

import (
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/compliance"
	"github.com/Clyra-AI/wrkr/core/governancequeue"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	scorecore "github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/core/state"
)

const SummaryVersion = "v1"

const (
	SectionHeadline    = "headline_posture"
	SectionMethodology = "methodology"
	SectionTopRisks    = "top_prioritized_risks"
	SectionChanges     = "change_since_previous"
	SectionLifecycle   = "lifecycle_actions"
	SectionProof       = "proof_verification_footer"
	SectionNextAction  = "next_actions"
)

type Template string

const (
	TemplateExec                 Template = "exec"
	TemplateOperator             Template = "operator"
	TemplateAudit                Template = "audit"
	TemplatePublic               Template = "public"
	TemplateCISO                 Template = "ciso"
	TemplateAppSec               Template = "appsec"
	TemplatePlatform             Template = "platform"
	TemplateCustomerDraft        Template = "customer-draft"
	TemplateAgentActionBOM       Template = "agent-action-bom"
	TemplateDesignPartnerSummary Template = "design-partner-summary"
)

type ShareProfile string

const (
	ShareProfileInternal         ShareProfile = "internal"
	ShareProfilePublic           ShareProfile = "public"
	ShareProfileCustomerRedacted ShareProfile = "customer-redacted"
	ShareProfileDesignPartner    ShareProfile = "design-partner"
	ShareProfileExternalRedacted ShareProfile = "external-redacted"
	ShareProfileInvestorSafe     ShareProfile = "investor-safe"
)

type BuildInput struct {
	GeneratedAt      time.Time
	StatePath        string
	Snapshot         state.Snapshot
	PreviousSnapshot *state.Snapshot
	Baseline         *regress.Baseline
	RegressResult    *regress.Result
	Manifest         *manifest.Manifest
	Top              int
	Template         Template
	ShareProfile     ShareProfile
	RedactionFields  []RedactionField
}

type Summary struct {
	SummaryVersion           string                                 `json:"summary_version"`
	GeneratedAt              string                                 `json:"generated_at"`
	Template                 string                                 `json:"template"`
	ShareProfile             string                                 `json:"share_profile"`
	DeploymentMode           string                                 `json:"deployment_mode,omitempty"`
	ShareProfileMetadata     *ShareProfileMetadata                  `json:"share_profile_metadata,omitempty"`
	ArtifactMetadata         *ArtifactMetadata                      `json:"artifact_metadata,omitempty"`
	ArtifactBudget           *ArtifactBudget                        `json:"artifact_budget,omitempty"`
	AppendixAvailable        bool                                   `json:"appendix_available,omitempty"`
	FocusedBundleAvailable   bool                                   `json:"focused_bundle_available,omitempty"`
	FullExportAvailable      bool                                   `json:"full_export_available,omitempty"`
	SectionOrder             []string                               `json:"section_order"`
	Sections                 []Section                              `json:"sections"`
	Headline                 Headline                               `json:"headline"`
	ScanScope                *ScanScopeSummary                      `json:"scan_scope,omitempty"`
	OperationalExposure      *scorecore.AxisSummary                 `json:"operational_exposure,omitempty"`
	GovernanceReadiness      *scorecore.AxisSummary                 `json:"governance_readiness,omitempty"`
	EvidenceCompleteness     *risk.EvidenceCompletenessSummary      `json:"evidence_completeness,omitempty"`
	ExecutiveRollup          *controlbacklog.ExecutiveRollup        `json:"executive_rollup,omitempty"`
	GovernedUsageMetrics     *controlbacklog.GovernedUsageMetrics   `json:"governed_usage_metrics,omitempty"`
	WorkflowHighlights       *WorkflowHighlights                    `json:"workflow_highlights,omitempty"`
	FocusView                *FocusView                             `json:"focus_view,omitempty"`
	RepeatUsageSignals       *RepeatUsageSignals                    `json:"repeat_usage_signals,omitempty"`
	AssessmentSummary        *AssessmentSummary                     `json:"assessment_summary,omitempty"`
	PublicSurfaceAssessment  *PublicSurfaceAssessment               `json:"public_surface_assessment,omitempty"`
	Methodology              Methodology                            `json:"methodology"`
	TopRisks                 []RiskItem                             `json:"top_risks"`
	PrivilegeBudget          agginventory.PrivilegeBudget           `json:"privilege_budget"`
	SecurityVisibility       agginventory.SecurityVisibilitySummary `json:"security_visibility"`
	Deltas                   DeltaSummary                           `json:"deltas"`
	Lifecycle                LifecycleSummary                       `json:"lifecycle"`
	RegressDrift             *RegressSummary                        `json:"regress_drift,omitempty"`
	AttackPaths              AttackPathSummary                      `json:"attack_paths"`
	ComplianceSummary        compliance.RollupSummary               `json:"compliance_summary"`
	ControlBacklog           *controlbacklog.Backlog                `json:"control_backlog,omitempty"`
	ScanQuality              *scanquality.Report                    `json:"scan_quality,omitempty"`
	RuntimeSessions          *ingest.SessionSummary                 `json:"runtime_sessions,omitempty"`
	RuntimeEvidence          *ingest.Summary                        `json:"runtime_evidence,omitempty"`
	EvidencePackets          *ingest.EvidencePacketSummary          `json:"evidence_packets,omitempty"`
	AgentActionBOM           *AgentActionBOM                        `json:"agent_action_bom,omitempty"`
	RecentPRReview           *RecentPRReview                        `json:"recent_pr_review,omitempty"`
	Proof                    ProofReference                         `json:"proof"`
	NextActions              []ChecklistItem                        `json:"next_actions"`
	Activation               *ActivationSummary                     `json:"activation,omitempty"`
	PolicyOutcomes           []PolicyOutcome                        `json:"policy_outcomes,omitempty"`
	SuppressedCounts         *SuppressedCounts                      `json:"suppressed_counts,omitempty"`
	ActionPaths              []risk.ActionPath                      `json:"action_paths,omitempty"`
	ActionPathToControlFirst *risk.ActionPathToControlFirst         `json:"action_path_to_control_first,omitempty"`
	ActionSurfaceRegistry    []ActionSurfaceRegistryEntry           `json:"action_surface_registry,omitempty"`
	ControlPathGraph         *aggattack.ControlPathGraph            `json:"control_path_graph,omitempty"`
	WorkflowChains           *agentresolver.WorkflowChainArtifact   `json:"workflow_chains,omitempty"`
	ExposureGroups           []risk.ExposureGroup                   `json:"exposure_groups,omitempty"`
	SourcePrivacy            *sourceprivacy.Contract                `json:"source_privacy,omitempty"`
	controlProofStatus       []ControlProofStatus
	decisionTraceRefsByPath  map[string][]string
	topAttackPaths           []riskattack.ScoredPath
}

type ShareProfileMetadata struct {
	RedactionApplied     bool     `json:"redaction_applied"`
	RedactionVersion     string   `json:"redaction_version,omitempty"`
	PolicySummary        []string `json:"policy_summary,omitempty"`
	SelectedFields       []string `json:"selected_fields,omitempty"`
	ProfileDefaultFields []string `json:"profile_default_fields,omitempty"`
}

type ArtifactMetadata struct {
	ArtifactID         string   `json:"artifact_id"`
	PairID             string   `json:"pair_id,omitempty"`
	VariantKind        string   `json:"variant_kind,omitempty"`
	ShareProfile       string   `json:"share_profile,omitempty"`
	RedactionVersion   string   `json:"redaction_version,omitempty"`
	SelectedFields     []string `json:"selected_fields,omitempty"`
	SourceArtifactRefs []string `json:"source_artifact_refs,omitempty"`
	PrivateJoinMapPath string   `json:"private_join_map_path,omitempty"`
	ShareabilityStatus string   `json:"shareability_status,omitempty"`
}

type ArtifactBudget struct {
	MaxActionPaths         int `json:"max_action_paths,omitempty"`
	MaxBacklogItems        int `json:"max_backlog_items,omitempty"`
	MaxGraphNodes          int `json:"max_graph_nodes,omitempty"`
	MaxGraphEdges          int `json:"max_graph_edges,omitempty"`
	MaxWorkflowChains      int `json:"max_workflow_chains,omitempty"`
	MaxExposureGroups      int `json:"max_exposure_groups,omitempty"`
	MaxAgentActionBOM      int `json:"max_agent_action_bom_items,omitempty"`
	MarkdownLineCap        int `json:"markdown_line_cap,omitempty"`
	MarkdownLeadLineCap    int `json:"markdown_lead_line_cap,omitempty"`
	MarkdownLeadSectionCap int `json:"markdown_lead_section_cap,omitempty"`
}

type PolicyOutcome = outputsignal.PolicyOutcome

type SuppressedCounts = outputsignal.SuppressedCounts

type ScanScopeSummary struct {
	Mode           string `json:"mode"`
	ScopeLabel     string `json:"scope_label"`
	SourceBoundary string `json:"source_boundary"`
	RepoCount      int    `json:"repo_count"`
	TargetCount    int    `json:"target_count"`
}

type AttackPathSummary struct {
	Total      int      `json:"total"`
	TopPathIDs []string `json:"top_path_ids"`
}

type RepeatUsageSignals struct {
	Status                string   `json:"status"`
	BaselinePresent       bool     `json:"baseline_present,omitempty"`
	AssessRuns            int      `json:"assess_runs,omitempty"`
	AssessRerunDetected   bool     `json:"assess_rerun_detected,omitempty"`
	RegressArtifacts      int      `json:"regress_artifacts,omitempty"`
	DriftArtifacts        int      `json:"drift_artifacts,omitempty"`
	EvidenceExports       int      `json:"evidence_exports,omitempty"`
	TicketExports         int      `json:"ticket_exports,omitempty"`
	ActionContractExports int      `json:"action_contract_exports,omitempty"`
	ReasonCodes           []string `json:"reason_codes,omitempty"`
}

type ActionSurfaceRegistryEntry struct {
	RegistryID             string                               `json:"registry_id"`
	SurfaceType            string                               `json:"surface_type,omitempty"`
	Org                    string                               `json:"org"`
	Repo                   string                               `json:"repo"`
	ToolType               string                               `json:"tool_type"`
	ToolInstanceID         string                               `json:"tool_instance_id,omitempty"`
	Location               string                               `json:"location,omitempty"`
	Label                  string                               `json:"label,omitempty"`
	Owner                  string                               `json:"owner,omitempty"`
	OwnerSource            string                               `json:"owner_source,omitempty"`
	Purpose                string                               `json:"purpose,omitempty"`
	PurposeSource          string                               `json:"purpose_source,omitempty"`
	PurposeConfidence      string                               `json:"purpose_confidence,omitempty"`
	Version                string                               `json:"version,omitempty"`
	VersionSource          string                               `json:"version_source,omitempty"`
	ConfigFingerprint      string                               `json:"config_fingerprint,omitempty"`
	ConfigSource           string                               `json:"config_source,omitempty"`
	Credentials            []*agginventory.CredentialProvenance `json:"credentials,omitempty"`
	CredentialAuthorityRef string                               `json:"credential_authority_ref,omitempty"`
	CredentialAuthority    *agginventory.CredentialAuthority    `json:"credential_authority,omitempty"`
	AuthorityBindingRefs   []string                             `json:"authority_binding_refs,omitempty"`
	ReachableActions       []string                             `json:"reachable_actions,omitempty"`
	agginventory.EndpointRefGroupProjection
	MutableEndpointSemanticRefs []string                               `json:"mutable_endpoint_semantic_refs,omitempty"`
	MutableEndpointSemantics    []agginventory.MutableEndpointSemantic `json:"mutable_endpoint_semantics,omitempty"`
	ConfidenceLane              string                                 `json:"confidence_lane,omitempty"`
	ProofStatus                 string                                 `json:"proof_status,omitempty"`
	Remediation                 string                                 `json:"remediation,omitempty"`
	PathIDs                     []string                               `json:"path_ids,omitempty"`
	ActionPathCount             int                                    `json:"action_path_count"`
	GraphRefs                   AgentActionBOMGraphRefs                `json:"graph_refs,omitempty"`
}

type Section struct {
	ID     string         `json:"id"`
	Title  string         `json:"title"`
	Facts  []string       `json:"facts"`
	Impact string         `json:"impact"`
	Action string         `json:"action"`
	Proof  ProofReference `json:"proof"`
}

type Headline struct {
	Score            float64 `json:"score"`
	Grade            string  `json:"grade"`
	ComplianceStatus string  `json:"compliance_status"`
	Compliance       float64 `json:"compliance_percent"`
}

type AssessmentSummary struct {
	GovernablePathCount        int                           `json:"governable_path_count"`
	WriteCapablePathCount      int                           `json:"write_capable_path_count"`
	ProductionBackedPathCount  int                           `json:"production_target_backed_path_count"`
	TopPathToControlFirst      *risk.ActionPath              `json:"top_path_to_control_first,omitempty"`
	TopExecutionIdentityBacked *risk.ActionPath              `json:"top_execution_identity_backed_path,omitempty"`
	OwnerlessExposure          *risk.OwnerlessExposure       `json:"ownerless_exposure,omitempty"`
	IdentityExposureSummary    *risk.IdentityExposureSummary `json:"identity_exposure_summary,omitempty"`
	IdentityToReviewFirst      *risk.IdentityActionTarget    `json:"identity_to_review_first,omitempty"`
	IdentityToRevokeFirst      *risk.IdentityActionTarget    `json:"identity_to_revoke_first,omitempty"`
	ProofChainPath             string                        `json:"proof_chain_path,omitempty"`
}

type PublicSurfaceAssessment struct {
	ManifestName string                   `json:"manifest_name,omitempty"`
	TotalSources int                      `json:"total_sources"`
	LabelCounts  PublicSurfaceLabelCounts `json:"label_counts"`
	Entries      []PublicSurfaceEntry     `json:"entries,omitempty"`
}

type PublicSurfaceLabelCounts struct {
	PublicObserved         int `json:"public_observed"`
	PublicInferred         int `json:"public_inferred"`
	UnsupportedPublicClaim int `json:"unsupported_public_claim"`
	PrivateEvidenceAbsent  int `json:"private_evidence_absent"`
}

type PublicSurfaceEntry struct {
	EntryID            string   `json:"entry_id"`
	SourceClass        string   `json:"source_class"`
	Title              string   `json:"title,omitempty"`
	PublicRef          string   `json:"public_ref"`
	CapturePath        string   `json:"capture_path,omitempty"`
	CapturedAt         string   `json:"captured_at,omitempty"`
	EvidenceLabel      string   `json:"evidence_label"`
	Confidence         string   `json:"confidence,omitempty"`
	InferenceRationale string   `json:"inference_rationale,omitempty"`
	Claims             []string `json:"claims,omitempty"`
}

type WorkflowHighlights struct {
	TotalItems int                 `json:"total_items"`
	Highlights []WorkflowHighlight `json:"highlights,omitempty"`
}

type WorkflowHighlight struct {
	PathID               string   `json:"path_id"`
	WorkflowChainRefs    []string `json:"workflow_chain_refs,omitempty"`
	Repo                 string   `json:"repo,omitempty"`
	Workflow             string   `json:"workflow,omitempty"`
	PathType             string   `json:"path_type,omitempty"`
	TargetClass          string   `json:"target_class,omitempty"`
	AutonomyTier         string   `json:"autonomy_tier,omitempty"`
	DelegationReadiness  string   `json:"delegation_readiness,omitempty"`
	Authority            string   `json:"authority,omitempty"`
	BlastRadius          string   `json:"blast_radius,omitempty"`
	EvidenceSummary      string   `json:"evidence_summary,omitempty"`
	ApprovalPath         string   `json:"approval_path,omitempty"`
	ProofStatus          string   `json:"proof_status,omitempty"`
	RuntimeStatus        string   `json:"runtime_status,omitempty"`
	RuntimeSessionStatus string   `json:"runtime_session_status,omitempty"`
	Recommendation       string   `json:"recommendation,omitempty"`
	BoundaryLabel        string   `json:"boundary_label,omitempty"`
	Explanation          string   `json:"explanation,omitempty"`
}

type FocusView struct {
	Preset                 string              `json:"preset"`
	Title                  string              `json:"title"`
	MatchingPaths          int                 `json:"matching_paths"`
	MatchingWorkflowChains int                 `json:"matching_workflow_chains"`
	MatchingBacklogItems   int                 `json:"matching_backlog_items"`
	EmptyStateStatus       string              `json:"empty_state_status,omitempty"`
	EmptyStateMessage      string              `json:"empty_state_message,omitempty"`
	RecommendedNextActions []string            `json:"recommended_next_actions,omitempty"`
	PathIDs                []string            `json:"path_ids,omitempty"`
	WorkflowChainRefs      []string            `json:"workflow_chain_refs,omitempty"`
	ControlBacklogIDs      []string            `json:"control_backlog_ids,omitempty"`
	Highlights             []WorkflowHighlight `json:"highlights,omitempty"`
}

type RecentPRReview struct {
	Mode            string               `json:"mode"`
	Limit           int                  `json:"limit"`
	SelectedIDs     []string             `json:"selected_ids,omitempty"`
	DateFrom        string               `json:"date_from,omitempty"`
	DateTo          string               `json:"date_to,omitempty"`
	TotalCandidates int                  `json:"total_candidates"`
	Ranked          []RecentPRReviewItem `json:"ranked,omitempty"`
}

type RecentPRReviewItem struct {
	Rank                     int                     `json:"rank"`
	ReviewID                 string                  `json:"review_id"`
	Reference                string                  `json:"reference,omitempty"`
	Provider                 string                  `json:"provider,omitempty"`
	Repo                     string                  `json:"repo,omitempty"`
	PathID                   string                  `json:"path_id,omitempty"`
	Workflow                 string                  `json:"workflow,omitempty"`
	AutonomyTier             string                  `json:"autonomy_tier,omitempty"`
	DelegationReadinessState string                  `json:"delegation_readiness_state,omitempty"`
	RecommendedControl       string                  `json:"recommended_control,omitempty"`
	TargetClass              string                  `json:"target_class,omitempty"`
	EvidenceCompleteness     string                  `json:"evidence_completeness,omitempty"`
	Contradiction            bool                    `json:"contradiction,omitempty"`
	AIAssisted               bool                    `json:"ai_assisted,omitempty"`
	AutomationAssisted       bool                    `json:"automation_assisted,omitempty"`
	CheckCount               int                     `json:"check_count,omitempty"`
	ApprovalCount            int                     `json:"approval_count,omitempty"`
	DeploymentCount          int                     `json:"deployment_count,omitempty"`
	FocusBOMPathID           string                  `json:"focus_bom_path_id,omitempty"`
	Provenance               *attribution.Result     `json:"provenance,omitempty"`
	WorkflowChainRefs        []string                `json:"workflow_chain_refs,omitempty"`
	GraphRefs                AgentActionBOMGraphRefs `json:"graph_refs,omitempty"`
	ProofRefs                []string                `json:"proof_refs,omitempty"`
	EvidencePacketRefs       []string                `json:"evidence_packet_refs,omitempty"`
	MissingEvidence          []string                `json:"missing_evidence,omitempty"`
}

type Methodology struct {
	WrkrVersion         string   `json:"wrkr_version"`
	ScanStartedAt       string   `json:"scan_started_at"`
	ScanCompletedAt     string   `json:"scan_completed_at"`
	ScanDurationSeconds float64  `json:"scan_duration_seconds"`
	RepoCount           int      `json:"repo_count"`
	FileCountProcessed  int      `json:"file_count_processed"`
	DetectorCount       int      `json:"detector_count"`
	CommandSet          []string `json:"command_set"`
	SampleDefinition    string   `json:"sample_definition"`
	ExclusionCriteria   []string `json:"exclusion_criteria"`
}

type RiskItem struct {
	Rank                   int      `json:"rank"`
	CanonicalKey           string   `json:"canonical_key"`
	Score                  float64  `json:"risk_score"`
	FindingType            string   `json:"finding_type"`
	Severity               string   `json:"severity"`
	ToolType               string   `json:"tool_type"`
	Org                    string   `json:"org"`
	Repo                   string   `json:"repo"`
	Location               string   `json:"location"`
	PathID                 string   `json:"path_id,omitempty"`
	InventoryRisk          string   `json:"inventory_risk,omitempty"`
	AttackPathScore        float64  `json:"attack_path_score,omitempty"`
	ControlPriority        string   `json:"control_priority,omitempty"`
	RiskTier               string   `json:"risk_tier,omitempty"`
	ControlState           string   `json:"control_state,omitempty"`
	RiskZone               string   `json:"risk_zone,omitempty"`
	ReviewBurden           string   `json:"review_burden,omitempty"`
	ConfidenceLane         string   `json:"confidence_lane,omitempty"`
	CredentialAccess       bool     `json:"credential_access,omitempty"`
	ProductionTargetStatus string   `json:"production_target_status,omitempty"`
	RecommendedAction      string   `json:"recommended_action,omitempty"`
	WriteCapable           bool     `json:"write_capable,omitempty"`
	ProductionWrite        bool     `json:"production_write,omitempty"`
	Rationale              []string `json:"rationale"`
	Remediation            string   `json:"remediation"`
}

type DeltaSummary struct {
	RiskScoreTrend         DeltaMetric `json:"risk_score_trend"`
	ProfileComplianceDelta DeltaMetric `json:"profile_compliance_delta"`
	PostureScoreTrend      DeltaMetric `json:"posture_score_trend_delta"`
}

type DeltaMetric struct {
	Current     float64 `json:"current"`
	Previous    float64 `json:"previous"`
	Delta       float64 `json:"delta"`
	HasPrevious bool    `json:"has_previous"`
}

type LifecycleSummary struct {
	IdentityCount      int                    `json:"identity_count"`
	UnderReviewCount   int                    `json:"under_review_count"`
	RevokedCount       int                    `json:"revoked_count"`
	DeprecatedCount    int                    `json:"deprecated_count"`
	PendingActionCount int                    `json:"pending_action_count"`
	Gaps               []lifecycle.Gap        `json:"gaps,omitempty"`
	Queue              []governancequeue.Item `json:"queue,omitempty"`
	RecentTransitions  []LifecycleTransition  `json:"recent_transitions"`
}

type LifecycleTransition struct {
	AgentID       string `json:"agent_id"`
	PreviousState string `json:"previous_state"`
	NewState      string `json:"new_state"`
	Trigger       string `json:"trigger"`
	Timestamp     string `json:"timestamp"`
}

type RegressSummary struct {
	BaselineProvided   bool                           `json:"baseline_provided"`
	DriftDetected      bool                           `json:"drift_detected"`
	ReasonCount        int                            `json:"reason_count"`
	ReasonGroups       []ReasonGroup                  `json:"reason_groups"`
	DriftCategoryCount int                            `json:"drift_category_count,omitempty"`
	DriftCategories    []regress.DriftCategorySummary `json:"drift_categories,omitempty"`
	ComparisonStatus   string                         `json:"comparison_status,omitempty"`
	ComparisonIssues   []string                       `json:"comparison_issues,omitempty"`
}

type ReasonGroup struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

type ProofReference struct {
	ChainPath            string            `json:"chain_path"`
	HeadHash             string            `json:"head_hash"`
	RecordCount          int               `json:"record_count"`
	RecordTypeCounts     []RecordTypeCount `json:"record_type_counts"`
	CanonicalFindingKeys []string          `json:"canonical_finding_keys"`
}

type RecordTypeCount struct {
	RecordType string `json:"record_type"`
	Count      int    `json:"count"`
}

type ChecklistItem struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type ActivationSummary struct {
	TargetMode            string           `json:"target_mode"`
	Message               string           `json:"message"`
	EligibleCount         int              `json:"eligible_count"`
	SuppressedPolicyItems bool             `json:"suppressed_policy_items,omitempty"`
	Reason                string           `json:"reason,omitempty"`
	Items                 []ActivationItem `json:"items"`
}

type ActivationItem struct {
	Rank                     int     `json:"rank"`
	RiskScore                float64 `json:"risk_score"`
	FindingType              string  `json:"finding_type"`
	ToolType                 string  `json:"tool_type"`
	Severity                 string  `json:"severity"`
	Location                 string  `json:"location"`
	Repo                     string  `json:"repo"`
	NextStep                 string  `json:"next_step"`
	ItemClass                string  `json:"item_class,omitempty"`
	WriteCapable             bool    `json:"write_capable,omitempty"`
	ProductionWrite          bool    `json:"production_write,omitempty"`
	ApprovalClassification   string  `json:"approval_classification,omitempty"`
	SecurityVisibilityStatus string  `json:"security_visibility_status,omitempty"`
}

func ParseTemplate(raw string) (Template, bool) {
	switch Template(raw) {
	case TemplateExec, TemplateOperator, TemplateAudit, TemplatePublic, TemplateCISO, TemplateAppSec, TemplatePlatform, TemplateCustomerDraft, TemplateAgentActionBOM, TemplateDesignPartnerSummary:
		return Template(raw), true
	default:
		return "", false
	}
}

func ParseShareProfile(raw string) (ShareProfile, bool) {
	switch ShareProfile(raw) {
	case ShareProfileInternal,
		ShareProfilePublic,
		ShareProfileCustomerRedacted,
		ShareProfileDesignPartner,
		ShareProfileExternalRedacted,
		ShareProfileInvestorSafe:
		return ShareProfile(raw), true
	default:
		return "", false
	}
}

func DefaultShareProfile(template Template) ShareProfile {
	switch template {
	case TemplatePublic, TemplateCustomerDraft:
		return ShareProfilePublic
	case TemplateDesignPartnerSummary:
		return ShareProfileDesignPartner
	default:
		return ShareProfileCustomerRedacted
	}
}

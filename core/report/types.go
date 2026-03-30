package report

import (
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/compliance"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/risk"
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
	TemplateExec     Template = "exec"
	TemplateOperator Template = "operator"
	TemplateAudit    Template = "audit"
	TemplatePublic   Template = "public"
)

type ShareProfile string

const (
	ShareProfileInternal ShareProfile = "internal"
	ShareProfilePublic   ShareProfile = "public"
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
}

type Summary struct {
	SummaryVersion           string                                 `json:"summary_version"`
	GeneratedAt              string                                 `json:"generated_at"`
	Template                 string                                 `json:"template"`
	ShareProfile             string                                 `json:"share_profile"`
	SectionOrder             []string                               `json:"section_order"`
	Sections                 []Section                              `json:"sections"`
	Headline                 Headline                               `json:"headline"`
	AssessmentSummary        *AssessmentSummary                     `json:"assessment_summary,omitempty"`
	Methodology              Methodology                            `json:"methodology"`
	TopRisks                 []RiskItem                             `json:"top_risks"`
	PrivilegeBudget          agginventory.PrivilegeBudget           `json:"privilege_budget"`
	SecurityVisibility       agginventory.SecurityVisibilitySummary `json:"security_visibility"`
	Deltas                   DeltaSummary                           `json:"deltas"`
	Lifecycle                LifecycleSummary                       `json:"lifecycle"`
	RegressDrift             *RegressSummary                        `json:"regress_drift,omitempty"`
	AttackPaths              AttackPathSummary                      `json:"attack_paths"`
	ComplianceSummary        compliance.RollupSummary               `json:"compliance_summary"`
	Proof                    ProofReference                         `json:"proof"`
	NextActions              []ChecklistItem                        `json:"next_actions"`
	Activation               *ActivationSummary                     `json:"activation,omitempty"`
	ActionPaths              []risk.ActionPath                      `json:"action_paths,omitempty"`
	ActionPathToControlFirst *risk.ActionPathToControlFirst         `json:"action_path_to_control_first,omitempty"`
	ExposureGroups           []risk.ExposureGroup                   `json:"exposure_groups,omitempty"`
}

type AttackPathSummary struct {
	Total      int      `json:"total"`
	TopPathIDs []string `json:"top_path_ids"`
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
	Rank              int      `json:"rank"`
	CanonicalKey      string   `json:"canonical_key"`
	Score             float64  `json:"risk_score"`
	FindingType       string   `json:"finding_type"`
	Severity          string   `json:"severity"`
	ToolType          string   `json:"tool_type"`
	Org               string   `json:"org"`
	Repo              string   `json:"repo"`
	Location          string   `json:"location"`
	PathID            string   `json:"path_id,omitempty"`
	RecommendedAction string   `json:"recommended_action,omitempty"`
	WriteCapable      bool     `json:"write_capable,omitempty"`
	ProductionWrite   bool     `json:"production_write,omitempty"`
	Rationale         []string `json:"rationale"`
	Remediation       string   `json:"remediation"`
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
	IdentityCount      int                   `json:"identity_count"`
	UnderReviewCount   int                   `json:"under_review_count"`
	RevokedCount       int                   `json:"revoked_count"`
	DeprecatedCount    int                   `json:"deprecated_count"`
	PendingActionCount int                   `json:"pending_action_count"`
	RecentTransitions  []LifecycleTransition `json:"recent_transitions"`
}

type LifecycleTransition struct {
	AgentID       string `json:"agent_id"`
	PreviousState string `json:"previous_state"`
	NewState      string `json:"new_state"`
	Trigger       string `json:"trigger"`
	Timestamp     string `json:"timestamp"`
}

type RegressSummary struct {
	BaselineProvided bool          `json:"baseline_provided"`
	DriftDetected    bool          `json:"drift_detected"`
	ReasonCount      int           `json:"reason_count"`
	ReasonGroups     []ReasonGroup `json:"reason_groups"`
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
	case TemplateExec, TemplateOperator, TemplateAudit, TemplatePublic:
		return Template(raw), true
	default:
		return "", false
	}
}

func ParseShareProfile(raw string) (ShareProfile, bool) {
	switch ShareProfile(raw) {
	case ShareProfileInternal, ShareProfilePublic:
		return ShareProfile(raw), true
	default:
		return "", false
	}
}

package report

import (
	"time"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/state"
)

const SummaryVersion = "v1"

const (
	SectionHeadline   = "headline_posture"
	SectionTopRisks   = "top_prioritized_risks"
	SectionChanges    = "change_since_previous"
	SectionLifecycle  = "lifecycle_actions"
	SectionProof      = "proof_verification_footer"
	SectionNextAction = "next_actions"
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
	SummaryVersion string           `json:"summary_version"`
	GeneratedAt    string           `json:"generated_at"`
	Template       string           `json:"template"`
	ShareProfile   string           `json:"share_profile"`
	SectionOrder   []string         `json:"section_order"`
	Sections       []Section        `json:"sections"`
	Headline       Headline         `json:"headline"`
	TopRisks       []RiskItem       `json:"top_risks"`
	Deltas         DeltaSummary     `json:"deltas"`
	Lifecycle      LifecycleSummary `json:"lifecycle"`
	RegressDrift   *RegressSummary  `json:"regress_drift,omitempty"`
	Proof          ProofReference   `json:"proof"`
	NextActions    []ChecklistItem  `json:"next_actions"`
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

type RiskItem struct {
	Rank         int      `json:"rank"`
	CanonicalKey string   `json:"canonical_key"`
	Score        float64  `json:"risk_score"`
	FindingType  string   `json:"finding_type"`
	Severity     string   `json:"severity"`
	ToolType     string   `json:"tool_type"`
	Org          string   `json:"org"`
	Repo         string   `json:"repo"`
	Location     string   `json:"location"`
	Rationale    []string `json:"rationale"`
	Remediation  string   `json:"remediation"`
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

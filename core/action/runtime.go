package action

import (
	"fmt"
	"strings"

	"github.com/Clyra-AI/wrkr/core/action/changes"
	"github.com/Clyra-AI/wrkr/core/state"
)

type ScheduledResult struct {
	ScoreDeltaText      string  `json:"score_delta_text"`
	ComplianceDeltaText string  `json:"compliance_delta_text"`
	Summary             string  `json:"summary"`
	PostureScore        float64 `json:"posture_score"`
	CompliancePercent   float64 `json:"compliance_percent"`
	SummaryArtifactPath string  `json:"summary_artifact_path,omitempty"`
}

type PRModeInput struct {
	ChangedPaths    []string
	RiskDelta       float64
	ComplianceDelta float64
	BlockThreshold  float64
}

type PRModeResult struct {
	ShouldComment bool     `json:"should_comment"`
	BlockMerge    bool     `json:"block_merge"`
	RelevantPaths []string `json:"relevant_paths"`
	Comment       string   `json:"comment"`
}

// RunScheduled derives deterministic scheduled-mode summary text from a scan snapshot.
func RunScheduled(snapshot state.Snapshot) ScheduledResult {
	return RunScheduledWithSummary(snapshot, "")
}

// RunScheduledWithSummary derives deterministic scheduled-mode summary text and includes a summary artifact path when available.
func RunScheduledWithSummary(snapshot state.Snapshot, summaryArtifactPath string) ScheduledResult {
	score := 0.0
	scoreDelta := 0.0
	if snapshot.PostureScore != nil {
		score = snapshot.PostureScore.Score
		scoreDelta = snapshot.PostureScore.TrendDelta
	}

	compliance := 0.0
	complianceDelta := 0.0
	if snapshot.Profile != nil {
		compliance = snapshot.Profile.CompliancePercent
		complianceDelta = snapshot.Profile.DeltaPercent
	}

	scoreDeltaText := fmt.Sprintf("posture score delta %+.2f (current %.2f)", scoreDelta, score)
	complianceDeltaText := fmt.Sprintf("profile compliance delta %+.2f%% (current %.2f%%)", complianceDelta, compliance)
	summary := "scheduled mode: " + scoreDeltaText + "; " + complianceDeltaText
	if strings.TrimSpace(summaryArtifactPath) != "" {
		summary += "; summary artifact " + strings.TrimSpace(summaryArtifactPath)
	}
	return ScheduledResult{
		ScoreDeltaText:      scoreDeltaText,
		ComplianceDeltaText: complianceDeltaText,
		Summary:             summary,
		PostureScore:        score,
		CompliancePercent:   compliance,
		SummaryArtifactPath: strings.TrimSpace(summaryArtifactPath),
	}
}

// RunPRMode emits deterministic PR comment payloads only for AI-config affecting file changes.
func RunPRMode(in PRModeInput) PRModeResult {
	relevant := changes.RelevantPaths(in.ChangedPaths)
	if len(relevant) == 0 {
		return PRModeResult{ShouldComment: false, BlockMerge: false, RelevantPaths: []string{}}
	}

	block := in.BlockThreshold > 0 && in.RiskDelta >= in.BlockThreshold
	comment := fmt.Sprintf(
		"wrkr PR mode: risk delta %+.2f, profile compliance delta %+.2f%%, relevant paths: %s",
		in.RiskDelta,
		in.ComplianceDelta,
		strings.Join(relevant, ", "),
	)
	if block {
		comment += fmt.Sprintf("; merge blocked (threshold %.2f)", in.BlockThreshold)
	}

	return PRModeResult{
		ShouldComment: true,
		BlockMerge:    block,
		RelevantPaths: relevant,
		Comment:       comment,
	}
}

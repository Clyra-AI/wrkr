package score

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"gopkg.in/yaml.v3"
)

type Breakdown struct {
	PolicyPassRate       float64 `json:"policy_pass_rate"`
	ApprovalCoverage     float64 `json:"approval_coverage"`
	SeverityDistribution float64 `json:"severity_distribution"`
	ProfileCompliance    float64 `json:"profile_compliance"`
	DriftRate            float64 `json:"drift_rate"`
}

type WeightedBreakdown struct {
	PolicyPassRate       float64 `json:"policy_pass_rate"`
	ApprovalCoverage     float64 `json:"approval_coverage"`
	SeverityDistribution float64 `json:"severity_distribution"`
	ProfileCompliance    float64 `json:"profile_compliance"`
	DriftRate            float64 `json:"drift_rate"`
}

type Result struct {
	Score             float64            `json:"score"`
	Grade             string             `json:"grade"`
	Breakdown         Breakdown          `json:"breakdown"`
	WeightedBreakdown WeightedBreakdown  `json:"weighted_breakdown"`
	Weights           scoremodel.Weights `json:"weights"`
	TrendDelta        float64            `json:"trend_delta"`
}

type Input struct {
	Findings        []model.Finding
	Identities      []manifest.IdentityRecord
	ProfileResult   profileeval.Result
	TransitionCount int
	Weights         scoremodel.Weights
	Previous        *Result
}

type AxisSummary struct {
	Grade     string   `json:"grade"`
	PathCount int      `json:"path_count"`
	Driver    string   `json:"driver"`
	Rationale []string `json:"rationale,omitempty"`
}

func Compute(in Input) Result {
	weights := in.Weights
	if err := weights.Validate(); err != nil {
		weights = scoremodel.DefaultWeights()
	}

	breakdown := Breakdown{
		PolicyPassRate:       policyPassRate(in.Findings),
		ApprovalCoverage:     approvalCoverage(in.Identities),
		SeverityDistribution: severityDistribution(in.Findings),
		ProfileCompliance:    in.ProfileResult.CompliancePercent,
		DriftRate:            driftScore(in.TransitionCount, len(in.Identities)),
	}
	weighted := WeightedBreakdown{
		PolicyPassRate:       round2(breakdown.PolicyPassRate * weights.PolicyPassRate / 100),
		ApprovalCoverage:     round2(breakdown.ApprovalCoverage * weights.ApprovalCoverage / 100),
		SeverityDistribution: round2(breakdown.SeverityDistribution * weights.SeverityDistribution / 100),
		ProfileCompliance:    round2(breakdown.ProfileCompliance * weights.ProfileCompliance / 100),
		DriftRate:            round2(breakdown.DriftRate * weights.DriftRate / 100),
	}
	total := round2(weighted.PolicyPassRate + weighted.ApprovalCoverage + weighted.SeverityDistribution + weighted.ProfileCompliance + weighted.DriftRate)
	delta := 0.0
	if in.Previous != nil {
		delta = round2(total - in.Previous.Score)
	}

	return Result{
		Score:             total,
		Grade:             scoremodel.Grade(total),
		Breakdown:         breakdown,
		WeightedBreakdown: weighted,
		Weights:           weights,
		TrendDelta:        delta,
	}
}

func SummarizeOperationalExposure(paths []risk.ActionPath) AxisSummary {
	summary := AxisSummary{Grade: "low", PathCount: len(paths), Driver: "no_governable_paths"}
	if len(paths) == 0 {
		summary.Rationale = []string{"no governable action paths were present in saved state"}
		return summary
	}

	productionBacked := 0
	credentialBearing := 0
	writeCapable := 0
	deployed := 0
	for _, path := range paths {
		if path.ProductionWrite || strings.EqualFold(strings.TrimSpace(path.DeploymentStatus), "deployed") {
			productionBacked++
		}
		if path.CredentialAccess {
			credentialBearing++
		}
		if path.WriteCapable || path.DeployWrite || path.MergeExecute || path.PullRequestWrite {
			writeCapable++
		}
		if strings.EqualFold(strings.TrimSpace(path.DeploymentStatus), "deployed") {
			deployed++
		}
	}

	switch {
	case productionBacked > 0 && credentialBearing > 0:
		summary.Grade = "critical"
		summary.Driver = "production_and_credentials"
	case productionBacked > 0 || credentialBearing > 0:
		summary.Grade = "high"
		summary.Driver = "credential_or_production"
	case writeCapable > 0 || deployed > 0:
		summary.Grade = "medium"
		summary.Driver = "write_or_runtime_capable"
	default:
		summary.Grade = "low"
		summary.Driver = "review_only"
	}
	summary.Rationale = []string{
		fmt.Sprintf("production_backed_paths=%d", productionBacked),
		fmt.Sprintf("credential_bearing_paths=%d", credentialBearing),
		fmt.Sprintf("write_capable_paths=%d", writeCapable),
		fmt.Sprintf("runtime_deployed_paths=%d", deployed),
	}
	return summary
}

func SummarizeGovernanceReadiness(paths []risk.ActionPath, missingProofCount int, coverageReduced bool) AxisSummary {
	summary := AxisSummary{Grade: "high", PathCount: len(paths), Driver: "controls_present"}
	if len(paths) == 0 && missingProofCount == 0 && !coverageReduced {
		summary.Rationale = []string{"no governable action paths require ownership, approval, proof, or policy follow-up"}
		return summary
	}

	approvalGaps := 0
	missingOwners := 0
	policyGaps := 0
	for _, path := range paths {
		if path.ApprovalGap {
			approvalGaps++
		}
		if strings.TrimSpace(path.OwnershipStatus) == "" || strings.EqualFold(strings.TrimSpace(path.OwnershipStatus), "unresolved") || strings.EqualFold(strings.TrimSpace(path.OwnershipState), "missing") || strings.EqualFold(strings.TrimSpace(path.OwnershipState), "conflicting") {
			missingOwners++
		}
		if strings.EqualFold(strings.TrimSpace(path.PolicyCoverageStatus), "") || strings.EqualFold(strings.TrimSpace(path.PolicyCoverageStatus), "none") || strings.EqualFold(strings.TrimSpace(path.PolicyCoverageStatus), "stale") || strings.EqualFold(strings.TrimSpace(path.PolicyCoverageStatus), "conflict") {
			policyGaps++
		}
	}

	switch {
	case coverageReduced || missingProofCount > 0 || approvalGaps > 0 || missingOwners > 0 || policyGaps > 0:
		summary.Grade = "low"
		summary.Driver = "governance_gaps_present"
		if !coverageReduced && missingProofCount == 0 && (approvalGaps+missingOwners+policyGaps) == 1 {
			summary.Grade = "medium"
			summary.Driver = "single_governance_gap"
		}
	default:
		summary.Grade = "high"
		summary.Driver = "controls_present"
	}
	summary.Rationale = []string{
		fmt.Sprintf("approval_gaps=%d", approvalGaps),
		fmt.Sprintf("missing_owner_paths=%d", missingOwners),
		fmt.Sprintf("policy_gaps=%d", policyGaps),
		fmt.Sprintf("missing_proof_paths=%d", missingProofCount),
		fmt.Sprintf("coverage_reduced=%t", coverageReduced),
	}
	return summary
}

func LoadWeights(policyPath, repoRoot string) (scoremodel.Weights, error) {
	weights := scoremodel.DefaultWeights()
	paths := []string{}
	if strings.TrimSpace(policyPath) != "" {
		paths = append(paths, policyPath)
	}
	if strings.TrimSpace(repoRoot) != "" {
		candidate := filepath.Join(repoRoot, "wrkr-policy.yaml")
		if _, err := os.Stat(candidate); err == nil {
			paths = append(paths, candidate)
		}
	}
	for _, path := range paths {
		override, err := loadWeightOverrides(path)
		if err != nil {
			return scoremodel.Weights{}, err
		}
		if override != nil {
			weights = *override
		}
	}
	if err := weights.Validate(); err != nil {
		return scoremodel.Weights{}, err
	}
	return weights, nil
}

type policyDoc struct {
	ScoreWeights map[string]any `yaml:"score_weights"`
}

func loadWeightOverrides(path string) (*scoremodel.Weights, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- path is a local policy file path supplied by explicit CLI/config input.
	if err != nil {
		return nil, fmt.Errorf("read score weights %s: %w", path, err)
	}
	var doc policyDoc
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("parse score weights %s: %w", path, err)
	}
	if len(doc.ScoreWeights) == 0 {
		return nil, nil
	}
	weights := scoremodel.DefaultWeights()
	for key, value := range doc.ScoreWeights {
		normalized := strings.ToLower(strings.TrimSpace(key))
		parsed, err := parseWeight(value)
		if err != nil {
			return nil, fmt.Errorf("invalid score weight %s in %s: %w", key, path, err)
		}
		switch normalized {
		case "policy_pass_rate":
			weights.PolicyPassRate = parsed
		case "approval_coverage":
			weights.ApprovalCoverage = parsed
		case "severity_distribution":
			weights.SeverityDistribution = parsed
		case "profile_compliance":
			weights.ProfileCompliance = parsed
		case "drift_rate":
			weights.DriftRate = parsed
		}
	}
	if err := weights.Validate(); err != nil {
		return nil, err
	}
	return &weights, nil
}

func parseWeight(value any) (float64, error) {
	switch typed := value.(type) {
	case int:
		return float64(typed), nil
	case int64:
		return float64(typed), nil
	case float64:
		return typed, nil
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return 0, err
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("unsupported type %T", value)
	}
}

func policyPassRate(findings []model.Finding) float64 {
	total := 0
	pass := 0
	for _, finding := range findings {
		if finding.FindingType != "policy_check" {
			continue
		}
		total++
		if strings.EqualFold(finding.CheckResult, model.CheckResultPass) {
			pass++
		}
	}
	if total == 0 {
		return 100
	}
	return round2(float64(pass) / float64(total) * 100)
}

func approvalCoverage(identities []manifest.IdentityRecord) float64 {
	total := 0
	approved := 0
	for _, item := range identities {
		if !item.Present {
			continue
		}
		total++
		if item.ApprovalState == "valid" {
			approved++
		}
	}
	if total == 0 {
		return 100
	}
	return round2(float64(approved) / float64(total) * 100)
}

func severityDistribution(findings []model.Finding) float64 {
	if len(findings) == 0 {
		return 100
	}
	penalty := 0.0
	for _, finding := range findings {
		switch finding.Severity {
		case model.SeverityCritical:
			penalty += 1.0
		case model.SeverityHigh:
			penalty += 0.7
		case model.SeverityMedium:
			penalty += 0.4
		case model.SeverityLow:
			penalty += 0.1
		}
	}
	raw := 100 - (penalty / float64(len(findings)) * 100)
	if raw < 0 {
		raw = 0
	}
	return round2(raw)
}

func driftScore(transitionCount, identityCount int) float64 {
	if identityCount <= 0 {
		return 100
	}
	rate := float64(transitionCount) / float64(identityCount)
	raw := 100 - (rate * 100)
	if raw < 0 {
		raw = 0
	}
	return round2(raw)
}

func round2(in float64) float64 {
	return float64(int(in*100+0.5)) / 100
}

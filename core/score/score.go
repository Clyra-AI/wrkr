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
	payload, err := os.ReadFile(path)
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
	raw := 100 - (penalty/float64(len(findings))*100)
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

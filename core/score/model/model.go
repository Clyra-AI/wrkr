package model

import (
	"fmt"
	"math"
)

type Weights struct {
	PolicyPassRate       float64 `yaml:"policy_pass_rate" json:"policy_pass_rate"`
	ApprovalCoverage     float64 `yaml:"approval_coverage" json:"approval_coverage"`
	SeverityDistribution float64 `yaml:"severity_distribution" json:"severity_distribution"`
	ProfileCompliance    float64 `yaml:"profile_compliance" json:"profile_compliance"`
	DriftRate            float64 `yaml:"drift_rate" json:"drift_rate"`
}

func DefaultWeights() Weights {
	return Weights{
		PolicyPassRate:       40,
		ApprovalCoverage:     20,
		SeverityDistribution: 20,
		ProfileCompliance:    10,
		DriftRate:            10,
	}
}

func (w Weights) Validate() error {
	values := []float64{w.PolicyPassRate, w.ApprovalCoverage, w.SeverityDistribution, w.ProfileCompliance, w.DriftRate}
	total := 0.0
	for _, value := range values {
		if value < 0 {
			return fmt.Errorf("weights cannot be negative")
		}
		total += value
	}
	if math.Abs(total-100) > 0.0001 {
		return fmt.Errorf("weights must sum to 100, got %.2f", total)
	}
	return nil
}

func Grade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

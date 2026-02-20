package profileeval

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/policy/profile"
)

type Result struct {
	ProfileName         string   `json:"profile"`
	CompliancePercent   float64  `json:"compliance_percent"`
	Fails               []string `json:"failing_rules"`
	DeltaPercent        float64  `json:"compliance_delta"`
	MinCompliance       float64  `json:"min_compliance"`
	Status              string   `json:"status"`
	Rationale           []string `json:"rationale"`
}

func Evaluate(p profile.Profile, findings []model.Finding, previous *Result) Result {
	ruleFails, totalRules := collectRuleResults(findings)
	if len(p.RuleThreshold) > totalRules {
		totalRules = len(p.RuleThreshold)
	}
	if totalRules == 0 {
		totalRules = len(p.RuleThreshold)
	}

	failList := make([]string, 0)
	rationale := make([]string, 0)
	for ruleID, threshold := range p.RuleThreshold {
		count := ruleFails[strings.ToUpper(ruleID)]
		if count > threshold {
			failList = append(failList, strings.ToUpper(ruleID))
			rationale = append(rationale, fmt.Sprintf("%s fail_count=%d threshold=%d", strings.ToUpper(ruleID), count, threshold))
		}
	}
	for ruleID, count := range ruleFails {
		if _, exists := p.RuleThreshold[ruleID]; exists {
			continue
		}
		if count > 0 {
			failList = append(failList, ruleID)
			rationale = append(rationale, fmt.Sprintf("%s fail_count=%d threshold=0", ruleID, count))
		}
	}

	sort.Strings(failList)
	sort.Strings(rationale)
	passCount := totalRules - len(unique(failList))
	if passCount < 0 {
		passCount = 0
	}
	compliance := 0.0
	if totalRules > 0 {
		compliance = round2(float64(passCount) / float64(totalRules) * 100)
	}

	delta := 0.0
	if previous != nil {
		delta = round2(compliance - previous.CompliancePercent)
	}
	status := "pass"
	if compliance < p.MinCompliance || len(failList) > 0 {
		status = "fail"
	}

	return Result{
		ProfileName:       strings.ToLower(strings.TrimSpace(p.Name)),
		CompliancePercent: compliance,
		Fails:             failList,
		DeltaPercent:      delta,
		MinCompliance:     p.MinCompliance,
		Status:            status,
		Rationale:         rationale,
	}
}

func collectRuleResults(findings []model.Finding) (map[string]int, int) {
	ruleFails := map[string]int{}
	ruleSeen := map[string]struct{}{}
	for _, finding := range findings {
		ruleID := strings.ToUpper(strings.TrimSpace(finding.RuleID))
		if ruleID == "" {
			continue
		}
		ruleSeen[ruleID] = struct{}{}
		if finding.FindingType == "policy_check" && strings.EqualFold(finding.CheckResult, model.CheckResultPass) {
			continue
		}
		if finding.FindingType == "policy_check" || finding.FindingType == "policy_violation" {
			ruleFails[ruleID] = 1
		}
	}
	return ruleFails, len(ruleSeen)
}

func unique(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func round2(in float64) float64 {
	return math.Round(in*100) / 100
}

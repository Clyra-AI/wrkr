package exposure

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk/autonomy"
)

type SkillPrivilegeConcentration struct {
	ExecRatio      float64 `json:"exec_ratio" yaml:"exec_ratio"`
	WriteRatio     float64 `json:"write_ratio" yaml:"write_ratio"`
	ExecWriteRatio float64 `json:"exec_write_ratio" yaml:"exec_write_ratio"`
}

type SkillSprawl struct {
	Total int `json:"total" yaml:"total"`
	Exec  int `json:"exec" yaml:"exec"`
	Write int `json:"write" yaml:"write"`
	Read  int `json:"read" yaml:"read"`
	None  int `json:"none" yaml:"none"`
}

type RepoExposureSummary struct {
	Org                         string                       `json:"org" yaml:"org"`
	Repo                        string                       `json:"repo" yaml:"repo"`
	PermissionUnion             []string                     `json:"permission_union" yaml:"permission_union"`
	DataUnion                   []string                     `json:"data_union" yaml:"data_union"`
	HighestAutonomy             string                       `json:"highest_autonomy" yaml:"highest_autonomy"`
	CombinedRiskScore           float64                      `json:"combined_risk_score" yaml:"combined_risk_score"`
	SkillPrivilegeCeiling       []string                     `json:"skill_privilege_ceiling" yaml:"skill_privilege_ceiling"`
	SkillPrivilegeConcentration SkillPrivilegeConcentration  `json:"skill_privilege_concentration" yaml:"skill_privilege_concentration"`
	SkillSprawl                 SkillSprawl                  `json:"skill_sprawl" yaml:"skill_sprawl"`
	ExposureFactors             []string                     `json:"exposure_factors" yaml:"exposure_factors"`
}

type accumulator struct {
	org             string
	repo            string
	permissions     map[string]struct{}
	dataClasses     map[string]struct{}
	autonomy        string
	skillCeiling    map[string]struct{}
	skillSprawl     SkillSprawl
	findingCount    int
	skillMetricSeen bool
}

func Build(findings []model.Finding, repoRisk map[string]float64) []RepoExposureSummary {
	acc := map[string]*accumulator{}
	for _, finding := range findings {
		repo := strings.TrimSpace(finding.Repo)
		if repo == "" {
			continue
		}
		org := strings.TrimSpace(finding.Org)
		if org == "" {
			org = "local"
		}
		key := org + "::" + repo
		item, exists := acc[key]
		if !exists {
			item = &accumulator{
				org:          org,
				repo:         repo,
				permissions:  map[string]struct{}{},
				dataClasses:  map[string]struct{}{},
				skillCeiling: map[string]struct{}{},
			}
			acc[key] = item
		}
		item.findingCount++
		for _, permission := range finding.Permissions {
			trimmed := strings.TrimSpace(permission)
			if trimmed == "" {
				continue
			}
			item.permissions[trimmed] = struct{}{}
		}
		if rankAutonomy(finding.Autonomy) > rankAutonomy(item.autonomy) {
			item.autonomy = finding.Autonomy
		}
		if strings.TrimSpace(finding.Autonomy) == "" && finding.FindingType == "ci_autonomy" {
			item.autonomy = autonomy.LevelHeadlessAuto
		}
		item.dataClasses[dataClassForFinding(finding)] = struct{}{}

		if finding.FindingType == "skill_metrics" {
			item.skillMetricSeen = true
			mergeSkillMetrics(item, finding)
		}
	}

	out := make([]RepoExposureSummary, 0, len(acc))
	for key, item := range acc {
		risk := repoRisk[key]
		if risk == 0 {
			risk = fallbackRepoRisk(item)
		}
		permissions := sortedSet(item.permissions)
		dataUnion := sortedSet(item.dataClasses)
		ceiling := sortedSet(item.skillCeiling)
		concentration := computeConcentration(item.skillSprawl)
		if item.autonomy == "" {
			item.autonomy = autonomy.LevelInteractive
		}
		factors := []string{
			fmt.Sprintf("permission_union=%d", len(permissions)),
			fmt.Sprintf("data_union=%d", len(dataUnion)),
			"highest_autonomy=" + item.autonomy,
		}
		if item.skillMetricSeen {
			factors = append(factors,
				fmt.Sprintf("skill_ceiling=%d", len(ceiling)),
				fmt.Sprintf("skill_exec_write_ratio=%.2f", concentration.ExecWriteRatio),
			)
		}
		sort.Strings(factors)

		out = append(out, RepoExposureSummary{
			Org:               item.org,
			Repo:              item.repo,
			PermissionUnion:   permissions,
			DataUnion:         dataUnion,
			HighestAutonomy:   item.autonomy,
			CombinedRiskScore: round2(risk),
			SkillPrivilegeCeiling:       ceiling,
			SkillPrivilegeConcentration: concentration,
			SkillSprawl:                 item.skillSprawl,
			ExposureFactors:             factors,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Org != out[j].Org {
			return out[i].Org < out[j].Org
		}
		return out[i].Repo < out[j].Repo
	})
	return out
}

func mergeSkillMetrics(item *accumulator, finding model.Finding) {
	for _, permission := range finding.Permissions {
		trimmed := strings.TrimSpace(permission)
		if trimmed == "" {
			continue
		}
		item.skillCeiling[trimmed] = struct{}{}
	}
	if ceilingEvidence := evidenceString(finding, "skill_privilege_ceiling"); ceilingEvidence != "" {
		for _, permission := range strings.Split(ceilingEvidence, ",") {
			trimmed := strings.TrimSpace(permission)
			if trimmed == "" {
				continue
			}
			item.skillCeiling[trimmed] = struct{}{}
		}
	}
	item.skillSprawl.Total += int(evidenceFloat(finding, "skill_sprawl.total"))
	item.skillSprawl.Exec += int(evidenceFloat(finding, "skill_sprawl.exec"))
	item.skillSprawl.Write += int(evidenceFloat(finding, "skill_sprawl.write"))
	item.skillSprawl.Read += int(evidenceFloat(finding, "skill_sprawl.read"))
	item.skillSprawl.None += int(evidenceFloat(finding, "skill_sprawl.none"))
}

func computeConcentration(sprawl SkillSprawl) SkillPrivilegeConcentration {
	if sprawl.Total <= 0 {
		return SkillPrivilegeConcentration{}
	}
	total := float64(sprawl.Total)
	return SkillPrivilegeConcentration{
		ExecRatio:      round2(float64(sprawl.Exec) / total),
		WriteRatio:     round2(float64(sprawl.Write) / total),
		ExecWriteRatio: round2(float64(sprawl.Exec+sprawl.Write) / total),
	}
}

func dataClassForFinding(finding model.Finding) string {
	if finding.FindingType == "secret_presence" {
		return "credentials"
	}
	location := strings.ToLower(strings.TrimSpace(finding.Location))
	switch {
	case strings.Contains(location, "profile"), strings.Contains(location, "customer"), strings.Contains(location, "user"):
		return "pii"
	case strings.Contains(location, ".github/workflows"), strings.Contains(location, "jenkinsfile"):
		return "delivery"
	default:
		return "code"
	}
}

func fallbackRepoRisk(item *accumulator) float64 {
	base := float64(item.findingCount) * 0.7
	if rankAutonomy(item.autonomy) >= rankAutonomy(autonomy.LevelHeadlessAuto) {
		base = base * 1.5
	}
	if base > 10 {
		return 10
	}
	return base
}

func rankAutonomy(level string) int {
	switch level {
	case autonomy.LevelHeadlessAuto:
		return 4
	case autonomy.LevelHeadlessGate:
		return 3
	case autonomy.LevelCopilot:
		return 2
	case autonomy.LevelInteractive:
		return 1
	default:
		return 0
	}
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func evidenceString(finding model.Finding, key string) string {
	needle := strings.ToLower(strings.TrimSpace(key))
	for _, item := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(item.Key)) == needle {
			return strings.TrimSpace(item.Value)
		}
	}
	return ""
}

func evidenceFloat(finding model.Finding, key string) float64 {
	value := evidenceString(finding, key)
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func round2(in float64) float64 {
	parsed, _ := strconv.ParseFloat(fmt.Sprintf("%.2f", in), 64)
	return parsed
}

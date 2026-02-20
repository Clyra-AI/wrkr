package profile

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed profiles/*.yaml
var profilesFS embed.FS

type Profile struct {
	Name          string         `yaml:"name" json:"name"`
	Description   string         `yaml:"description" json:"description"`
	MinCompliance float64        `yaml:"min_compliance" json:"min_compliance"`
	RuleThreshold map[string]int `yaml:"rule_thresholds" json:"rule_thresholds"`
}

func Builtin(name string) (Profile, error) {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" {
		trimmed = "standard"
	}
	payload, err := profilesFS.ReadFile("profiles/" + trimmed + ".yaml")
	if err != nil {
		return Profile{}, fmt.Errorf("load profile %s: %w", trimmed, err)
	}
	var out Profile
	if err := yaml.Unmarshal(payload, &out); err != nil {
		return Profile{}, fmt.Errorf("parse profile %s: %w", trimmed, err)
	}
	out.Name = trimmed
	normalize(&out)
	return out, nil
}

func WithOverrides(base Profile, policyPath, repoRoot string) (Profile, error) {
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
		overrides, err := loadOverrides(path)
		if err != nil {
			return Profile{}, err
		}
		if override, exists := overrides[strings.ToLower(base.Name)]; exists {
			if override.MinCompliance > 0 {
				base.MinCompliance = override.MinCompliance
			}
			for ruleID, threshold := range override.RuleThreshold {
				base.RuleThreshold[ruleID] = threshold
			}
		}
	}
	normalize(&base)
	return base, nil
}

type policyDoc struct {
	Profiles map[string]Profile `yaml:"profiles"`
}

func loadOverrides(path string) (map[string]Profile, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- path is a local policy file path supplied by explicit CLI/config input.
	if err != nil {
		return nil, fmt.Errorf("read profile overrides %s: %w", path, err)
	}
	var doc policyDoc
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("parse profile overrides %s: %w", path, err)
	}
	out := map[string]Profile{}
	for name, p := range doc.Profiles {
		p.Name = strings.ToLower(strings.TrimSpace(name))
		normalize(&p)
		out[p.Name] = p
	}
	return out, nil
}

func normalize(p *Profile) {
	if p.RuleThreshold == nil {
		p.RuleThreshold = map[string]int{}
	}
	normalized := map[string]int{}
	for key, value := range p.RuleThreshold {
		normalized[strings.ToUpper(strings.TrimSpace(key))] = value
	}
	keys := make([]string, 0, len(normalized))
	for key := range normalized {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sorted := map[string]int{}
	for _, key := range keys {
		sorted[key] = normalized[key]
	}
	p.RuleThreshold = sorted
	if p.MinCompliance < 0 {
		p.MinCompliance = 0
	}
	if p.MinCompliance > 100 {
		p.MinCompliance = 100
	}
}

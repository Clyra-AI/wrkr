package policy

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rules/builtin.yaml
var builtinPolicyFS embed.FS

func LoadRules(customPolicyPath, repoRoot string) ([]Rule, error) {
	builtin, err := loadBuiltinRulePack()
	if err != nil {
		return nil, err
	}

	rulesByID := map[string]Rule{}
	for _, rule := range builtin {
		rulesByID[rule.ID] = rule
	}

	paths := make([]string, 0, 2)
	if strings.TrimSpace(customPolicyPath) != "" {
		paths = append(paths, customPolicyPath)
	}
	if strings.TrimSpace(repoRoot) != "" {
		localPath := filepath.Join(repoRoot, "wrkr-policy.yaml")
		if _, statErr := os.Stat(localPath); statErr == nil {
			paths = append(paths, localPath)
		}
	}

	for _, path := range paths {
		custom, loadErr := loadRulePack(path)
		if loadErr != nil {
			return nil, loadErr
		}
		for _, rule := range custom {
			rulesByID[rule.ID] = rule
		}
	}

	ids := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]Rule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, rulesByID[id])
	}
	return rules, nil
}

func loadRulePack(path string) ([]Rule, error) {
	// #nosec G304 -- policy path is explicitly selected from repository or CLI input.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy rules %s: %w", path, err)
	}
	return parseRulePack(payload, path)
}

func loadBuiltinRulePack() ([]Rule, error) {
	payload, err := builtinPolicyFS.ReadFile("rules/builtin.yaml")
	if err != nil {
		return nil, fmt.Errorf("read embedded builtin policy rules: %w", err)
	}
	return parseRulePack(payload, "embedded builtin rule pack")
}

func parseRulePack(payload []byte, source string) ([]Rule, error) {
	var pack RulePack
	if decodeErr := yaml.Unmarshal(payload, &pack); decodeErr != nil {
		return nil, fmt.Errorf("parse policy rules %s: %w", source, decodeErr)
	}
	for i := range pack.Rules {
		pack.Rules[i].ID = strings.TrimSpace(pack.Rules[i].ID)
		pack.Rules[i].Title = strings.TrimSpace(pack.Rules[i].Title)
		pack.Rules[i].Severity = strings.ToLower(strings.TrimSpace(pack.Rules[i].Severity))
		pack.Rules[i].Remediation = strings.TrimSpace(pack.Rules[i].Remediation)
		pack.Rules[i].Kind = strings.TrimSpace(pack.Rules[i].Kind)
		if pack.Rules[i].Version == 0 {
			pack.Rules[i].Version = 1
		}
		if pack.Rules[i].ID == "" || pack.Rules[i].Title == "" || pack.Rules[i].Kind == "" {
			return nil, fmt.Errorf("policy rule missing required fields in %s", source)
		}
	}
	return pack.Rules, nil
}

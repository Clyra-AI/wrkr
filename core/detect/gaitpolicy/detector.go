package gaitpolicy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

const detectorID = "gaitpolicy"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	blocked, files, err := LoadBlockedTools(scope.Root)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}

	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	findings := make([]model.Finding, 0, len(paths))
	for _, path := range paths {
		findings = append(findings, model.Finding{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "gait_policy",
			Location:    path,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "blocked_tool_count", Value: fmt.Sprintf("%d", len(blocked))},
			},
		})
	}
	model.SortFindings(findings)
	return findings, nil
}

// LoadBlockedTools reads gait policy files and returns blocked tools keyed to stable rule IDs.
func LoadBlockedTools(root string) (map[string]string, map[string]struct{}, error) {
	files := map[string]struct{}{}
	blocked := map[string]string{}

	for _, rel := range []string{"gait.yaml", ".gait/policy.yaml", ".gait/policies.yaml"} {
		if !detect.FileExists(root, rel) {
			continue
		}
		if err := mergePolicyFile(root, rel, blocked); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", rel, err)
		}
		files[rel] = struct{}{}
	}
	more, err := detect.Glob(root, ".gait/*.yaml")
	if err != nil {
		return nil, nil, err
	}
	for _, rel := range more {
		if _, exists := files[rel]; exists {
			continue
		}
		if err := mergePolicyFile(root, rel, blocked); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", rel, err)
		}
		files[rel] = struct{}{}
	}
	return blocked, files, nil
}

func mergePolicyFile(root, rel string, blocked map[string]string) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- parser reads policy files from selected repository root.
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var node any
	if yamlErr := yaml.Unmarshal(payload, &node); yamlErr != nil {
		return yamlErr
	}
	collectBlockedTools(node, rel, blocked)
	return nil
}

func collectBlockedTools(node any, source string, blocked map[string]string) {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			lower := strings.ToLower(strings.TrimSpace(key))
			if lower == "block_tools" || lower == "blocked_tools" || lower == "deny_tools" {
				if tools, ok := value.([]any); ok {
					for _, tool := range tools {
						if toolName, castOK := tool.(string); castOK {
							trimmed := strings.TrimSpace(toolName)
							if trimmed == "" {
								continue
							}
							blocked[trimmed] = source + ":" + lower
						}
					}
				}
			}
			collectBlockedTools(value, source, blocked)
		}
	case []any:
		for _, value := range typed {
			collectBlockedTools(value, source, blocked)
		}
	}
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

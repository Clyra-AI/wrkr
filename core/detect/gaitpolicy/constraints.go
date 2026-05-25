package gaitpolicy

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"gopkg.in/yaml.v3"
)

type DeploymentConstraint struct {
	PolicyPath       string   `json:"policy_path,omitempty" yaml:"-"`
	Workflow         string   `json:"workflow,omitempty" yaml:"workflow"`
	Path             string   `json:"path,omitempty" yaml:"path"`
	Environment      string   `json:"environment,omitempty" yaml:"environment"`
	Branch           string   `json:"branch,omitempty" yaml:"branch"`
	RequiredChecks   []string `json:"required_checks,omitempty" yaml:"required_checks"`
	SecurityGates    []string `json:"security_gates,omitempty" yaml:"security_gates"`
	FreezeWindows    []string `json:"freeze_windows,omitempty" yaml:"freeze_windows"`
	KillSwitches     []string `json:"kill_switches,omitempty" yaml:"kill_switches"`
	ApprovalRequired bool     `json:"approval_required,omitempty" yaml:"approval_required"`
}

type deploymentConstraintDoc struct {
	DeploymentConstraints []DeploymentConstraint `yaml:"deployment_constraints"`
	Controls              struct {
		DeploymentConstraints []DeploymentConstraint `yaml:"deployment_constraints"`
	} `yaml:"controls"`
}

func LoadDeploymentConstraints(root string) ([]DeploymentConstraint, error) {
	if err := detect.ValidateScopeRoot(root); err != nil {
		return nil, err
	}
	paths := []string{}
	for _, rel := range []string{"gait.yaml", ".gait/policy.yaml", ".gait/policies.yaml"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			paths = append(paths, rel)
		}
	}
	additional, _ := listAdditionalPolicyFiles(root)
	paths = append(paths, additional...)
	paths = uniqueSorted(paths)

	out := make([]DeploymentConstraint, 0)
	for _, rel := range paths {
		payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, rel)
		if parseErr != nil {
			continue
		}
		var doc deploymentConstraintDoc
		if err := yaml.Unmarshal(payload, &doc); err != nil {
			continue
		}
		items := append([]DeploymentConstraint(nil), doc.DeploymentConstraints...)
		items = append(items, doc.Controls.DeploymentConstraints...)
		for _, item := range items {
			normalized := normalizeDeploymentConstraint(item, rel)
			if normalized.Workflow == "" && normalized.Path == "" {
				continue
			}
			out = append(out, normalized)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PolicyPath != out[j].PolicyPath {
			return out[i].PolicyPath < out[j].PolicyPath
		}
		if out[i].Workflow != out[j].Workflow {
			return out[i].Workflow < out[j].Workflow
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Environment != out[j].Environment {
			return out[i].Environment < out[j].Environment
		}
		return out[i].Branch < out[j].Branch
	})
	return out, nil
}

func normalizeDeploymentConstraint(in DeploymentConstraint, rel string) DeploymentConstraint {
	out := in
	out.PolicyPath = filepath.ToSlash(strings.TrimSpace(rel))
	out.Workflow = filepath.ToSlash(strings.TrimSpace(out.Workflow))
	out.Path = filepath.ToSlash(strings.TrimSpace(out.Path))
	out.Environment = strings.TrimSpace(out.Environment)
	out.Branch = strings.TrimSpace(out.Branch)
	out.RequiredChecks = uniqueSorted(out.RequiredChecks)
	out.SecurityGates = uniqueSorted(out.SecurityGates)
	out.FreezeWindows = uniqueSorted(out.FreezeWindows)
	out.KillSwitches = uniqueSorted(out.KillSwitches)
	return out
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

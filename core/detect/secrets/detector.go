package secrets

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "secrets"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

var workflowSecretRE = regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`)

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	candidates := []string{".env"}
	envFiles, globErr := detect.Glob(scope.Root, ".env.*")
	if globErr != nil {
		return nil, globErr
	}
	candidates = append(candidates, envFiles...)
	for _, rel := range candidates {
		if !detect.FileExists(scope.Root, rel) {
			continue
		}
		keys, parseErr := parseEnvKeys(scope.Root, rel)
		if parseErr != nil {
			return nil, parseErr
		}
		if len(keys) == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			FindingType: "secret_presence",
			Severity:    model.SeverityHigh,
			ToolType:    "secret",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "credential_keys", Value: strings.Join(keys, ",")},
				{Key: "value_redacted", Value: "true"},
			},
			Remediation: "Move credentials to secure secret stores and reference them by name only.",
		})
	}

	workflowFiles, wfErr := detect.Glob(scope.Root, ".github/workflows/*")
	if wfErr != nil {
		return nil, wfErr
	}
	for _, rel := range workflowFiles {
		keys, parseErr := parseWorkflowSecrets(scope.Root, rel)
		if parseErr != nil {
			return nil, parseErr
		}
		if len(keys) == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			FindingType: "secret_presence",
			Severity:    model.SeverityMedium,
			ToolType:    "secret",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence:    []model.Evidence{{Key: "workflow_secret_refs", Value: strings.Join(keys, ",")}},
		})
	}

	if detect.FileExists(scope.Root, "Jenkinsfile") {
		keys, parseErr := parseWorkflowSecrets(scope.Root, "Jenkinsfile")
		if parseErr != nil {
			return nil, parseErr
		}
		if len(keys) > 0 {
			findings = append(findings, model.Finding{
				FindingType: "secret_presence",
				Severity:    model.SeverityMedium,
				ToolType:    "secret",
				Location:    "Jenkinsfile",
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Evidence:    []model.Evidence{{Key: "workflow_secret_refs", Value: strings.Join(keys, ",")}},
			})
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseEnvKeys(root, rel string) ([]string, error) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- detector reads env files from selected repository root.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	keys := make([]string, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" || value == "" {
			continue
		}
		upperName := strings.ToUpper(name)
		if strings.Contains(upperName, "KEY") || strings.Contains(upperName, "TOKEN") || strings.Contains(upperName, "SECRET") || strings.Contains(upperName, "OPENAI") || strings.Contains(upperName, "ANTHROPIC") {
			keys = append(keys, name)
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return nil, scanErr
	}
	keys = dedupe(keys)
	return keys, nil
}

func parseWorkflowSecrets(root, rel string) ([]string, error) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- detector reads workflow files from selected repository root.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	matches := workflowSecretRE.FindAllStringSubmatch(string(payload), -1)
	keys := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			keys = append(keys, match[1])
		}
	}
	keys = dedupe(keys)
	return keys, nil
}

func dedupe(in []string) []string {
	set := map[string]struct{}{}
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

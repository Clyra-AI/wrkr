package secrets

import (
	"bufio"
	"context"
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
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	candidates := []string{".env"}
	envFiles, globErr := detect.Glob(scope.Root, ".env.*")
	if globErr != nil {
		return nil, globErr
	}
	candidates = append(candidates, envFiles...)
	for _, rel := range candidates {
		exists, fileErr := detect.FileExistsWithinRoot(detectorID, scope.Root, rel)
		if fileErr != nil {
			findings = append(findings, parseErrorFinding(scope, rel, fileErr))
			continue
		}
		if !exists {
			continue
		}
		keys, parseErr := parseEnvKeys(scope.Root, rel)
		if parseErr != nil {
			findings = append(findings, parseErrorFinding(scope, rel, parseErr))
			continue
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
			findings = append(findings, parseErrorFinding(scope, rel, parseErr))
			continue
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

	if exists, fileErr := detect.FileExistsWithinRoot(detectorID, scope.Root, "Jenkinsfile"); fileErr != nil {
		findings = append(findings, parseErrorFinding(scope, "Jenkinsfile", fileErr))
	} else if exists {
		keys, parseErr := parseWorkflowSecrets(scope.Root, "Jenkinsfile")
		if parseErr != nil {
			findings = append(findings, parseErrorFinding(scope, "Jenkinsfile", parseErr))
		} else if len(keys) > 0 {
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

func parseEnvKeys(root, rel string) ([]string, *model.ParseError) {
	f, err := detect.OpenFileWithinRoot(detectorID, root, rel)
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
		return nil, &model.ParseError{Kind: "file_read_error", Path: rel, Detector: detectorID, Message: scanErr.Error()}
	}
	keys = dedupe(keys)
	return keys, nil
}

func parseWorkflowSecrets(root, rel string) ([]string, *model.ParseError) {
	payload, err := detect.ReadFileWithinRoot(detectorID, root, rel)
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

func parseErrorFinding(scope detect.Scope, location string, parseErr *model.ParseError) model.Finding {
	parseErr.Detector = detectorID
	return model.Finding{
		FindingType: "parse_error",
		Severity:    model.SeverityMedium,
		ToolType:    "secret",
		Location:    location,
		Repo:        scope.Repo,
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		ParseError:  parseErr,
		Remediation: "Keep secret-bearing files inside the selected repository root.",
	}
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

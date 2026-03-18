package actionruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	IssueDeprecatedRuntimeUse  = "deprecated runtime use"
	IssueDisallowedOverride    = "disallowed override policy"
	defaultWorkflowPatternYML  = ".github/workflows/*.yml"
	defaultWorkflowPatternYAML = ".github/workflows/*.yaml"
)

var deprecatedRefs = map[string]struct{}{
	"actions/checkout@v4":                  {},
	"actions/setup-go@v5":                  {},
	"actions/setup-python@v5":              {},
	"actions/setup-node@v4":                {},
	"actions/upload-artifact@v4":           {},
	"actions/upload-pages-artifact@v3":     {},
	"actions/attest-build-provenance@v2":   {},
	"dorny/paths-filter@v3":                {},
	"github/codeql-action/init@v3":         {},
	"github/codeql-action/upload-sarif@v3": {},
	"goreleaser/goreleaser-action@v6":      {},
	"sigstore/cosign-installer@v3":         {},
}

var disallowedOverrideNames = map[string]struct{}{
	"FORCE_JAVASCRIPT_ACTIONS_TO_NODE24":      {},
	"ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION": {},
}

type Finding struct {
	Issue    string
	Path     string
	Subject  string
	Location string
}

type workflowFile struct {
	Env  map[string]any         `yaml:"env"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Env   map[string]any `yaml:"env"`
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	Env  map[string]any `yaml:"env"`
}

func Scan(root string) ([]Finding, error) {
	files, err := workflowFiles(root)
	if err != nil {
		return nil, err
	}

	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open workflow root %s: %w", root, err)
	}
	defer func() {
		_ = rootFS.Close()
	}()

	findings := make([]Finding, 0)
	for _, path := range files {
		payload, err := rootFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read workflow %s: %w", path, err)
		}

		var wf workflowFile
		if err := yaml.Unmarshal(payload, &wf); err != nil {
			return nil, fmt.Errorf("parse workflow %s: %w", path, err)
		}

		findings = append(findings, collectEnvFindings(path, "workflow env", wf.Env)...)
		findings = append(findings, collectJobFindings(path, wf.Jobs)...)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].Issue != findings[j].Issue {
			return findings[i].Issue < findings[j].Issue
		}
		if findings[i].Subject != findings[j].Subject {
			return findings[i].Subject < findings[j].Subject
		}
		return findings[i].Location < findings[j].Location
	})
	return findings, nil
}

func FormatFindings(findings []Finding) []string {
	lines := make([]string, 0, len(findings))
	for _, finding := range findings {
		line := fmt.Sprintf("%s: %s -> %s", finding.Issue, finding.Path, finding.Subject)
		if strings.TrimSpace(finding.Location) != "" {
			line += " (" + finding.Location + ")"
		}
		lines = append(lines, line)
	}
	return lines
}

func workflowFiles(root string) ([]string, error) {
	patterns := []string{
		filepath.Join(root, defaultWorkflowPatternYML),
		filepath.Join(root, defaultWorkflowPatternYAML),
	}

	files := make([]string, 0)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("glob workflows %s: %w", pattern, err)
		}
		for _, match := range matches {
			relPath, err := filepath.Rel(root, match)
			if err != nil {
				return nil, fmt.Errorf("relativize workflow path %s: %w", match, err)
			}
			files = append(files, filepath.ToSlash(relPath))
		}
	}
	sort.Strings(files)
	return files, nil
}

func collectJobFindings(relPath string, jobs map[string]workflowJob) []Finding {
	jobNames := make([]string, 0, len(jobs))
	for name := range jobs {
		jobNames = append(jobNames, name)
	}
	sort.Strings(jobNames)

	findings := make([]Finding, 0)
	for _, jobName := range jobNames {
		job := jobs[jobName]
		findings = append(findings, collectEnvFindings(relPath, "job "+jobName+" env", job.Env)...)
		for idx, step := range job.Steps {
			if _, blocked := deprecatedRefs[strings.TrimSpace(step.Uses)]; blocked {
				location := fmt.Sprintf("job %s step %d", jobName, idx+1)
				if strings.TrimSpace(step.Name) != "" {
					location += " " + strings.TrimSpace(step.Name)
				}
				findings = append(findings, Finding{
					Issue:    IssueDeprecatedRuntimeUse,
					Path:     relPath,
					Subject:  strings.TrimSpace(step.Uses),
					Location: location,
				})
			}
			findings = append(findings, collectEnvFindings(relPath, "job "+jobName+" step "+stepLabel(idx, step.Name)+" env", step.Env)...)
			findings = append(findings, collectRunFindings(relPath, jobName, idx, step)...)
		}
	}
	return findings
}

func collectEnvFindings(relPath, location string, values map[string]any) []Finding {
	if len(values) == 0 {
		return nil
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	findings := make([]Finding, 0)
	for _, key := range keys {
		if _, blocked := disallowedOverrideNames[key]; !blocked {
			continue
		}
		if !isTruthyScalar(values[key]) {
			continue
		}
		findings = append(findings, Finding{
			Issue:    IssueDisallowedOverride,
			Path:     relPath,
			Subject:  key + "=" + normalizedScalar(values[key]),
			Location: location,
		})
	}
	return findings
}

func collectRunFindings(relPath, jobName string, idx int, step workflowStep) []Finding {
	runText := strings.TrimSpace(step.Run)
	if runText == "" {
		return nil
	}

	location := fmt.Sprintf("job %s step %d", jobName, idx+1)
	if strings.TrimSpace(step.Name) != "" {
		location += " " + strings.TrimSpace(step.Name)
	}

	findings := make([]Finding, 0)
	for name := range disallowedOverrideNames {
		subject := overrideSubjectFromRun(name, runText)
		if subject == "" {
			continue
		}
		findings = append(findings, Finding{
			Issue:    IssueDisallowedOverride,
			Path:     relPath,
			Subject:  subject,
			Location: location,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Subject < findings[j].Subject
	})
	return findings
}

func stepLabel(idx int, name string) string {
	if trimmed := strings.TrimSpace(name); trimmed != "" {
		return trimmed
	}
	return fmt.Sprintf("%d", idx+1)
}

func isTruthyScalar(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "'true'", "\"true\"":
			return true
		}
	}
	return false
}

func normalizedScalar(value any) string {
	switch typed := value.(type) {
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case string:
		return strings.Trim(strings.TrimSpace(typed), `"'`)
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func overrideSubjectFromRun(name, runText string) string {
	for _, rawLine := range strings.Split(runText, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		candidate := line
		if strings.HasPrefix(candidate, "export ") {
			candidate = strings.TrimSpace(strings.TrimPrefix(candidate, "export "))
		}

		if !strings.HasPrefix(candidate, name+"=") {
			continue
		}
		value := strings.Trim(strings.TrimSpace(strings.TrimPrefix(candidate, name+"=")), `"'`)
		switch strings.ToLower(value) {
		case "1", "true":
			return name + "=" + value
		}
	}
	return ""
}

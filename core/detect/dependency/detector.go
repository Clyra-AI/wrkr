package dependency

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"golang.org/x/mod/modfile"
)

const detectorID = "dependency"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

var aiKeywords = []string{"openai", "anthropic", "langchain", "llama", "cohere", "mistral", "gemini", "agent", "copilot"}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	if detect.FileExists(scope.Root, "go.mod") {
		deps, parseErr := parseGoMod(scope.Root)
		if parseErr != nil {
			findings = append(findings, parseErrorFinding(scope, "go.mod", parseErr.Error()))
		} else {
			findings = append(findings, dependencyFindings(scope, "go.mod", deps)...)
		}
	}
	if detect.FileExists(scope.Root, "package.json") {
		deps, parseErr := parsePackageJSON(scope.Root)
		if parseErr != nil {
			findings = append(findings, parseErrorFinding(scope, "package.json", parseErr.Error()))
		} else {
			findings = append(findings, dependencyFindings(scope, "package.json", deps)...)
		}
	}
	if detect.FileExists(scope.Root, "requirements.txt") {
		deps, parseErr := parseRequirements(scope.Root)
		if parseErr != nil {
			findings = append(findings, parseErrorFinding(scope, "requirements.txt", parseErr.Error()))
		} else {
			findings = append(findings, dependencyFindings(scope, "requirements.txt", deps)...)
		}
	}
	if detect.FileExists(scope.Root, "pyproject.toml") {
		deps, parseErr := parsePyproject(scope.Root)
		if parseErr != nil {
			findings = append(findings, parseErrorFinding(scope, "pyproject.toml", parseErr.Error()))
		} else {
			findings = append(findings, dependencyFindings(scope, "pyproject.toml", deps)...)
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseGoMod(root string) ([]string, error) {
	path := filepath.Join(root, "go.mod")
	// #nosec G304 -- parser reads go.mod from selected repository root.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	parsed, parseErr := modfile.Parse("go.mod", payload, nil)
	if parseErr != nil {
		return nil, parseErr
	}
	deps := make([]string, 0, len(parsed.Require))
	for _, req := range parsed.Require {
		deps = append(deps, req.Mod.Path)
	}
	return deps, nil
}

func parsePackageJSON(root string) ([]string, error) {
	type packageJSON struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	var parsed packageJSON
	if parseErr := detect.ParseJSONFile(detectorID, root, "package.json", &parsed); parseErr != nil {
		return nil, fmt.Errorf("%s", parseErr.Message)
	}
	deps := make([]string, 0, len(parsed.Dependencies)+len(parsed.DevDependencies))
	for dep := range parsed.Dependencies {
		deps = append(deps, dep)
	}
	for dep := range parsed.DevDependencies {
		deps = append(deps, dep)
	}
	return deps, nil
}

func parseRequirements(root string) ([]string, error) {
	path := filepath.Join(root, "requirements.txt")
	// #nosec G304 -- parser reads requirements file from selected repository root.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	deps := make([]string, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, sep := range []string{"==", ">=", "<=", "~=", "!="} {
			line = strings.Split(line, sep)[0]
		}
		deps = append(deps, strings.TrimSpace(line))
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return nil, scanErr
	}
	return deps, nil
}

func parsePyproject(root string) ([]string, error) {
	type pyproject struct {
		Project struct {
			Dependencies []string `toml:"dependencies"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}

	path := filepath.Join(root, "pyproject.toml")
	// #nosec G304 -- parser reads pyproject file from selected repository root.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var parsed pyproject
	if _, decodeErr := toml.Decode(string(payload), &parsed); decodeErr != nil {
		return nil, decodeErr
	}
	deps := make([]string, 0, len(parsed.Project.Dependencies)+len(parsed.Tool.Poetry.Dependencies))
	deps = append(deps, parsed.Project.Dependencies...)
	for dep := range parsed.Tool.Poetry.Dependencies {
		deps = append(deps, dep)
	}
	return deps, nil
}

func dependencyFindings(scope detect.Scope, location string, deps []string) []model.Finding {
	matches := make([]string, 0)
	for _, dep := range deps {
		normalized := strings.ToLower(strings.TrimSpace(dep))
		if normalized == "" {
			continue
		}
		for _, keyword := range aiKeywords {
			if strings.Contains(normalized, keyword) {
				matches = append(matches, dep)
				break
			}
		}
	}
	if len(matches) == 0 {
		return nil
	}
	sort.Strings(matches)
	findings := make([]model.Finding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, model.Finding{
			FindingType: "ai_dependency",
			Severity:    model.SeverityMedium,
			ToolType:    "dependency",
			Location:    location,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence:    []model.Evidence{{Key: "dependency", Value: match}},
		})
	}
	return findings
}

func parseErrorFinding(scope detect.Scope, location, message string) model.Finding {
	return model.Finding{
		FindingType: "parse_error",
		Severity:    model.SeverityMedium,
		ToolType:    "dependency",
		Location:    location,
		Repo:        scope.Repo,
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		ParseError: &model.ParseError{
			Kind:     "parse_error",
			Format:   filepath.Ext(location),
			Path:     location,
			Detector: detectorID,
			Message:  message,
		},
	}
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

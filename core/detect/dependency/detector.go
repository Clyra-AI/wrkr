package dependency

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
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

var aiKeywords = []string{
	"openai",
	"anthropic",
	"langchain",
	"langgraph",
	"llama",
	"llamaindex",
	"cohere",
	"mistral",
	"gemini",
	"vertexai",
	"google-generativeai",
	"azure-openai",
	"ollama",
	"openrouter",
	"autogen",
	"crewai",
	"pydantic-ai",
	"semantic-kernel",
	"litellm",
	"dspy",
	"haystack",
	"smolagents",
	"agent",
	"copilot",
}

var projectSignalKeywords = []string{
	"mcp",
	"agent",
	"llm",
	"openai",
	"anthropic",
	"claude",
	"copilot",
	"codex",
	"langchain",
	"langgraph",
	"rag",
	"prompt",
	"autogen",
	"crewai",
	"gemini",
}

var ignoredDirectoryNames = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"vendor":       {},
	"dist":         {},
	"build":        {},
	"target":       {},
	".venv":        {},
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	files, err := collectDependencyManifests(scope.Root)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	for _, rel := range files {
		base := strings.ToLower(filepath.Base(rel))
		switch {
		case base == "go.mod":
			deps, parseErr := parseGoMod(scope.Root, rel)
			if parseErr != nil {
				findings = append(findings, parseErrorFinding(scope, rel, parseErr.Error()))
			} else {
				findings = append(findings, dependencyFindings(scope, rel, deps)...)
			}
		case base == "package.json":
			deps, parseErr := parsePackageJSON(scope.Root, rel)
			if parseErr != nil {
				findings = append(findings, parseErrorFinding(scope, rel, parseErr.Error()))
			} else {
				findings = append(findings, dependencyFindings(scope, rel, deps)...)
			}
		case base == "pyproject.toml":
			deps, parseErr := parsePyproject(scope.Root, rel)
			if parseErr != nil {
				findings = append(findings, parseErrorFinding(scope, rel, parseErr.Error()))
			} else {
				findings = append(findings, dependencyFindings(scope, rel, deps)...)
			}
		case base == "cargo.toml":
			deps, parseErr := parseCargoToml(scope.Root, rel)
			if parseErr != nil {
				findings = append(findings, parseErrorFinding(scope, rel, parseErr.Error()))
			} else {
				findings = append(findings, dependencyFindings(scope, rel, deps)...)
			}
		case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
			deps, parseErr := parseRequirements(scope.Root, rel)
			if parseErr != nil {
				findings = append(findings, parseErrorFinding(scope, rel, parseErr.Error()))
			} else {
				findings = append(findings, dependencyFindings(scope, rel, deps)...)
			}
		}
	}
	if len(findings) == 0 {
		location, reason, keyword, ok := projectSignal(scope, scope.Root)
		if ok {
			findings = append(findings, model.Finding{
				FindingType: "ai_project_signal",
				Severity:    model.SeverityMedium,
				ToolType:    "dependency",
				Location:    location,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Evidence: []model.Evidence{
					{Key: "reason", Value: reason},
					{Key: "keyword", Value: keyword},
				},
			})
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseGoMod(root, rel string) ([]string, error) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- parser reads go.mod from selected repository root.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	parsed, parseErr := modfile.Parse(rel, payload, nil)
	if parseErr != nil {
		return nil, parseErr
	}
	deps := make([]string, 0, len(parsed.Require))
	for _, req := range parsed.Require {
		deps = append(deps, req.Mod.Path)
	}
	return deps, nil
}

func parsePackageJSON(root, rel string) ([]string, error) {
	type packageJSON struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	var parsed packageJSON
	if parseErr := detect.ParseJSONFile(detectorID, root, rel, &parsed); parseErr != nil {
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

func parseRequirements(root, rel string) ([]string, error) {
	path := filepath.Join(root, filepath.FromSlash(rel))
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

func parsePyproject(root, rel string) ([]string, error) {
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

	path := filepath.Join(root, filepath.FromSlash(rel))
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

func parseCargoToml(root, rel string) ([]string, error) {
	type cargo struct {
		Dependencies map[string]any `toml:"dependencies"`
		Workspace    struct {
			Dependencies map[string]any `toml:"dependencies"`
		} `toml:"workspace"`
	}

	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- parser reads Cargo.toml from selected repository root.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var parsed cargo
	if _, decodeErr := toml.Decode(string(payload), &parsed); decodeErr != nil {
		return nil, decodeErr
	}
	deps := make([]string, 0, len(parsed.Dependencies)+len(parsed.Workspace.Dependencies))
	for dep := range parsed.Dependencies {
		deps = append(deps, dep)
	}
	for dep := range parsed.Workspace.Dependencies {
		deps = append(deps, dep)
	}
	return deps, nil
}

func dependencyFindings(scope detect.Scope, location string, deps []string) []model.Finding {
	matches := make([]string, 0)
	for _, dep := range deps {
		normalized := normalizeDependencyToken(dep)
		if normalized == "" {
			continue
		}
		if matchesAIKeyword(normalized) {
			matches = append(matches, dep)
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

func matchesAIKeyword(normalized string) bool {
	for _, keyword := range aiKeywords {
		if strings.Contains(normalized, keyword) {
			return true
		}
	}
	return false
}

func normalizeDependencyToken(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	return normalized
}

func collectDependencyManifests(root string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			rel = ""
		}
		if walkErr != nil {
			if shouldSkipTraversal(rel) {
				return filepath.SkipDir
			}
			return walkErr
		}
		if d != nil && d.IsDir() {
			if shouldSkipTraversal(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if isDependencyManifest(rel) {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func isDependencyManifest(rel string) bool {
	base := strings.ToLower(filepath.Base(rel))
	switch {
	case base == "go.mod", base == "package.json", base == "pyproject.toml", base == "cargo.toml":
		return true
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return true
	default:
		return false
	}
}

func shouldSkipTraversal(rel string) bool {
	if strings.TrimSpace(rel) == "" {
		return false
	}
	parts := strings.Split(strings.ToLower(filepath.ToSlash(rel)), "/")
	for _, part := range parts {
		if _, ok := ignoredDirectoryNames[part]; ok {
			return true
		}
	}
	return false
}

func projectSignal(scope detect.Scope, root string) (string, string, string, bool) {
	if keyword, ok := firstProjectSignalKeyword(scope.Repo); ok {
		return "__project_signal__/" + repoSignalSlug(scope.Repo), "repo_name", keyword, true
	}

	for _, rel := range []string{"README.md", "readme.md", "README"} {
		if !detect.FileExists(root, rel) {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		// #nosec G304 -- reads README from selected repository root.
		payload, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if keyword, ok := firstProjectSignalKeyword(string(payload)); ok {
			return rel, "readme_text", keyword, true
		}
	}
	return "", "", "", false
}

func firstProjectSignalKeyword(value string) (string, bool) {
	tokens := tokenizeProjectSignal(value)
	if len(tokens) == 0 {
		return "", false
	}
	tokenSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
	}
	for _, keyword := range projectSignalKeywords {
		if _, ok := tokenSet[strings.ToLower(strings.TrimSpace(keyword))]; ok {
			return keyword, true
		}
	}
	return "", false
}

func tokenizeProjectSignal(value string) []string {
	lower := strings.ToLower(value)
	return strings.FieldsFunc(lower, func(r rune) bool {
		if r >= 'a' && r <= 'z' {
			return false
		}
		if r >= '0' && r <= '9' {
			return false
		}
		return true
	})
}

func repoSignalSlug(value string) string {
	slug := strings.ToLower(strings.TrimSpace(value))
	slug = strings.ReplaceAll(slug, "/", "-")
	slug = strings.ReplaceAll(slug, " ", "-")
	if slug == "" {
		return "unknown"
	}
	return slug
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

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
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	loaded, err := LoadBlockedTools(scope.Root)
	if err != nil {
		return nil, err
	}
	if len(loaded.PolicyFiles) == 0 && len(loaded.ParseErrors) == 0 {
		return nil, nil
	}

	findings := make([]model.Finding, 0, len(loaded.PolicyFiles)+len(loaded.ParseErrors))
	for _, parseErr := range loaded.ParseErrors {
		findings = append(findings, parseErrorFinding(scope, parseErr))
	}
	for _, path := range loaded.PolicyFiles {
		findings = append(findings, model.Finding{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "gait_policy",
			Location:    path,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "blocked_tool_count", Value: fmt.Sprintf("%d", len(loaded.BlockedTools))},
			},
		})
	}
	model.SortFindings(findings)
	return findings, nil
}

type LoadResult struct {
	BlockedTools map[string]string
	PolicyFiles  []string
	ParseErrors  []*model.ParseError
}

// LoadBlockedTools reads gait policy files and returns blocked tools keyed to stable rule IDs.
func LoadBlockedTools(root string) (LoadResult, error) {
	if err := detect.ValidateScopeRoot(root); err != nil {
		return LoadResult{}, err
	}

	blocked := map[string]string{}
	policyFiles := make([]string, 0)
	parseErrors := make(map[string]*model.ParseError)
	candidates := make(map[string]struct{})

	for _, rel := range []string{"gait.yaml", ".gait/policy.yaml", ".gait/policies.yaml"} {
		exists, parseErr := detect.FileExistsWithinRoot(detectorID, root, rel)
		if parseErr != nil {
			parseErrors[parseErr.Path] = normalizeParseError(rel, parseErr)
			continue
		}
		if exists {
			candidates[rel] = struct{}{}
		}
	}

	additional, additionalErrs := listAdditionalPolicyFiles(root)
	for _, parseErr := range additionalErrs {
		parseErrors[parseErr.Path] = normalizeParseError(parseErr.Path, parseErr)
	}
	for _, rel := range additional {
		candidates[rel] = struct{}{}
	}

	paths := make([]string, 0, len(candidates))
	for rel := range candidates {
		paths = append(paths, rel)
	}
	sort.Strings(paths)

	for _, rel := range paths {
		node, parseErr := readPolicyDocument(root, rel)
		if parseErr != nil {
			parseErrors[parseErr.Path] = normalizeParseError(rel, parseErr)
			continue
		}
		collectBlockedTools(node, rel, blocked)
		policyFiles = append(policyFiles, rel)
	}

	return LoadResult{
		BlockedTools: blocked,
		PolicyFiles:  policyFiles,
		ParseErrors:  sortParseErrors(parseErrors),
	}, nil
}

func listAdditionalPolicyFiles(root string) ([]string, []*model.ParseError) {
	dirExists, parseErr := detect.DirExistsWithinRoot(detectorID, root, ".gait")
	if parseErr != nil {
		return nil, []*model.ParseError{normalizeParseError(".gait", parseErr)}
	}
	if !dirExists {
		return nil, nil
	}

	entries, err := os.ReadDir(filepath.Join(root, ".gait"))
	if err != nil {
		return nil, []*model.ParseError{directoryParseError(".gait", err)}
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name())
		if !strings.HasSuffix(strings.ToLower(name), ".yaml") {
			continue
		}
		files = append(files, filepath.ToSlash(filepath.Join(".gait", name)))
	}
	sort.Strings(files)
	return files, nil
}

func readPolicyDocument(root, rel string) (any, *model.ParseError) {
	payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, rel)
	if parseErr != nil {
		return nil, normalizeParseError(rel, parseErr)
	}

	var node any
	if err := yaml.Unmarshal(payload, &node); err != nil {
		return nil, &model.ParseError{
			Kind:     "parse_error",
			Format:   "yaml",
			Path:     filepath.ToSlash(rel),
			Detector: detectorID,
			Message:  strings.TrimSpace(err.Error()),
		}
	}
	return node, nil
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

func parseErrorFinding(scope detect.Scope, parseErr *model.ParseError) model.Finding {
	normalized := normalizeParseError("", parseErr)
	return model.Finding{
		FindingType: "parse_error",
		Severity:    model.SeverityMedium,
		ToolType:    "gait_policy",
		Location:    normalized.Path,
		Repo:        scope.Repo,
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		ParseError:  normalized,
		Remediation: "Keep Gait policy files inside the selected repository root and valid YAML.",
	}
}

func normalizeParseError(rel string, parseErr *model.ParseError) *model.ParseError {
	if parseErr == nil {
		return nil
	}
	normalized := *parseErr
	if strings.TrimSpace(normalized.Path) == "" {
		normalized.Path = filepath.ToSlash(rel)
	}
	if strings.TrimSpace(normalized.Format) == "" {
		normalized.Format = "yaml"
	}
	normalized.Detector = detectorID
	normalized.Message = strings.TrimSpace(normalized.Message)
	return &normalized
}

func directoryParseError(rel string, err error) *model.ParseError {
	kind := "parse_error"
	switch {
	case os.IsNotExist(err):
		kind = "file_not_found"
	case os.IsPermission(err):
		kind = "permission_denied"
	}
	return &model.ParseError{
		Kind:     kind,
		Format:   "yaml",
		Path:     filepath.ToSlash(rel),
		Detector: detectorID,
		Message:  strings.TrimSpace(err.Error()),
	}
}

func sortParseErrors(in map[string]*model.ParseError) []*model.ParseError {
	if len(in) == 0 {
		return nil
	}
	out := make([]*model.ParseError, 0, len(in))
	for _, item := range in {
		out = append(out, normalizeParseError("", item))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

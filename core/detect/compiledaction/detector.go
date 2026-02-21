package compiledaction

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

const detectorID = "compiledaction"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type actionDoc struct {
	Steps []struct {
		Tool string `json:"tool" yaml:"tool"`
	} `json:"steps" yaml:"steps"`
	ToolSequence   []string `json:"tool_sequence" yaml:"tool_sequence"`
	RiskClasses    []string `json:"risk_classes" yaml:"risk_classes"`
	ApprovalSource string   `json:"approval_source" yaml:"approval_source"`
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	files, walkErr := detect.WalkFiles(scope.Root)
	if walkErr != nil {
		return nil, walkErr
	}

	findings := make([]model.Finding, 0)
	for _, rel := range files {
		if strings.HasPrefix(rel, ".claude/scripts/") {
			findings = append(findings, model.Finding{
				FindingType: "compiled_action",
				Severity:    model.SeverityMedium,
				ToolType:    "compiled_action",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Evidence: []model.Evidence{
					{Key: "step_count", Value: "1"},
					{Key: "tool_sequence", Value: "script"},
				},
			})
			continue
		}

		isCompiledActionPath := strings.HasPrefix(rel, "workflows/") ||
			strings.HasPrefix(rel, "agent-plans/") ||
			strings.HasSuffix(rel, ".agent-script.json") ||
			strings.HasSuffix(rel, ".ptc.json") ||
			strings.HasPrefix(rel, ".github/workflows/")
		if !isCompiledActionPath {
			continue
		}

		doc, parseErr := parseActionDocument(scope.Root, rel)
		if parseErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "compiled_action",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
			continue
		}

		if isEmptyAction(doc) {
			if strings.HasPrefix(rel, ".github/workflows/") {
				path := filepath.Join(scope.Root, filepath.FromSlash(rel))
				// #nosec G304 -- detector reads workflow from selected repository root.
				payload, readErr := os.ReadFile(path)
				if readErr != nil {
					return nil, readErr
				}
				if strings.Contains(string(payload), "gait eval --script") {
					findings = append(findings, model.Finding{
						FindingType: "compiled_action",
						Severity:    model.SeverityHigh,
						ToolType:    "compiled_action",
						Location:    rel,
						Repo:        scope.Repo,
						Org:         fallbackOrg(scope.Org),
						Detector:    detectorID,
						Evidence: []model.Evidence{
							{Key: "step_count", Value: "1"},
							{Key: "tool_sequence", Value: "gait.eval.script"},
						},
					})
				}
			}
			continue
		}

		sequence := append([]string(nil), doc.ToolSequence...)
		if len(sequence) == 0 {
			for _, step := range doc.Steps {
				if strings.TrimSpace(step.Tool) != "" {
					sequence = append(sequence, strings.TrimSpace(step.Tool))
				}
			}
		}
		sort.Strings(sequence)
		findings = append(findings, model.Finding{
			FindingType: "compiled_action",
			Severity:    model.SeverityMedium,
			ToolType:    "compiled_action",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "step_count", Value: fmt.Sprintf("%d", len(doc.Steps))},
				{Key: "tool_sequence", Value: strings.Join(sequence, ",")},
				{Key: "risk_classes", Value: strings.Join(doc.RiskClasses, ",")},
				{Key: "approval_source", Value: doc.ApprovalSource},
			},
		})
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseActionDocument(root, rel string) (actionDoc, *model.ParseError) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- detector reads workflow/plan definitions from selected root.
	payload, err := os.ReadFile(path)
	if err != nil {
		return actionDoc{}, &model.ParseError{Kind: "file_read_error", Path: rel, Detector: detectorID, Message: err.Error()}
	}

	var doc actionDoc
	ext := strings.ToLower(filepath.Ext(rel))
	switch ext {
	case ".json":
		if decodeErr := json.Unmarshal(payload, &doc); decodeErr != nil {
			return actionDoc{}, &model.ParseError{Kind: "parse_error", Format: "json", Path: rel, Detector: detectorID, Message: decodeErr.Error()}
		}
	case ".yaml", ".yml":
		if decodeErr := yaml.Unmarshal(payload, &doc); decodeErr != nil {
			return actionDoc{}, &model.ParseError{Kind: "parse_error", Format: "yaml", Path: rel, Detector: detectorID, Message: decodeErr.Error()}
		}
	default:
		return actionDoc{}, nil
	}
	return doc, nil
}

func isEmptyAction(doc actionDoc) bool {
	return len(doc.Steps) == 0 && len(doc.ToolSequence) == 0 && len(doc.RiskClasses) == 0 && strings.TrimSpace(doc.ApprovalSource) == ""
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

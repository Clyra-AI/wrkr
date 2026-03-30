package compiledaction

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/workflowcap"
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
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}
	if detect.IsLocalMachineScope(scope) {
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

		payload, parseErr := detect.ReadFileWithinRoot(detectorID, scope.Root, rel)
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
		workflowAnalysis, workflowErr := workflowcap.Analyze(rel, payload)

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
				if workflowErr == nil && len(workflowAnalysis.Capabilities) > 0 {
					findings = append(findings, workflowFinding(scope, rel, workflowAnalysis))
					continue
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
						Permissions: nil,
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
		evidence := []model.Evidence{
			{Key: "step_count", Value: fmt.Sprintf("%d", len(doc.Steps))},
			{Key: "tool_sequence", Value: strings.Join(sequence, ",")},
			{Key: "risk_classes", Value: strings.Join(doc.RiskClasses, ",")},
			{Key: "approval_source", Value: doc.ApprovalSource},
		}
		permissions := []string(nil)
		if workflowErr == nil {
			evidence = append(evidence, workflowAnalysis.Evidence...)
			permissions = append(permissions, workflowAnalysis.Capabilities...)
		}
		findings = append(findings, model.Finding{
			FindingType: "compiled_action",
			Severity:    model.SeverityMedium,
			ToolType:    "compiled_action",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Permissions: uniqueStrings(permissions),
			Evidence:    evidence,
		})
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseActionDocument(root, rel string) (actionDoc, *model.ParseError) {
	payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, rel)
	if parseErr != nil {
		return actionDoc{}, parseErr
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

func workflowFinding(scope detect.Scope, rel string, analysis workflowcap.Result) model.Finding {
	severity := model.SeverityMedium
	if containsAny(analysis.Capabilities, "merge.execute", "deploy.write", "db.write", "iac.write") {
		severity = model.SeverityHigh
	}
	evidence := append([]model.Evidence{
		{Key: "step_count", Value: fmt.Sprintf("%d", analysis.StepCount)},
	}, analysis.Evidence...)
	return model.Finding{
		FindingType: "compiled_action",
		Severity:    severity,
		ToolType:    "compiled_action",
		Location:    rel,
		Repo:        scope.Repo,
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		Permissions: uniqueStrings(analysis.Capabilities),
		Evidence:    evidence,
	}
}

func containsAny(values []string, needles ...string) bool {
	set := map[string]struct{}{}
	for _, value := range values {
		set[strings.TrimSpace(value)] = struct{}{}
	}
	for _, needle := range needles {
		if _, ok := set[strings.TrimSpace(needle)]; ok {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

package ciagent

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk/autonomy"
)

const detectorID = "ciagent"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	files := make([]string, 0)
	workflowFiles, wfErr := detect.Glob(scope.Root, ".github/workflows/*")
	if wfErr != nil {
		return nil, wfErr
	}
	files = append(files, workflowFiles...)
	if detect.FileExists(scope.Root, "Jenkinsfile") {
		files = append(files, "Jenkinsfile")
	}
	sort.Strings(files)

	findings := make([]model.Finding, 0)
	for _, rel := range files {
		path := filepath.Join(scope.Root, filepath.FromSlash(rel))
		// #nosec G304 -- detector reads workflow definitions from selected repository root.
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		content := string(payload)
		signals := autonomy.Signals{
			Tool:            detectTool(content),
			Headless:        isHeadlessInvocation(content),
			HasApprovalGate: hasApprovalGate(content),
			HasSecretAccess: hasSecretAccess(content),
			DangerousFlags:  hasDangerousFlags(content),
		}
		if !signals.Headless && signals.Tool == "" {
			continue
		}
		level := autonomy.Classify(signals)
		severity := severityForSignals(signals, level)
		checkResult := model.CheckResultPass
		if signals.Headless && signals.HasSecretAccess && !signals.HasApprovalGate {
			checkResult = model.CheckResultFail
		}
		findings = append(findings, model.Finding{
			FindingType: "ci_autonomy",
			Severity:    severity,
			CheckResult: checkResult,
			ToolType:    "ci_agent",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Autonomy:    level,
			Permissions: permissionsFromSignals(signals),
			Evidence: []model.Evidence{
				{Key: "tool", Value: signals.Tool},
				{Key: "headless", Value: boolString(signals.Headless)},
				{Key: "approval_gate", Value: boolString(signals.HasApprovalGate)},
				{Key: "secret_access", Value: boolString(signals.HasSecretAccess)},
				{Key: "dangerous_flags", Value: boolString(signals.DangerousFlags)},
			},
			Remediation: "Require approval gates for headless agent workflows that can access secrets.",
		})
	}

	model.SortFindings(findings)
	return findings, nil
}

func detectTool(content string) string {
	lower := strings.ToLower(content)
	switch {
	case strings.Contains(lower, "claude"):
		return "claude"
	case strings.Contains(lower, "codex"):
		return "codex"
	case strings.Contains(lower, "copilot"):
		return "copilot"
	case strings.Contains(lower, "cursor"):
		return "cursor"
	default:
		return ""
	}
}

func isHeadlessInvocation(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "claude -p") ||
		strings.Contains(lower, "claude code -p") ||
		strings.Contains(lower, "codex --full-auto") ||
		strings.Contains(lower, "full-auto") ||
		strings.Contains(lower, "gait eval --script")
}

func hasApprovalGate(content string) bool {
	lower := strings.ToLower(content)
	return (strings.Contains(lower, "environment:") && strings.Contains(lower, "reviewers")) || strings.Contains(lower, "required_reviewers")
}

func hasSecretAccess(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "secrets.") || strings.Contains(lower, "deploy_key") || strings.Contains(lower, "api_key")
}

func hasDangerousFlags(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "--dangerouslyskippermissions") || strings.Contains(lower, "--approval never") || strings.Contains(lower, "full-auto")
}

func severityForSignals(signals autonomy.Signals, level string) string {
	if autonomy.IsCritical(signals) {
		return model.SeverityCritical
	}
	switch level {
	case autonomy.LevelHeadlessAuto:
		return model.SeverityHigh
	case autonomy.LevelHeadlessGate:
		return model.SeverityMedium
	case autonomy.LevelCopilot:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func permissionsFromSignals(signals autonomy.Signals) []string {
	perms := make([]string, 0)
	if signals.HasSecretAccess {
		perms = append(perms, "secret.read")
	}
	if signals.DangerousFlags {
		perms = append(perms, "proc.exec")
	}
	if signals.Headless {
		perms = append(perms, "headless.execute")
	}
	return perms
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

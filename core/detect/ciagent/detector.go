package ciagent

import (
	"context"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/workflowcap"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk/autonomy"
	"github.com/Clyra-AI/wrkr/core/workflowloc"
)

const detectorID = "ciagent"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	files, err := collectWorkflowFiles(scope.Root)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	for _, rel := range files {
		payload, parseErr := detect.ReadFileWithinRoot(detectorID, scope.Root, rel)
		if parseErr != nil {
			findings = append(findings, parseErrorFinding(scope, rel, parseErr))
			continue
		}
		content := string(payload)
		workflowAnalysis, workflowErr := workflowcap.AnalyzeInRoot(scope.Root, rel, payload)
		if workflowErr != nil {
			findings = append(findings, parseErrorFinding(scope, rel, workflowErr))
		}
		signals := autonomy.Signals{
			Tool:            workflowAnalysis.Tool,
			Headless:        workflowAnalysis.Headless,
			HasApprovalGate: workflowAnalysis.HasApprovalGate,
			HasSecretAccess: workflowAnalysis.HasSecretAccess,
			DangerousFlags:  workflowAnalysis.DangerousFlags,
		}
		if workflowErr != nil {
			signals.Tool = detectTool(content)
			signals.Headless = isHeadlessInvocation(content)
			signals.HasApprovalGate = hasApprovalGate(content)
			signals.HasSecretAccess = hasSecretAccess(content)
			signals.DangerousFlags = hasDangerousFlags(content)
		}
		if signals.Tool == "" {
			signals.Tool = detectTool(content)
		}
		if !signals.Headless {
			signals.Headless = isHeadlessInvocation(content)
		}
		if !signals.HasSecretAccess {
			signals.HasSecretAccess = hasSecretAccess(content)
		}
		if !signals.DangerousFlags {
			signals.DangerousFlags = hasDangerousFlags(content)
		}
		permissions := permissionsFromSignals(signals)
		permissions = append(permissions, workflowAnalysis.Capabilities...)
		if !signals.Headless && signals.Tool == "" && len(uniqueStrings(permissions)) == 0 {
			continue
		}
		level := autonomy.Classify(signals)
		severity := severityForWorkflow(signals, level, permissions)
		checkResult := model.CheckResultPass
		if signals.Headless && signals.HasSecretAccess && !signals.HasApprovalGate {
			checkResult = model.CheckResultFail
		}
		evidence := []model.Evidence{
			{Key: "headless", Value: boolString(signals.Headless)},
			{Key: "approval_gate", Value: boolString(signals.HasApprovalGate)},
			{Key: "secret_access", Value: boolString(signals.HasSecretAccess)},
			{Key: "dangerous_flags", Value: boolString(signals.DangerousFlags)},
		}
		if strings.TrimSpace(signals.Tool) != "" {
			evidence = append(evidence, model.Evidence{Key: "tool", Value: signals.Tool})
		}
		if workflowErr == nil {
			evidence = append(evidence, workflowAnalysis.Evidence...)
		} else {
			if provenanceType, subject := credentialProvenanceForWorkflow(content); provenanceType != "" {
				evidence = append(evidence,
					model.Evidence{Key: "credential_provenance_type", Value: provenanceType},
					model.Evidence{Key: "credential_subject", Value: subject},
					model.Evidence{Key: "credential_scope", Value: "workflow"},
					model.Evidence{Key: "credential_confidence", Value: "high"},
				)
			}
			if len(workflowAnalysis.Evidence) > 0 {
				evidence = append(evidence, workflowAnalysis.Evidence...)
			}
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
			Permissions: uniqueStrings(permissions),
			Evidence:    evidence,
			Remediation: "Require approval gates for headless agent workflows that can access secrets.",
		})
	}

	model.SortFindings(findings)
	return findings, nil
}

func collectWorkflowFiles(root string) ([]string, error) {
	set := map[string]struct{}{}
	patterns := []string{
		".github/workflows/*",
		".azure/pipelines/*.yml",
		".azure/pipelines/*.yaml",
	}
	for _, pattern := range patterns {
		matches, err := detect.Glob(root, pattern)
		if err != nil {
			return nil, err
		}
		for _, rel := range matches {
			if workflowloc.IsCIWorkflow(rel) {
				set[rel] = struct{}{}
			}
		}
	}
	for _, rel := range []string{"Jenkinsfile", ".gitlab-ci.yml", ".gitlab-ci.yaml", "azure-pipelines.yml", "azure-pipelines.yaml"} {
		exists, parseErr := detect.FileExistsWithinRoot(detectorID, root, rel)
		if parseErr != nil {
			return nil, detect.ParseErrorAsError(parseErr)
		}
		if exists {
			set[rel] = struct{}{}
		}
	}
	files := make([]string, 0, len(set))
	for rel := range set {
		files = append(files, rel)
	}
	sort.Strings(files)
	return files, nil
}

func parseErrorFinding(scope detect.Scope, rel string, parseErr *model.ParseError) model.Finding {
	if parseErr == nil {
		parseErr = &model.ParseError{Kind: "parse_error", Path: rel, Detector: detectorID, Message: "unknown parse error"}
	}
	normalized := *parseErr
	normalized.Path = strings.TrimSpace(rel)
	normalized.Detector = detectorID
	return model.Finding{
		FindingType: "parse_error",
		Severity:    model.SeverityMedium,
		ToolType:    "ci_agent",
		Location:    rel,
		Repo:        scope.Repo,
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		ParseError:  &normalized,
	}
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

func credentialProvenanceForWorkflow(content string) (string, string) {
	lower := strings.ToLower(content)
	switch {
	case strings.Contains(lower, "id-token: write"),
		strings.Contains(lower, "aws-actions/configure-aws-credentials"),
		strings.Contains(lower, "google-github-actions/auth"),
		strings.Contains(lower, "azure/login"),
		strings.Contains(lower, "workload_identity_federation"),
		strings.Contains(lower, "assume_role"),
		strings.Contains(lower, "sts:assumerole"):
		return "jit", "workflow_federation"
	default:
		return "", ""
	}
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

func severityForWorkflow(signals autonomy.Signals, level string, permissions []string) string {
	if base := severityForSignals(signals, level); base != model.SeverityInfo {
		return base
	}
	normalized := uniqueStrings(permissions)
	switch {
	case containsPermission(normalized, "deploy.write", "db.write", "iac.write", "release.write"):
		return model.SeverityHigh
	case containsPermission(normalized, "merge.execute", "package.write", "repo.write", "pull_request.write"):
		return model.SeverityMedium
	case containsPermission(normalized, "secret.read"):
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

func containsPermission(values []string, targets ...string) bool {
	for _, value := range values {
		for _, target := range targets {
			if value == target {
				return true
			}
		}
	}
	return false
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

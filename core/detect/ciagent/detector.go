package ciagent

import (
	"context"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/workflowcap"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk/autonomy"
)

const detectorID = "ciagent"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) SurfaceCoverage(scope detect.Scope, options detect.Options) []detect.SurfaceCoverage {
	catalog, err := workflowcap.CatalogFor(scope.Root, options)
	if err != nil {
		return []detect.SurfaceCoverage{{Surface: "ci_workflow", Org: scope.Org, Repo: scope.Repo, Detector: detectorID, ParserVersion: "2", Unsupported: 1, ReasonCodes: []string{"catalog:unavailable"}}}
	}
	byPlatform := map[string]*detect.SurfaceCoverage{}
	for _, path := range catalog.Paths() {
		entry, ok := catalog.Lookup(path)
		if !ok {
			continue
		}
		surface := entry.Platform
		if entry.SurfaceRole == "shared_source" {
			surface += ":shared_source"
		}
		receipt := byPlatform[surface]
		if receipt == nil {
			receipt = &detect.SurfaceCoverage{Surface: "ci_workflow:" + surface, Org: scope.Org, Repo: scope.Repo, Detector: detectorID, ParserVersion: "2"}
			byPlatform[surface] = receipt
		}
		receipt.Discovered++
		receipt.Selected++
		receipt.Attempted++
		if entry.ParseError != nil {
			receipt.Partial++
			receipt.ReasonCodes = append(receipt.ReasonCodes, "parser:"+entry.ParseError.Kind)
		} else {
			receipt.Parsed++
		}
		receipt.Findings += catalogEntryFindingCount(entry)
		unresolvedOverrides := map[string]string{}
		for _, evidence := range entry.Result.Evidence {
			if evidence.Key != "execution_resolution" {
				continue
			}
			state := relationshipState(evidence.Value)
			if isUnresolvedRelationshipState(state) {
				unresolvedOverrides[relationshipCoverageKey(evidence.Value)] = state
			}
		}
		usedOverrides := map[string]struct{}{}
		for _, evidence := range entry.Result.Evidence {
			switch evidence.Key {
			case "execution_relationship":
				key := relationshipCoverageKey(evidence.Value)
				if state, overridden := unresolvedOverrides[key]; overridden {
					receipt.Unresolved++
					receipt.ReasonCodes = append(receipt.ReasonCodes, "relationship:"+state)
					usedOverrides[key] = struct{}{}
				} else if strings.Contains(evidence.Value, "|resolved_local") || strings.Contains(evidence.Value, "|resolved_declared") {
					receipt.Resolved++
				} else {
					receipt.Unresolved++
					receipt.ReasonCodes = append(receipt.ReasonCodes, "relationship:"+relationshipState(evidence.Value))
				}
			}
		}
		for key, state := range unresolvedOverrides {
			if _, used := usedOverrides[key]; used {
				continue
			}
			receipt.Unresolved++
			receipt.ReasonCodes = append(receipt.ReasonCodes, "relationship:"+state)
		}
	}
	out := make([]detect.SurfaceCoverage, 0, len(byPlatform))
	for _, receipt := range byPlatform {
		receipt.ReasonCodes = uniqueStrings(receipt.ReasonCodes)
		out = append(out, *receipt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Surface < out[j].Surface })
	return out
}

func relationshipState(value string) string {
	parts := strings.Split(strings.TrimSpace(value), "|")
	for _, part := range parts {
		switch part {
		case "resolved_local", "resolved_declared", "unresolved_external", "unsupported_dynamic", "cycle_blocked", "depth_limited", "fanout_limited", "contradictory":
			return part
		}
	}
	return "unknown"
}

func relationshipCoverageKey(value string) string {
	parts := strings.Split(strings.TrimSpace(value), "|")
	if len(parts) < 3 {
		return strings.TrimSpace(value)
	}
	return strings.Join(parts[:3], "|")
}

func catalogEntryFindingCount(entry workflowcap.CatalogEntry) int {
	count := 0
	if entry.ParseError != nil {
		count++
	}
	analysis := entry.Result
	signals := autonomy.Signals{
		Tool:            analysis.Tool,
		Headless:        analysis.Headless,
		HasApprovalGate: analysis.HasApprovalGate,
		HasSecretAccess: analysis.HasSecretAccess,
		DangerousFlags:  analysis.DangerousFlags,
	}
	permissions := append(permissionsFromSignals(signals), analysis.Capabilities...)
	if entry.SurfaceRole == "entrypoint" && (signals.Headless || signals.Tool != "" || len(uniqueStrings(permissions)) > 0) {
		count++
	}
	return count
}

func isUnresolvedRelationshipState(state string) bool {
	switch state {
	case "unresolved_external", "unsupported_dynamic", "cycle_blocked", "depth_limited", "fanout_limited", "contradictory":
		return true
	default:
		return false
	}
}

func (Detector) Detect(_ context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	catalog, err := workflowcap.CatalogFor(scope.Root, options)
	if err != nil {
		return nil, err
	}
	files := catalog.EntrypointPaths()

	findings := make([]model.Finding, 0)
	for _, rel := range catalog.Paths() {
		entry, ok := catalog.Lookup(rel)
		if ok && entry.SurfaceRole == "shared_source" && entry.ParseError != nil {
			findings = append(findings, parseErrorFinding(scope, rel, entry.ParseError))
		}
	}
	for _, rel := range files {
		entry, ok := catalog.Lookup(rel)
		if !ok {
			continue
		}
		workflowAnalysis, workflowErr := entry.Result, entry.ParseError
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
		if len(workflowAnalysis.Evidence) > 0 {
			evidence = append(evidence, workflowAnalysis.Evidence...)
		}
		findings = append(findings, model.Finding{
			FindingType:            "ci_autonomy",
			Severity:               severity,
			CheckResult:            checkResult,
			ToolType:               "ci_agent",
			Location:               rel,
			Repo:                   scope.Repo,
			Org:                    fallbackOrg(scope.Org),
			Detector:               detectorID,
			Autonomy:               level,
			Permissions:            uniqueStrings(permissions),
			Evidence:               evidence,
			ExecutionRelationships: model.NormalizeExecutionRelationships(workflowAnalysis.ExecutionRelationships),
			Remediation:            "Require approval gates for headless agent workflows that can access secrets.",
		})
	}

	model.SortFindings(findings)
	return findings, nil
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

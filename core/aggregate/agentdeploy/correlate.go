package agentdeploy

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
)

type deploymentSignals struct {
	artifacts map[string]struct{}
	evidence  map[string]struct{}
}

func Resolve(findings []model.Finding) map[string]agginventory.AgentDeploymentContext {
	resolved := map[string]deploymentSignals{}
	for _, finding := range findings {
		if !model.IsInventoryBearingFinding(finding) {
			continue
		}
		instanceID := agentInstanceID(finding)
		entry := resolved[instanceID]
		if entry.artifacts == nil {
			entry.artifacts = map[string]struct{}{}
			entry.evidence = map[string]struct{}{}
		}

		for _, artifact := range inferredArtifacts(finding) {
			entry.artifacts[artifact] = struct{}{}
			entry.evidence["deployment:"+artifact] = struct{}{}
		}
		resolved[instanceID] = entry
	}

	out := map[string]agginventory.AgentDeploymentContext{}
	for instanceID, entry := range resolved {
		artifacts := sortedKeys(entry.artifacts)
		status := "unknown"
		switch {
		case len(artifacts) == 1:
			status = "deployed"
		case len(artifacts) > 1:
			status = "ambiguous"
		}
		out[instanceID] = agginventory.AgentDeploymentContext{
			DeploymentStatus:       status,
			DeploymentArtifacts:    artifacts,
			DeploymentEvidenceKeys: sortedKeys(entry.evidence),
		}
	}
	return out
}

func inferredArtifacts(finding model.Finding) []string {
	artifacts := map[string]struct{}{}
	location := strings.TrimSpace(finding.Location)
	if strings.HasPrefix(location, ".github/workflows/") || strings.HasSuffix(location, ".github/workflows") {
		artifacts[location] = struct{}{}
	}
	lowerLocation := strings.ToLower(location)
	if strings.Contains(lowerLocation, "dockerfile") || strings.Contains(lowerLocation, "k8s") || strings.Contains(lowerLocation, "helm") {
		artifacts[location] = struct{}{}
	}
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		if key != "deployment_artifacts" && key != "deployment_artifact" {
			continue
		}
		for _, item := range splitCSV(evidence.Value) {
			artifacts[item] = struct{}{}
		}
	}
	return sortedKeys(artifacts)
}

func agentInstanceID(finding model.Finding) string {
	symbol := ""
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		if key == "symbol" || key == "name" || key == "agent_name" {
			symbol = strings.TrimSpace(evidence.Value)
			break
		}
	}
	startLine := 0
	endLine := 0
	if finding.LocationRange != nil {
		startLine = finding.LocationRange.StartLine
		endLine = finding.LocationRange.EndLine
	}
	return identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for item := range values {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

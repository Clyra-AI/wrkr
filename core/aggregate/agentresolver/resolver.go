package agentresolver

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
)

type bucket struct {
	tools        map[string]struct{}
	dataSources  map[string]struct{}
	authSurfaces map[string]struct{}
	evidenceKeys map[string]struct{}
}

func Resolve(findings []model.Finding) map[string]agginventory.AgentBindingContext {
	resolved := map[string]bucket{}
	for _, finding := range findings {
		if !model.IsInventoryBearingFinding(finding) {
			continue
		}
		instanceID := agentInstanceID(finding)
		if strings.TrimSpace(instanceID) == "" {
			continue
		}
		entry := resolved[instanceID]
		if entry.tools == nil {
			entry = bucket{
				tools:        map[string]struct{}{},
				dataSources:  map[string]struct{}{},
				authSurfaces: map[string]struct{}{},
				evidenceKeys: map[string]struct{}{},
			}
		}
		for _, evidence := range finding.Evidence {
			key := strings.ToLower(strings.TrimSpace(evidence.Key))
			value := strings.TrimSpace(evidence.Value)
			if key == "" || value == "" {
				continue
			}
			switch key {
			case "bound_tools", "tools", "tool", "mcp_server", "server":
				for _, item := range splitCSV(value) {
					entry.tools[item] = struct{}{}
					entry.evidenceKeys["tool:"+item] = struct{}{}
				}
			case "data_sources", "data_source", "dataset", "table", "bucket":
				for _, item := range splitCSV(value) {
					entry.dataSources[item] = struct{}{}
					entry.evidenceKeys["data:"+item] = struct{}{}
				}
			case "auth_surfaces", "auth", "auth_surface", "credentials", "credential":
				for _, item := range splitCSV(value) {
					entry.authSurfaces[item] = struct{}{}
					entry.evidenceKeys["auth:"+item] = struct{}{}
				}
			}
		}
		resolved[instanceID] = entry
	}

	out := map[string]agginventory.AgentBindingContext{}
	for instanceID, entry := range resolved {
		bindings := agginventory.AgentBindingContext{
			BoundTools:          sortedKeys(entry.tools),
			BoundDataSources:    sortedKeys(entry.dataSources),
			BoundAuthSurfaces:   sortedKeys(entry.authSurfaces),
			BindingEvidenceKeys: sortedKeys(entry.evidenceKeys),
		}
		if len(bindings.BoundTools) == 0 {
			bindings.MissingBindings = append(bindings.MissingBindings, "tool_binding_unknown")
		}
		if len(bindings.BoundDataSources) == 0 {
			bindings.MissingBindings = append(bindings.MissingBindings, "data_binding_unknown")
		}
		if len(bindings.BoundAuthSurfaces) == 0 {
			bindings.MissingBindings = append(bindings.MissingBindings, "auth_binding_unknown")
		}
		if len(bindings.MissingBindings) > 0 {
			sort.Strings(bindings.MissingBindings)
		}
		out[instanceID] = bindings
	}
	return out
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
	for _, item := range parts {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(in map[string]struct{}) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for item := range in {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

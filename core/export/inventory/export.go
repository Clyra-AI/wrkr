package inventory

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	agg "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

type Snapshot struct {
	ExportVersion string      `json:"export_version" yaml:"export_version"`
	ExportedAt    string      `json:"exported_at" yaml:"exported_at"`
	Org           string      `json:"org" yaml:"org"`
	Agents        []agg.Agent `json:"agents" yaml:"agents"`
	Tools         []agg.Tool  `json:"tools" yaml:"tools"`
}

func Build(inv agg.Inventory, now time.Time) Snapshot {
	return BuildWithOptions(inv, now, BuildOptions{})
}

type BuildOptions struct {
	Anonymize bool
}

func BuildWithOptions(inv agg.Inventory, now time.Time, opts BuildOptions) Snapshot {
	exportedAt := now.UTC()
	if exportedAt.IsZero() {
		exportedAt = time.Now().UTC().Truncate(time.Second)
	}
	tools := append([]agg.Tool{}, inv.Tools...)
	agents := append([]agg.Agent{}, inv.Agents...)
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Org != tools[j].Org {
			return tools[i].Org < tools[j].Org
		}
		if tools[i].ToolType != tools[j].ToolType {
			return tools[i].ToolType < tools[j].ToolType
		}
		return tools[i].ToolID < tools[j].ToolID
	})
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].Org != agents[j].Org {
			return agents[i].Org < agents[j].Org
		}
		if agents[i].Framework != agents[j].Framework {
			return agents[i].Framework < agents[j].Framework
		}
		if agents[i].AgentInstanceID != agents[j].AgentInstanceID {
			return agents[i].AgentInstanceID < agents[j].AgentInstanceID
		}
		if agents[i].Location != agents[j].Location {
			return agents[i].Location < agents[j].Location
		}
		if agents[i].Repo != agents[j].Repo {
			return agents[i].Repo < agents[j].Repo
		}
		return agents[i].AgentID < agents[j].AgentID
	})
	org := inv.Org
	if opts.Anonymize {
		tools = anonymizeTools(tools)
		agents = anonymizeAgents(agents)
		org = redact("org", org, 8)
	}
	return Snapshot{
		ExportVersion: "1",
		ExportedAt:    exportedAt.Format(time.RFC3339),
		Org:           org,
		Agents:        agents,
		Tools:         tools,
	}
}

func anonymizeTools(tools []agg.Tool) []agg.Tool {
	out := make([]agg.Tool, 0, len(tools))
	for _, tool := range tools {
		copyTool := tool
		copyTool.ToolID = redact("tool", copyTool.ToolID, 12)
		copyTool.ToolFamilyID = redact("family", copyTool.ToolFamilyID, 12)
		copyTool.ToolInstanceID = redact("tool-inst", copyTool.ToolInstanceID, 12)
		copyTool.AgentID = redact("agent", copyTool.AgentID, 12)
		copyTool.Org = redact("org", copyTool.Org, 8)
		copyTool.ConfigFingerprint = redact("cfg", copyTool.ConfigFingerprint, 12)
		copyTool.ConfigSource = redact("config", copyTool.ConfigSource, 12)
		repos := make([]string, 0, len(copyTool.Repos))
		for _, repo := range copyTool.Repos {
			repos = append(repos, redact("repo", repo, 10))
		}
		copyTool.Repos = repos
		locations := make([]agg.ToolLocation, 0, len(copyTool.Locations))
		for _, loc := range copyTool.Locations {
			locations = append(locations, agg.ToolLocation{
				Repo:                redact("repo", loc.Repo, 10),
				Location:            redact("loc", loc.Location, 10),
				Owner:               redact("owner", loc.Owner, 10),
				OwnerSource:         strings.TrimSpace(loc.OwnerSource),
				OwnershipStatus:     strings.TrimSpace(loc.OwnershipStatus),
				OwnershipState:      strings.TrimSpace(loc.OwnershipState),
				OwnershipConfidence: loc.OwnershipConfidence,
				OwnershipEvidence:   redactList("owner-evidence", loc.OwnershipEvidence, 12),
				OwnershipConflicts:  redactList("owner-conflict", loc.OwnershipConflicts, 12),
			})
		}
		copyTool.Locations = locations
		copyTool.GovernanceControls = anonymizeGovernanceControls(copyTool.GovernanceControls)
		out = append(out, copyTool)
	}
	return out
}

func anonymizeAgents(agents []agg.Agent) []agg.Agent {
	out := make([]agg.Agent, 0, len(agents))
	for _, agent := range agents {
		copyAgent := agent
		copyAgent.AgentID = redact("agent", copyAgent.AgentID, 12)
		copyAgent.AgentInstanceID = redact("instance", copyAgent.AgentInstanceID, 12)
		copyAgent.ToolFamilyID = redact("family", copyAgent.ToolFamilyID, 12)
		copyAgent.ToolInstanceID = redact("tool-inst", copyAgent.ToolInstanceID, 12)
		copyAgent.ConfigFingerprint = redact("cfg", copyAgent.ConfigFingerprint, 12)
		copyAgent.Org = redact("org", copyAgent.Org, 8)
		copyAgent.Repo = redact("repo", copyAgent.Repo, 10)
		copyAgent.Location = redact("loc", copyAgent.Location, 10)
		copyAgent.ConfigSource = redact("config", copyAgent.ConfigSource, 12)
		copyAgent.BoundTools = redactList("bound-tool", copyAgent.BoundTools, 12)
		copyAgent.BoundDataSources = redactList("bound-data", copyAgent.BoundDataSources, 12)
		copyAgent.BoundAuthSurfaces = redactList("bound-auth", copyAgent.BoundAuthSurfaces, 12)
		copyAgent.BindingEvidenceKeys = redactList("binding-evidence", copyAgent.BindingEvidenceKeys, 12)
		copyAgent.DeploymentArtifacts = redactList("deploy-artifact", copyAgent.DeploymentArtifacts, 12)
		copyAgent.DeploymentEvidenceKeys = redactList("deploy-evidence", copyAgent.DeploymentEvidenceKeys, 12)
		out = append(out, copyAgent)
	}
	return out
}

func anonymizeGovernanceControls(in []agg.GovernanceControlMapping) []agg.GovernanceControlMapping {
	if len(in) == 0 {
		return nil
	}
	out := make([]agg.GovernanceControlMapping, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.Evidence = redactList("evidence", copyItem.Evidence, 12)
		out = append(out, copyItem)
	}
	return out
}

func redactList(prefix string, values []string, width int) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, redact(prefix, value, width))
	}
	return out
}

func redact(prefix, value string, width int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	hex := fmt.Sprintf("%x", sum)
	if width <= 0 || width > len(hex) {
		width = len(hex)
	}
	return fmt.Sprintf("%s-%s", prefix, hex[:width])
}

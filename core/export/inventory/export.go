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
	ExportVersion string     `json:"export_version" yaml:"export_version"`
	ExportedAt    string     `json:"exported_at" yaml:"exported_at"`
	Org           string     `json:"org" yaml:"org"`
	Tools         []agg.Tool `json:"tools" yaml:"tools"`
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
	tools := append([]agg.Tool(nil), inv.Tools...)
	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Org != tools[j].Org {
			return tools[i].Org < tools[j].Org
		}
		if tools[i].ToolType != tools[j].ToolType {
			return tools[i].ToolType < tools[j].ToolType
		}
		return tools[i].ToolID < tools[j].ToolID
	})
	org := inv.Org
	if opts.Anonymize {
		tools = anonymizeTools(tools)
		org = redact("org", org, 8)
	}
	return Snapshot{
		ExportVersion: "1",
		ExportedAt:    exportedAt.Format(time.RFC3339),
		Org:           org,
		Tools:         tools,
	}
}

func anonymizeTools(tools []agg.Tool) []agg.Tool {
	out := make([]agg.Tool, 0, len(tools))
	for _, tool := range tools {
		copyTool := tool
		copyTool.ToolID = redact("tool", copyTool.ToolID, 12)
		copyTool.AgentID = redact("agent", copyTool.AgentID, 12)
		copyTool.Org = redact("org", copyTool.Org, 8)
		repos := make([]string, 0, len(copyTool.Repos))
		for _, repo := range copyTool.Repos {
			repos = append(repos, redact("repo", repo, 10))
		}
		copyTool.Repos = repos
		locations := make([]agg.ToolLocation, 0, len(copyTool.Locations))
		for _, loc := range copyTool.Locations {
			locations = append(locations, agg.ToolLocation{
				Repo:     redact("repo", loc.Repo, 10),
				Location: redact("loc", loc.Location, 10),
				Owner:    redact("owner", loc.Owner, 10),
			})
		}
		copyTool.Locations = locations
		out = append(out, copyTool)
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

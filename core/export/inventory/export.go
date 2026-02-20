package inventory

import (
	"sort"
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
	return Snapshot{
		ExportVersion: "1",
		ExportedAt:    exportedAt.Format(time.RFC3339),
		Org:           inv.Org,
		Tools:         tools,
	}
}

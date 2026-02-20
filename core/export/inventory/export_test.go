package inventory

import (
	"testing"
	"time"

	agg "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestBuildEmptyInventoryIsStable(t *testing.T) {
	t.Parallel()
	snapshot := Build(agg.Inventory{Org: "acme", Tools: []agg.Tool{}}, time.Date(2026, 2, 20, 13, 0, 0, 0, time.UTC))
	if snapshot.ExportVersion != "1" {
		t.Fatalf("unexpected export version: %s", snapshot.ExportVersion)
	}
	if len(snapshot.Tools) != 0 {
		t.Fatalf("expected empty tools, got %d", len(snapshot.Tools))
	}
}

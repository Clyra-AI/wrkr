//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestTicketExport(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")
	_ = runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	payload := runScenarioCommandJSON(t, []string{"export", "tickets", "--top", "10", "--format", "jira", "--dry-run", "--state", statePath, "--json"})
	if payload["ticket_export_version"] != "1" || payload["dry_run"] != true {
		t.Fatalf("unexpected ticket export payload: %v", payload)
	}
	tickets, ok := payload["tickets"].([]any)
	if !ok || len(tickets) == 0 {
		t.Fatalf("expected ticket payloads, got %v", payload["tickets"])
	}
	first, _ := tickets[0].(map[string]any)
	for _, key := range []string{"owner", "evidence", "recommended_action", "sla", "closure_criteria"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("ticket missing %s: %v", key, first)
		}
	}
}

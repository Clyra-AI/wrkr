//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestDeliveryChainCorrelationScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "delivery-chain-correlation", "repos")
	targetsPath := filepath.Join(repoRoot, "scenarios", "wrkr", "delivery-chain-correlation", "production-targets.yaml")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--production-targets", targetsPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	actionPaths, ok := payload["action_paths"].([]any)
	if !ok || len(actionPaths) == 0 {
		t.Fatalf("expected action_paths payload, got %v", payload["action_paths"])
	}
	first, ok := actionPaths[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected action path payload: %T", actionPaths[0])
	}
	if first["delivery_chain_status"] != "pr_merge_deploy" {
		t.Fatalf("expected delivery_chain_status=pr_merge_deploy, got %v", first["delivery_chain_status"])
	}
	if first["production_target_status"] != "configured" {
		t.Fatalf("expected production_target_status=configured, got %v", first["production_target_status"])
	}
	if first["production_write"] != true {
		t.Fatalf("expected production_write=true, got %v", first["production_write"])
	}
	if first["recommended_action"] != "control" {
		t.Fatalf("expected recommended_action=control, got %v", first["recommended_action"])
	}
}

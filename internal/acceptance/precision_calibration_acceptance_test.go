package acceptance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestPrecisionCalibrationAcceptance(t *testing.T) {
	paths := loadAcceptancePaths(t)
	scanRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "precision-calibration", "repos")
	statePath := filepath.Join(t.TempDir(), "precision-acceptance-state.json")

	scanPayload := runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--json")
	deployAgentPathID := acceptanceFirstRepoPathID(t, requireArray(t, scanPayload, "action_paths"), "deploy-agent")

	runtimeEvidencePath := filepath.Join(t.TempDir(), "runtime-evidence.json")
	runtimeEvidence := `{
  "schema_version": "v1",
  "generated_at": "2026-05-31T17:00:00Z",
  "records": [
    {
      "record_kind": "runtime",
      "record_id": "deploy-agent-approval",
      "path_id": "` + deployAgentPathID + `",
      "repo": "deploy-agent",
      "location": ".github/workflows/release.yml",
      "tool": "ci_agent",
      "source": "demo_runtime_export",
      "observed_at": "2026-05-31T16:55:00Z",
      "evidence_class": "approval",
      "status": "matched"
    }
  ]
}`
	if err := os.WriteFile(runtimeEvidencePath, []byte(runtimeEvidence), 0o600); err != nil {
		t.Fatalf("write runtime evidence: %v", err)
	}
	runJSONOK(t, "ingest", "--state", statePath, "--input", runtimeEvidencePath, "--json")

	reportPayload := runJSONOK(t, "report", "--state", statePath, "--template", "agent-action-bom", "--json")

	actionPaths := requireArray(t, reportPayload, "action_paths")
	deployAgent := findAcceptanceRepoPath(t, actionPaths, "deploy-agent")
	if deployAgent["action_path_type"] != "ai_assisted_workflow" {
		t.Fatalf("expected deploy-agent to stay AI-assisted, got %v", deployAgent)
	}
	bomItems := requireArrayFromObject(t, requireObject(t, reportPayload, "agent_action_bom"), "items")
	deployAgentBOM := findAcceptanceRepoPath(t, bomItems, "deploy-agent")
	if deployAgentBOM["runtime_evidence_status"] != "matched" {
		t.Fatalf("expected deploy-agent BOM runtime evidence to match after ingest, got %v", deployAgentBOM["runtime_evidence_status"])
	}

	findingsFromScan := requireArray(t, scanPayload, "findings")
	sawCIAutonomy := false
	for _, raw := range findingsFromScan {
		item := requireObjectItem(t, raw)
		if item["repo"] != "ci-without-agent" {
			continue
		}
		if item["finding_type"] == "ci_autonomy" {
			sawCIAutonomy = true
		}
		if item["finding_type"] == "agent_framework" {
			t.Fatalf("ci-without-agent fixture should not escalate to agent_framework: %v", item)
		}
	}
	if !sawCIAutonomy {
		t.Fatalf("expected ci-without-agent to emit ci_autonomy findings, got %v", findingsFromScan)
	}

	approvalSidecar := findAcceptanceRepoPath(t, actionPaths, "approval-sidecar")
	if approvalSidecar["approval_evidence_state"] != "verified" {
		t.Fatalf("expected approval-sidecar approval evidence to verify, got %v", approvalSidecar["approval_evidence_state"])
	}

	sawContradictionSecret := false
	for _, raw := range findingsFromScan {
		item := requireObjectItem(t, raw)
		if item["repo"] == "non-prod-contradiction" && item["finding_type"] == "secret_presence" {
			sawContradictionSecret = true
			break
		}
	}
	if !sawContradictionSecret {
		t.Fatalf("expected non-prod contradiction fixture to surface secret_presence findings, got %v", findingsFromScan)
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", filepath.Join(scanRoot, "dependency-only"), "--state", filepath.Join(t.TempDir(), "dependency-only-state.json"), "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("dependency-only scan failed: %d %s", code, scanErr.String())
	}
	dependencyPayload := map[string]any{}
	if err := json.Unmarshal(scanOut.Bytes(), &dependencyPayload); err != nil {
		t.Fatalf("parse dependency-only scan payload: %v", err)
	}
	findings := requireArray(t, dependencyPayload, "findings")
	sawFrameworkCandidate := false
	for _, raw := range findings {
		item := requireObjectItem(t, raw)
		if item["finding_type"] == "framework_candidate" {
			sawFrameworkCandidate = true
		}
		if item["finding_type"] == "agent_framework" {
			t.Fatalf("did not expect dependency-only fixture to escalate to agent_framework: %v", item)
		}
	}
	if !sawFrameworkCandidate {
		t.Fatalf("expected dependency-only fixture to produce framework_candidate findings, got %v", findings)
	}
}

func findAcceptanceRepoPath(t *testing.T, actionPaths []any, repo string) map[string]any {
	t.Helper()
	for _, raw := range actionPaths {
		row := requireObjectItem(t, raw)
		if row["repo"] == repo {
			return row
		}
	}
	t.Fatalf("expected action path for repo %s, got %v", repo, actionPaths)
	return nil
}

func acceptanceFirstRepoPathID(t *testing.T, actionPaths []any, repo string) string {
	t.Helper()
	for _, raw := range actionPaths {
		row := requireObjectItem(t, raw)
		if row["repo"] == repo {
			id, _ := row["path_id"].(string)
			return id
		}
	}
	t.Fatalf("expected action path for repo %s, got %v", repo, actionPaths)
	return ""
}

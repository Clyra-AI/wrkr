package acceptance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExternalControlEvidenceAcceptance(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join(t.TempDir(), "demo-app")
	if err := os.MkdirAll(filepath.Join(repoRoot, ".github", "workflows"), 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr", "provenance"), 0o755); err != nil {
		t.Fatalf("mkdir provenance dir: %v", err)
	}
	workflow := []byte(`name: Release
on:
  workflow_dispatch:
jobs:
  release:
    environment: production
    permissions:
      contents: write
    steps:
      - run: gh release create v1.0.0
`)
	if err := os.WriteFile(filepath.Join(repoRoot, ".github", "workflows", "release.yml"), workflow, 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	sidecar := []byte(`{
  "schema_version": "v1",
  "generated_at": "2026-05-25T17:30:30Z",
  "records": [
    {
      "record_kind": "external_control",
      "source_type": "provider_export",
      "source": "github_branch_protection_export",
      "repo": "local/demo-app",
      "path": ".github/workflows/release.yml",
      "observed_at": "2026-05-25T17:00:00Z",
      "evidence_class": "branch_protection",
      "status": "matched",
      "evidence_refs": ["evidence://fake/provider-export.json#branch/main"]
    },
    {
      "record_kind": "external_control",
      "source_type": "repo_policy",
      "source": "local_gait_policy",
      "repo": "local/demo-app",
      "path": ".github/workflows/release.yml",
      "observed_at": "2026-05-25T17:00:00Z",
      "evidence_class": "deployment_approval",
      "status": "matched",
      "evidence_refs": ["evidence://fake/policy.yaml#approval"]
    }
  ]
}`)
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "provenance", "external-control-evidence.json"), sidecar, 0o600); err != nil {
		t.Fatalf("write external control evidence: %v", err)
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	runJSONOK(t, "scan", "--path", repoRoot, "--state", statePath, "--json")
	reportPayload := runJSONOK(t, "report", "--state", statePath, "--template", "agent-action-bom", "--json")
	actionPaths := requireArray(t, reportPayload, "action_paths")
	if len(actionPaths) == 0 {
		t.Fatalf("expected action paths in report payload, got %v", reportPayload)
	}
	first := requireObjectItem(t, actionPaths[0])
	classes := requireArrayFromObject(t, first, "constraint_evidence_classes")
	if len(classes) == 0 {
		t.Fatalf("expected constraint evidence classes in action path, got %v", first)
	}
	if first["approval_evidence_state"] != "verified" {
		t.Fatalf("expected verified approval evidence from provider export, got %v", first["approval_evidence_state"])
	}
}

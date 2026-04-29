package agnt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectorPreservesAgntManifestDeclarations(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	manifest := []byte(`
name: release-agent
file: agents/release.py
tools:
  - deploy
mcp_refs:
  - prod-mcp
permissions:
  - repo.read
policy_refs:
  - gait://release
owner_refs:
  - '@acme/security'
lifecycle:
  state: approved
  approval_status: valid
`)
	if err := os.WriteFile(filepath.Join(root, "agent.yaml"), manifest, 0o600); err != nil {
		t.Fatalf("write agent manifest: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "acme/backend", Org: "acme"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect agnt manifest: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
	finding := findings[0]
	if finding.FindingType != "agnt_manifest" {
		t.Fatalf("expected agnt_manifest finding, got %+v", finding)
	}
	if finding.Location != "agents/release.py" {
		t.Fatalf("expected manifest file location, got %q", finding.Location)
	}
	if got := evidenceValue(finding, "declared_tools"); got != "deploy" {
		t.Fatalf("expected declared tool evidence, got %q", got)
	}
	if got := evidenceValue(finding, "declared_owner_refs"); got != "@acme/security" {
		t.Fatalf("expected declared owner refs, got %q", got)
	}
	if got := evidenceValue(finding, "declared_lifecycle_state"); got != "approved" {
		t.Fatalf("expected lifecycle state evidence, got %q", got)
	}
}

func TestSynthesizeDriftFlagsObservedCapabilityBeyondManifest(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "agnt_manifest",
			ToolType:    "agnt_agent",
			Location:    "agents/release.py",
			Repo:        "acme/backend",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "manifest_name", Value: "release-agent"},
				{Key: "manifest_path", Value: "agent.yaml"},
				{Key: "declared_tools", Value: "search"},
				{Key: "declared_mcp_refs", Value: ""},
				{Key: "declared_permissions", Value: "repo.read"},
				{Key: "declared_policy_refs", Value: "gait://release"},
			},
		},
		{
			FindingType: "agent_framework",
			ToolType:    "crewai",
			Location:    "agents/release.py",
			Repo:        "acme/backend",
			Org:         "acme",
			Permissions: []string{"repo.write"},
			Evidence: []model.Evidence{
				{Key: "bound_tools", Value: "deploy.write"},
				{Key: "server", Value: "prod-mcp"},
			},
		},
	}

	drift := SynthesizeDrift(findings)
	if len(drift) != 1 {
		t.Fatalf("expected one drift finding, got %+v", drift)
	}
	if drift[0].FindingType != "agnt_declared_observed_drift" {
		t.Fatalf("expected drift finding, got %+v", drift[0])
	}
	if drift[0].Severity != model.SeverityHigh {
		t.Fatalf("expected high severity drift for undeclared MCP/write posture, got %s", drift[0].Severity)
	}
	if !containsValue(drift[0].Permissions, "repo.write") {
		t.Fatalf("expected observed excess permission, got %+v", drift[0].Permissions)
	}
	if got := evidenceValue(drift[0], "observed_excess_tools"); got != "deploy.write" {
		t.Fatalf("expected observed excess tool evidence, got %q", got)
	}
	if got := evidenceValue(drift[0], "observed_excess_mcp_refs"); got != "prod-mcp" {
		t.Fatalf("expected observed excess MCP evidence, got %q", got)
	}
}

func evidenceValue(finding model.Finding, key string) string {
	for _, item := range finding.Evidence {
		if strings.TrimSpace(item.Key) == key {
			return strings.TrimSpace(item.Value)
		}
	}
	return ""
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

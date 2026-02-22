package diff

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
)

func TestComputeAddedRemovedChanged(t *testing.T) {
	t.Parallel()

	previous := []source.Finding{
		{ToolType: "repo", Location: "acme/a", Org: "acme", Permissions: []string{"read"}},
		{ToolType: "repo", Location: "acme/b", Org: "acme", Permissions: []string{"read"}},
	}
	current := []source.Finding{
		{ToolType: "repo", Location: "acme/a", Org: "acme", Permissions: []string{"write"}},
		{ToolType: "repo", Location: "acme/c", Org: "acme", Permissions: []string{"read"}},
	}

	result := Compute(previous, current)
	if len(result.Added) != 1 || result.Added[0].Location != "acme/c" {
		t.Fatalf("unexpected added: %+v", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0].Location != "acme/b" {
		t.Fatalf("unexpected removed: %+v", result.Removed)
	}
	if len(result.Changed) != 1 || result.Changed[0].Key.Location != "acme/a" {
		t.Fatalf("unexpected changed: %+v", result.Changed)
	}
	if !result.Changed[0].PermissionChanged {
		t.Fatalf("expected permission_changed=true")
	}
}

func TestComputeNoChanges(t *testing.T) {
	t.Parallel()

	items := []source.Finding{{ToolType: "repo", Location: "acme/a", Org: "acme", Permissions: []string{"read"}}}
	result := Compute(items, items)
	if !Empty(result) {
		t.Fatalf("expected empty diff, got %+v", result)
	}
}

func TestComputePreservesDuplicateIdentityFindings(t *testing.T) {
	t.Parallel()

	previous := []source.Finding{
		{
			FindingType: "ai_dependency",
			ToolType:    "dependency",
			Location:    "package.json",
			Repo:        "frontend",
			Org:         "acme",
			Evidence:    []model.Evidence{{Key: "dependency", Value: "openai"}},
		},
	}
	current := []source.Finding{
		{
			FindingType: "ai_dependency",
			ToolType:    "dependency",
			Location:    "package.json",
			Repo:        "frontend",
			Org:         "acme",
			Evidence:    []model.Evidence{{Key: "dependency", Value: "openai"}},
		},
		{
			FindingType: "ai_dependency",
			ToolType:    "dependency",
			Location:    "package.json",
			Repo:        "frontend",
			Org:         "acme",
			Evidence:    []model.Evidence{{Key: "dependency", Value: "anthropic"}},
		},
	}

	result := Compute(previous, current)
	if len(result.Added) != 1 {
		t.Fatalf("expected one added duplicate finding, got %d", len(result.Added))
	}
	if result.Added[0].Evidence[0].Value != "anthropic" {
		t.Fatalf("expected anthropic dependency in added finding, got %+v", result.Added[0])
	}
}

func TestComputeTreatsMissingDiscoveryMethodAsStaticForLegacyState(t *testing.T) {
	t.Parallel()

	previous := []source.Finding{
		{
			FindingType: "mcp_server",
			ToolType:    "mcp",
			Location:    ".mcp.json",
			Repo:        "backend",
			Org:         "local",
		},
	}
	current := []source.Finding{
		{
			FindingType:     "mcp_server",
			DiscoveryMethod: model.DiscoveryMethodStatic,
			ToolType:        "mcp",
			Location:        ".mcp.json",
			Repo:            "backend",
			Org:             "local",
		},
	}

	result := Compute(previous, current)
	if !Empty(result) {
		t.Fatalf("expected empty diff for legacy missing discovery_method, got %+v", result)
	}
}

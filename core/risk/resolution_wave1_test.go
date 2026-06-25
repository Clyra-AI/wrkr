package risk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
)

func TestResolutionKeyStableAcrossReportOrdering(t *testing.T) {
	t.Parallel()

	base := ActionPath{
		PathID:           "apc-release",
		Org:              "acme",
		Repo:             "acme/release",
		ToolType:         "compiled_action",
		Location:         ".github/workflows/release.yml",
		WriteCapable:     true,
		ProductionWrite:  true,
		CredentialAccess: true,
		ActionClasses:    []string{"deploy"},
		SourceFindingKeys: []string{
			"compiled_action||ci_agent|.github/workflows/release.yml|acme/release|acme",
		},
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			CredentialKind:         agginventory.CredentialKindGitHubWorkflowToken,
			AccessType:             agginventory.CredentialAccessTypeJIT,
		},
	}
	other := ActionPath{
		PathID:           "apc-other",
		Org:              "acme",
		Repo:             "acme/app",
		ToolType:         "mcp",
		Location:         ".cursor/mcp.json",
		WriteCapable:     true,
		CredentialAccess: true,
		ActionClasses:    []string{"write"},
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			CredentialKind:         agginventory.CredentialKindGitHubPAT,
			AccessType:             agginventory.CredentialAccessTypeStanding,
		},
	}

	first := findPathByID(t, ProjectActionPaths([]ActionPath{base, other}), base.PathID)
	second := findPathByID(t, ProjectActionPaths([]ActionPath{other, base}), base.PathID)

	if first.ResolutionKey == "" {
		t.Fatalf("expected resolution_key on projected action path, got %+v", first)
	}
	if first.ResolutionKey != second.ResolutionKey {
		t.Fatalf("expected resolution_key to stay stable across ordering changes, first=%q second=%q", first.ResolutionKey, second.ResolutionKey)
	}
}

func TestDeclarationSelectorMatchesPathIDChurn(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr"), 0o755); err != nil {
		t.Fatalf("mkdir .wrkr: %v", err)
	}
	payload := `schema_version: v1
review_dispositions:
  - state: accepted_risk
    source: governance-ticket
    issuer: release-cab
    rationale: Reviewed release workflow and accepted temporary residual risk.
    observed_at: 2026-06-25T10:00:00Z
    scope: repo
    path_id: apc-stale-path-id
    selector:
      repo: acme/release
      tool_type: compiled_action
      action_classes:
        - deploy
      credential_kinds:
        - github_workflow_token
`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "control-declarations.yaml"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	path := ProjectActionPath(ActionPath{
		PathID:           "apc-current-path-id",
		Org:              "acme",
		Repo:             "acme/release",
		ToolType:         "compiled_action",
		Location:         ".github/workflows/release.yml",
		WriteCapable:     true,
		ProductionWrite:  true,
		CredentialAccess: true,
		ActionClasses:    []string{"deploy"},
		SourceFindingKeys: []string{
			"compiled_action||ci_agent|.github/workflows/release.yml|acme/release|acme",
		},
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			CredentialKind:         agginventory.CredentialKindGitHubWorkflowToken,
			AccessType:             agginventory.CredentialAccessTypeJIT,
		},
	})

	ctx := attribution.LoadContextAt(repoRoot, time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC))
	decorated := ProjectActionPaths(DecorateControlMetadata([]ActionPath{path}, map[string]attribution.Context{
		repoKey(path.Org, path.Repo): ctx,
	}))
	if len(decorated) != 1 {
		t.Fatalf("expected one decorated path, got %+v", decorated)
	}
	if decorated[0].ReviewLifecycleState != ReviewLifecycleStateAcceptedRisk {
		t.Fatalf("expected accepted-risk lifecycle state via selector fallback, got %+v", decorated[0])
	}
	if decorated[0].ResolutionSelector == nil {
		t.Fatalf("expected fallback selector metadata on decorated path, got %+v", decorated[0])
	}
	if decorated[0].ResolutionMatchConfidence == "" {
		t.Fatalf("expected selector match confidence on decorated path, got %+v", decorated[0])
	}
}

func TestDeclarationResolutionKeyMatchesWhenPathIDIsStale(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr"), 0o755); err != nil {
		t.Fatalf("mkdir .wrkr: %v", err)
	}
	payload := `schema_version: v1
review_dispositions:
  - state: accepted_risk
    source: governance-ticket
    issuer: release-cab
    rationale: Stable resolution keys should survive stale path ids.
    observed_at: 2026-06-25T10:00:00Z
    scope: repo
    path_id: apc-stale-path-id
    resolution_key: rk-stable-path
    evidence_refs:
      - evidence://governance/release-risk-123
`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "control-declarations.yaml"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	path := ProjectActionPath(ActionPath{
		PathID:         "apc-current-path-id",
		Org:            "acme",
		Repo:           "acme/release",
		ToolType:       "compiled_action",
		Location:       ".github/workflows/release.yml",
		WriteCapable:   true,
		ActionClasses:  []string{"deploy"},
		ResolutionKey:  "rk-stable-path",
		ConfidenceLane: ConfidenceLaneConfirmedActionPath,
	})

	ctx := attribution.LoadContextAt(repoRoot, time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC))
	decorated := DecorateControlMetadata([]ActionPath{path}, map[string]attribution.Context{
		repoKey(path.Org, path.Repo): ctx,
	})
	if len(decorated) != 1 {
		t.Fatalf("expected one decorated path, got %+v", decorated)
	}
	if decorated[0].ReviewLifecycleState != ReviewLifecycleStateAcceptedRisk {
		t.Fatalf("expected accepted-risk lifecycle state via resolution_key fallback, got %+v", decorated[0])
	}
}

func TestResolutionSelectorAmbiguityFailsClosed(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr"), 0o755); err != nil {
		t.Fatalf("mkdir .wrkr: %v", err)
	}
	payload := `schema_version: v1
review_dispositions:
  - state: accepted_risk
    source: governance-ticket
    issuer: release-cab
    rationale: This declaration is intentionally broad to test fail-closed ambiguity handling.
    observed_at: 2026-06-25T10:00:00Z
    scope: repo
    selector:
      repo: acme/release
      tool_type: compiled_action
      action_classes:
        - deploy
      credential_kinds:
        - github_workflow_token
`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "control-declarations.yaml"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	paths := []ActionPath{
		ProjectActionPath(ActionPath{
			PathID:           "apc-release-a",
			Org:              "acme",
			Repo:             "acme/release",
			ToolType:         "compiled_action",
			Location:         ".github/workflows/release-a.yml",
			WriteCapable:     true,
			ProductionWrite:  true,
			CredentialAccess: true,
			ActionClasses:    []string{"deploy"},
			CredentialAuthority: &agginventory.CredentialAuthority{
				CredentialPresent:      true,
				CredentialUsableByPath: true,
				CredentialKind:         agginventory.CredentialKindGitHubWorkflowToken,
				AccessType:             agginventory.CredentialAccessTypeJIT,
			},
		}),
		ProjectActionPath(ActionPath{
			PathID:           "apc-release-b",
			Org:              "acme",
			Repo:             "acme/release",
			ToolType:         "compiled_action",
			Location:         ".github/workflows/release-b.yml",
			WriteCapable:     true,
			ProductionWrite:  true,
			CredentialAccess: true,
			ActionClasses:    []string{"deploy"},
			CredentialAuthority: &agginventory.CredentialAuthority{
				CredentialPresent:      true,
				CredentialUsableByPath: true,
				CredentialKind:         agginventory.CredentialKindGitHubWorkflowToken,
				AccessType:             agginventory.CredentialAccessTypeJIT,
			},
		}),
	}

	ctx := attribution.LoadContextAt(repoRoot, time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC))
	decorated := DecorateControlMetadata(paths, map[string]attribution.Context{
		repoKey("acme", "acme/release"): ctx,
	})
	for _, item := range decorated {
		if item.ReviewLifecycleState != "" {
			t.Fatalf("expected ambiguous selector to fail closed, got %+v", decorated)
		}
		if item.ResolutionMatchConfidence == "ambiguous" {
			if !containsReason(item.ResolutionMismatchReasons, "selector:ambiguous_match") {
				t.Fatalf("expected ambiguity reasons on selector failure, got %+v", item)
			}
			return
		}
	}
	t.Fatalf("expected at least one ambiguous selector annotation, got %+v", decorated)
}

func TestExpiredDeclarationDoesNotResolvePath(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr"), 0o755); err != nil {
		t.Fatalf("mkdir .wrkr: %v", err)
	}
	payload := `schema_version: v1
review_dispositions:
  - state: accepted_risk
    source: governance-ticket
    issuer: release-cab
    rationale: This accepted risk has expired.
    observed_at: 2026-06-20T10:00:00Z
    valid_until: 2026-06-21T10:00:00Z
    scope: repo
    resolution_key: rk-expired
`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "control-declarations.yaml"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	path := ActionPath{
		PathID:         "apc-expired",
		Org:            "acme",
		Repo:           "acme/release",
		ToolType:       "compiled_action",
		Location:       ".github/workflows/release.yml",
		WriteCapable:   true,
		ActionClasses:  []string{"deploy"},
		ResolutionKey:  "rk-expired",
		ReviewBurden:   ReviewBurdenHigh,
		ConfidenceLane: ConfidenceLaneConfirmedActionPath,
	}

	ctx := attribution.LoadContextAt(repoRoot, time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC))
	decorated := ProjectReviewLifecycleTransitions(DecorateControlMetadata([]ActionPath{path}, map[string]attribution.Context{
		repoKey(path.Org, path.Repo): ctx,
	}), nil)
	if decorated[0].ReviewLifecycleState != ReviewLifecycleStateExpired {
		t.Fatalf("expected expired declaration to stay inactive and explicit, got %+v", decorated[0])
	}
	if !containsReason(decorated[0].ReviewLifecycleReasons, "review_declaration:expired") {
		t.Fatalf("expected expired declaration reason on decorated path, got %+v", decorated[0])
	}
}

func findPathByID(t *testing.T, paths []ActionPath, pathID string) ActionPath {
	t.Helper()
	for _, item := range paths {
		if item.PathID == pathID {
			return item
		}
	}
	t.Fatalf("path_id %q not found in %+v", pathID, paths)
	return ActionPath{}
}

func containsReason(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

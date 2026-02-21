package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStory8DocsAndCommandAnchorsPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	requiredPaths := []string{
		"docs/commands/index.md",
		"docs/commands/root.md",
		"docs/commands/init.md",
		"docs/commands/scan.md",
		"docs/commands/report.md",
		"docs/commands/export.md",
		"docs/commands/identity.md",
		"docs/commands/lifecycle.md",
		"docs/commands/manifest.md",
		"docs/commands/regress.md",
		"docs/commands/score.md",
		"docs/commands/verify.md",
		"docs/commands/evidence.md",
		"docs/commands/fix.md",
		"docs/examples/quickstart.md",
		"docs/examples/operator-playbooks.md",
		"scripts/check_docs_cli_parity.sh",
		"scripts/check_docs_storyline.sh",
		"scripts/run_docs_smoke.sh",
		"scripts/run_v1_acceptance.sh",
	}
	for _, rel := range requiredPaths {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("missing Story 8 contract path %s: %v", rel, err)
		}
	}
}

func TestStory8ManifestSpecFieldsAndSchemaProfileCoverage(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	specPath := filepath.Join(repoRoot, "docs", "specs", "wrkr-manifest.md")
	schemaPath := filepath.Join(repoRoot, "schemas", "v1", "manifest", "manifest.schema.json")

	specPayload, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read manifest spec: %v", err)
	}
	specText := string(specPayload)
	for _, token := range []string{"approved_tools", "blocked_tools", "review_pending_tools", "policy_constraints", "permission_scopes", "approver_metadata", "spec_version"} {
		if !strings.Contains(specText, token) {
			t.Fatalf("manifest spec missing canonical token %q", token)
		}
	}

	schemaPayload, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read manifest schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaPayload, &schema); err != nil {
		t.Fatalf("parse manifest schema: %v", err)
	}
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("manifest schema missing $defs object")
	}
	for _, key := range []string{"identityProfile", "policyProfile", "policyConstraint", "permissionScope", "approverMetadata"} {
		if _, exists := defs[key]; !exists {
			t.Fatalf("manifest schema missing %s definition", key)
		}
	}
}

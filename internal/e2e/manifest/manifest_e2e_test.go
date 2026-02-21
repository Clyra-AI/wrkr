package manifeste2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/core/manifest"
)

func TestE2EManifestGenerateUnderReviewAndSchemaArtifacts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	runJSONOK(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	payload := runJSONOK(t, []string{"manifest", "generate", "--state", statePath, "--json"})
	if payload["status"] != "ok" {
		t.Fatalf("unexpected manifest generate payload: %v", payload)
	}
	manifestPathValue, _ := payload["manifest_path"].(string)
	if filepath.Clean(manifestPathValue) != filepath.Clean(manifest.ResolvePath(statePath)) {
		t.Fatalf("manifest path mismatch: got %q want %q", manifestPathValue, manifest.ResolvePath(statePath))
	}

	generated, err := manifest.Load(manifest.ResolvePath(statePath))
	if err != nil {
		t.Fatalf("load generated manifest: %v", err)
	}
	if len(generated.Identities) == 0 {
		t.Fatal("expected generated identities")
	}
	for _, record := range generated.Identities {
		if record.Status != "under_review" {
			t.Fatalf("expected under_review state, got %q for %s", record.Status, record.AgentID)
		}
		if record.ApprovalState != "missing" {
			t.Fatalf("expected missing approval_status, got %q for %s", record.ApprovalState, record.AgentID)
		}
	}

	schemaPath := filepath.Join(repoRoot, "schemas", "v1", "manifest", "manifest.schema.json")
	payloadBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(payloadBytes, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	if _, ok := schema["oneOf"].([]any); !ok {
		t.Fatalf("manifest schema missing oneOf profile contract: %v", schema)
	}
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("manifest schema missing $defs map")
	}
	for _, def := range []string{"identityProfile", "policyProfile"} {
		if _, exists := defs[def]; !exists {
			t.Fatalf("manifest schema missing %s definition", def)
		}
	}
}

func TestE2EManifestApprovalWorkflowAlignment(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	runJSONOK(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	runJSONOK(t, []string{"manifest", "generate", "--state", statePath, "--json"})

	generated, err := manifest.Load(manifest.ResolvePath(statePath))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if len(generated.Identities) == 0 {
		t.Fatal("expected at least one generated identity")
	}
	agentID := strings.TrimSpace(generated.Identities[0].AgentID)
	if agentID == "" {
		t.Fatalf("generated identity missing agent_id: %+v", generated.Identities[0])
	}

	runJSONOK(t, []string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"})
	updated, err := manifest.Load(manifest.ResolvePath(statePath))
	if err != nil {
		t.Fatalf("load updated manifest: %v", err)
	}

	foundApproved := false
	for _, record := range updated.Identities {
		if record.AgentID != agentID {
			continue
		}
		foundApproved = true
		if record.Status != "approved" {
			t.Fatalf("expected approved status after manual approval, got %q", record.Status)
		}
		if record.ApprovalState != "valid" {
			t.Fatalf("expected valid approval status after manual approval, got %q", record.ApprovalState)
		}
	}
	if !foundApproved {
		t.Fatalf("approved identity %s not found", agentID)
	}
}

func runJSONOK(t *testing.T, args []string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run(args, &out, &errOut); code != 0 {
		t.Fatalf("command %v failed: %d (%s)", args, code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected empty stderr for %v, got %q", args, errOut.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse json payload for %v: %v (%q)", args, err, out.String())
	}
	return payload
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not locate repo root")
		}
		wd = next
	}
}

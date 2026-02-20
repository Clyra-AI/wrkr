package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestStory4SchemasPresent(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	required := []string{
		"schemas/v1/proof-outputs/proof-chain.schema.json",
		"schemas/v1/proof-outputs/proof-record.schema.json",
		"schemas/v1/evidence/evidence-bundle.schema.json",
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("expected schema %s: %v", rel, err)
		}
	}
}

func TestScanEmitsSignedProofRecordsWithCanonicalKeys(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}

	chainPath := filepath.Join(filepath.Dir(statePath), "proof-chain.json")
	payload, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("read proof chain: %v", err)
	}
	var chain map[string]any
	if err := json.Unmarshal(payload, &chain); err != nil {
		t.Fatalf("parse proof chain: %v", err)
	}
	records, ok := chain["records"].([]any)
	if !ok || len(records) == 0 {
		t.Fatalf("expected proof chain records, got %v", chain)
	}
	seenCanonical := map[string]struct{}{}
	for _, raw := range records {
		record, castOK := raw.(map[string]any)
		if !castOK {
			continue
		}
		integrity, _ := record["integrity"].(map[string]any)
		if signature, _ := integrity["signature"].(string); signature == "" {
			t.Fatalf("expected signed proof record, got %v", record)
		}
		if recordType, _ := record["record_type"].(string); recordType == "scan_finding" {
			metadata, _ := record["metadata"].(map[string]any)
			canonical, _ := metadata["canonical_finding_key"].(string)
			if canonical == "" {
				t.Fatalf("scan_finding record missing canonical_finding_key metadata: %v", record)
			}
			if _, exists := seenCanonical[canonical]; exists {
				t.Fatalf("duplicate canonical_finding_key emitted: %s", canonical)
			}
			seenCanonical[canonical] = struct{}{}
		}
	}
}

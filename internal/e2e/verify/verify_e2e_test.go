package verifye2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EVerifyChainSuccessAndTamper(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	if code := cli.Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify failed: %d (%s)", code, verifyErr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(verifyOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse verify output: %v", err)
	}
	chain, _ := payload["chain"].(map[string]any)
	if chain["intact"] != true {
		t.Fatalf("expected intact chain, got %v", chain)
	}

	chainPath := filepath.Join(filepath.Dir(statePath), "proof-chain.json")
	chainPayload, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var chainJSON map[string]any
	if err := json.Unmarshal(chainPayload, &chainJSON); err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	records := chainJSON["records"].([]any)
	first := records[0].(map[string]any)
	integrity := first["integrity"].(map[string]any)
	integrity["record_hash"] = "sha256:tampered"
	mutated, err := json.MarshalIndent(chainJSON, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered chain: %v", err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(chainPath, mutated, 0o600); err != nil {
		t.Fatalf("write tampered chain: %v", err)
	}

	verifyOut.Reset()
	verifyErr.Reset()
	if code := cli.Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr); code != 2 {
		t.Fatalf("expected exit 2 after tamper, got %d (%s)", code, verifyErr.String())
	}
}

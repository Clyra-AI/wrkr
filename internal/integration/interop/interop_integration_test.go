package interop

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	verifycore "github.com/Clyra-AI/wrkr/core/verify"
	"gopkg.in/yaml.v3"
)

type fixtureRecord struct {
	SourceProduct string         `json:"source_product"`
	RecordType    string         `json:"record_type"`
	Event         map[string]any `json:"event"`
}

func TestIntegrationCrossProductProofInterop(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	fixturePath := filepath.Join(repoRoot, "scenarios", "cross-product", "proof-record-interop", "records-from-all-3.jsonl")
	expectedPath := filepath.Join(repoRoot, "scenarios", "cross-product", "proof-record-interop", "expected.yaml")

	records := loadFixtureRecords(t, fixturePath)
	if len(records) < 3 {
		t.Fatalf("expected at least 3 fixture records, got %d", len(records))
	}

	sourceProducts := map[string]struct{}{}
	agentIDs := map[string]struct{}{}
	for _, record := range records {
		sourceProducts[strings.TrimSpace(record.SourceProduct)] = struct{}{}
		agentID, _ := record.Event["agent_id"].(string)
		if strings.TrimSpace(agentID) != "" {
			agentIDs[strings.TrimSpace(agentID)] = struct{}{}
		}
	}
	if len(agentIDs) != 1 {
		t.Fatalf("expected single agent_id across fixture records, got %v", keys(agentIDs))
	}
	if len(sourceProducts) != 3 {
		t.Fatalf("expected 3 source products, got %v", keys(sourceProducts))
	}

	chain := proof.NewChain("wrkr-proof")
	for i, item := range records {
		record, err := proof.NewRecord(proof.RecordOpts{
			Timestamp:     time.Date(2026, 2, 21, 12, 0, i, 0, time.UTC),
			Source:        "scenario",
			SourceProduct: item.SourceProduct,
			Type:          item.RecordType,
			Event:         item.Event,
			Controls:      proof.Controls{PermissionsEnforced: true},
		})
		if err != nil {
			t.Fatalf("new record %d: %v", i, err)
		}
		if err := proof.AppendToChain(chain, record); err != nil {
			t.Fatalf("append record %d: %v", i, err)
		}
	}

	tmp := t.TempDir()
	chainPath := filepath.Join(tmp, "chain.json")
	writeChain(t, chainPath, chain)

	result, err := verifycore.Chain(chainPath)
	if err != nil {
		t.Fatalf("verify mixed chain: %v", err)
	}
	if !result.Intact {
		t.Fatalf("expected mixed chain to verify intact, got %+v", result)
	}

	expected := loadExpectedInterop(t, expectedPath)
	if strings.TrimSpace(expected["chain"].(string)) != "intact" {
		t.Fatalf("unexpected expected.yaml chain contract: %v", expected)
	}
}

func loadFixtureRecords(t *testing.T, path string) []fixtureRecord {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = file.Close() }()

	out := make([]fixtureRecord, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record fixtureRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("parse jsonl line %q: %v", line, err)
		}
		out = append(out, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	return out
}

func loadExpectedInterop(t *testing.T, path string) map[string]any {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read expected yaml: %v", err)
	}
	out := map[string]any{}
	if err := yaml.Unmarshal(payload, &out); err != nil {
		t.Fatalf("parse expected yaml: %v", err)
	}
	return out
}

func writeChain(t *testing.T, path string, chain *proof.Chain) {
	t.Helper()

	payload, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write chain: %v", err)
	}
}

func keys(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not find repo root")
		}
		wd = next
	}
}

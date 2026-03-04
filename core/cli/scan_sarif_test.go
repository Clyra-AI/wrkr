package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScanSARIFModeDoesNotAlterNativeOutput(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	tmp := t.TempDir()
	stateA := filepath.Join(tmp, "state-a.json")
	stateB := filepath.Join(tmp, "state-b.json")
	sarifPath := filepath.Join(tmp, "wrkr.sarif")

	var outA bytes.Buffer
	var errA bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", stateA, "--json"}, &outA, &errA); code != 0 {
		t.Fatalf("baseline scan failed: code=%d stderr=%s", code, errA.String())
	}
	var payloadA map[string]any
	if err := json.Unmarshal(outA.Bytes(), &payloadA); err != nil {
		t.Fatalf("parse baseline scan payload: %v", err)
	}

	var outB bytes.Buffer
	var errB bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", stateB, "--sarif", "--sarif-path", sarifPath, "--json"}, &outB, &errB); code != 0 {
		t.Fatalf("sarif scan failed: code=%d stderr=%s", code, errB.String())
	}
	var payloadB map[string]any
	if err := json.Unmarshal(outB.Bytes(), &payloadB); err != nil {
		t.Fatalf("parse sarif scan payload: %v", err)
	}

	if _, present := payloadB["sarif"]; !present {
		t.Fatalf("expected sarif metadata in payload, got %v", payloadB)
	}
	if !reflect.DeepEqual(payloadA["findings"], payloadB["findings"]) {
		t.Fatal("expected SARIF mode to preserve native findings output")
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("read sarif output: %v", err)
	}
	var sarifEnvelope map[string]any
	if err := json.Unmarshal(data, &sarifEnvelope); err != nil {
		t.Fatalf("parse sarif output json: %v", err)
	}
	if sarifEnvelope["version"] != "2.1.0" {
		t.Fatalf("expected sarif version 2.1.0, got %v", sarifEnvelope["version"])
	}
}

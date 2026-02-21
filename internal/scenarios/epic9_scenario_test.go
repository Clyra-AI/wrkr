//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestScenarioEpic9DeterministicShareableReportsAC21(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	mdA := filepath.Join(tmp, "summary-a.md")
	mdB := filepath.Join(tmp, "summary-b.md")
	pdfA := filepath.Join(tmp, "summary-a.pdf")
	pdfB := filepath.Join(tmp, "summary-b.pdf")
	publicMD := filepath.Join(tmp, "summary-public.md")

	_ = runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})

	first := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--md", "--md-path", mdA, "--pdf", "--pdf-path", pdfA, "--template", "operator", "--share-profile", "internal", "--json"})
	second := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--md", "--md-path", mdB, "--pdf", "--pdf-path", pdfB, "--template", "operator", "--share-profile", "internal", "--json"})

	normalizedFirst := normalizeScenarioVolatile(first)
	normalizedSecond := normalizeScenarioVolatile(second)
	if !reflect.DeepEqual(normalizedFirst, normalizedSecond) {
		t.Fatalf("deterministic report payload mismatch\nfirst=%v\nsecond=%v", normalizedFirst, normalizedSecond)
	}

	mdABytes, err := os.ReadFile(mdA)
	if err != nil {
		t.Fatalf("read first markdown output: %v", err)
	}
	mdBBytes, err := os.ReadFile(mdB)
	if err != nil {
		t.Fatalf("read second markdown output: %v", err)
	}
	if string(mdABytes) != string(mdBBytes) {
		t.Fatal("expected deterministic markdown report output")
	}

	pdfABytes, err := os.ReadFile(pdfA)
	if err != nil {
		t.Fatalf("read first pdf output: %v", err)
	}
	pdfBBytes, err := os.ReadFile(pdfB)
	if err != nil {
		t.Fatalf("read second pdf output: %v", err)
	}
	if string(pdfABytes) != string(pdfBBytes) {
		t.Fatal("expected deterministic pdf report output")
	}

	summary, ok := first["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", first["summary"])
	}
	proof, ok := summary["proof"].(map[string]any)
	if !ok {
		t.Fatalf("expected proof object, got %T", summary["proof"])
	}
	for _, key := range []string{"chain_path", "head_hash", "record_count", "record_type_counts", "canonical_finding_keys"} {
		if _, present := proof[key]; !present {
			t.Fatalf("proof summary missing %q: %v", key, proof)
		}
	}

	publicPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--md", "--md-path", publicMD, "--template", "public", "--share-profile", "public", "--json"})
	publicSummary, _ := publicPayload["summary"].(map[string]any)
	publicProof, _ := publicSummary["proof"].(map[string]any)
	if publicProof["chain_path"] != "redacted://proof-chain.json" {
		t.Fatalf("expected public proof chain path redaction, got %v", publicProof["chain_path"])
	}
}

func TestScenarioEpic9SummaryIntegrationHooksAC10AC11(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	scanSummaryPath := filepath.Join(tmp, "scan-summary.md")
	baselinePath := filepath.Join(tmp, "baseline.json")
	regressSummaryPath := filepath.Join(tmp, "regress-summary.md")
	lifecycleSummaryPath := filepath.Join(tmp, "lifecycle-summary.md")
	evidenceOut := filepath.Join(tmp, "evidence")

	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--report-md", "--report-md-path", scanSummaryPath, "--report-template", "operator", "--json"})
	reportBlock, ok := scanPayload["report"].(map[string]any)
	if !ok || reportBlock["md_path"] != scanSummaryPath {
		t.Fatalf("scan summary hook missing expected md path: %v", scanPayload)
	}

	_ = runScenarioCommandJSON(t, []string{"regress", "init", "--baseline", statePath, "--output", baselinePath, "--json"})
	regressPayload := runScenarioCommandJSONAllowExit5(t, []string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--summary-md", "--summary-md-path", regressSummaryPath, "--template", "operator", "--json"})
	if regressPayload["summary_md_path"] != regressSummaryPath {
		t.Fatalf("regress summary hook missing expected md path: %v", regressPayload)
	}
	if _, err := os.Stat(regressSummaryPath); err != nil {
		t.Fatalf("expected regress summary markdown artifact: %v", err)
	}

	lifecyclePayload := runScenarioCommandJSON(t, []string{"lifecycle", "--state", statePath, "--summary-md", "--summary-md-path", lifecycleSummaryPath, "--template", "audit", "--json"})
	if lifecyclePayload["summary_md_path"] != lifecycleSummaryPath {
		t.Fatalf("lifecycle summary hook missing expected md path: %v", lifecyclePayload)
	}

	evidencePayload := runScenarioCommandJSON(t, []string{"evidence", "--frameworks", "soc2", "--state", statePath, "--output", evidenceOut, "--json"})
	reportArtifacts, ok := evidencePayload["report_artifacts"].([]any)
	if !ok || len(reportArtifacts) == 0 {
		t.Fatalf("evidence payload missing report_artifacts: %v", evidencePayload)
	}
	firstArtifact, _ := reportArtifacts[0].(string)
	if _, err := os.Stat(firstArtifact); err != nil {
		t.Fatalf("expected evidence report artifact to exist: %s (%v)", firstArtifact, err)
	}
}

func runScenarioCommandJSON(t *testing.T, args []string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run(args, &out, &errOut); code != 0 {
		t.Fatalf("command failed: %v code=%d stderr=%s", args, code, errOut.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse command json output for %v: %v", args, err)
	}
	return payload
}

func runScenarioCommandJSONAllowExit5(t *testing.T, args []string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run(args, &out, &errOut)
	if code != 0 && code != 5 {
		t.Fatalf("command failed: %v code=%d stderr=%s", args, code, errOut.String())
	}
	if out.Len() == 0 {
		t.Fatalf("expected JSON output on stdout for %v", args)
	}
	payload := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse command json output for %v: %v", args, err)
	}
	return payload
}

func normalizeScenarioVolatile(input map[string]any) map[string]any {
	normalized := map[string]any{}
	for key, value := range input {
		switch key {
		case "generated_at", "md_path", "pdf_path":
			continue
		default:
			normalized[key] = normalizeScenarioAny(value)
		}
	}
	return normalized
}

func normalizeScenarioAny(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, v := range typed {
			if strings.HasSuffix(k, "_path") || k == "generated_at" {
				continue
			}
			out[k] = normalizeScenarioAny(v)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeScenarioAny(item))
		}
		return out
	default:
		return typed
	}
}

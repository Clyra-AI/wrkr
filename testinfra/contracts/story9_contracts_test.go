package contracts

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

func TestStory9ReportSchemaAndDeterministicSectionContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	schemaPath := filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json")
	schemaPayload, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read report schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaPayload, &schema); err != nil {
		t.Fatalf("parse report schema json: %v", err)
	}
	if _, ok := schema["$defs"].(map[string]any); !ok {
		t.Fatal("report schema missing $defs")
	}

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed with exit %d", code)
	}

	first := runReportJSON(t, statePath, []string{"--template", "operator", "--share-profile", "internal", "--top", "5"})
	second := runReportJSON(t, statePath, []string{"--template", "operator", "--share-profile", "internal", "--top", "5"})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("report output must be deterministic for fixed state\nfirst=%v\nsecond=%v", first, second)
	}

	summary, ok := first["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object in report payload, got %T", first["summary"])
	}
	order, ok := summary["section_order"].([]any)
	if !ok {
		t.Fatalf("expected section_order array, got %T", summary["section_order"])
	}
	if len(order) != 6 {
		t.Fatalf("expected six section ids, got %d", len(order))
	}
	sections, ok := summary["sections"].([]any)
	if !ok || len(sections) != 6 {
		t.Fatalf("expected six sections, got %T len=%d", summary["sections"], len(sections))
	}
	for _, item := range sections {
		section, ok := item.(map[string]any)
		if !ok {
			continue
		}
		proof, ok := section["proof"].(map[string]any)
		if !ok {
			t.Fatalf("section missing proof block: %v", section)
		}
		for _, key := range []string{"chain_path", "head_hash", "record_count", "record_type_counts", "canonical_finding_keys"} {
			if _, present := proof[key]; !present {
				t.Fatalf("section proof missing key %s: %v", key, proof)
			}
		}
	}
}

func TestStory9PublicShareSanitizationContract(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed with exit %d", code)
	}

	payload := runReportJSON(t, statePath, []string{"--template", "public", "--share-profile", "public", "--top", "5"})
	findings, ok := payload["top_findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected top_findings array, got %T", payload["top_findings"])
	}
	firstFinding, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected finding shape: %T", findings[0])
	}
	findingBody, ok := firstFinding["finding"].(map[string]any)
	if !ok {
		t.Fatalf("expected finding object: %v", firstFinding)
	}
	location, _ := findingBody["location"].(string)
	if strings.Contains(location, "/") || strings.Contains(location, "\\") {
		t.Fatalf("public share location must be redacted, got %q", location)
	}

	summary, _ := payload["summary"].(map[string]any)
	proof, _ := summary["proof"].(map[string]any)
	chainPath, _ := proof["chain_path"].(string)
	if chainPath != "redacted://proof-chain.json" {
		t.Fatalf("expected redacted public proof chain path, got %q", chainPath)
	}
}

func TestStory9IntegratedSummaryArtifactHooks(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	scanSummaryPath := filepath.Join(tmp, "scan-summary.md")

	scanPayload := runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", statePath, "--report-md", "--report-md-path", scanSummaryPath, "--report-template", "operator", "--json"})
	reportBlock, ok := scanPayload["report"].(map[string]any)
	if !ok {
		t.Fatalf("scan payload missing report block: %v", scanPayload)
	}
	if reportBlock["md_path"] != scanSummaryPath {
		t.Fatalf("unexpected scan report path: %v", reportBlock["md_path"])
	}
	if _, err := os.Stat(scanSummaryPath); err != nil {
		t.Fatalf("expected scan summary artifact at %s: %v", scanSummaryPath, err)
	}

	baselinePath := filepath.Join(tmp, "baseline.json")
	_ = runJSONCommand(t, []string{"regress", "init", "--baseline", statePath, "--output", baselinePath, "--json"})
	regressSummaryPath := filepath.Join(tmp, "regress-summary.md")
	regressPayload := runJSONCommand(t, []string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--summary-md", "--summary-md-path", regressSummaryPath, "--json"})
	if regressPayload["summary_md_path"] != regressSummaryPath {
		t.Fatalf("unexpected regress summary path: %v", regressPayload["summary_md_path"])
	}

	lifecycleSummaryPath := filepath.Join(tmp, "lifecycle-summary.md")
	lifecyclePayload := runJSONCommand(t, []string{"lifecycle", "--state", statePath, "--summary-md", "--summary-md-path", lifecycleSummaryPath, "--json"})
	if lifecyclePayload["summary_md_path"] != lifecycleSummaryPath {
		t.Fatalf("unexpected lifecycle summary path: %v", lifecyclePayload["summary_md_path"])
	}

	evidenceDir := filepath.Join(tmp, "evidence")
	evidencePayload := runJSONCommand(t, []string{"evidence", "--frameworks", "soc2", "--state", statePath, "--output", evidenceDir, "--json"})
	reportArtifacts, ok := evidencePayload["report_artifacts"].([]any)
	if !ok || len(reportArtifacts) == 0 {
		t.Fatalf("expected report_artifacts in evidence payload: %v", evidencePayload)
	}
	firstArtifact, _ := reportArtifacts[0].(string)
	if _, err := os.Stat(firstArtifact); err != nil {
		t.Fatalf("expected evidence report artifact path to exist: %s (%v)", firstArtifact, err)
	}
}

func runReportJSON(t *testing.T, statePath string, extraArgs []string) map[string]any {
	t.Helper()
	args := []string{"report", "--state", statePath, "--json"}
	args = append(args, extraArgs...)
	return runJSONCommand(t, args)
}

func runJSONCommand(t *testing.T, args []string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run(args, &out, &errOut)
	if code != 0 {
		t.Fatalf("command %v failed with exit %d stderr=%s", args, code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload for %v: %v", args, err)
	}
	return payload
}

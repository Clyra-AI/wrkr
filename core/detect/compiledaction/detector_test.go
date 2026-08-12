package compiledaction

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/workflowcap"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectCompiledActionDerivesWorkflowCapabilities(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "release.yml"), []byte(`name: release
on:
  pull_request:
    branches: [main]
permissions:
  contents: write
  pull-requests: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto "$PR_URL"
      - run: terraform apply -auto-approve
      - run: kubectl apply -f k8s/
`), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect compiled action: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
	for _, permission := range []string{"repo.write", "pull_request.write", "merge.execute", "deploy.write", "iac.write"} {
		if !containsPermission(findings[0].Permissions, permission) {
			t.Fatalf("expected permission %q in %+v", permission, findings[0].Permissions)
		}
	}
	if evidenceValue(findings[0], "workflow_capability.iac.write") == "" {
		t.Fatalf("expected iac capability evidence, got %+v", findings[0].Evidence)
	}
}

func TestDetectCompiledActionDoesNotDuplicateCatalogParseError(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "bad.yml"), []byte("jobs:\n  release:\n    steps: ["), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect compiled action: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("compiled-action projection must not duplicate the catalog-owned parser outcome, got %+v", findings)
	}
}

func TestDetectStandaloneCompiledActionsAndScripts(t *testing.T) {
	root := t.TempDir()
	writeCompiledAction(t, root, "agent-plans/release.agent-script.json", `{"steps":[{"tool":"gait.eval.script"}],"risk_classes":["release"],"approval_source":"security"}`)
	writeCompiledAction(t, root, "workflows/empty.json", `{}`)
	writeCompiledAction(t, root, ".claude/scripts/release.sh", "#!/bin/sh\necho release\n")

	detector := New()
	if detector.ID() != detectorID {
		t.Fatalf("unexpected detector id %q", detector.ID())
	}
	findings, err := detector.Detect(context.Background(), detect.Scope{Repo: "service", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect standalone actions: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected script and compiled action findings, got %+v", findings)
	}
	if findings[0].Org != "local" && findings[1].Org != "local" {
		t.Fatalf("expected local org fallback, got %+v", findings)
	}
	foundEval := false
	for _, finding := range findings {
		if evidenceValue(finding, "validation_requirement") == "review_eval_config" {
			foundEval = true
		}
	}
	if !foundEval {
		t.Fatalf("expected gait validation evidence, got %+v", findings)
	}
}

func TestDetectStandaloneParseErrorAndScopeBoundaries(t *testing.T) {
	root := t.TempDir()
	writeCompiledAction(t, root, "agent-plans/bad.agent-script.json", `{`)
	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "service", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect malformed action: %v", err)
	}
	if len(findings) != 1 || findings[0].FindingType != "parse_error" || findings[0].ParseError == nil {
		t.Fatalf("expected parse error finding, got %+v", findings)
	}
	if findings[0].ParseError.Format != "json" {
		t.Fatalf("unexpected parse error: %+v", findings[0].ParseError)
	}
	if findings, err := New().Detect(context.Background(), detect.Scope{Root: root, TargetMode: "my_setup"}, detect.Options{}); err != nil || len(findings) != 0 {
		t.Fatalf("local machine scope must be skipped: findings=%+v err=%v", findings, err)
	}
	if _, err := New().Detect(context.Background(), detect.Scope{Root: filepath.Join(root, "missing")}, detect.Options{}); err == nil {
		t.Fatal("expected invalid root failure")
	}
}

func TestCompiledActionHelpers(t *testing.T) {
	if !isEmptyAction(actionDoc{}) {
		t.Fatal("expected empty action")
	}
	if isEmptyAction(actionDoc{ToolSequence: []string{"codex"}}) {
		t.Fatal("expected non-empty action")
	}
	if !workflowResultRelevant(workflowcap.Result{ExecutionRelationships: []model.ExecutionRelationship{{Kind: "workflow_call"}}}) {
		t.Fatal("expected relationship to make workflow relevant")
	}
	if !workflowResultRelevant(workflowcap.Result{Evidence: []model.Evidence{{Key: "delivery_harness", Value: "compiled_action"}}}) {
		t.Fatal("expected delivery evidence to make workflow relevant")
	}
	if workflowResultRelevant(workflowcap.Result{Evidence: []model.Evidence{{Key: "other", Value: "value"}}}) {
		t.Fatal("unexpected relevant workflow")
	}
	if got := uniqueStrings([]string{"b", "", "a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected unique strings: %+v", got)
	}
	if uniqueStrings(nil) != nil || uniqueStrings([]string{" "}) != nil {
		t.Fatal("expected empty unique strings to be nil")
	}
}

func writeCompiledAction(t *testing.T, root, rel, payload string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
}

func containsPermission(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func evidenceValue(finding model.Finding, key string) string {
	for _, evidence := range finding.Evidence {
		if evidence.Key == key {
			return evidence.Value
		}
	}
	return ""
}

package ciagent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/workflowcap"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk/autonomy"
)

func TestDetectorProjectsCatalogSignalsAndCoverage(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, ".github/workflows/release.yml", `name: release
on: workflow_dispatch
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: codex --full-auto
        env:
          RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}
      - run: kubectl apply -f deploy/
`)

	detector := New()
	if detector.ID() != detectorID {
		t.Fatalf("unexpected detector id %q", detector.ID())
	}
	findings, err := detector.Detect(context.Background(), detect.Scope{Repo: "service", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
	if findings[0].Org != "local" || findings[0].CheckResult != model.CheckResultFail || findings[0].Severity != model.SeverityHigh {
		t.Fatalf("unexpected finding projection: %+v", findings[0])
	}
	coverage := detector.SurfaceCoverage(detect.Scope{Org: "acme", Repo: "service", Root: root}, detect.Options{})
	if len(coverage) != 1 || coverage[0].Surface != "ci_workflow:github_actions" || coverage[0].Parsed != 1 || coverage[0].Findings != 1 {
		t.Fatalf("unexpected surface coverage: %+v", coverage)
	}
}

func TestSurfaceCoverageKeepsRelationshipResolutionPerCallee(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWorkflow(t, root, "Jenkinsfile", "load 'vars/present.groovy'\nload 'vars/missing.groovy'\n")
	writeWorkflow(t, root, "vars/present.groovy", "def call() { sh 'echo present' }\n")
	catalog, err := workflowcap.BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	resolved := workflowcap.ResolveCatalogs([]workflowcap.CatalogScope{{Repo: "acme/service", Root: root, Catalog: catalog}})
	coverage := New().SurfaceCoverage(detect.Scope{Org: "acme", Repo: "service", Root: root}, detect.Options{WorkflowCatalogs: map[string]any{root: resolved[root]}})
	if len(coverage) != 2 || coverage[0].Surface != "ci_workflow:jenkins" || coverage[0].Resolved != 1 || coverage[0].Unresolved != 1 {
		t.Fatalf("each callee must retain its own resolution state: %+v", coverage)
	}
}

func TestDetectorReportsCatalogFailuresAndParseErrors(t *testing.T) {
	detector := New()
	coverage := detector.SurfaceCoverage(detect.Scope{Root: filepath.Join(t.TempDir(), "missing")}, detect.Options{})
	if len(coverage) != 1 || coverage[0].Unsupported != 1 {
		t.Fatalf("expected unavailable catalog receipt, got %+v", coverage)
	}

	root := t.TempDir()
	writeWorkflow(t, root, ".github/workflows/bad.yml", "jobs:\n  release:\n    steps: [")
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "acme", Repo: "service", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect malformed workflow: %v", err)
	}
	if len(findings) != 1 || findings[0].FindingType != "parse_error" {
		t.Fatalf("expected one parse error, got %+v", findings)
	}
	if findings[0].ParseError == nil || findings[0].ParseError.Detector != detectorID {
		t.Fatalf("expected normalized parse error, got %+v", findings[0].ParseError)
	}

	if _, err := detector.Detect(context.Background(), detect.Scope{Root: filepath.Join(root, "missing")}, detect.Options{}); err == nil {
		t.Fatal("expected invalid root failure")
	}
}

func TestDetectorReportsMalformedSharedSourceAndReconcilesCoverage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWorkflow(t, root, ".github/workflows/caller.yml", `name: caller
on: push
jobs:
  local:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/bad
`)
	writeWorkflow(t, root, ".github/actions/bad/action.yml", "name: bad\nruns: [")

	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "acme", Repo: "service", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	parseFindings := 0
	for _, finding := range findings {
		if finding.FindingType == "parse_error" && finding.Location == ".github/actions/bad/action.yml" {
			parseFindings++
		}
	}
	if parseFindings != 1 {
		t.Fatalf("expected one shared-source parse finding, got %+v", findings)
	}
	coverage := detector.SurfaceCoverage(detect.Scope{Org: "acme", Repo: "service", Root: root}, detect.Options{})
	for _, receipt := range coverage {
		if receipt.Surface == "ci_workflow:github_actions:shared_source" {
			if receipt.Partial != 1 || receipt.Findings != 1 {
				t.Fatalf("shared-source coverage must reconcile with emitted parse finding: %+v", receipt)
			}
			return
		}
	}
	t.Fatalf("missing shared-source coverage receipt: %+v", coverage)
}

func TestDetectorTreatsNonCompositeActionAsParsedOpaqueSource(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWorkflow(t, root, ".github/actions/verify/action.yaml", `name: verify
runs:
  using: node20
  main: dist/index.js
`)

	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "acme", Repo: "service", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("valid opaque action must not emit a parser finding: %+v", findings)
	}
	coverage := detector.SurfaceCoverage(detect.Scope{Org: "acme", Repo: "service", Root: root}, detect.Options{})
	if len(coverage) != 1 || coverage[0].Surface != "ci_workflow:github_actions:shared_source" || coverage[0].Parsed != 1 || coverage[0].Partial != 0 {
		t.Fatalf("valid opaque action must count as parsed shared-source coverage: %+v", coverage)
	}
}

func TestSurfaceCoverageTreatsResolverLimitAsUnresolved(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWorkflow(t, root, "Jenkinsfile", "load 'vars/a.groovy'\n")
	writeWorkflow(t, root, "vars/a.groovy", "load 'vars/b.groovy'\n")
	writeWorkflow(t, root, "vars/b.groovy", "load 'vars/a.groovy'\n")

	catalog, err := workflowcap.BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	resolved := workflowcap.ResolveCatalogs([]workflowcap.CatalogScope{{Repo: "acme/service", Root: root, Catalog: catalog}})
	coverage := New().SurfaceCoverage(detect.Scope{Org: "acme", Repo: "service", Root: root}, detect.Options{WorkflowCatalogs: map[string]any{root: resolved[root]}})
	if len(coverage) == 0 {
		t.Fatal("expected CI surface coverage")
	}
	for _, receipt := range coverage {
		if receipt.Unresolved > 0 {
			return
		}
	}
	t.Fatalf("resolver-limited relationship must reduce coverage instead of remaining resolved: %+v", coverage)
}

func TestCIProjectionHelpersCoverSeverityAndRelationshipStates(t *testing.T) {
	for input, want := range map[string]string{
		"kind|caller|callee|resolved_local":      "resolved_local",
		"kind|caller|callee|unsupported_dynamic": "unsupported_dynamic",
		"kind|caller|callee|contradictory":       "contradictory",
		"malformed":                              "unknown",
	} {
		if got := relationshipState(input); got != want {
			t.Fatalf("relationshipState(%q)=%q want %q", input, got, want)
		}
	}

	cases := []struct {
		name        string
		signals     autonomy.Signals
		level       string
		permissions []string
		want        string
	}{
		{name: "critical", signals: autonomy.Signals{Headless: true, HasSecretAccess: true, DangerousFlags: true}, level: autonomy.LevelHeadlessAuto, want: model.SeverityCritical},
		{name: "gated", level: autonomy.LevelHeadlessGate, want: model.SeverityMedium},
		{name: "copilot", level: autonomy.LevelCopilot, want: model.SeverityLow},
		{name: "deploy", permissions: []string{"deploy.write"}, want: model.SeverityHigh},
		{name: "merge", permissions: []string{"merge.execute"}, want: model.SeverityMedium},
		{name: "secret", permissions: []string{"secret.read"}, want: model.SeverityLow},
		{name: "none", want: model.SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := severityForWorkflow(tc.signals, tc.level, tc.permissions); got != tc.want {
				t.Fatalf("severity=%q want %q", got, tc.want)
			}
		})
	}
	if got := uniqueStrings([]string{"b", "", "a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected unique strings: %+v", got)
	}
	if uniqueStrings(nil) != nil || uniqueStrings([]string{" "}) != nil {
		t.Fatal("expected empty input to normalize to nil")
	}
	if boolString(true) != "true" || boolString(false) != "false" {
		t.Fatal("unexpected bool string")
	}
}

func writeWorkflow(t *testing.T, root, rel, payload string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
}

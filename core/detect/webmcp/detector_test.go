package webmcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectWebMCPDeclarationsFromHTMLAndJS(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "ui/index.html", `<form tool-name="summarize"></form>`)
	writeFile(t, root, "ui/register.js", `navigator.modelContext.registerTool("classify", {description: "classifier"});`)
	writeFile(t, root, ".well-known/webmcp", `{"version":"1"}`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "web", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect webmcp: %v", err)
	}
	if count := countFindingType(findings, "webmcp_declaration"); count < 3 {
		t.Fatalf("expected at least 3 webmcp_declaration findings, got %d (%#v)", count, findings)
	}
	if !hasEvidencePair(findings, "declaration_method", "declarative_html") {
		t.Fatal("expected declarative_html evidence in webmcp findings")
	}
	if !hasEvidencePair(findings, "declaration_method", "imperative_js") {
		t.Fatal("expected imperative_js evidence in webmcp findings")
	}
}

func TestDetectWebMCPGatewayCoverageSignal(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "ui/register.js", `navigator.modelContext.registerTool("classify", {description: "classifier"});`)
	writeFile(t, root, "mcp-gateway.yaml", "gateway:\n  default_action: allow\n")

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "web", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect webmcp: %v", err)
	}
	finding := mustFindWebMCPFinding(t, findings)
	if coverage := evidenceValue(finding, "coverage"); coverage != "unprotected" {
		t.Fatalf("expected unprotected coverage, got %q", coverage)
	}
	if finding.Severity != model.SeverityHigh {
		t.Fatalf("expected high severity for unprotected declaration, got %q", finding.Severity)
	}
}

func TestDetectWebMCPParseErrorForInvalidJavaScript(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "ui/register.js", `navigator.modelContext.registerTool("classify"`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "web", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect webmcp: %v", err)
	}
	if count := countFindingType(findings, "parse_error"); count == 0 {
		t.Fatalf("expected parse_error finding for invalid JavaScript, got %#v", findings)
	}
}

func TestWebMCPParserRejectsRuntimeEvalPath(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	payload, err := os.ReadFile(filepath.Join(repoRoot, "core", "detect", "webmcp", "detector.go"))
	if err != nil {
		t.Fatalf("read detector source: %v", err)
	}
	source := string(payload)
	for _, forbidden := range []string{"goja.New(", ".RunString(", ".RunProgram(", "AssertFunction(", ".Call("} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("webmcp detector must remain AST-parse-only; found forbidden token %q", forbidden)
		}
	}
	if !strings.Contains(source, "goja/parser") || !strings.Contains(source, "goja/ast") {
		t.Fatal("expected parser-only goja imports for AST analysis")
	}
}

func mustFindWebMCPFinding(t *testing.T, findings []model.Finding) model.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.FindingType == "webmcp_declaration" {
			return finding
		}
	}
	t.Fatalf("expected webmcp_declaration finding, got %#v", findings)
	return model.Finding{}
}

func countFindingType(findings []model.Finding, findingType string) int {
	count := 0
	for _, finding := range findings {
		if finding.FindingType == findingType {
			count++
		}
	}
	return count
}

func hasEvidencePair(findings []model.Finding, key, value string) bool {
	for _, finding := range findings {
		for _, evidence := range finding.Evidence {
			if evidence.Key == key && evidence.Value == value {
				return true
			}
		}
	}
	return false
}

func evidenceValue(finding model.Finding, key string) string {
	for _, item := range finding.Evidence {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
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

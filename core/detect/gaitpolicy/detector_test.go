package gaitpolicy

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectRejectsExternalGaitPolicySymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outsideRoot := t.TempDir()
	outsidePath := filepath.Join(outsideRoot, "external.yaml")
	payload := strings.Join([]string{
		"rules:",
		"  - id: outside-only",
		"    block_tools:",
		"      - proc.exec",
		"    note: SHOULD_NOT_LEAK",
	}, "\n")
	if err := os.WriteFile(outsidePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write outside policy: %v", err)
	}
	mustSymlinkOrSkip(t, outsidePath, filepath.Join(root, ".gait", "external.yaml"))

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "repo", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect gait policy: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}

	finding := findings[0]
	if finding.FindingType != "parse_error" || finding.ToolType != "gait_policy" || finding.Location != ".gait/external.yaml" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.ParseError == nil || finding.ParseError.Kind != "unsafe_path" {
		t.Fatalf("expected unsafe_path parse error, got %#v", finding.ParseError)
	}
	if strings.Contains(finding.ParseError.Message, outsideRoot) || strings.Contains(finding.ParseError.Message, "SHOULD_NOT_LEAK") {
		t.Fatalf("parse error leaked outside details: %#v", finding.ParseError)
	}
}

func TestDetectReportsDirectAndGlobbedPoliciesDeterministically(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writePolicyFile(t, root, "gait.yaml", "rules:\n  - id: root\n    block_tools:\n      - mcp.access\n")
	writePolicyFile(t, root, "policies/in-root.yaml", "rules:\n  - id: in-root\n    deny_tools:\n      - proc.exec\n")
	mustSymlinkOrSkip(t, filepath.Join(root, "policies", "in-root.yaml"), filepath.Join(root, ".gait", "policy.yaml"))
	writePolicyFile(t, root, ".gait/custom.yaml", "rules:\n  - id: custom\n    blocked_tools:\n      - filesystem.write\n")
	writePolicyFile(t, root, ".gait/policies.yaml", "rules:\n  - id: broken\n    block_tools: [\n")
	mustSymlinkOrSkip(t, filepath.Join(root, ".gait", "missing.yaml"), filepath.Join(root, ".gait", "dangling.yaml"))

	first, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "repo", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect gait policy: %v", err)
	}
	second, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "repo", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect gait policy second run: %v", err)
	}
	if !reflect.DeepEqual(findingSignatures(first), findingSignatures(second)) {
		t.Fatalf("expected deterministic findings\nfirst=%v\nsecond=%v", findingSignatures(first), findingSignatures(second))
	}

	signatures := findingSignatures(first)
	want := []string{
		"parse_error|gait_policy|.gait/dangling.yaml|file_not_found",
		"parse_error|gait_policy|.gait/policies.yaml|parse_error",
		"tool_config|gait_policy|.gait/custom.yaml|blocked_tool_count=3",
		"tool_config|gait_policy|.gait/policy.yaml|blocked_tool_count=3",
		"tool_config|gait_policy|gait.yaml|blocked_tool_count=3",
	}
	if !reflect.DeepEqual(signatures, want) {
		t.Fatalf("unexpected signatures\nwant=%v\ngot=%v", want, signatures)
	}
}

func TestLoadBlockedToolsSkipsUnsafePolicyContents(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writePolicyFile(t, root, "gait.yaml", "rules:\n  - id: local\n    block_tools:\n      - proc.exec\n")

	outsideRoot := t.TempDir()
	outsidePath := filepath.Join(outsideRoot, "external.yaml")
	if err := os.WriteFile(outsidePath, []byte("rules:\n  - id: unsafe\n    block_tools:\n      - filesystem.write\n"), 0o600); err != nil {
		t.Fatalf("write outside policy: %v", err)
	}
	mustSymlinkOrSkip(t, outsidePath, filepath.Join(root, ".gait", "external.yaml"))

	loaded, err := LoadBlockedTools(root)
	if err != nil {
		t.Fatalf("load blocked tools: %v", err)
	}
	if len(loaded.PolicyFiles) != 1 || loaded.PolicyFiles[0] != "gait.yaml" {
		t.Fatalf("expected only safe gait.yaml to load, got %#v", loaded.PolicyFiles)
	}
	if len(loaded.ParseErrors) != 1 || loaded.ParseErrors[0].Kind != "unsafe_path" || loaded.ParseErrors[0].Path != ".gait/external.yaml" {
		t.Fatalf("expected unsafe parse error for external policy, got %#v", loaded.ParseErrors)
	}
	if got := loaded.BlockedTools["proc.exec"]; got != "gait.yaml:block_tools" {
		t.Fatalf("expected safe blocked tool provenance, got %q", got)
	}
	if _, exists := loaded.BlockedTools["filesystem.write"]; exists {
		t.Fatalf("expected external policy contents to be ignored, got %#v", loaded.BlockedTools)
	}
}

func writePolicyFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func mustSymlinkOrSkip(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir symlink parent: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}
}

func findingSignatures(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.FindingType == "parse_error" && finding.ParseError != nil {
			out = append(out, strings.Join([]string{
				finding.FindingType,
				finding.ToolType,
				finding.Location,
				finding.ParseError.Kind,
			}, "|"))
			continue
		}
		blockedToolCount := ""
		for _, evidence := range finding.Evidence {
			if evidence.Key == "blocked_tool_count" {
				blockedToolCount = evidence.Value
				break
			}
		}
		out = append(out, strings.Join([]string{
			finding.FindingType,
			finding.ToolType,
			finding.Location,
			"blocked_tool_count=" + blockedToolCount,
		}, "|"))
	}
	return out
}

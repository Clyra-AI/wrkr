package extension

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestExtensionRegistryDeterministicOrdering(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	descriptorDir := filepath.Join(root, ".wrkr", "detectors")
	if err := os.MkdirAll(descriptorDir, 0o755); err != nil {
		t.Fatalf("mkdir descriptor dir: %v", err)
	}
	payload := []byte(`{
  "version": "v1",
  "detectors": [
    {"id":"zeta","finding_type":"custom_zeta","tool_type":"custom_detector","location":".custom/zeta.yaml","severity":"low"},
    {"id":"alpha","finding_type":"custom_alpha","tool_type":"custom_detector","location":".custom/alpha.yaml","severity":"low"}
  ]
}`)
	if err := os.WriteFile(filepath.Join(descriptorDir, "extensions.json"), payload, 0o600); err != nil {
		t.Fatalf("write descriptors: %v", err)
	}

	scope := detect.Scope{Org: "acme", Repo: "backend", Root: root}
	first, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("first detect: %v", err)
	}
	second, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("second detect: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic output across runs\nfirst=%+v\nsecond=%+v", first, second)
	}
	if len(first) != 2 {
		t.Fatalf("expected 2 extension findings, got %d", len(first))
	}
	if first[0].FindingType != "custom_alpha" || first[1].FindingType != "custom_zeta" {
		t.Fatalf("expected deterministic finding ordering by normalized sort, got %+v", first)
	}
}

func TestInvalidExtensionDescriptorFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	descriptorDir := filepath.Join(root, ".wrkr", "detectors")
	if err := os.MkdirAll(descriptorDir, 0o755); err != nil {
		t.Fatalf("mkdir descriptor dir: %v", err)
	}
	payload := []byte(`{
  "version": "v1",
  "detectors": [
    {"id":"", "finding_type":"custom", "tool_type":"custom", "location":".custom/policy.yaml", "severity":"low"}
  ]
}`)
	if err := os.WriteFile(filepath.Join(descriptorDir, "extensions.json"), payload, 0o600); err != nil {
		t.Fatalf("write descriptors: %v", err)
	}

	scope := detect.Scope{Org: "acme", Repo: "backend", Root: root}
	_, err := New().Detect(context.Background(), scope, detect.Options{})
	if err == nil {
		t.Fatal("expected invalid extension descriptor to fail closed")
	}
	if got := err.Error(); got == "" || !containsAll(got, "invalid extension descriptor", "id is required") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestExtensionRegistryNormalizesSeverity(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	descriptorDir := filepath.Join(root, ".wrkr", "detectors")
	if err := os.MkdirAll(descriptorDir, 0o755); err != nil {
		t.Fatalf("mkdir descriptor dir: %v", err)
	}
	payload := []byte(`{
  "version": "v1",
  "detectors": [
    {"id":"alpha","finding_type":"custom_alpha","tool_type":"custom_detector","location":".custom/alpha.yaml","severity":"HIGH"}
  ]
}`)
	if err := os.WriteFile(filepath.Join(descriptorDir, "extensions.json"), payload, 0o600); err != nil {
		t.Fatalf("write descriptors: %v", err)
	}

	scope := detect.Scope{Org: "acme", Repo: "backend", Root: root}
	findings, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "high" {
		t.Fatalf("expected normalized severity high, got %q", findings[0].Severity)
	}
}

func containsAll(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			return false
		}
	}
	return true
}

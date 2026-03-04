package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
)

func TestSARIFEmitterBuildDeterministic(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "policy_violation",
			RuleID:      "WRKR-001",
			Severity:    model.SeverityHigh,
			ToolType:    "policy",
			Location:    ".wrkr/policy.yaml",
			Repo:        "backend",
			Org:         "acme",
			Detector:    "policy",
		},
		{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "codex",
			Location:    ".codex/config.toml",
			Repo:        "backend",
			Org:         "acme",
			Detector:    "codex",
		},
	}

	first := Build(findings, "v1.2.3")
	second := Build(findings, "v1.2.3")
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic SARIF build output\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.Version != version {
		t.Fatalf("unexpected SARIF version: %s", first.Version)
	}
	if first.Schema != schemaURL {
		t.Fatalf("unexpected SARIF schema url: %s", first.Schema)
	}
	if len(first.Runs) != 1 || len(first.Runs[0].Results) != 2 {
		t.Fatalf("unexpected SARIF run/result counts: %+v", first)
	}
}

func TestSARIFEmitterValidatesAgainstSchema(t *testing.T) {
	t.Parallel()

	report := Build([]model.Finding{
		{
			FindingType: "custom_extension_finding",
			Severity:    model.SeverityMedium,
			ToolType:    "custom_detector",
			Location:    ".custom/policy.yaml",
			Repo:        "ext-repo",
			Org:         "local",
			Detector:    "extension",
		},
	}, "devel")

	tmp := t.TempDir()
	path := filepath.Join(tmp, "wrkr.sarif")
	if err := Write(path, report); err != nil {
		t.Fatalf("write sarif: %v", err)
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sarif output: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("parse sarif output json: %v", err)
	}
	if envelope["version"] != version {
		t.Fatalf("unexpected sarif version in output: %v", envelope["version"])
	}
	if envelope["$schema"] != schemaURL {
		t.Fatalf("unexpected sarif schema URL: %v", envelope["$schema"])
	}
	runs, ok := envelope["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly one sarif run, got %v", envelope["runs"])
	}
}

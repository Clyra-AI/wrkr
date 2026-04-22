package scanquality

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestBuildScanQualityReportsGeneratedSuppressionAndParseErrors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "pkg", "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write package: %v", err)
	}

	report := Build(Input{
		Mode:   "governance",
		Scopes: []detect.Scope{{Org: "acme", Repo: "app", Root: root}},
		Findings: []model.Finding{{
			FindingType: "parse_error",
			Location:    "node_modules/pkg/package.json",
			Repo:        "app",
			Org:         "acme",
			ParseError:  &model.ParseError{Kind: "parse_error", Path: "node_modules/pkg/package.json", Detector: "dependency", Message: "broken"},
		}},
	})
	if report.ScanQualityVersion != ReportVersion {
		t.Fatalf("unexpected version: %s", report.ScanQualityVersion)
	}
	if len(report.SuppressedPaths) == 0 {
		t.Fatalf("expected suppressed generated/package path, got %+v", report)
	}
	if len(report.ParseErrors) != 1 || report.ParseErrors[0].Reason != "generated_or_package_noise" {
		t.Fatalf("expected generated parse issue, got %+v", report.ParseErrors)
	}
	if report.ParseErrors[0].RecommendedAction != "suppress" {
		t.Fatalf("expected suppress action for generated parse issue, got %+v", report.ParseErrors[0])
	}
}

func TestDeepModeDoesNotReportSuppressedPathSet(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dist"), 0o755); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}
	report := Build(Input{
		Mode:   "deep",
		Scopes: []detect.Scope{{Repo: "app", Root: root}},
	})
	if report.Mode != "deep" {
		t.Fatalf("expected deep mode, got %s", report.Mode)
	}
	if len(report.SuppressedPaths) != 0 {
		t.Fatalf("deep mode should not report generated suppression as active, got %+v", report.SuppressedPaths)
	}
}

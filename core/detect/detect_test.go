package detect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
)

type fakeDetector struct {
	id      string
	detectF func(scope Scope) ([]model.Finding, error)
}

func (f fakeDetector) ID() string { return f.id }

func (f fakeDetector) Detect(_ context.Context, scope Scope, _ Options) ([]model.Finding, error) {
	if f.detectF == nil {
		return nil, nil
	}
	return f.detectF(scope)
}

func TestRegistryRunDeterministicOrder(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	registry := NewRegistry()
	if err := registry.Register(fakeDetector{id: "b", detectF: func(scope Scope) ([]model.Finding, error) {
		return []model.Finding{{Severity: model.SeverityLow, FindingType: "b", ToolType: "b", Location: "2", Org: scope.Org, Repo: scope.Repo}}, nil
	}}); err != nil {
		t.Fatalf("register b: %v", err)
	}
	if err := registry.Register(fakeDetector{id: "a", detectF: func(scope Scope) ([]model.Finding, error) {
		return []model.Finding{{Severity: model.SeverityCritical, FindingType: "a", ToolType: "a", Location: "1", Org: scope.Org, Repo: scope.Repo}}, nil
	}}); err != nil {
		t.Fatalf("register a: %v", err)
	}

	result, err := registry.Run(context.Background(), []Scope{{Org: "o", Repo: "r", Root: root}}, Options{})
	if err != nil {
		t.Fatalf("run registry: %v", err)
	}
	if len(result.DetectorErrors) != 0 {
		t.Fatalf("expected no detector errors, got %+v", result.DetectorErrors)
	}
	findings := result.Findings
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].FindingType != "a" {
		t.Fatalf("expected severity sorting to put critical finding first, got %s", findings[0].FindingType)
	}
}

func TestRegistryContinuesOnDetectorError(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	registry := NewRegistry()
	if err := registry.Register(fakeDetector{id: "good", detectF: func(scope Scope) ([]model.Finding, error) {
		return []model.Finding{{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "codex",
			Location:    ".codex/config.toml",
			Org:         scope.Org,
			Repo:        scope.Repo,
			Detector:    "good",
		}}, nil
	}}); err != nil {
		t.Fatalf("register good: %v", err)
	}
	if err := registry.Register(fakeDetector{id: "bad", detectF: func(_ Scope) ([]model.Finding, error) {
		return nil, fmt.Errorf("read file: %w", os.ErrPermission)
	}}); err != nil {
		t.Fatalf("register bad: %v", err)
	}

	result, err := registry.Run(context.Background(), []Scope{{Org: "acme", Repo: "backend", Root: root}}, Options{})
	if err != nil {
		t.Fatalf("run registry: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected findings to be preserved, got %+v", result.Findings)
	}
	if len(result.DetectorErrors) != 1 {
		t.Fatalf("expected one detector error, got %+v", result.DetectorErrors)
	}
	detectorErr := result.DetectorErrors[0]
	if detectorErr.Detector != "bad" || detectorErr.Repo != "backend" || detectorErr.Org != "acme" {
		t.Fatalf("unexpected detector error context: %+v", detectorErr)
	}
	if detectorErr.Code != "permission_denied" || detectorErr.Class != "filesystem" {
		t.Fatalf("unexpected detector error classification: %+v", detectorErr)
	}
}

func TestRegistryScopeValidationIsSurfacedAndDeterministic(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	fileScope := root + "/not-a-dir.txt"
	if err := os.WriteFile(fileScope, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file scope: %v", err)
	}
	missingScope := root + "/missing"

	registry := NewRegistry()
	if err := registry.Register(fakeDetector{id: "noop", detectF: func(_ Scope) ([]model.Finding, error) { return nil, nil }}); err != nil {
		t.Fatalf("register noop: %v", err)
	}

	result, err := registry.Run(context.Background(), []Scope{
		{Org: "acme", Repo: "repo-b", Root: missingScope},
		{Org: "acme", Repo: "repo-a", Root: fileScope},
	}, Options{})
	if err != nil {
		t.Fatalf("run registry: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", result.Findings)
	}
	if len(result.DetectorErrors) != 2 {
		t.Fatalf("expected two scope errors, got %+v", result.DetectorErrors)
	}
	if result.DetectorErrors[0].Repo != "repo-a" || result.DetectorErrors[0].Detector != "scope" {
		t.Fatalf("expected deterministic sorting by repo/detector, got %+v", result.DetectorErrors)
	}
	if result.DetectorErrors[0].Code != "invalid_scope" && result.DetectorErrors[0].Code != "detector_error" {
		t.Fatalf("expected invalid scope classification, got %+v", result.DetectorErrors[0])
	}
	if result.DetectorErrors[1].Code != "path_not_found" {
		t.Fatalf("expected missing scope classification, got %+v", result.DetectorErrors[1])
	}
}

func TestRegistryReturnsContextCancellation(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	registry := NewRegistry()
	if err := registry.Register(fakeDetector{id: "cancel", detectF: func(_ Scope) ([]model.Finding, error) {
		return nil, context.Canceled
	}}); err != nil {
		t.Fatalf("register cancel detector: %v", err)
	}

	_, err := registry.Run(context.Background(), []Scope{{Org: "o", Repo: "r", Root: root}}, Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestRegistryRejectsDuplicateIDs(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	if err := registry.Register(fakeDetector{id: "dup"}); err != nil {
		t.Fatalf("unexpected first register error: %v", err)
	}
	if err := registry.Register(fakeDetector{id: "dup"}); err == nil {
		t.Fatal("expected duplicate register error")
	}
}

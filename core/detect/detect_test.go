package detect

import (
	"context"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
)

type fakeDetector struct {
	id       string
	findings []model.Finding
}

func (f fakeDetector) ID() string { return f.id }

func (f fakeDetector) Detect(_ context.Context, _ Scope, _ Options) ([]model.Finding, error) {
	return append([]model.Finding(nil), f.findings...), nil
}

func TestRegistryRunDeterministicOrder(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	if err := registry.Register(fakeDetector{id: "b", findings: []model.Finding{{Severity: model.SeverityLow, FindingType: "b", ToolType: "b", Location: "2", Org: "o"}}}); err != nil {
		t.Fatalf("register b: %v", err)
	}
	if err := registry.Register(fakeDetector{id: "a", findings: []model.Finding{{Severity: model.SeverityCritical, FindingType: "a", ToolType: "a", Location: "1", Org: "o"}}}); err != nil {
		t.Fatalf("register a: %v", err)
	}

	findings, err := registry.Run(context.Background(), []Scope{{Org: "o", Repo: "r", Root: "/tmp"}}, Options{})
	if err != nil {
		t.Fatalf("run registry: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].FindingType != "a" {
		t.Fatalf("expected severity sorting to put critical finding first, got %s", findings[0].FindingType)
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

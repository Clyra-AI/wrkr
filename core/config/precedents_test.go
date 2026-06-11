package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDecisionPrecedentsRejectsConflictingShape(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "decision-precedents.json")
	payload := []byte("{\n  \"schema_version\": \"v1\",\n  \"precedents\": [\n    {\n      \"precedent_key\": \"path:deploy\",\n      \"prior_decision\": \"approved\",\n      \"confidence\": \"high\",\n      \"decision_trace_ref\": \"decision_trace:trace-1\",\n      \"expires_at\": \"2026-07-01T00:00:00Z\"\n    },\n    {\n      \"precedent_key\": \"path:deploy\",\n      \"prior_decision\": \"blocked\",\n      \"confidence\": \"high\",\n      \"decision_trace_ref\": \"decision_trace:trace-2\"\n    }\n  ]\n}\n")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write precedent file: %v", err)
	}

	if _, err := LoadDecisionPrecedents(path); err == nil {
		t.Fatal("expected conflicting precedence shape to fail closed")
	}
}

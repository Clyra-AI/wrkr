package org

import (
	"path/filepath"
	"testing"
)

func TestTargetSetCheckpointRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	materializedRoot := filepath.Join(tmp, "materialized-sources")
	targets := []string{"beta", "acme"}

	if err := SaveTargetSet(statePath, targets, materializedRoot); err != nil {
		t.Fatalf("save target set: %v", err)
	}
	if err := ValidateTargetSet(statePath, []string{"acme", "beta"}, materializedRoot); err != nil {
		t.Fatalf("validate target set: %v", err)
	}
}

func TestTargetSetCheckpointMismatchFailsClosed(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	materializedRoot := filepath.Join(tmp, "materialized-sources")
	if err := SaveTargetSet(statePath, []string{"acme", "beta"}, materializedRoot); err != nil {
		t.Fatalf("save target set: %v", err)
	}
	if err := ValidateTargetSet(statePath, []string{"acme", "gamma"}, materializedRoot); err == nil {
		t.Fatal("expected target-set mismatch to fail")
	} else if !IsCheckpointInputError(err) {
		t.Fatalf("expected checkpoint input error, got %v", err)
	}
}

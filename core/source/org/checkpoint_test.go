package org

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/internal/managedmarker"
)

func TestCheckpointPathCreatesSignedManagedRoot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	path, err := checkpointPath(statePath, "acme")
	if err != nil {
		t.Fatalf("checkpoint path: %v", err)
	}
	root := filepath.Dir(path)
	payload, err := os.ReadFile(filepath.Join(root, checkpointMarkerFile))
	if err != nil {
		t.Fatalf("read checkpoint marker: %v", err)
	}
	if err := managedmarker.ValidatePayload(statePath, root, checkpointMarkerKind, payload); err != nil {
		t.Fatalf("expected signed checkpoint marker, got: %v", err)
	}
}

func TestCheckpointPathRejectsLegacyMarkerContent(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	root := filepath.Join(filepath.Dir(statePath), checkpointRootName)
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir checkpoint root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, checkpointMarkerFile), []byte(checkpointMarkerContent), 0o600); err != nil {
		t.Fatalf("write legacy checkpoint marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	_, err := checkpointPath(statePath, "acme")
	if err == nil {
		t.Fatal("expected legacy checkpoint marker to fail")
	}
	if !IsCheckpointSafetyError(err) {
		t.Fatalf("expected checkpoint safety error, got %v", err)
	}
}

func TestCheckpointErrorHelpersClassifyMissingAndSafety(t *testing.T) {
	t.Parallel()

	var nilInputErr *checkpointInputError
	if got := nilInputErr.Error(); got != "" {
		t.Fatalf("nil checkpoint input error should render empty text, got %q", got)
	}
	var nilSafetyErr *checkpointSafetyError
	if got := nilSafetyErr.Error(); got != "" {
		t.Fatalf("nil checkpoint safety error should render empty text, got %q", got)
	}

	inputErr := newCheckpointInputError("bad %s", "input")
	if got := inputErr.Error(); got != "bad input" {
		t.Fatalf("unexpected checkpoint input error text %q", got)
	}
	if !IsCheckpointInputError(inputErr) {
		t.Fatal("expected checkpoint input helper to classify input errors")
	}
	if IsCheckpointMissingError(inputErr) {
		t.Fatal("ordinary input errors must not classify as missing checkpoints")
	}

	missingErr := newCheckpointMissingError("missing %s", "checkpoint")
	if got := missingErr.Error(); got != "missing checkpoint" {
		t.Fatalf("unexpected checkpoint missing error text %q", got)
	}
	if !IsCheckpointInputError(missingErr) || !IsCheckpointMissingError(missingErr) {
		t.Fatal("expected missing checkpoint helper to classify as input and missing")
	}

	safetyErr := newCheckpointSafetyError("unsafe %s", "root")
	if got := safetyErr.Error(); got != "unsafe root" {
		t.Fatalf("unexpected checkpoint safety error text %q", got)
	}
	if !IsCheckpointSafetyError(safetyErr) {
		t.Fatal("expected safety helper to classify safety errors")
	}
	if IsCheckpointInputError(safetyErr) {
		t.Fatal("safety errors must not classify as checkpoint input errors")
	}
}

func TestCheckpointFileNameNormalizesOrgNames(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"":                 "org",
		" Acme/Team Repo ": "acme_team_repo",
		"Org.Name-1_id":    "org.name-1_id",
	}
	for input, want := range cases {
		if got := checkpointFileName(input); got != want {
			t.Fatalf("checkpoint file name for %q: got %q want %q", input, got, want)
		}
	}
}

func TestMaterializedLocationWithinRootRejectsEscapes(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "materialized")
	if err := os.MkdirAll(filepath.Join(root, "acme", "repo"), 0o750); err != nil {
		t.Fatalf("mkdir materialized tree: %v", err)
	}

	if !materializedLocationWithinRoot(root, root) {
		t.Fatal("managed root should be considered within itself")
	}
	if !materializedLocationWithinRoot(root, filepath.Join(root, "acme", "repo")) {
		t.Fatal("nested materialized repo should stay within the managed root")
	}
	if materializedLocationWithinRoot(root, filepath.Join(root, "..", "escape")) {
		t.Fatal("sibling path must not be considered within the managed root")
	}
}

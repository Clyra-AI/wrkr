package sourceprivacy

import (
	"path/filepath"
	"testing"
)

func TestInitialContractHostedDefaultsToEphemeralLogicalAndPendingCleanup(t *testing.T) {
	t.Parallel()

	contract := InitialContract("", true, false)
	if contract.RetentionMode != RetentionEphemeral {
		t.Fatalf("expected default ephemeral retention, got %s", contract.RetentionMode)
	}
	if contract.MaterializedSourceRetained {
		t.Fatal("expected hosted default to start as not retained")
	}
	if contract.RawSourceInArtifacts {
		t.Fatal("expected raw source artifact contract to remain false")
	}
	if contract.SerializedLocations != SerializedLocationsLogical {
		t.Fatalf("expected logical serialized locations, got %s", contract.SerializedLocations)
	}
	if contract.CleanupStatus != CleanupPending {
		t.Fatalf("expected pending cleanup, got %s", contract.CleanupStatus)
	}
}

func TestSanitizerRedactsMaterializedSourceRoots(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), ".wrkr", "materialized-sources", "acme", "backend")
	value := filepath.Join(root, ".codex", "config.toml")
	got := NewSanitizer(root).String(value)
	if ContainsMaterializedSourcePath(got) {
		t.Fatalf("expected materialized path to be redacted, got %s", got)
	}
	if got == value {
		t.Fatalf("expected sanitizer to modify materialized path %s", value)
	}
}

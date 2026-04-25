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

func TestSanitizerRedactsLegacyManagedMaterializedPath(t *testing.T) {
	t.Parallel()

	value := "/tmp/work/.wrkr/materialized-sources/acme/backend/.codex/config.toml"
	got := NewSanitizer().String(value)
	if got == value {
		t.Fatalf("expected legacy managed materialized path to be redacted")
	}
	if ContainsMaterializedSourcePath(got) {
		t.Fatalf("expected redacted output to omit managed materialized path markers, got %s", got)
	}
}

func TestSanitizerDoesNotRedactUnmanagedMaterializedSourcesSegment(t *testing.T) {
	t.Parallel()

	value := "/repo/docs/materialized-sources/reference.md"
	got := NewSanitizer().String(value)
	if got != value {
		t.Fatalf("expected unmanaged materialized-sources segment to remain unchanged, got %s", got)
	}
	if ContainsMaterializedSourcePath(value) {
		t.Fatalf("expected unmanaged path not to match managed materialized root detection")
	}
}

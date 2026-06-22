package report

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildArtifactMetadataIncludesSourceArtifactDigests(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "last-scan.json")
	payload := []byte(`{"summary":"stable source artifact"}` + "\n")
	if err := os.WriteFile(statePath, payload, 0o600); err != nil {
		t.Fatalf("write state artifact: %v", err)
	}
	sum := sha256.Sum256(payload)
	expectedDigest := "sha256:" + hex.EncodeToString(sum[:])

	summary := Summary{
		GeneratedAt:  "2026-06-21T20:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
	}
	metadata := BuildArtifactMetadata(summary, []string{statePath}, ArtifactVariantInternal, "pair-1", filepath.Join(tmp, "join.json"))
	if metadata == nil {
		t.Fatal("expected artifact metadata")
	}
	if len(metadata.SourceArtifactDigests) != 1 || metadata.SourceArtifactDigests[0] != expectedDigest {
		t.Fatalf("expected source digest %s, got %+v", expectedDigest, metadata.SourceArtifactDigests)
	}
	if len(metadata.SourceArtifactRefs) != 1 || metadata.SourceArtifactRefs[0] != statePath {
		t.Fatalf("expected internal source ref to remain cleartext, got %+v", metadata.SourceArtifactRefs)
	}

	redactedSummary := summary
	redactedSummary.ShareProfile = string(ShareProfileCustomerRedacted)
	redacted := BuildArtifactMetadata(redactedSummary, []string{statePath}, ArtifactVariantCustomerRedacted, "pair-1", filepath.Join(tmp, "join.json"))
	if redacted == nil {
		t.Fatal("expected redacted artifact metadata")
	}
	if len(redacted.SourceArtifactDigests) != 1 || redacted.SourceArtifactDigests[0] != expectedDigest {
		t.Fatalf("expected redacted metadata to preserve digest %s, got %+v", expectedDigest, redacted.SourceArtifactDigests)
	}
	if len(redacted.SourceArtifactRefs) != 1 || redacted.SourceArtifactRefs[0] == statePath {
		t.Fatalf("expected redacted source ref to be masked, got %+v", redacted.SourceArtifactRefs)
	}
	if redacted.PrivateJoinMapPath != "" {
		t.Fatalf("expected shareable metadata to omit private join-map path, got %q", redacted.PrivateJoinMapPath)
	}
}

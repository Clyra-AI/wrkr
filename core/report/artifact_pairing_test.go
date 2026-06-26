package report

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
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

func TestBuildPrivateJoinMapCarriesResolutionKeysAndEvidenceRefs(t *testing.T) {
	t.Parallel()

	internal := Summary{
		GeneratedAt:  "2026-06-25T18:00:00Z",
		ShareProfile: string(ShareProfileInternal),
		ActionPaths: []risk.ActionPath{{
			PathID:              "apc-internal",
			ResolutionKey:       "rk-internal",
			Repo:                "acme/payments",
			Location:            ".github/workflows/release.yml",
			ControlEvidenceRefs: []string{"evidence://internal/branch-protection"},
		}},
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{{
				PathID:              "apc-internal",
				ResolutionKey:       "rk-internal",
				Repo:                "acme/payments",
				Location:            ".github/workflows/release.yml",
				ControlEvidenceRefs: []string{"evidence://internal/branch-protection"},
				EvidenceRefs:        []string{"evidence://internal/customer-review"},
			}},
		},
	}
	external := Summary{
		GeneratedAt:  "2026-06-25T18:00:00Z",
		ShareProfile: string(ShareProfileCustomerRedacted),
		ActionPaths: []risk.ActionPath{{
			PathID:              "path-12345678",
			ResolutionKey:       "rk-internal",
			Repo:                "repo-123456",
			Location:            "path-abcdef12",
			ControlEvidenceRefs: []string{"evidence-12345678"},
		}},
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{{
				PathID:              "path-12345678",
				ResolutionKey:       "rk-internal",
				Repo:                "repo-123456",
				Location:            "path-abcdef12",
				ControlEvidenceRefs: []string{"evidence-12345678"},
				EvidenceRefs:        []string{"evidence-87654321"},
			}},
		},
	}

	joinMap := BuildPrivateJoinMap(internal, external, "pair-review-loop")
	if len(joinMap.Entries) == 0 {
		t.Fatalf("expected join-map entries, got %+v", joinMap)
	}
	if !containsJoinKind(joinMap.Entries, "resolution_key") {
		t.Fatalf("expected action-path resolution key entry, got %+v", joinMap.Entries)
	}
	if !containsJoinKind(joinMap.Entries, "bom_resolution_key") {
		t.Fatalf("expected BOM resolution key entry, got %+v", joinMap.Entries)
	}
	if !containsJoinKind(joinMap.Entries, "bom_control_evidence_ref") {
		t.Fatalf("expected BOM control evidence ref entry, got %+v", joinMap.Entries)
	}
}

func containsJoinKind(entries []ArtifactJoinEntry, kind string) bool {
	for _, entry := range entries {
		if entry.Kind == kind {
			return true
		}
	}
	return false
}

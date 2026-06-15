package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ArtifactVariantInternal         = "internal"
	ArtifactVariantCustomerRedacted = "customer_redacted"

	ArtifactShareabilityInternal  = "internal_only"
	ArtifactShareabilityShareable = "shareable"
)

type ArtifactJoinMap struct {
	PairID               string              `json:"pair_id"`
	GeneratedAt          string              `json:"generated_at"`
	InternalShareProfile string              `json:"internal_share_profile"`
	ExternalShareProfile string              `json:"external_share_profile"`
	Entries              []ArtifactJoinEntry `json:"entries,omitempty"`
}

type ArtifactJoinEntry struct {
	Kind     string `json:"kind"`
	Internal string `json:"internal"`
	External string `json:"external"`
}

func BuildArtifactMetadata(summary Summary, sourceArtifactRefs []string, variantKind string, pairID string, privateJoinMapPath string) *ArtifactMetadata {
	selectedFields := []string{}
	redactionVersion := ""
	shareability := ArtifactShareabilityInternal
	if summary.ShareProfileMetadata != nil {
		selectedFields = append([]string(nil), summary.ShareProfileMetadata.SelectedFields...)
		redactionVersion = strings.TrimSpace(summary.ShareProfileMetadata.RedactionVersion)
	}
	if strings.TrimSpace(variantKind) == ArtifactVariantCustomerRedacted || strings.TrimSpace(summary.ShareProfile) != string(ShareProfileInternal) {
		shareability = ArtifactShareabilityShareable
	}
	sourceRefs := uniqueSortedStrings(sourceArtifactRefs)
	joinMapPath := strings.TrimSpace(privateJoinMapPath)
	if shareability == ArtifactShareabilityShareable {
		sourceRefs = redactStringSlice(sourceRefs, "artifact")
		joinMapPath = ""
	}
	return &ArtifactMetadata{
		ArtifactID:         buildArtifactID(summary, variantKind),
		PairID:             strings.TrimSpace(pairID),
		VariantKind:        strings.TrimSpace(variantKind),
		ShareProfile:       strings.TrimSpace(summary.ShareProfile),
		RedactionVersion:   redactionVersion,
		SelectedFields:     selectedFields,
		SourceArtifactRefs: sourceRefs,
		PrivateJoinMapPath: joinMapPath,
		ShareabilityStatus: shareability,
	}
}

func BuildPrivateJoinMap(internal Summary, external Summary, pairID string) ArtifactJoinMap {
	entries := []ArtifactJoinEntry{}
	addEntry := func(kind, internalValue, externalValue string) {
		internalValue = strings.TrimSpace(internalValue)
		externalValue = strings.TrimSpace(externalValue)
		if internalValue == "" || externalValue == "" || internalValue == externalValue {
			return
		}
		entries = append(entries, ArtifactJoinEntry{
			Kind:     strings.TrimSpace(kind),
			Internal: internalValue,
			External: externalValue,
		})
	}

	for idx := 0; idx < minInt(len(internal.ActionPaths), len(external.ActionPaths)); idx++ {
		addEntry("path_id", internal.ActionPaths[idx].PathID, external.ActionPaths[idx].PathID)
		addEntry("repo", internal.ActionPaths[idx].Repo, external.ActionPaths[idx].Repo)
		addEntry("location", internal.ActionPaths[idx].Location, external.ActionPaths[idx].Location)
		addEntry("agent_id", internal.ActionPaths[idx].AgentID, external.ActionPaths[idx].AgentID)
	}
	if internal.RuntimeSessions != nil && external.RuntimeSessions != nil {
		for idx := 0; idx < minInt(len(internal.RuntimeSessions.Correlations), len(external.RuntimeSessions.Correlations)); idx++ {
			addEntry("session_id", internal.RuntimeSessions.Correlations[idx].SessionID, external.RuntimeSessions.Correlations[idx].SessionID)
			addEntry("session_path_id", internal.RuntimeSessions.Correlations[idx].PathID, external.RuntimeSessions.Correlations[idx].PathID)
			for itemIdx := 0; itemIdx < minInt(len(internal.RuntimeSessions.Correlations[idx].ProofRefs), len(external.RuntimeSessions.Correlations[idx].ProofRefs)); itemIdx++ {
				addEntry("session_proof_ref", internal.RuntimeSessions.Correlations[idx].ProofRefs[itemIdx], external.RuntimeSessions.Correlations[idx].ProofRefs[itemIdx])
			}
		}
	}
	if internal.EvidencePackets != nil && external.EvidencePackets != nil {
		for idx := 0; idx < minInt(len(internal.EvidencePackets.Correlations), len(external.EvidencePackets.Correlations)); idx++ {
			addEntry("packet_id", internal.EvidencePackets.Correlations[idx].PacketID, external.EvidencePackets.Correlations[idx].PacketID)
			addEntry("packet_path_id", internal.EvidencePackets.Correlations[idx].PathID, external.EvidencePackets.Correlations[idx].PathID)
		}
	}
	if internal.AgentActionBOM != nil && external.AgentActionBOM != nil {
		for idx := 0; idx < minInt(len(internal.AgentActionBOM.Items), len(external.AgentActionBOM.Items)); idx++ {
			addEntry("bom_path_id", internal.AgentActionBOM.Items[idx].PathID, external.AgentActionBOM.Items[idx].PathID)
			addEntry("bom_repo", internal.AgentActionBOM.Items[idx].Repo, external.AgentActionBOM.Items[idx].Repo)
			addEntry("bom_location", internal.AgentActionBOM.Items[idx].Location, external.AgentActionBOM.Items[idx].Location)
			for itemIdx := 0; itemIdx < minInt(len(internal.AgentActionBOM.Items[idx].ProofRefs), len(external.AgentActionBOM.Items[idx].ProofRefs)); itemIdx++ {
				addEntry("bom_proof_ref", internal.AgentActionBOM.Items[idx].ProofRefs[itemIdx], external.AgentActionBOM.Items[idx].ProofRefs[itemIdx])
			}
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		if entries[i].Internal != entries[j].Internal {
			return entries[i].Internal < entries[j].Internal
		}
		return entries[i].External < entries[j].External
	})

	return ArtifactJoinMap{
		PairID:               strings.TrimSpace(pairID),
		GeneratedAt:          firstNonEmptyValue(internal.GeneratedAt, external.GeneratedAt),
		InternalShareProfile: firstNonEmptyValue(internal.ShareProfile, string(ShareProfileInternal)),
		ExternalShareProfile: strings.TrimSpace(external.ShareProfile),
		Entries:              entries,
	}
}

func BuildPairID(summary Summary, pairedProfile ShareProfile) string {
	seed := strings.Join([]string{
		strings.TrimSpace(summary.Template),
		strings.TrimSpace(summary.GeneratedAt),
		strings.TrimSpace(summary.ShareProfile),
		string(pairedProfile),
		fmt.Sprintf("%d", len(summary.ActionPaths)),
	}, "|")
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("pair-%s", hex.EncodeToString(sum[:])[:12])
}

func buildArtifactID(summary Summary, variantKind string) string {
	seed := strings.Join([]string{
		strings.TrimSpace(summary.Template),
		strings.TrimSpace(summary.GeneratedAt),
		strings.TrimSpace(summary.ShareProfile),
		strings.TrimSpace(variantKind),
		fmt.Sprintf("%d", len(summary.ActionPaths)),
	}, "|")
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("artifact-%s", hex.EncodeToString(sum[:])[:12])
}

func PairedArtifactPath(path string, suffix string) string {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	if ext == "" {
		return base + "-" + suffix
	}
	return base + "-" + suffix + ext
}

func cloneArtifactMetadata(in *ArtifactMetadata) *ArtifactMetadata {
	if in == nil {
		return nil
	}
	out := *in
	out.SelectedFields = append([]string(nil), in.SelectedFields...)
	out.SourceArtifactRefs = append([]string(nil), in.SourceArtifactRefs...)
	return &out
}

func cloneArtifactBudget(in *ArtifactBudget) *ArtifactBudget {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneSuppressedCounts(in *SuppressedCounts) *SuppressedCounts {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

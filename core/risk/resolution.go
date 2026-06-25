package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/resolution"
)

func applyResolutionDefaults(path ActionPath) ActionPath {
	out := path
	if strings.TrimSpace(out.ResolutionKey) == "" {
		out.ResolutionKey = deriveResolutionKey(out)
	}
	out.ResolutionMatchConfidence = strings.TrimSpace(out.ResolutionMatchConfidence)
	out.ResolutionMismatchReasons = dedupeSortedStrings(out.ResolutionMismatchReasons)
	out.ResolutionSelector = resolution.CloneSelector(out.ResolutionSelector)
	return out
}

func deriveResolutionKey(path ActionPath) string {
	candidate := resolution.NormalizeCandidate(resolutionCandidateForActionPath(path))
	parts := []string{
		firstNonEmptyString(strings.TrimSpace(path.Org), "local"),
		candidate.Repo,
		candidate.ToolType,
		candidate.Location,
		strings.Join(candidate.FindingKeys, ","),
		strings.Join(candidate.ActionClasses, ","),
		candidate.TargetClass,
		strings.Join(candidate.CredentialKinds, ","),
		strings.Join(candidate.EvidenceLocations, ","),
		strings.TrimSpace(path.AgentID),
		strings.TrimSpace(path.ToolFamilyID),
		strings.TrimSpace(path.ToolInstanceID),
		strings.TrimSpace(path.ConfigFingerprint),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "rk-" + hex.EncodeToString(sum[:8])
}

func resolutionCandidateForActionPath(path ActionPath) resolution.Candidate {
	return resolution.Candidate{
		Org:               strings.TrimSpace(path.Org),
		Repo:              strings.TrimSpace(path.Repo),
		ToolType:          strings.TrimSpace(path.ToolType),
		Location:          strings.TrimSpace(path.Location),
		ActionClasses:     dedupeSortedStrings(path.ActionClasses),
		TargetClass:       strings.TrimSpace(path.TargetClass),
		CredentialKinds:   credentialKindsForResolution(path),
		FindingKeys:       dedupeSortedStrings(path.SourceFindingKeys),
		EvidenceLocations: evidenceLocationsForResolution(path),
	}
}

func credentialKindsForResolution(path ActionPath) []string {
	values := []string{}
	if normalized := agginventory.NormalizeCredentialAuthority(path.CredentialAuthority); normalized != nil {
		values = append(values, strings.TrimSpace(normalized.CredentialKind))
	}
	if normalized := agginventory.NormalizeCredentialProvenance(path.CredentialProvenance); normalized != nil {
		values = append(values, strings.TrimSpace(normalized.CredentialKind))
	}
	for _, item := range agginventory.NormalizeCredentialProvenances(path.Credentials) {
		values = append(values, strings.TrimSpace(item.CredentialKind))
	}
	return dedupeSortedStrings(values)
}

func evidenceLocationsForResolution(path ActionPath) []string {
	values := []string{}
	if normalized := agginventory.NormalizeCredentialProvenance(path.CredentialProvenance); normalized != nil {
		values = append(values, strings.TrimSpace(normalized.EvidenceLocation))
	}
	for _, item := range agginventory.NormalizeCredentialProvenances(path.Credentials) {
		values = append(values, strings.TrimSpace(item.EvidenceLocation))
	}
	return dedupeSortedStrings(values)
}

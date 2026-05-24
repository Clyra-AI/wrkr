package attribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ControlMetadata struct {
	Path                     string   `json:"path"`
	Owner                    string   `json:"owner,omitempty"`
	OwnerSource              string   `json:"owner_source,omitempty"`
	ControlResolutionState   string   `json:"control_resolution_state,omitempty"`
	ControlResolutionReasons []string `json:"control_resolution_reasons,omitempty"`
	ControlEvidenceRefs      []string `json:"control_evidence_refs,omitempty"`
	ApprovalEvidenceState    string   `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState       string   `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState       string   `json:"proof_evidence_state,omitempty"`
	RuntimeEvidenceState     string   `json:"runtime_evidence_state,omitempty"`
	TargetEvidenceState      string   `json:"target_evidence_state,omitempty"`
	CredentialEvidenceState  string   `json:"credential_evidence_state,omitempty"`
	ExternalReferences       []string `json:"external_references,omitempty"`
}

type controlMetadataPayload struct {
	Controls []ControlMetadata `json:"controls"`
}

func loadControlMetadata(repoRoot string) map[string]ControlMetadata {
	if strings.TrimSpace(repoRoot) == "" {
		return nil
	}

	files := []string{
		filepath.Join(repoRoot, ".wrkr", "provenance", "control-metadata.json"),
		filepath.Join(repoRoot, ".wrkr", "provenance", "control-declarations.json"),
	}
	byPath := map[string]ControlMetadata{}
	for _, path := range files {
		payload, err := os.ReadFile(path) // #nosec G304 -- deterministic local control metadata sidecar under the scanned repo root.
		if err != nil {
			continue
		}
		var decoded controlMetadataPayload
		if json.Unmarshal(payload, &decoded) != nil {
			continue
		}
		for _, item := range decoded.Controls {
			normalizedPath := filepath.ToSlash(strings.TrimSpace(item.Path))
			if normalizedPath == "" {
				continue
			}
			item.Path = normalizedPath
			item.Owner = strings.TrimSpace(item.Owner)
			item.OwnerSource = strings.TrimSpace(item.OwnerSource)
			item.ControlResolutionState = strings.TrimSpace(item.ControlResolutionState)
			item.ControlResolutionReasons = normalizeStringList(item.ControlResolutionReasons)
			item.ControlEvidenceRefs = normalizeStringList(item.ControlEvidenceRefs)
			item.ApprovalEvidenceState = strings.TrimSpace(item.ApprovalEvidenceState)
			item.OwnerEvidenceState = strings.TrimSpace(item.OwnerEvidenceState)
			item.ProofEvidenceState = strings.TrimSpace(item.ProofEvidenceState)
			item.RuntimeEvidenceState = strings.TrimSpace(item.RuntimeEvidenceState)
			item.TargetEvidenceState = strings.TrimSpace(item.TargetEvidenceState)
			item.CredentialEvidenceState = strings.TrimSpace(item.CredentialEvidenceState)
			item.ExternalReferences = normalizeStringList(item.ExternalReferences)

			current := byPath[normalizedPath]
			byPath[normalizedPath] = mergeControlMetadata(current, item)
		}
	}
	if len(byPath) == 0 {
		return nil
	}
	return byPath
}

func mergeControlMetadata(current, incoming ControlMetadata) ControlMetadata {
	if strings.TrimSpace(current.Path) == "" {
		return incoming
	}
	current.Owner = firstNonEmptyMetadata(current.Owner, incoming.Owner)
	current.OwnerSource = firstNonEmptyMetadata(current.OwnerSource, incoming.OwnerSource)
	current.ControlResolutionState = firstNonEmptyMetadata(current.ControlResolutionState, incoming.ControlResolutionState)
	current.ControlResolutionReasons = normalizeStringList(append(append([]string(nil), current.ControlResolutionReasons...), incoming.ControlResolutionReasons...))
	current.ControlEvidenceRefs = normalizeStringList(append(append([]string(nil), current.ControlEvidenceRefs...), incoming.ControlEvidenceRefs...))
	current.ApprovalEvidenceState = firstNonEmptyMetadata(current.ApprovalEvidenceState, incoming.ApprovalEvidenceState)
	current.OwnerEvidenceState = firstNonEmptyMetadata(current.OwnerEvidenceState, incoming.OwnerEvidenceState)
	current.ProofEvidenceState = firstNonEmptyMetadata(current.ProofEvidenceState, incoming.ProofEvidenceState)
	current.RuntimeEvidenceState = firstNonEmptyMetadata(current.RuntimeEvidenceState, incoming.RuntimeEvidenceState)
	current.TargetEvidenceState = firstNonEmptyMetadata(current.TargetEvidenceState, incoming.TargetEvidenceState)
	current.CredentialEvidenceState = firstNonEmptyMetadata(current.CredentialEvidenceState, incoming.CredentialEvidenceState)
	current.ExternalReferences = normalizeStringList(append(append([]string(nil), current.ExternalReferences...), incoming.ExternalReferences...))
	return current
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := set[trimmed]; ok {
			continue
		}
		set[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmptyMetadata(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

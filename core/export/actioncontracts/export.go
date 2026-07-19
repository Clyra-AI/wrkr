// Package actioncontracts builds portable, report-only proposed Action
// Contract envelopes from a completed saved Wrkr scan. It does not rescan,
// score, invoke a network service, or change saved state.
package actioncontracts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	proofcanon "github.com/Clyra-AI/proof/core/canon"
	"github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

const (
	SchemaID      = "https://wrkr.dev/schemas/v1/proposed-action-contract-artifact.schema.json"
	SchemaVersion = "1"
	Producer      = "wrkr"
)

var safeContractID = regexp.MustCompile(`^pac-[a-f0-9]{8,64}$`)

type ProducerMetadata struct {
	Name                  string `json:"name"`
	ArtifactSchemaVersion string `json:"artifact_schema_version"`
	ContractSchemaVersion string `json:"contract_schema_version"`
}

type VariantMetadata struct {
	ShareProfile string `json:"share_profile"`
	Redacted     bool   `json:"redacted"`
}

// Artifact deliberately has no creation timestamp. Presentation time belongs
// in the CLI manifest, never in the JCS content identity.
type Artifact struct {
	SchemaID               string                      `json:"schema_id"`
	SchemaVersion          string                      `json:"schema_version"`
	ArtifactID             string                      `json:"artifact_id"`
	ContractID             string                      `json:"contract_id"`
	ContractFamilyID       string                      `json:"contract_family_id"`
	Revision               int                         `json:"revision"`
	Producer               ProducerMetadata            `json:"producer"`
	SourceScanRefs         []string                    `json:"source_scan_refs"`
	CompositionRefs        []string                    `json:"composition_refs"`
	ResolutionKey          string                      `json:"resolution_key,omitempty"`
	CreationEvidence       []string                    `json:"creation_evidence"`
	CanonicalContentDigest string                      `json:"canonical_content_digest"`
	Variant                VariantMetadata             `json:"variant"`
	ReportOnly             bool                        `json:"report_only"`
	Contract               risk.ProposedActionContract `json:"contract"`
}

type ManifestItem struct {
	ArtifactID             string `json:"artifact_id"`
	ContractID             string `json:"contract_id"`
	CanonicalContentDigest string `json:"canonical_content_digest"`
	Filename               string `json:"filename"`
}

type Collection struct {
	SchemaID      string         `json:"schema_id"`
	SchemaVersion string         `json:"schema_version"`
	ShareProfile  string         `json:"share_profile"`
	Artifacts     []Artifact     `json:"artifacts"`
	Manifest      []ManifestItem `json:"manifest"`
}

type BuildOptions struct {
	ShareProfile report.ShareProfile
	ContractID   string
}

func Build(snapshot state.Snapshot, options BuildOptions) (Collection, error) {
	profile := options.ShareProfile
	if profile == "" {
		profile = report.ShareProfileInternal
	}
	if _, ok := report.ParseShareProfile(string(profile)); !ok {
		return Collection{}, fmt.Errorf("unsupported share profile %q", profile)
	}
	if snapshot.RiskReport == nil {
		return Collection{}, fmt.Errorf("saved state does not contain risk_report composed action contracts")
	}

	compositions := append([]risk.ComposedActionPath(nil), snapshot.RiskReport.ComposedActionPaths...)
	if len(compositions) == 0 {
		return Collection{}, fmt.Errorf("saved state does not contain proposed Action Contracts")
	}
	if profile != report.ShareProfileInternal {
		var err error
		compositions, err = redactedCompositions(snapshot, profile)
		if err != nil {
			return Collection{}, err
		}
	}

	sort.Slice(compositions, func(i, j int) bool {
		left, right := compositions[i].ProposedActionContract, compositions[j].ProposedActionContract
		if left == nil {
			return false
		}
		if right == nil {
			return true
		}
		return strings.TrimSpace(left.ContractID) < strings.TrimSpace(right.ContractID)
	})
	collection := Collection{SchemaID: SchemaID, SchemaVersion: SchemaVersion, ShareProfile: string(profile)}
	selector := strings.TrimSpace(options.ContractID)
	for _, composition := range compositions {
		if composition.ProposedActionContract == nil {
			continue
		}
		contract := risk.CloneProposedActionContract(composition.ProposedActionContract)
		if strings.TrimSpace(contract.ContractVersion) != risk.ProposedActionContractVersionV3 {
			continue
		}
		if selector != "" && strings.TrimSpace(contract.ContractID) != selector {
			continue
		}
		artifact, err := buildArtifact(snapshot, composition, *contract, profile)
		if err != nil {
			return Collection{}, err
		}
		collection.Artifacts = append(collection.Artifacts, artifact)
		collection.Manifest = append(collection.Manifest, ManifestItem{
			ArtifactID:             artifact.ArtifactID,
			ContractID:             artifact.ContractID,
			CanonicalContentDigest: artifact.CanonicalContentDigest,
			Filename:               Filename(artifact),
		})
	}
	if selector != "" && len(collection.Artifacts) == 0 {
		return Collection{}, fmt.Errorf("proposed Action Contract %q was not found", selector)
	}
	if len(collection.Artifacts) == 0 {
		return Collection{}, fmt.Errorf("saved state has no exportable proposed Action Contract v3 artifacts")
	}
	return collection, nil
}

func buildArtifact(snapshot state.Snapshot, composition risk.ComposedActionPath, contract risk.ProposedActionContract, profile report.ShareProfile) (Artifact, error) {
	if !safeContractID.MatchString(strings.TrimSpace(contract.ContractID)) {
		return Artifact{}, fmt.Errorf("unsafe contract id %q", contract.ContractID)
	}
	artifact := Artifact{
		SchemaID:         SchemaID,
		SchemaVersion:    SchemaVersion,
		ContractID:       strings.TrimSpace(contract.ContractID),
		ContractFamilyID: strings.TrimSpace(contract.ContractFamilyID),
		Revision:         contract.Revision,
		Producer: ProducerMetadata{
			Name:                  Producer,
			ArtifactSchemaVersion: SchemaVersion,
			ContractSchemaVersion: strings.TrimSpace(contract.ContractVersion),
		},
		SourceScanRefs:   []string{"saved_scan:" + strings.TrimSpace(snapshot.Version)},
		CompositionRefs:  []string{strings.TrimSpace(composition.CompositionID)},
		ResolutionKey:    strings.TrimSpace(composition.ResolutionKey),
		CreationEvidence: dedupeSorted(append(append([]string(nil), composition.ProofRefs...), composition.SourceDecisionRefs...)),
		Variant: VariantMetadata{
			ShareProfile: string(profile),
			Redacted:     profile != report.ShareProfileInternal,
		},
		ReportOnly: true,
		Contract:   contract,
	}
	if len(artifact.CreationEvidence) == 0 {
		artifact.CreationEvidence = []string{"risk_assessment:" + artifact.ContractID}
	}
	digest, err := canonicalContentDigest(artifact)
	if err != nil {
		return Artifact{}, err
	}
	artifact.CanonicalContentDigest = digest
	artifact.ArtifactID = "paca-" + strings.TrimPrefix(digest, "sha256:")[:16]
	return artifact, nil
}

func canonicalContentDigest(artifact Artifact) (string, error) {
	payload := struct {
		SchemaID         string                      `json:"schema_id"`
		SchemaVersion    string                      `json:"schema_version"`
		ContractID       string                      `json:"contract_id"`
		ContractFamilyID string                      `json:"contract_family_id"`
		Revision         int                         `json:"revision"`
		Producer         ProducerMetadata            `json:"producer"`
		SourceScanRefs   []string                    `json:"source_scan_refs"`
		CompositionRefs  []string                    `json:"composition_refs"`
		ResolutionKey    string                      `json:"resolution_key,omitempty"`
		CreationEvidence []string                    `json:"creation_evidence"`
		Variant          VariantMetadata             `json:"variant"`
		ReportOnly       bool                        `json:"report_only"`
		Contract         risk.ProposedActionContract `json:"contract"`
	}{
		SchemaID: artifact.SchemaID, SchemaVersion: artifact.SchemaVersion, ContractID: artifact.ContractID,
		ContractFamilyID: artifact.ContractFamilyID, Revision: artifact.Revision, Producer: artifact.Producer,
		SourceScanRefs: artifact.SourceScanRefs, CompositionRefs: artifact.CompositionRefs, ResolutionKey: artifact.ResolutionKey,
		CreationEvidence: artifact.CreationEvidence, Variant: artifact.Variant, ReportOnly: artifact.ReportOnly, Contract: artifact.Contract,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal artifact canonical content: %w", err)
	}
	digest, err := proofcanon.DigestHex(encoded, proofcanon.DomainJSON)
	if err != nil {
		return "", fmt.Errorf("canonicalize artifact content: %w", err)
	}
	return "sha256:" + digest, nil
}

func Filename(artifact Artifact) string {
	return strings.TrimSpace(artifact.ContractID) + ".json"
}

// Write writes new artifact files and a collection manifest atomically. It
// never overwrites an existing target and rejects a symlink output directory.
func Write(collection Collection, outputDir string) ([]string, error) {
	dir := filepath.Clean(strings.TrimSpace(outputDir))
	if dir == "" || dir == "." {
		return nil, fmt.Errorf("output directory must not be empty")
	}
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("output directory must not be a symlink: %s", dir)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("output directory is not a directory: %s", dir)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect output directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	paths := make([]string, 0, len(collection.Artifacts)+1)
	for _, artifact := range collection.Artifacts {
		filename := Filename(artifact)
		if !safeContractID.MatchString(strings.TrimSuffix(filename, ".json")) || filepath.Base(filename) != filename {
			return nil, fmt.Errorf("unsafe artifact filename %q", filename)
		}
		path := filepath.Join(dir, filename)
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf("refusing artifact collision at %s", path)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect artifact target %s: %w", path, err)
		}
		encoded, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal artifact %s: %w", artifact.ContractID, err)
		}
		encoded = append(encoded, '\n')
		if err := atomicwrite.WriteFile(path, encoded, 0o600); err != nil {
			return nil, fmt.Errorf("write artifact %s: %w", artifact.ContractID, err)
		}
		paths = append(paths, path)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if _, err := os.Lstat(manifestPath); err == nil {
		return nil, fmt.Errorf("refusing artifact collision at %s", manifestPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect manifest target %s: %w", manifestPath, err)
	}
	encoded, err := json.MarshalIndent(struct {
		SchemaID      string         `json:"schema_id"`
		SchemaVersion string         `json:"schema_version"`
		ShareProfile  string         `json:"share_profile"`
		Artifacts     []ManifestItem `json:"artifacts"`
	}{collection.SchemaID, collection.SchemaVersion, collection.ShareProfile, collection.Manifest}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal artifact manifest: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := atomicwrite.WriteFile(manifestPath, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write artifact manifest: %w", err)
	}
	return append(paths, manifestPath), nil
}

func redactedCompositions(snapshot state.Snapshot, profile report.ShareProfile) ([]risk.ComposedActionPath, error) {
	summary, err := report.BuildSummary(report.BuildInput{
		Snapshot: snapshot, Template: report.TemplateAgentActionBOM, ShareProfile: profile, Top: 10,
	})
	if err != nil {
		return nil, fmt.Errorf("build redacted Action Contract projection: %w", err)
	}
	summary = report.FinalizeSummaryForSerialization(summary)
	summary, err = report.ApplyShareableResidualRedaction(snapshot, summary)
	if err != nil {
		return nil, fmt.Errorf("apply residual Action Contract redaction: %w", err)
	}
	return append([]risk.ComposedActionPath(nil), summary.ComposedActionPaths...), nil
}

func dedupeSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

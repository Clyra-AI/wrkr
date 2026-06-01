package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/ingest"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
)

type PortableArtifactManifest struct {
	SchemaVersion    string                        `json:"schema_version"`
	GeneratedAt      string                        `json:"generated_at"`
	GeneratorVersion string                        `json:"generator_version"`
	DeploymentMode   string                        `json:"deployment_mode,omitempty"`
	Artifacts        []PortableArtifactManifestRow `json:"artifacts"`
}

type PortableArtifactManifestRow struct {
	RelativePath         string                  `json:"relative_path"`
	ArtifactKind         string                  `json:"artifact_kind"`
	VariantKind          string                  `json:"variant_kind,omitempty"`
	SchemaVersion        string                  `json:"schema_version,omitempty"`
	ShareProfile         string                  `json:"share_profile,omitempty"`
	RedactionVersion     string                  `json:"redaction_version,omitempty"`
	BoundaryLabel        string                  `json:"boundary_label,omitempty"`
	ProofRefs            []string                `json:"proof_refs,omitempty"`
	SourcePrivacy        *sourceprivacy.Contract `json:"source_privacy,omitempty"`
	EvidenceStateSummary []string                `json:"evidence_state_summary,omitempty"`
	Digest               string                  `json:"digest"`
}

func buildPortableArtifactManifest(
	outputDir string,
	generatedAt time.Time,
	sourcePrivacy *sourceprivacy.Contract,
	internalSummary reportcore.Summary,
	redactedSummary reportcore.Summary,
	runtimeSessions *ingest.SessionSummary,
	runtimeEvidence *ingest.Summary,
	evidencePackets *ingest.EvidencePacketSummary,
) (PortableArtifactManifest, error) {
	rows := []PortableArtifactManifestRow{}
	err := filepath.WalkDir(outputDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "artifact-manifest.json" {
			return nil
		}
		payload, err := os.ReadFile(path) // #nosec G304 -- bundle files are deterministic local outputs under outputDir.
		if err != nil {
			return err
		}
		sum := sha256.Sum256(payload)
		row := PortableArtifactManifestRow{
			RelativePath:         rel,
			ArtifactKind:         portableArtifactKind(rel),
			VariantKind:          portableVariantKind(rel),
			SchemaVersion:        portableSchemaVersion(rel),
			ShareProfile:         portableShareProfile(rel),
			RedactionVersion:     portableRedactionVersion(rel, internalSummary, redactedSummary),
			BoundaryLabel:        portableBoundaryLabel(rel, internalSummary, redactedSummary, runtimeSessions, runtimeEvidence, evidencePackets),
			ProofRefs:            portableProofRefs(rel, internalSummary, redactedSummary),
			SourcePrivacy:        cloneSourcePrivacyContract(sourcePrivacy),
			EvidenceStateSummary: portableEvidenceStateSummary(rel, runtimeSessions, runtimeEvidence, evidencePackets),
			Digest:               "sha256:" + hex.EncodeToString(sum[:]),
		}
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		return PortableArtifactManifest{}, err
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].RelativePath < rows[j].RelativePath
	})
	return PortableArtifactManifest{
		SchemaVersion:    "v1",
		GeneratedAt:      generatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		GeneratorVersion: "wrkr-evidence-v1",
		DeploymentMode:   resolvePortableDeploymentMode(sourcePrivacy),
		Artifacts:        rows,
	}, nil
}

func resolvePortableDeploymentMode(in *sourceprivacy.Contract) string {
	if in == nil {
		return sourceprivacy.DeploymentModeLocalOnly
	}
	return sourceprivacy.Normalize(*in).DeploymentMode
}

func portableArtifactKind(rel string) string {
	switch rel {
	case "runtime-sessions.json":
		return "runtime_sessions"
	case "runtime-session-correlation.json":
		return "runtime_session_correlation"
	case "runtime-evidence.json":
		return "runtime_evidence"
	case "runtime-evidence-correlation.json":
		return "runtime_evidence_correlation"
	case "agentic-evidence-packets.json":
		return "evidence_packets"
	case "agentic-evidence-packet-correlation.json":
		return "evidence_packet_correlation"
	case "control-evidence.json":
		return "control_evidence"
	case "manifest.json":
		return "proof_bundle_manifest"
	case "reports/audit-summary.md", "reports/audit-summary-customer-redacted.md":
		return "audit_summary"
	case "reports/agent-action-bom.json", "reports/agent-action-bom-customer-redacted.json":
		return "agent_action_bom"
	case "reports/report-evidence.json", "reports/report-evidence-customer-redacted.json":
		return "report_evidence_bundle"
	default:
		base := strings.TrimSuffix(filepath.Base(rel), filepath.Ext(rel))
		base = strings.ReplaceAll(base, "-", "_")
		return base
	}
}

func portableVariantKind(rel string) string {
	if strings.Contains(rel, "customer-redacted") {
		return reportcore.ArtifactVariantCustomerRedacted
	}
	if strings.HasPrefix(rel, "reports/") {
		return reportcore.ArtifactVariantInternal
	}
	return reportcore.ArtifactVariantInternal
}

func portableSchemaVersion(rel string) string {
	switch portableArtifactKind(rel) {
	case "runtime_sessions":
		return ingest.SessionSchemaVersion
	case "runtime_evidence", "runtime_evidence_correlation":
		return ingest.SchemaVersion
	case "evidence_packets", "evidence_packet_correlation":
		return ingest.EvidencePacketSchemaVersion
	case "agent_action_bom":
		return reportcore.AgentActionBOMSchemaVersion
	case "report_evidence_bundle":
		return "1"
	default:
		return ""
	}
}

func portableShareProfile(rel string) string {
	if strings.Contains(rel, "customer-redacted") {
		return string(reportcore.ShareProfileCustomerRedacted)
	}
	if strings.HasPrefix(rel, "reports/") {
		return string(reportcore.ShareProfileInternal)
	}
	return ""
}

func portableRedactionVersion(rel string, internalSummary, redactedSummary reportcore.Summary) string {
	if strings.Contains(rel, "customer-redacted") && redactedSummary.ShareProfileMetadata != nil {
		return strings.TrimSpace(redactedSummary.ShareProfileMetadata.RedactionVersion)
	}
	if strings.HasPrefix(rel, "reports/") && internalSummary.ShareProfileMetadata != nil {
		return strings.TrimSpace(internalSummary.ShareProfileMetadata.RedactionVersion)
	}
	return ""
}

func portableBoundaryLabel(
	rel string,
	internalSummary reportcore.Summary,
	redactedSummary reportcore.Summary,
	runtimeSessions *ingest.SessionSummary,
	runtimeEvidence *ingest.Summary,
	evidencePackets *ingest.EvidencePacketSummary,
) string {
	switch portableArtifactKind(rel) {
	case "runtime_sessions", "runtime_session_correlation":
		if runtimeSessions != nil {
			return strings.TrimSpace(runtimeSessions.BoundaryLabel)
		}
	case "runtime_evidence", "runtime_evidence_correlation":
		if runtimeEvidence != nil {
			return strings.TrimSpace(runtimeEvidence.BoundaryLabel)
		}
	case "evidence_packets", "evidence_packet_correlation":
		if evidencePackets != nil {
			return strings.TrimSpace(evidencePackets.BoundaryLabel)
		}
	default:
		if strings.Contains(rel, "customer-redacted") {
			return strongestSummaryBoundary(redactedSummary)
		}
		if strings.HasPrefix(rel, "reports/") {
			return strongestSummaryBoundary(internalSummary)
		}
	}
	return ""
}

func portableProofRefs(rel string, internalSummary, redactedSummary reportcore.Summary) []string {
	switch {
	case strings.Contains(rel, "customer-redacted"):
		return summaryProofRefs(redactedSummary)
	case strings.HasPrefix(rel, "reports/"):
		return summaryProofRefs(internalSummary)
	default:
		return nil
	}
}

func portableEvidenceStateSummary(rel string, runtimeSessions *ingest.SessionSummary, runtimeEvidence *ingest.Summary, evidencePackets *ingest.EvidencePacketSummary) []string {
	switch portableArtifactKind(rel) {
	case "runtime_sessions", "runtime_session_correlation":
		if runtimeSessions == nil {
			return nil
		}
		return []string{
			fmt.Sprintf("matched_sessions=%d", runtimeSessions.MatchedSessions),
			fmt.Sprintf("unmatched_sessions=%d", runtimeSessions.UnmatchedSessions),
		}
	case "runtime_evidence", "runtime_evidence_correlation":
		if runtimeEvidence == nil {
			return nil
		}
		return []string{
			fmt.Sprintf("matched_records=%d", runtimeEvidence.MatchedRecords),
			fmt.Sprintf("unmatched_records=%d", runtimeEvidence.UnmatchedRecords),
		}
	case "evidence_packets", "evidence_packet_correlation":
		if evidencePackets == nil {
			return nil
		}
		return []string{
			fmt.Sprintf("matched_packets=%d", evidencePackets.MatchedPackets),
			fmt.Sprintf("unmatched_packets=%d", evidencePackets.UnmatchedPackets),
		}
	default:
		return nil
	}
}

func strongestSummaryBoundary(summary reportcore.Summary) string {
	best := ""
	for _, path := range summary.ActionPaths {
		best = strongestBoundary(best, strings.TrimSpace(path.BoundaryLabel))
	}
	return best
}

func strongestBoundary(current, incoming string) string {
	if boundaryRank(incoming) > boundaryRank(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func boundaryRank(value string) int {
	switch strings.TrimSpace(value) {
	case reportcore.BoundaryLabelEnforcementCapable:
		return 4
	case reportcore.BoundaryLabelApprovalCapable:
		return 3
	case reportcore.BoundaryLabelReportOnly:
		return 2
	case reportcore.BoundaryLabelDiscoveryOnly:
		return 1
	default:
		return 0
	}
}

func summaryProofRefs(summary reportcore.Summary) []string {
	refs := []string{}
	if strings.TrimSpace(summary.Proof.HeadHash) != "" {
		refs = append(refs, "proof_head:"+strings.TrimSpace(summary.Proof.HeadHash))
	}
	if strings.TrimSpace(summary.Proof.ChainPath) != "" {
		refs = append(refs, "proof_chain:"+strings.TrimSpace(summary.Proof.ChainPath))
	}
	return uniqueSortedStrings(refs)
}

func cloneSourcePrivacyContract(in *sourceprivacy.Contract) *sourceprivacy.Contract {
	if in == nil {
		return nil
	}
	out := *in
	out.Warnings = append([]string(nil), in.Warnings...)
	return &out
}

func uniqueSortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

package source

import (
	"sort"

	"github.com/Clyra-AI/wrkr/core/model"
)

// Target describes a user-selected source scope.
type Target struct {
	Mode  string `json:"mode"`
	Value string `json:"value"`
}

const TargetModeMulti = "multi"
const TargetModePublicSurface = "public-surface"

const (
	PublicSourceClassRepo            = "public_repo"
	PublicSourceClassDocs            = "public_docs"
	PublicSourceClassSDK             = "public_sdk"
	PublicSourceClassEngineeringBlog = "engineering_blog"
	PublicSourceClassReleaseNotes    = "release_notes"
	PublicSourceClassStatusPage      = "status_page"
	PublicSourceClassWorkflow        = "public_workflow"
)

const (
	PublicEvidenceLabelObserved              = "public_observed"
	PublicEvidenceLabelInferred              = "public_inferred"
	PublicEvidenceLabelUnsupportedClaim      = "unsupported_public_claim"
	PublicEvidenceLabelPrivateEvidenceAbsent = "private_evidence_absent"
)

type PublicEvidence struct {
	ID                 string   `json:"id" yaml:"id"`
	SourceClass        string   `json:"source_class" yaml:"source_class"`
	Title              string   `json:"title,omitempty" yaml:"title,omitempty"`
	PublicRef          string   `json:"public_ref" yaml:"public_ref"`
	CapturePath        string   `json:"capture_path,omitempty" yaml:"capture_path,omitempty"`
	CapturedAt         string   `json:"captured_at,omitempty" yaml:"captured_at,omitempty"`
	EvidenceLabel      string   `json:"evidence_label" yaml:"evidence_label"`
	Confidence         string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	InferenceRationale string   `json:"inference_rationale,omitempty" yaml:"inference_rationale,omitempty"`
	Claims             []string `json:"claims,omitempty" yaml:"claims,omitempty"`
}

// RepoManifest identifies a repository acquisition result.
type RepoManifest struct {
	Repo              string                 `json:"repo"`
	Location          string                 `json:"location"`
	ScanRoot          string                 `json:"-" yaml:"-"`
	Source            string                 `json:"source"`
	OwnershipMetadata *RepoOwnershipMetadata `json:"ownership_metadata,omitempty"`
}

type RepoOwnershipMetadata struct {
	Topics []string `json:"topics,omitempty"`
	Teams  []string `json:"teams,omitempty"`
}

// RepoFailure captures one non-fatal source failure.
type RepoFailure struct {
	Repo   string `json:"repo"`
	Reason string `json:"reason"`
}

// Manifest is the deterministic source acquisition output.
type Manifest struct {
	Target                     Target           `json:"target"`
	Targets                    []Target         `json:"targets,omitempty"`
	Repos                      []RepoManifest   `json:"repos"`
	PublicEvidenceManifestName string           `json:"public_evidence_manifest_name,omitempty"`
	PublicEvidence             []PublicEvidence `json:"public_evidence,omitempty"`
	Failures                   []RepoFailure    `json:"failures,omitempty"`
	MaterializedRoot           string           `json:"-" yaml:"-"`
}

// Finding is the canonical scan record used by diff/state.
type Finding = model.Finding

func SortManifest(m Manifest) Manifest {
	m.Targets = SortTargets(m.Targets)
	m.PublicEvidence = SortPublicEvidence(m.PublicEvidence)
	sort.Slice(m.Repos, func(i, j int) bool {
		if m.Repos[i].Repo == m.Repos[j].Repo {
			if m.Repos[i].Location == m.Repos[j].Location {
				return m.Repos[i].Source < m.Repos[j].Source
			}
			return m.Repos[i].Location < m.Repos[j].Location
		}
		return m.Repos[i].Repo < m.Repos[j].Repo
	})
	sort.Slice(m.Failures, func(i, j int) bool {
		if m.Failures[i].Repo == m.Failures[j].Repo {
			return m.Failures[i].Reason < m.Failures[j].Reason
		}
		return m.Failures[i].Repo < m.Failures[j].Repo
	})
	return m
}

func SortPublicEvidence(items []PublicEvidence) []PublicEvidence {
	if len(items) == 0 {
		return nil
	}
	sorted := append([]PublicEvidence(nil), items...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].EvidenceLabel != sorted[j].EvidenceLabel {
			return sorted[i].EvidenceLabel < sorted[j].EvidenceLabel
		}
		if sorted[i].SourceClass != sorted[j].SourceClass {
			return sorted[i].SourceClass < sorted[j].SourceClass
		}
		if sorted[i].PublicRef != sorted[j].PublicRef {
			return sorted[i].PublicRef < sorted[j].PublicRef
		}
		return sorted[i].ID < sorted[j].ID
	})
	return sorted
}

func SortTargets(targets []Target) []Target {
	if len(targets) == 0 {
		return nil
	}
	sorted := append([]Target(nil), targets...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Mode == sorted[j].Mode {
			return sorted[i].Value < sorted[j].Value
		}
		return sorted[i].Mode < sorted[j].Mode
	})
	return sorted
}

func SortFindings(findings []Finding) {
	model.SortFindings(findings)
}

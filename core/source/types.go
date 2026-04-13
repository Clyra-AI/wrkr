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

// RepoManifest identifies a repository acquisition result.
type RepoManifest struct {
	Repo     string `json:"repo"`
	Location string `json:"location"`
	Source   string `json:"source"`
}

// RepoFailure captures one non-fatal source failure.
type RepoFailure struct {
	Repo   string `json:"repo"`
	Reason string `json:"reason"`
}

// Manifest is the deterministic source acquisition output.
type Manifest struct {
	Target   Target         `json:"target"`
	Targets  []Target       `json:"targets,omitempty"`
	Repos    []RepoManifest `json:"repos"`
	Failures []RepoFailure  `json:"failures,omitempty"`
}

// Finding is the canonical scan record used by diff/state.
type Finding = model.Finding

func SortManifest(m Manifest) Manifest {
	m.Targets = SortTargets(m.Targets)
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

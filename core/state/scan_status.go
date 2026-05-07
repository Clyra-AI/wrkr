package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

const ScanStatusVersion = "1"

const (
	ScanStatusUnknown     = "unknown"
	ScanStatusRunning     = "running"
	ScanStatusCompleted   = "completed"
	ScanStatusInterrupted = "interrupted"
	ScanStatusFailed      = "failed"
)

type ScanStatus struct {
	ScanStatusVersion   string                  `json:"scan_status_version"`
	Status              string                  `json:"status"`
	StatePath           string                  `json:"state_path"`
	Target              any                     `json:"target,omitempty"`
	Targets             any                     `json:"targets,omitempty"`
	CurrentPhase        string                  `json:"current_phase,omitempty"`
	LastSuccessfulPhase string                  `json:"last_successful_phase,omitempty"`
	RepoTotal           int                     `json:"repo_total,omitempty"`
	ReposCompleted      int                     `json:"repos_completed,omitempty"`
	ReposFailed         int                     `json:"repos_failed,omitempty"`
	ProgressPercent     int                     `json:"progress_percent,omitempty"`
	ProgressMessage     string                  `json:"progress_message,omitempty"`
	LastProgressAt      string                  `json:"last_progress_at,omitempty"`
	ElapsedSeconds      int64                   `json:"elapsed_seconds,omitempty"`
	PhaseProgress       *ScanPhaseProgress      `json:"phase_progress,omitempty"`
	RepoProgress        *ScanRepoProgress       `json:"repo_progress,omitempty"`
	DetectorProgress    *ScanDetectorProgress   `json:"detector_progress,omitempty"`
	PartialResult       bool                    `json:"partial_result,omitempty"`
	PartialResultMarker string                  `json:"partial_result_marker,omitempty"`
	StartedAt           string                  `json:"started_at,omitempty"`
	UpdatedAt           string                  `json:"updated_at,omitempty"`
	CompletedAt         string                  `json:"completed_at,omitempty"`
	Error               string                  `json:"error,omitempty"`
	ArtifactPaths       map[string]string       `json:"artifact_paths,omitempty"`
	PhaseTimings        []PhaseTiming           `json:"phase_timings,omitempty"`
	SourcePrivacy       *sourceprivacy.Contract `json:"source_privacy,omitempty"`
}

type PhaseTiming struct {
	Phase          string `json:"phase"`
	StartedAt      string `json:"started_at,omitempty"`
	CompletedAt    string `json:"completed_at,omitempty"`
	DurationMillis int64  `json:"duration_ms,omitempty"`
}

type ScanPhaseProgress struct {
	Phase   string `json:"phase,omitempty"`
	Percent int    `json:"percent,omitempty"`
}

type ScanRepoProgress struct {
	Total     int `json:"total,omitempty"`
	Completed int `json:"completed,omitempty"`
	Failed    int `json:"failed,omitempty"`
	Pending   int `json:"pending,omitempty"`
}

type ScanDetectorProgress struct {
	Total          int    `json:"total,omitempty"`
	Completed      int    `json:"completed,omitempty"`
	Failed         int    `json:"failed,omitempty"`
	Pending        int    `json:"pending,omitempty"`
	ActiveDetector string `json:"active_detector,omitempty"`
}

func ScanStatusPath(statePath string) string {
	resolved := ResolvePath(strings.TrimSpace(statePath))
	ext := filepath.Ext(resolved)
	if ext == "" {
		return resolved + ".status.json"
	}
	return strings.TrimSuffix(resolved, ext) + ".status.json"
}

func SaveScanStatus(statePath string, status ScanStatus) error {
	status.ScanStatusVersion = ScanStatusVersion
	status.StatePath = filepath.Clean(ResolvePath(statePath))
	if strings.TrimSpace(status.Status) == "" {
		status.Status = ScanStatusUnknown
	}
	payload, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal scan status: %w", err)
	}
	payload = append(payload, '\n')
	if err := atomicwrite.WriteFile(ScanStatusPath(statePath), payload, 0o600); err != nil {
		return fmt.Errorf("write scan status: %w", err)
	}
	return nil
}

func LoadScanStatus(statePath string) (ScanStatus, error) {
	resolved := ResolvePath(statePath)
	payload, err := os.ReadFile(ScanStatusPath(resolved)) // #nosec G304 -- status path is derived from explicit scan state path.
	if err == nil {
		var status ScanStatus
		if decodeErr := json.Unmarshal(payload, &status); decodeErr != nil {
			return ScanStatus{}, fmt.Errorf("parse scan status: %w", decodeErr)
		}
		return normalizeScanStatus(resolved, status), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ScanStatus{}, fmt.Errorf("read scan status: %w", err)
	}
	snapshot, snapshotErr := loadSnapshot(resolved)
	if snapshotErr == nil {
		return ScanStatus{
			ScanStatusVersion:   ScanStatusVersion,
			Status:              ScanStatusCompleted,
			StatePath:           filepath.Clean(resolved),
			Target:              snapshot.Target,
			Targets:             snapshot.Targets,
			CurrentPhase:        "artifact_commit",
			LastSuccessfulPhase: "artifact_commit",
			ArtifactPaths:       map[string]string{"state": filepath.Clean(resolved)},
			SourcePrivacy:       snapshot.SourcePrivacy,
		}, nil
	}
	return ScanStatus{
		ScanStatusVersion: ScanStatusVersion,
		Status:            ScanStatusUnknown,
		StatePath:         filepath.Clean(resolved),
	}, nil
}

func normalizeScanStatus(statePath string, status ScanStatus) ScanStatus {
	status.ScanStatusVersion = fallbackString(status.ScanStatusVersion, ScanStatusVersion)
	status.Status = fallbackString(status.Status, ScanStatusUnknown)
	status.StatePath = filepath.Clean(fallbackString(status.StatePath, ResolvePath(statePath)))
	status.ProgressMessage = strings.TrimSpace(status.ProgressMessage)
	status.LastProgressAt = strings.TrimSpace(status.LastProgressAt)
	if status.ArtifactPaths != nil {
		normalized := map[string]string{}
		for key, value := range status.ArtifactPaths {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key == "" || value == "" {
				continue
			}
			normalized[key] = filepath.Clean(value)
		}
		status.ArtifactPaths = normalized
	}
	if status.SourcePrivacy != nil {
		normalizedPrivacy := sourceprivacy.Normalize(*status.SourcePrivacy)
		status.SourcePrivacy = &normalizedPrivacy
	}
	if status.PhaseProgress != nil {
		phaseProgress := *status.PhaseProgress
		phaseProgress.Phase = strings.TrimSpace(phaseProgress.Phase)
		status.PhaseProgress = &phaseProgress
	}
	if status.RepoProgress != nil {
		repoProgress := *status.RepoProgress
		status.RepoProgress = &repoProgress
	}
	if status.DetectorProgress != nil {
		detectorProgress := *status.DetectorProgress
		detectorProgress.ActiveDetector = strings.TrimSpace(detectorProgress.ActiveDetector)
		status.DetectorProgress = &detectorProgress
	}
	return status
}

func fallbackString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

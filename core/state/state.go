package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
	"os"
)

const SnapshotVersion = "v1"

// Snapshot stores deterministic scan material for diff mode.
type Snapshot struct {
	Version      string                    `json:"version"`
	Target       source.Target             `json:"target"`
	Targets      []source.Target           `json:"targets,omitempty"`
	Findings     []source.Finding          `json:"findings"`
	Inventory    *agginventory.Inventory   `json:"inventory,omitempty"`
	RiskReport   *risk.Report              `json:"risk_report,omitempty"`
	Profile      *profileeval.Result       `json:"profile,omitempty"`
	PostureScore *score.Result             `json:"posture_score,omitempty"`
	Identities   []manifest.IdentityRecord `json:"identities,omitempty"`
	Transitions  []lifecycle.Transition    `json:"lifecycle_transitions,omitempty"`
}

type ScoreView struct {
	Findings        []source.Finding
	PostureScore    *score.Result
	Identities      []manifest.IdentityRecord
	TransitionCount int
	AttackPaths     []riskattack.ScoredPath
	TopAttackPaths  []riskattack.ScoredPath
}

type scoreSnapshotEnvelope struct {
	Target       json.RawMessage `json:"target"`
	Targets      json.RawMessage `json:"targets,omitempty"`
	Findings     json.RawMessage `json:"findings"`
	Inventory    json.RawMessage `json:"inventory,omitempty"`
	RiskReport   json.RawMessage `json:"risk_report,omitempty"`
	Profile      json.RawMessage `json:"profile,omitempty"`
	PostureScore *score.Result   `json:"posture_score,omitempty"`
	Identities   json.RawMessage `json:"identities,omitempty"`
	Transitions  json.RawMessage `json:"lifecycle_transitions,omitempty"`
}

type scoreRiskReportEnvelope struct {
	GeneratedAt              json.RawMessage         `json:"generated_at"`
	TopN                     json.RawMessage         `json:"top_findings"`
	Ranked                   json.RawMessage         `json:"ranked_findings"`
	Repos                    json.RawMessage         `json:"repo_risk"`
	AttackPaths              []riskattack.ScoredPath `json:"attack_paths,omitempty"`
	TopAttackPaths           []riskattack.ScoredPath `json:"top_attack_paths,omitempty"`
	ActionPaths              json.RawMessage         `json:"action_paths,omitempty"`
	ActionPathToControlFirst json.RawMessage         `json:"action_path_to_control_first,omitempty"`
}

func ResolvePath(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if fromEnv := strings.TrimSpace(os.Getenv("WRKR_STATE_PATH")); fromEnv != "" {
		return fromEnv
	}
	return filepath.Join(".wrkr", "last-scan.json")
}

func Save(path string, snapshot Snapshot) error {
	snapshot.Version = SnapshotVersion
	snapshot.Targets = source.SortTargets(snapshot.Targets)
	source.SortFindings(snapshot.Findings)
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	payload = append(payload, '\n')
	if err := atomicwrite.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

func loadSnapshot(path string) (Snapshot, error) {
	// #nosec G304 -- caller controls state path selection; reading that explicit path is intended.
	payload, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read state: %w", err)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("parse state: %w", err)
	}
	if snapshot.Version == "" {
		snapshot.Version = SnapshotVersion
	}
	return snapshot, nil
}

func LoadRaw(path string) (Snapshot, error) {
	return loadSnapshot(path)
}

func Load(path string) (Snapshot, error) {
	snapshot, err := loadSnapshot(path)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Targets = source.SortTargets(snapshot.Targets)
	source.SortFindings(snapshot.Findings)
	return snapshot, nil
}

// LoadScoreView validates the stored scan snapshot shape needed by the score
// command without fully materializing large unused report sections on the
// cached-score path.
func LoadScoreView(path string) (ScoreView, error) {
	// #nosec G304 -- caller controls state path selection; reading that explicit path is intended.
	payload, err := os.ReadFile(path)
	if err != nil {
		return ScoreView{}, fmt.Errorf("read state: %w", err)
	}

	var envelope scoreSnapshotEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return ScoreView{}, fmt.Errorf("parse state: %w", err)
	}

	if envelope.PostureScore != nil {
		report, err := validateCachedScoreSnapshot(envelope)
		if err != nil {
			return ScoreView{}, fmt.Errorf("parse state: %w", err)
		}
		view := ScoreView{PostureScore: envelope.PostureScore}
		if report != nil {
			view.AttackPaths = report.AttackPaths
			view.TopAttackPaths = report.TopAttackPaths
		}
		return view, nil
	}

	var snapshot Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return ScoreView{}, fmt.Errorf("parse state: %w", err)
	}

	var attackPaths []riskattack.ScoredPath
	var topAttackPaths []riskattack.ScoredPath
	if snapshot.RiskReport != nil {
		attackPaths = snapshot.RiskReport.AttackPaths
		topAttackPaths = snapshot.RiskReport.TopAttackPaths
	}

	return ScoreView{
		Findings:        snapshot.Findings,
		PostureScore:    snapshot.PostureScore,
		Identities:      snapshot.Identities,
		TransitionCount: len(snapshot.Transitions),
		AttackPaths:     attackPaths,
		TopAttackPaths:  topAttackPaths,
	}, nil
}

func validateCachedScoreSnapshot(envelope scoreSnapshotEnvelope) (*scoreRiskReportEnvelope, error) {
	if err := validateRawShape(envelope.Target, rawObject, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(envelope.Targets, rawArray, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(envelope.Findings, rawArray, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(envelope.Inventory, rawObject, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(envelope.Profile, rawObject, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(envelope.Identities, rawArray, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(envelope.Transitions, rawArray, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(envelope.RiskReport, rawObject, rawNull); err != nil {
		return nil, err
	}
	trimmedRiskReport := bytes.TrimSpace(envelope.RiskReport)
	if len(trimmedRiskReport) == 0 || bytes.Equal(trimmedRiskReport, []byte("null")) {
		return nil, nil
	}

	var report scoreRiskReportEnvelope
	if err := json.Unmarshal(envelope.RiskReport, &report); err != nil {
		return nil, err
	}
	if err := validateRawShape(report.GeneratedAt, rawString, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(report.TopN, rawArray, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(report.Ranked, rawArray, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(report.Repos, rawArray, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(report.ActionPaths, rawArray, rawNull); err != nil {
		return nil, err
	}
	if err := validateRawShape(report.ActionPathToControlFirst, rawObject, rawNull); err != nil {
		return nil, err
	}
	return &report, nil
}

type rawShapeKind string

const (
	rawArray  rawShapeKind = "array"
	rawOther  rawShapeKind = "other"
	rawNull   rawShapeKind = "null"
	rawObject rawShapeKind = "object"
	rawString rawShapeKind = "string"
)

func validateRawShape(raw json.RawMessage, allowed ...rawShapeKind) error {
	kind := detectRawShape(raw)
	if kind == "" {
		return nil
	}
	for _, candidate := range allowed {
		if kind == candidate {
			return nil
		}
	}
	return fmt.Errorf("unexpected JSON %s", kind)
}

func detectRawShape(raw json.RawMessage) rawShapeKind {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return rawNull
	}
	switch trimmed[0] {
	case '{':
		return rawObject
	case '[':
		return rawArray
	case '"':
		return rawString
	default:
		return rawOther
	}
}

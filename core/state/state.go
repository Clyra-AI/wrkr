package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

const SnapshotVersion = "v1"
const ApprovalInventoryVersion = "1"

const (
	maxSavedAttackPaths           = 150
	maxSavedActionPaths           = 150
	maxSavedBacklogItems          = 150
	maxSavedGraphNodes            = 5000
	maxSavedGraphEdges            = 7500
	maxSavedWorkflowChains        = 150
	maxSavedRankedFindings        = 200
	maxSavedRepoExposureSummaries = 150
)

// Snapshot stores deterministic scan material for diff mode.
type Snapshot struct {
	Version                    string                         `json:"version"`
	ApprovalInventoryVersion   string                         `json:"approval_inventory_version,omitempty"`
	Target                     source.Target                  `json:"target"`
	Targets                    []source.Target                `json:"targets,omitempty"`
	Findings                   []source.Finding               `json:"findings"`
	PolicyOutcomes             []outputsignal.PolicyOutcome   `json:"policy_outcomes,omitempty"`
	Inventory                  *agginventory.Inventory        `json:"inventory,omitempty"`
	ControlBacklog             *controlbacklog.Backlog        `json:"control_backlog,omitempty"`
	LifecycleGaps              []lifecycle.Gap                `json:"lifecycle_gaps,omitempty"`
	ScanQuality                *scanquality.Report            `json:"scan_quality,omitempty"`
	ScanMode                   string                         `json:"scan_mode,omitempty"`
	RiskReport                 *risk.Report                   `json:"risk_report,omitempty"`
	SuppressedCounts           *outputsignal.SuppressedCounts `json:"suppressed_counts,omitempty"`
	Profile                    *profileeval.Result            `json:"profile,omitempty"`
	PostureScore               *score.Result                  `json:"posture_score,omitempty"`
	Identities                 []manifest.IdentityRecord      `json:"identities,omitempty"`
	Transitions                []lifecycle.Transition         `json:"lifecycle_transitions,omitempty"`
	SourcePrivacy              *sourceprivacy.Contract        `json:"source_privacy,omitempty"`
	PublicEvidenceManifestName string                         `json:"public_evidence_manifest_name,omitempty"`
	PublicEvidence             []source.PublicEvidence        `json:"public_evidence,omitempty"`
}

type ScoreView struct {
	Findings        []source.Finding
	PolicyOutcomes  []outputsignal.PolicyOutcome
	PostureScore    *score.Result
	Identities      []manifest.IdentityRecord
	TransitionCount int
	AttackPaths     []riskattack.ScoredPath
	TopAttackPaths  []riskattack.ScoredPath
	HasRiskReport   bool
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
	snapshot = FinalizeSnapshotForOutput(snapshot)
	applySnapshotSignalCaps(&snapshot)
	if err := atomicwrite.WriteFileFunc(path, 0o600, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(snapshot)
	}); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

func FinalizeSnapshotForOutput(snapshot Snapshot) Snapshot {
	snapshot = cloneSnapshotForSave(snapshot)
	snapshot.Version = SnapshotVersion
	snapshot.ApprovalInventoryVersion = ApprovalInventoryVersion
	snapshot.Targets = source.SortTargets(snapshot.Targets)
	snapshot.PublicEvidence = source.SortPublicEvidence(snapshot.PublicEvidence)
	source.SortFindings(snapshot.Findings)
	if len(snapshot.PolicyOutcomes) == 0 {
		snapshot.PolicyOutcomes = outputsignal.BuildPolicyOutcomes(snapshot.Findings)
	}
	canonicalizeSnapshotForOutput(&snapshot)
	return snapshot
}

func cloneSnapshotForSave(in Snapshot) Snapshot {
	out := in
	out.PolicyOutcomes = append([]outputsignal.PolicyOutcome(nil), in.PolicyOutcomes...)
	if in.SuppressedCounts != nil {
		copyCounts := *in.SuppressedCounts
		out.SuppressedCounts = &copyCounts
	}
	if in.Inventory != nil {
		copyInventory := *in.Inventory
		copyInventory.Tools = append([]agginventory.Tool(nil), in.Inventory.Tools...)
		copyInventory.Agents = append([]agginventory.Agent(nil), in.Inventory.Agents...)
		copyInventory.AgentPrivilegeMap = append([]agginventory.AgentPrivilegeMapEntry(nil), in.Inventory.AgentPrivilegeMap...)
		out.Inventory = &copyInventory
	}
	if in.RiskReport != nil {
		copyReport := *in.RiskReport
		copyReport.TopN = append([]risk.ScoredFinding(nil), in.RiskReport.TopN...)
		copyReport.Ranked = append([]risk.ScoredFinding(nil), in.RiskReport.Ranked...)
		copyReport.Repos = append([]risk.RepoAggregate(nil), in.RiskReport.Repos...)
		copyReport.AttackPaths = append([]riskattack.ScoredPath(nil), in.RiskReport.AttackPaths...)
		copyReport.TopAttackPaths = append([]riskattack.ScoredPath(nil), in.RiskReport.TopAttackPaths...)
		copyReport.ActionPaths = append([]risk.ActionPath(nil), in.RiskReport.ActionPaths...)
		out.RiskReport = &copyReport
	}
	if in.ControlBacklog != nil {
		copyBacklog := *in.ControlBacklog
		copyBacklog.Items = append([]controlbacklog.Item(nil), in.ControlBacklog.Items...)
		out.ControlBacklog = &copyBacklog
	}
	return out
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
	if snapshot.ApprovalInventoryVersion == "" {
		snapshot.ApprovalInventoryVersion = ApprovalInventoryVersion
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
	snapshot.PublicEvidence = source.SortPublicEvidence(snapshot.PublicEvidence)
	source.SortFindings(snapshot.Findings)
	normalizeSnapshotAfterLoad(&snapshot)
	return snapshot, nil
}

func normalizeSnapshotAfterLoad(snapshot *Snapshot) {
	if snapshot == nil {
		return
	}
	if len(snapshot.PolicyOutcomes) == 0 {
		snapshot.PolicyOutcomes = outputsignal.BuildPolicyOutcomes(snapshot.Findings)
	}
	if snapshot.Inventory != nil {
		agginventory.EnsureCanonicalStores(snapshot.Inventory)
		agginventory.HydrateCanonicalProjectionDetails(snapshot.Inventory)
	}
	if snapshot.RiskReport != nil {
		snapshot.RiskReport.ActionPaths = risk.BackfillCanonicalProjectionRefs(snapshot.RiskReport.ActionPaths, snapshot.Inventory)
		snapshot.RiskReport.ActionPaths = risk.HydrateCanonicalProjectionDetails(snapshot.RiskReport.ActionPaths, snapshot.Inventory)
		snapshot.RiskReport.ActionPathToControlFirst = risk.BackfillActionPathToControlFirstCanonicalProjectionRefs(snapshot.RiskReport.ActionPathToControlFirst, snapshot.Inventory)
		snapshot.RiskReport.ActionPathToControlFirst = risk.HydrateActionPathToControlFirstCanonicalDetails(snapshot.RiskReport.ActionPathToControlFirst, snapshot.Inventory)
	}
	if snapshot.ControlBacklog != nil {
		snapshot.ControlBacklog = controlbacklog.BackfillCanonicalProjectionRefs(snapshot.ControlBacklog)
		snapshot.ControlBacklog = controlbacklog.HydrateCanonicalProjectionDetails(snapshot.ControlBacklog, snapshot.Inventory)
	}
}

func prepareSnapshotForSave(snapshot *Snapshot) {
	canonicalizeSnapshotForOutput(snapshot)
	applySnapshotSignalCaps(snapshot)
}

func canonicalizeSnapshotForOutput(snapshot *Snapshot) {
	if snapshot == nil {
		return
	}
	if len(snapshot.PolicyOutcomes) == 0 {
		snapshot.PolicyOutcomes = outputsignal.BuildPolicyOutcomes(snapshot.Findings)
	}
	ensureSnapshotCanonicalStores(snapshot)
	if snapshot.Inventory != nil {
		agginventory.EnsureCanonicalStores(snapshot.Inventory)
		agginventory.StripCanonicalProjectionDetails(snapshot.Inventory)
	}
	if snapshot.RiskReport != nil {
		snapshot.RiskReport.ActionPaths = risk.BackfillCanonicalProjectionRefs(snapshot.RiskReport.ActionPaths, snapshot.Inventory)
		snapshot.RiskReport.ActionPaths = risk.StripCanonicalProjectionDetails(snapshot.RiskReport.ActionPaths)
		snapshot.RiskReport.ActionPathToControlFirst = risk.BackfillActionPathToControlFirstCanonicalProjectionRefs(snapshot.RiskReport.ActionPathToControlFirst, snapshot.Inventory)
		snapshot.RiskReport.ActionPathToControlFirst = risk.StripActionPathToControlFirstCanonicalProjectionDetails(snapshot.RiskReport.ActionPathToControlFirst)
		snapshot.RiskReport.ControlPathGraph = aggattack.StripCanonicalProjectionDetails(snapshot.RiskReport.ControlPathGraph)
	}
	if snapshot.ControlBacklog != nil {
		snapshot.ControlBacklog = controlbacklog.BackfillCanonicalProjectionRefs(snapshot.ControlBacklog)
		snapshot.ControlBacklog = controlbacklog.StripCanonicalProjectionDetails(snapshot.ControlBacklog)
	}
}

func applySnapshotSignalCaps(snapshot *Snapshot) {
	if snapshot == nil {
		return
	}
	suppressed := &outputsignal.SuppressedCounts{}

	if snapshot.Inventory != nil {
		snapshot.Inventory.RepoExposureSummaries, suppressed.RepoExposureSummaries = outputsignal.CapSlice(snapshot.Inventory.RepoExposureSummaries, maxSavedRepoExposureSummaries)
	}
	if snapshot.RiskReport != nil {
		snapshot.RiskReport.Ranked, suppressed.RankedFindings = outputsignal.CapSlice(snapshot.RiskReport.Ranked, maxSavedRankedFindings)
		snapshot.RiskReport.AttackPaths, suppressed.AttackPaths = outputsignal.CapSlice(snapshot.RiskReport.AttackPaths, maxSavedAttackPaths)
		snapshot.RiskReport.ActionPaths, suppressed.ActionPaths = outputsignal.CapSlice(snapshot.RiskReport.ActionPaths, maxSavedActionPaths)
		if snapshot.RiskReport.ControlPathGraph != nil {
			snapshot.RiskReport.ControlPathGraph.Nodes, suppressed.GraphNodes = outputsignal.CapSlice(snapshot.RiskReport.ControlPathGraph.Nodes, maxSavedGraphNodes)
			snapshot.RiskReport.ControlPathGraph.Edges, suppressed.GraphEdges = outputsignal.CapSlice(snapshot.RiskReport.ControlPathGraph.Edges, maxSavedGraphEdges)
		}
		if snapshot.RiskReport.WorkflowChains != nil {
			snapshot.RiskReport.WorkflowChains.Chains, suppressed.WorkflowChains = outputsignal.CapSlice(snapshot.RiskReport.WorkflowChains.Chains, maxSavedWorkflowChains)
		}
	}
	if snapshot.ControlBacklog != nil {
		snapshot.ControlBacklog.Items, suppressed.ControlBacklog = outputsignal.CapSlice(snapshot.ControlBacklog.Items, maxSavedBacklogItems)
	}

	snapshot.SuppressedCounts = outputsignal.MergeSuppressedCounts(snapshot.SuppressedCounts, suppressed)
}

func ensureSnapshotCanonicalStores(snapshot *Snapshot) {
	if snapshot == nil {
		return
	}
	if snapshot.Inventory == nil && !snapshotHasProjectionCanonicalDetails(snapshot) {
		return
	}
	if snapshot.Inventory == nil {
		snapshot.Inventory = &agginventory.Inventory{}
	}
	agginventory.EnsureCanonicalStores(snapshot.Inventory)
	agginventory.AugmentCanonicalStores(
		snapshot.Inventory,
		snapshotMutableEndpointGroups(snapshot),
		snapshotCredentialAuthorities(snapshot),
		snapshotAuthorityBindingGroups(snapshot),
	)
}

func snapshotHasProjectionCanonicalDetails(snapshot *Snapshot) bool {
	if snapshot == nil {
		return false
	}
	for _, path := range snapshotRiskActionPaths(snapshot) {
		if len(path.MutableEndpointSemantics) > 0 || path.CredentialAuthority != nil || len(path.AuthorityBindings) > 0 {
			return true
		}
	}
	if snapshot.ControlBacklog != nil {
		for _, item := range snapshot.ControlBacklog.Items {
			if item.CredentialAuthority != nil || len(item.AuthorityBindings) > 0 {
				return true
			}
		}
	}
	return false
}

func snapshotRiskActionPaths(snapshot *Snapshot) []risk.ActionPath {
	if snapshot == nil || snapshot.RiskReport == nil {
		return nil
	}
	paths := append([]risk.ActionPath(nil), snapshot.RiskReport.ActionPaths...)
	if snapshot.RiskReport.ActionPathToControlFirst != nil {
		paths = append(paths, snapshot.RiskReport.ActionPathToControlFirst.Path)
	}
	return paths
}

func snapshotMutableEndpointGroups(snapshot *Snapshot) [][]agginventory.MutableEndpointSemantic {
	paths := snapshotRiskActionPaths(snapshot)
	if len(paths) == 0 {
		return nil
	}
	groups := make([][]agginventory.MutableEndpointSemantic, 0, len(paths))
	for _, path := range paths {
		if len(path.MutableEndpointSemantics) == 0 {
			continue
		}
		groups = append(groups, path.MutableEndpointSemantics)
	}
	return groups
}

func snapshotCredentialAuthorities(snapshot *Snapshot) []*agginventory.CredentialAuthority {
	paths := snapshotRiskActionPaths(snapshot)
	authorities := make([]*agginventory.CredentialAuthority, 0, len(paths))
	for _, path := range paths {
		if path.CredentialAuthority != nil {
			authorities = append(authorities, path.CredentialAuthority)
		}
	}
	if snapshot != nil && snapshot.ControlBacklog != nil {
		for _, item := range snapshot.ControlBacklog.Items {
			if item.CredentialAuthority != nil {
				authorities = append(authorities, item.CredentialAuthority)
			}
		}
	}
	return authorities
}

func snapshotAuthorityBindingGroups(snapshot *Snapshot) [][]*agginventory.AuthorityBinding {
	paths := snapshotRiskActionPaths(snapshot)
	groups := make([][]*agginventory.AuthorityBinding, 0, len(paths))
	for _, path := range paths {
		if len(path.AuthorityBindings) > 0 {
			groups = append(groups, path.AuthorityBindings)
		}
	}
	if snapshot != nil && snapshot.ControlBacklog != nil {
		for _, item := range snapshot.ControlBacklog.Items {
			if len(item.AuthorityBindings) > 0 {
				groups = append(groups, item.AuthorityBindings)
			}
		}
	}
	return groups
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
			view.HasRiskReport = true
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
		PolicyOutcomes:  snapshot.PolicyOutcomes,
		PostureScore:    snapshot.PostureScore,
		Identities:      snapshot.Identities,
		TransitionCount: len(snapshot.Transitions),
		AttackPaths:     attackPaths,
		TopAttackPaths:  topAttackPaths,
		HasRiskReport:   snapshot.RiskReport != nil,
	}, nil
}

func validateCachedScoreSnapshot(envelope scoreSnapshotEnvelope) (*scoreRiskReportEnvelope, error) {
	if err := validateRequiredRawShape(envelope.Target, rawObject); err != nil {
		return nil, err
	}
	if err := validateRawShape(envelope.Targets, rawArray, rawNull); err != nil {
		return nil, err
	}
	if err := validateRequiredRawShape(envelope.Findings, rawArray, rawNull); err != nil {
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

func validateRequiredRawShape(raw json.RawMessage, allowed ...rawShapeKind) error {
	kind := detectRawShape(raw)
	if kind == "" {
		return fmt.Errorf("missing required JSON value")
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

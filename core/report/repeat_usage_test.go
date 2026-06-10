package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildSummaryIncludesRepeatUsageSignals(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	stateDir := filepath.Join(root, ".wrkr")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	statePath := filepath.Join(stateDir, "last-scan.json")
	if err := os.WriteFile(filepath.Join(stateDir, "wrkr-regress-baseline.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	firstAssess := filepath.Join(root, "wrkr-assessment")
	secondAssess := filepath.Join(root, "wrkr-assessment-rerun")
	for _, dir := range []string{
		filepath.Join(firstAssess, "export"),
		filepath.Join(firstAssess, "report"),
		filepath.Join(firstAssess, "regress"),
		filepath.Join(secondAssess, "export"),
		filepath.Join(secondAssess, "report"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir artifact dir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(firstAssess, "export", "export-pack.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write export pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(firstAssess, "export", "tickets-jira.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write ticket export: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secondAssess, "export", "export-pack.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write second export pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(firstAssess, "regress", "drift.json"), []byte("{\"status\":\"drift_detected\"}\n"), 0o600); err != nil {
		t.Fatalf("write drift artifact: %v", err)
	}
	for _, reportDir := range []string{
		filepath.Join(firstAssess, "report"),
		filepath.Join(secondAssess, "report"),
	} {
		if err := os.WriteFile(filepath.Join(reportDir, "wrkr-report.md"), []byte("# report\n"), 0o600); err != nil {
			t.Fatalf("write report markdown: %v", err)
		}
	}

	evidenceDir := filepath.Join(root, "wrkr-evidence")
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		t.Fatalf("mkdir evidence dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(evidenceDir, ".wrkr-evidence-managed"), []byte("managed by wrkr evidence build\n"), 0o600); err != nil {
		t.Fatalf("write evidence marker: %v", err)
	}

	summary, err := BuildSummary(BuildInput{
		StatePath: statePath,
		Snapshot: state.Snapshot{
			Target: source.Target{Mode: "path", Value: filepath.Join(root, "repo")},
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                   "apc-repeat-use",
					Org:                      "acme",
					Repo:                     "acme/payments",
					ToolType:                 "compiled_action",
					Location:                 ".github/workflows/release.yml",
					WriteCapable:             true,
					CredentialAccess:         true,
					ControlPriority:          risk.ControlPriorityControlFirst,
					ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
					DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
					RecommendedControl:       risk.RecommendedControlApprovalRequired,
					ApprovalEvidenceState:    risk.EvidenceStateUnknown,
					OwnerEvidenceState:       risk.EvidenceStateUnknown,
					ProofEvidenceState:       risk.EvidenceStateUnknown,
					ControlResolutionState:   risk.ControlResolutionStateNoVisibleControl,
				}},
			},
		},
		GeneratedAt: time.Date(2026, 6, 10, 15, 4, 5, 0, time.UTC),
		Template:    TemplateAgentActionBOM,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.RepeatUsageSignals == nil {
		t.Fatal("expected summary repeat_usage_signals")
	}
	if summary.RepeatUsageSignals.Status != "repeat_use_detected" {
		t.Fatalf("expected repeat_use_detected status, got %+v", summary.RepeatUsageSignals)
	}
	if !summary.RepeatUsageSignals.BaselinePresent {
		t.Fatalf("expected baseline_present, got %+v", summary.RepeatUsageSignals)
	}
	if !summary.RepeatUsageSignals.AssessRerunDetected {
		t.Fatalf("expected assess rerun detection, got %+v", summary.RepeatUsageSignals)
	}
	if summary.RepeatUsageSignals.AssessRuns != 2 {
		t.Fatalf("expected 2 assess runs, got %+v", summary.RepeatUsageSignals)
	}
	if summary.RepeatUsageSignals.DriftArtifacts != 1 {
		t.Fatalf("expected 1 drift artifact, got %+v", summary.RepeatUsageSignals)
	}
	if summary.RepeatUsageSignals.EvidenceExports != 1 {
		t.Fatalf("expected 1 evidence export, got %+v", summary.RepeatUsageSignals)
	}
	if summary.RepeatUsageSignals.TicketExports != 1 {
		t.Fatalf("expected 1 ticket export, got %+v", summary.RepeatUsageSignals)
	}
	if summary.RepeatUsageSignals.ActionContractExports != 2 {
		t.Fatalf("expected 2 action contract exports, got %+v", summary.RepeatUsageSignals)
	}
	if summary.AgentActionBOM == nil || summary.AgentActionBOM.Summary.RepeatUsageSignals == nil {
		t.Fatalf("expected BOM repeat_usage_signals, got %+v", summary.AgentActionBOM)
	}
	if summary.AgentActionBOM.Summary.RepeatUsageSignals.AssessRuns != summary.RepeatUsageSignals.AssessRuns {
		t.Fatalf("expected BOM repeat-usage signals to mirror summary, summary=%+v bom=%+v", summary.RepeatUsageSignals, summary.AgentActionBOM.Summary.RepeatUsageSignals)
	}
}

func TestRepeatUsageSignalsRemainShareSafe(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	stateDir := filepath.Join(root, ".wrkr")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	statePath := filepath.Join(stateDir, "last-scan.json")
	if err := os.WriteFile(filepath.Join(stateDir, "wrkr-regress-baseline.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	reportDir := filepath.Join(root, "wrkr-assessment", "report")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		t.Fatalf("mkdir report dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reportDir, "wrkr-report.md"), []byte("# report\n"), 0o600); err != nil {
		t.Fatalf("write report markdown: %v", err)
	}

	summary, err := BuildSummary(BuildInput{
		StatePath: statePath,
		Snapshot: state.Snapshot{
			Target: source.Target{Mode: "path", Value: filepath.Join(root, "repo")},
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                 "apc-share-safe",
					Org:                    "acme",
					Repo:                   "acme/payments",
					ToolType:               "compiled_action",
					Location:               ".github/workflows/release.yml",
					WriteCapable:           true,
					CredentialAccess:       true,
					ControlPriority:        risk.ControlPriorityControlFirst,
					ConfidenceLane:         risk.ConfidenceLaneConfirmedActionPath,
					ControlResolutionState: risk.ControlResolutionStateNoVisibleControl,
				}},
			},
		},
		GeneratedAt:  time.Date(2026, 6, 10, 15, 4, 5, 0, time.UTC),
		Template:     TemplateAgentActionBOM,
		ShareProfile: ShareProfileCustomerRedacted,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}

	payload, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	if strings.Contains(string(payload), root) {
		t.Fatalf("expected repeat-usage signals to avoid local paths, got %s", string(payload))
	}
	if !strings.Contains(string(payload), "\"repeat_usage_signals\"") {
		t.Fatalf("expected repeat_usage_signals in payload, got %s", string(payload))
	}
}

func TestBuildRepeatUsageSignalsSkipsNonArtifactRepoDirs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	stateDir := filepath.Join(root, ".wrkr")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	statePath := filepath.Join(stateDir, "last-scan.json")
	if err := os.WriteFile(filepath.Join(stateDir, "wrkr-regress-baseline.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "export-pack.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write false-positive export pack: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
		t.Fatalf("mkdir vendor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "vendor", "drift.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write false-positive drift artifact: %v", err)
	}

	signals := BuildRepeatUsageSignals(statePath)
	if signals == nil {
		t.Fatal("expected repeat usage signals")
	}
	if signals.ActionContractExports != 0 || signals.DriftArtifacts != 0 {
		t.Fatalf("expected non-artifact repo dirs to be ignored, got %+v", signals)
	}
	if signals.Status != repeatUsageStatusFollowUpReady {
		t.Fatalf("expected follow_up_ready from baseline only, got %+v", signals)
	}
}

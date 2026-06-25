package risk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/attribution"
)

func TestImportedBranchProtectionCoversMatchingPath(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr", "provenance"), 0o755); err != nil {
		t.Fatalf("mkdir provenance dir: %v", err)
	}
	payload := `{
  "schema_version": "v1",
  "generated_at": "2026-06-25T12:00:00Z",
  "records": [
    {
      "record_kind": "external_control",
      "source_type": "provider_export",
      "source": "github_branch_protection_export",
      "repo": "acme/release",
      "resolution_key": "rk-release-governed",
      "observed_at": "2026-06-25T11:00:00Z",
      "evidence_class": "branch_protection",
      "status": "matched",
      "evidence_refs": ["evidence://provider/branch-protection.json#main"]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "provenance", "external-control-evidence.json"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write external control evidence: %v", err)
	}

	path := ActionPath{
		PathID:         "apc-release-current",
		Org:            "acme",
		Repo:           "acme/release",
		ToolType:       "compiled_action",
		Location:       ".github/workflows/release-renamed.yml",
		WriteCapable:   true,
		ActionClasses:  []string{"deploy"},
		ResolutionKey:  "rk-release-governed",
		ConfidenceLane: ConfidenceLaneConfirmedActionPath,
	}

	ctx := attribution.LoadContextAt(repoRoot, time.Date(2026, 6, 25, 12, 30, 0, 0, time.UTC))
	decorated := ProjectActionPaths(DecorateControlMetadata([]ActionPath{path}, map[string]attribution.Context{
		repoKey(path.Org, path.Repo): ctx,
	}))
	if len(decorated) != 1 {
		t.Fatalf("expected one decorated path, got %+v", decorated)
	}
	if decorated[0].ControlResolutionState != ControlResolutionStateExternalControlReference {
		t.Fatalf("expected imported branch protection to mark external control reference, got %+v", decorated[0])
	}
	if decorated[0].ApprovalEvidenceState != EvidenceStateVerified {
		t.Fatalf("expected imported branch protection to verify approval evidence, got %+v", decorated[0])
	}
	if decorated[0].ReviewLifecycleState != ReviewLifecycleStateCoveredByImportedControl {
		t.Fatalf("expected imported branch protection to move path into covered-by-imported-control lifecycle, got %+v", decorated[0])
	}
}

func TestImportedPRApprovalResolvesWorkflowApprovalEvidence(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr", "provenance"), 0o755); err != nil {
		t.Fatalf("mkdir provenance dir: %v", err)
	}
	payload := `{
  "schema_version": "v1",
  "generated_at": "2026-06-25T12:00:00Z",
  "records": [
    {
      "record_kind": "external_control",
      "source_type": "provider_export",
      "source": "github_pr_review_export",
      "repo": "acme/release",
      "workflow": ".github/workflows/release.yml",
      "observed_at": "2026-06-25T11:00:00Z",
      "evidence_class": "approval",
      "status": "matched",
      "evidence_refs": ["evidence://provider/pr-review.json#42"]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "provenance", "external-control-evidence.json"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write external control evidence: %v", err)
	}

	path := ActionPath{
		PathID:                "apc-release-workflow",
		Org:                   "acme",
		Repo:                  "acme/release",
		ToolType:              "compiled_action",
		Location:              ".github/workflows/release.yml",
		WriteCapable:          true,
		ActionClasses:         []string{"deploy"},
		ApprovalEvidenceState: EvidenceStateUnknown,
		ConfidenceLane:        ConfidenceLaneConfirmedActionPath,
	}

	ctx := attribution.LoadContextAt(repoRoot, time.Date(2026, 6, 25, 12, 30, 0, 0, time.UTC))
	decorated := ProjectActionPaths(DecorateControlMetadata([]ActionPath{path}, map[string]attribution.Context{
		repoKey(path.Org, path.Repo): ctx,
	}))
	if len(decorated) != 1 {
		t.Fatalf("expected one decorated path, got %+v", decorated)
	}
	if decorated[0].ApprovalEvidenceState != EvidenceStateVerified {
		t.Fatalf("expected imported PR approval to verify approval evidence, got %+v", decorated[0])
	}
	if decorated[0].ReviewLifecycleState != ReviewLifecycleStateCoveredByImportedControl {
		t.Fatalf("expected imported PR approval to move path into covered-by-imported-control lifecycle, got %+v", decorated[0])
	}
}

func TestNonMatchingProviderEvidenceDoesNotResolvePath(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr", "provenance"), 0o755); err != nil {
		t.Fatalf("mkdir provenance dir: %v", err)
	}
	payload := `{
  "schema_version": "v1",
  "generated_at": "2026-06-25T12:00:00Z",
  "records": [
    {
      "record_kind": "external_control",
      "source_type": "provider_export",
      "source": "github_environment_export",
      "repo": "acme/release",
      "resolution_key": "rk-other-path",
      "observed_at": "2026-06-25T11:00:00Z",
      "evidence_class": "deployment_approval",
      "status": "matched",
      "evidence_refs": ["evidence://provider/environment.json#prod"]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "provenance", "external-control-evidence.json"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write external control evidence: %v", err)
	}

	path := ProjectActionPath(ActionPath{
		PathID:         "apc-release-current",
		Org:            "acme",
		Repo:           "acme/release",
		ToolType:       "compiled_action",
		Location:       ".github/workflows/release.yml",
		WriteCapable:   true,
		ActionClasses:  []string{"deploy"},
		ResolutionKey:  "rk-release-current",
		ConfidenceLane: ConfidenceLaneConfirmedActionPath,
	})

	ctx := attribution.LoadContextAt(repoRoot, time.Date(2026, 6, 25, 12, 30, 0, 0, time.UTC))
	decorated := ProjectActionPaths(DecorateControlMetadata([]ActionPath{path}, map[string]attribution.Context{
		repoKey(path.Org, path.Repo): ctx,
	}))
	if len(decorated) != 1 {
		t.Fatalf("expected one decorated path, got %+v", decorated)
	}
	if decorated[0].ControlResolutionState == ControlResolutionStateExternalControlReference {
		t.Fatalf("expected non-matching imported control to stay unresolved, got %+v", decorated[0])
	}
	if decorated[0].ReviewLifecycleState == ReviewLifecycleStateCoveredByImportedControl {
		t.Fatalf("expected non-matching imported control not to change lifecycle state, got %+v", decorated[0])
	}
}

func TestGovernedCIDoesNotRankAsTopControlFirst(t *testing.T) {
	t.Parallel()

	path := ProjectActionPath(ActionPath{
		PathID:                 "apc-governed-ci",
		Org:                    "acme",
		Repo:                   "acme/platform",
		ToolType:               "compiled_action",
		Location:               ".github/workflows/ci.yml",
		WriteCapable:           true,
		CredentialAccess:       true,
		ActionClasses:          []string{"write"},
		ActionPathType:         ActionPathTypeCICDWorkflow,
		ControlResolutionState: ControlResolutionStateExternalControlReference,
		ConstraintEvidenceClasses: []string{
			"branch_protection",
			"required_check",
		},
		ConstraintEvidenceRefs: []string{
			"evidence://provider/branch-protection.json#main",
			"evidence://provider/required-checks.json#fast-lane",
		},
		ControlEvidenceRefs: []string{
			"evidence://provider/branch-protection.json#main",
		},
		ApprovalEvidenceState: EvidenceStateVerified,
		OwnerEvidenceState:    EvidenceStateVerified,
		ProofEvidenceState:    EvidenceStateVerified,
		ConfidenceLane:        ConfidenceLaneConfirmedActionPath,
	})

	if path.CIFlowClass != CIFlowClassStandardGovernedCI {
		t.Fatalf("expected governed CI classification, got %+v", path)
	}
	if path.ControlPriority == ControlPriorityControlFirst {
		t.Fatalf("expected governed CI to stay out of top control-first ranking, got %+v", path)
	}
}

func TestUnknownAuthorityAvoidsStandingCredentialRemediation(t *testing.T) {
	t.Parallel()

	path := ProjectActionPath(ActionPath{
		PathID:                 "apc-unknown-authority",
		Org:                    "acme",
		Repo:                   "acme/platform",
		ToolType:               "mcp",
		Location:               ".cursor/mcp.json",
		WriteCapable:           true,
		CredentialAccess:       true,
		ActionPathType:         ActionPathTypeAgentFramework,
		OwnerEvidenceState:     EvidenceStateVerified,
		ApprovalEvidenceState:  EvidenceStateVerified,
		ProofEvidenceState:     EvidenceStateUnknown,
		ControlResolutionState: ControlResolutionStateNoVisibleControl,
		ConfidenceLane:         ConfidenceLaneConfirmedActionPath,
		ControlPriority:        ControlPriorityReviewQueue,
	})

	if path.RecommendedActionContract == nil {
		t.Fatalf("expected recommended action contract, got %+v", path)
	}
	requiredAuthority := strings.ToLower(path.RecommendedActionContract.RequiredAuthority)
	if strings.Contains(requiredAuthority, "workload or brokered authority") || strings.Contains(requiredAuthority, "standing credential") {
		t.Fatalf("expected unknown authority to avoid direct standing-credential remediation, got %+v", path.RecommendedActionContract)
	}
	if !strings.Contains(requiredAuthority, "classif") && !strings.Contains(requiredAuthority, "correlat") {
		t.Fatalf("expected unknown authority guidance to ask for authority classification or correlation, got %+v", path.RecommendedActionContract)
	}
}

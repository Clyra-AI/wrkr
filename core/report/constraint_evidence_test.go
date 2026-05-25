package report

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestWorkflowDeploymentConstraintCorrelation(t *testing.T) {
	t.Parallel()

	paths := decorateActionPathsForReport([]risk.ActionPath{{
		PathID:                    "apc-release-1",
		Repo:                      "acme/payments",
		Location:                  ".github/workflows/release.yml",
		DeployWrite:               true,
		ConstraintEvidenceClasses: []string{"protected_environment", "deployment_approval"},
		ConstraintEvidenceRefs:    []string{"gait.yaml#environment=production"},
		ConstraintEvidenceStatus:  "matched",
	}}, nil)
	if len(paths) != 1 || paths[0].GaitCoverage == nil {
		t.Fatalf("expected gait coverage, got %+v", paths)
	}
	if paths[0].GaitCoverage.Approval.Status != risk.GaitStatusPresent {
		t.Fatalf("expected protected-environment constraint to satisfy approval coverage, got %+v", paths[0].GaitCoverage)
	}
}

func TestStaleDeploymentConstraintDoesNotVerifyControl(t *testing.T) {
	t.Parallel()

	paths := decorateActionPathsForReport([]risk.ActionPath{{
		PathID:                    "apc-release-1",
		Repo:                      "acme/payments",
		Location:                  ".github/workflows/release.yml",
		DeployWrite:               true,
		ApprovalEvidenceState:     risk.EvidenceStateUnknown,
		ConstraintEvidenceClasses: []string{"protected_environment", "deployment_approval"},
		ConstraintEvidenceRefs:    []string{"provider-export.json#environment=production"},
		ConstraintEvidenceStatus:  "stale",
	}}, nil)
	if len(paths) != 1 || paths[0].GaitCoverage == nil {
		t.Fatalf("expected gait coverage, got %+v", paths)
	}
	if paths[0].GaitCoverage.Approval.Status != risk.GaitStatusStale {
		t.Fatalf("expected stale protected-environment evidence to stay stale, got %+v", paths[0].GaitCoverage)
	}
	if paths[0].ApprovalEvidenceState != risk.EvidenceStateUnknown {
		t.Fatalf("expected stale constraint evidence not to verify approval state, got %+v", paths[0])
	}
}

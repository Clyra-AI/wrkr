package risk

import (
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

func TestClosureRequirementsForUnknownOwnerAndApproval(t *testing.T) {
	t.Parallel()

	paths := DecorateEvidenceContext([]ActionPath{{
		PathID:                 "apc-owner-approval",
		Org:                    "acme",
		Repo:                   "platform",
		ToolType:               "compiled_action",
		Location:               ".github/workflows/release.yml",
		WriteCapable:           true,
		DeployWrite:            true,
		ApprovalGap:            true,
		ApprovalGapReasons:     []string{"approval_source_missing"},
		OwnerEvidenceState:     EvidenceStateUnknown,
		ControlResolutionState: ControlResolutionStateNoVisibleControl,
		PolicyCoverageStatus:   PolicyCoverageStatusNone,
		ConfidenceLane:         ConfidenceLaneConfirmedActionPath,
		ActionPathType:         ActionPathTypeCICDWorkflow,
		ControlPriority:        ControlPriorityControlFirst,
		RiskTier:               RiskTierHigh,
	}}, nil)

	if len(paths) != 1 {
		t.Fatalf("expected one path, got %+v", paths)
	}
	requirements := paths[0].ClosureRequirements
	if _, ok := findClosureRequirement(requirements, ClosureRequirementAssignOwner); !ok {
		t.Fatalf("expected assign_owner requirement, got %+v", requirements)
	}
	if _, ok := findClosureRequirement(requirements, ClosureRequirementAttachApproval); !ok {
		t.Fatalf("expected attach_approval requirement, got %+v", requirements)
	}
	policyRequirement, ok := findClosureRequirement(requirements, ClosureRequirementAttachPolicyReference)
	if !ok {
		t.Fatalf("expected attach_policy_reference requirement, got %+v", requirements)
	}
	if !strings.Contains(strings.ToLower(policyRequirement.Guidance), "policy") {
		t.Fatalf("expected policy guidance, got %+v", policyRequirement)
	}
}

func TestClosureRequirementsForExpiredEvidenceAndRuntimeGap(t *testing.T) {
	t.Parallel()

	paths := DecorateEvidenceContext([]ActionPath{{
		PathID:               "apc-expired-runtime",
		Org:                  "acme",
		Repo:                 "payments",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/deploy.yml",
		WriteCapable:         true,
		DeployWrite:          true,
		ProductionWrite:      true,
		CredentialAccess:     true,
		CredentialProvenance: &credentialProvenanceJIT,
		EvidenceDecisions: []evidencepolicy.Decision{{
			Field:                  evidencepolicy.FieldApproval,
			SelectedSourceType:     evidencepolicy.SourceTypeProviderExport,
			SelectedFreshnessState: evidencepolicy.FreshnessStateExpired,
			SelectedEvidenceRefs:   []string{"evidence://approval/export.json#release"},
		}},
		GaitCoverage: &GaitCoverage{
			PolicyDecision: GaitCoverageDetail{
				Status:  GaitStatusMissing,
				Reasons: []string{"runtime_absence_status:" + RuntimeEvidenceAbsenceNotCollected},
			},
		},
		PolicyCoverageStatus: PolicyCoverageStatusMatched,
		PolicyEvidenceRefs:   []string{"policy://release-gate"},
		ControlPriority:      ControlPriorityControlFirst,
		RiskTier:             RiskTierHigh,
	}}, nil)

	requirements := paths[0].ClosureRequirements
	if _, ok := findClosureRequirement(requirements, ClosureRequirementRefreshExpiredEvidence); !ok {
		t.Fatalf("expected refresh_expired_evidence requirement, got %+v", requirements)
	}
	if _, ok := findClosureRequirement(requirements, ClosureRequirementProveJITCredential); !ok {
		t.Fatalf("expected prove_jit_credential requirement, got %+v", requirements)
	}
	if _, ok := findClosureRequirement(requirements, ClosureRequirementProveDeploymentConstraint); !ok {
		t.Fatalf("expected deployment constraint requirement, got %+v", requirements)
	}
}

func TestClosureRequirementsForAcceptedInternalTooling(t *testing.T) {
	t.Parallel()

	paths := DecorateEvidenceContext([]ActionPath{{
		PathID:              "apc-internal-tooling",
		Org:                 "acme",
		Repo:                "platform",
		ToolType:            "codex",
		Location:            ".codex/config.toml",
		ConfidenceLane:      ConfidenceLaneLikelyActionPath,
		ActionPathType:      ActionPathTypeAgentFramework,
		TargetClass:         TargetClassInternalTooling,
		TargetEvidenceState: EvidenceStateDeclared,
		ControlPriority:     ControlPriorityReviewQueue,
		RiskTier:            RiskTierMedium,
	}}, nil)

	requirement, ok := findClosureRequirement(paths[0].ClosureRequirements, ClosureRequirementAcceptInternalTooling)
	if !ok {
		t.Fatalf("expected accepted internal tooling requirement, got %+v", paths[0].ClosureRequirements)
	}
	if !strings.Contains(strings.ToLower(requirement.Guidance), "internal-only") {
		t.Fatalf("expected internal-tooling guidance, got %+v", requirement)
	}
}

func TestEvidenceCompletenessAxes(t *testing.T) {
	t.Parallel()

	paths := DecorateEvidenceContext([]ActionPath{{
		PathID:                  "apc-complete",
		Org:                     "acme",
		Repo:                    "platform",
		ToolType:                "compiled_action",
		Location:                ".github/workflows/release.yml",
		WriteCapable:            true,
		DeployWrite:             true,
		ProductionWrite:         true,
		ApprovalEvidenceState:   EvidenceStateVerified,
		OwnerEvidenceState:      EvidenceStateVerified,
		ProofEvidenceState:      EvidenceStateVerified,
		RuntimeEvidenceState:    EvidenceStateVerified,
		TargetEvidenceState:     EvidenceStateVerified,
		CredentialEvidenceState: EvidenceStateVerified,
		ControlResolutionState:  ControlResolutionStateDetectedControl,
		ConstraintEvidenceRefs:  []string{"constraint://release-gate"},
		PolicyCoverageStatus:    PolicyCoverageStatusMatched,
		PolicyEvidenceRefs:      []string{"policy://release"},
		ConfidenceLane:          ConfidenceLaneConfirmedActionPath,
		ActionPathType:          ActionPathTypeCICDWorkflow,
	}}, nil)

	completeness := paths[0].EvidenceCompleteness
	if completeness == nil {
		t.Fatal("expected completeness")
	} else {
		if completeness.TotalScore < 85 {
			t.Fatalf("expected strong completeness score, got %+v", completeness)
		}
		if completeness.Label != EvidenceCompletenessStrong {
			t.Fatalf("expected strong completeness label, got %+v", completeness)
		}
		if len(completeness.AxisScores) != len(completenessAxisOrder) {
			t.Fatalf("expected one score per completeness axis, got %+v", completeness.AxisScores)
		}
	}
}

func TestLowCompletenessDoesNotDowngradeRiskAndAccountsForReducedCoverage(t *testing.T) {
	t.Parallel()

	scanSignals := &scanquality.Report{
		Detectors: []scanquality.DetectorHealth{{
			Org:             "acme",
			Repo:            "payments",
			Detector:        "mcp",
			Status:          "reduced",
			CoverageReasons: []string{"generated_suppression"},
		}},
		AbsenceClaims: []scanquality.AbsenceClaim{{
			Org:     "acme",
			Repo:    "payments",
			Surface: scanquality.SurfaceMCPServer,
			Status:  scanquality.AbsenceStatusUnsupportedSurface,
		}},
	}
	projected := ProjectActionPath(ActionPath{
		PathID:               "apc-low-completeness",
		Org:                  "acme",
		Repo:                 "payments",
		ToolType:             "mcp",
		Location:             ".cursor/mcp.json",
		WriteCapable:         true,
		CredentialAccess:     true,
		ProductionWrite:      true,
		ApprovalGap:          true,
		OwnerEvidenceState:   EvidenceStateUnknown,
		PolicyCoverageStatus: PolicyCoverageStatusNone,
		ControlPriority:      ControlPriorityControlFirst,
		RiskTier:             RiskTierHigh,
		ConfidenceLane:       ConfidenceLaneConfirmedActionPath,
		ActionPathType:       ActionPathTypeAgentFramework,
	})

	paths := DecorateEvidenceContext([]ActionPath{projected}, scanSignals)
	if len(paths) != 1 {
		t.Fatalf("expected one path, got %+v", paths)
	}
	if paths[0].ControlPriority != projected.ControlPriority || paths[0].RiskTier != projected.RiskTier {
		t.Fatalf("expected completeness decoration not to change risk posture\nbefore=%+v\nafter=%+v", projected, paths[0])
	}
	completeness := paths[0].EvidenceCompleteness
	if completeness == nil || completeness.Label != EvidenceCompletenessInsufficient {
		t.Fatalf("expected insufficient completeness, got %+v", completeness)
	}
	if len(completeness.UnsupportedSurfaces) == 0 || completeness.UnsupportedSurfaces[0] != scanquality.SurfaceMCPServer {
		t.Fatalf("expected unsupported surface penalty, got %+v", completeness)
	}
	if axisScore(t, completeness, CompletenessAxisDiscovery) >= 100 {
		t.Fatalf("expected reduced discovery score, got %+v", completeness)
	}
}

func TestEvidenceCompletenessSummaryCountsReducedCoverageWithoutUnsupportedSurfaces(t *testing.T) {
	t.Parallel()

	paths := DecorateEvidenceContext([]ActionPath{{
		PathID:               "apc-reduced-coverage-summary",
		Org:                  "acme",
		Repo:                 "payments",
		ToolType:             "mcp",
		Location:             ".cursor/mcp.json",
		WriteCapable:         true,
		ConfidenceLane:       ConfidenceLaneConfirmedActionPath,
		ActionPathType:       ActionPathTypeAgentFramework,
		ControlPriority:      ControlPriorityControlFirst,
		PolicyCoverageStatus: PolicyCoverageStatusNone,
	}}, &scanquality.Report{
		Detectors: []scanquality.DetectorHealth{{
			Org:             "acme",
			Repo:            "payments",
			Detector:        "mcp",
			Status:          "reduced",
			CoverageReasons: []string{"generated_suppression"},
		}},
	})

	summary := BuildEvidenceCompletenessSummary(paths)
	if summary == nil {
		t.Fatal("expected completeness summary")
	} else if summary.ReducedCoveragePathCount != 1 {
		t.Fatalf("expected reduced coverage path count to include detector-only reduction, got %+v", summary)
	}
}

func TestClosureCopyByPathType(t *testing.T) {
	t.Parallel()

	openAPISemantics := []agginventory.MutableEndpointSemantic{{
		Semantic:     agginventory.EndpointSemanticPayment,
		Confidence:   "high",
		Surface:      "openapi",
		Operation:    "POST /v1/payments",
		EvidenceRefs: []string{"POST /v1/payments"},
	}}

	cases := []struct {
		name            string
		path            ActionPath
		requirementType string
		wantContains    []string
		wantExcludes    []string
	}{
		{
			name: "openapi target context uses caller correlation guidance",
			path: ProjectActionPath(ActionPath{
				PathID:                   "apc-openapi-closure",
				Org:                      "acme",
				Repo:                     "acme/payments",
				ToolType:                 "openapi",
				Location:                 "openapi/payments.yaml",
				WriteCapable:             true,
				MutableEndpointSemantics: openAPISemantics,
			}),
			requirementType: ClosureRequirementCorrelateSurface,
			wantContains:    []string{"API specification surface", "runtime caller"},
			wantExcludes:    []string{"approval evidence"},
		},
		{
			name: "route target context uses route-specific correlation guidance",
			path: ProjectActionPath(ActionPath{
				PathID:       "apc-route-closure",
				Org:          "acme",
				Repo:         "acme/payments",
				ToolType:     "route",
				Location:     "api/routes/payments.ts",
				WriteCapable: true,
			}),
			requirementType: ClosureRequirementCorrelateSurface,
			wantContains:    []string{"route surface", "deploy path"},
			wantExcludes:    []string{"approval evidence"},
		},
		{
			name: "agents instruction surface uses owner governance wording",
			path: ProjectActionPath(ActionPath{
				PathID:                 "apc-agents-owner",
				Org:                    "acme",
				Repo:                   "acme/app",
				ToolType:               "codex",
				Location:               "AGENTS.md",
				OwnerEvidenceState:     EvidenceStateUnknown,
				ApprovalEvidenceState:  EvidenceStateVerified,
				ProofEvidenceState:     EvidenceStateVerified,
				ControlResolutionState: ControlResolutionStateNoVisibleControl,
				ControlPriority:        ControlPriorityControlFirst,
			}),
			requirementType: ClosureRequirementAssignOwner,
			wantContains:    []string{"instruction surface"},
			wantExcludes:    []string{"workflow path"},
		},
		{
			name: "mcp config uses mcp-specific governance wording",
			path: ProjectActionPath(ActionPath{
				PathID:                 "apc-mcp-correlation",
				Org:                    "acme",
				Repo:                   "acme/app",
				ToolType:               "mcp",
				Location:               ".mcp.json",
				OwnerEvidenceState:     EvidenceStateUnknown,
				ApprovalEvidenceState:  EvidenceStateUnknown,
				ControlResolutionState: ControlResolutionStateNoVisibleControl,
				ControlPriority:        ControlPriorityControlFirst,
			}),
			requirementType: ClosureRequirementAssignOwner,
			wantContains:    []string{"MCP configuration surface"},
			wantExcludes:    []string{"workflow path"},
		},
		{
			name: "dependency signal keeps dependency guidance",
			path: ProjectActionPath(ActionPath{
				PathID:                 "apc-dependency-closure",
				Org:                    "acme",
				Repo:                   "acme/app",
				ToolType:               "dependency",
				Location:               "package-lock.json",
				ControlResolutionState: ControlResolutionStateNoVisibleControl,
			}),
			requirementType: ClosureRequirementCorrelateSurface,
			wantContains:    []string{"dependency inventory signal", "context"},
			wantExcludes:    []string{"workflow path"},
		},
		{
			name: "ci workflow keeps workflow-specific approval wording",
			path: ProjectActionPath(ActionPath{
				PathID:                 "apc-ci-approval",
				Org:                    "acme",
				Repo:                   "acme/app",
				ToolType:               "compiled_action",
				Location:               ".github/workflows/ci.yml",
				WriteCapable:           true,
				OwnerEvidenceState:     EvidenceStateVerified,
				ApprovalEvidenceState:  EvidenceStateUnknown,
				ProofEvidenceState:     EvidenceStateVerified,
				ControlResolutionState: ControlResolutionStateNoVisibleControl,
				ControlPriority:        ControlPriorityControlFirst,
			}),
			requirementType: ClosureRequirementAttachApproval,
			wantContains:    []string{"workflow path"},
			wantExcludes:    []string{"instruction surface"},
		},
		{
			name: "release workflow keeps release-specific proof wording",
			path: ProjectActionPath(ActionPath{
				PathID:                 "apc-release-proof",
				Org:                    "acme",
				Repo:                   "acme/app",
				ToolType:               "compiled_action",
				Location:               ".github/workflows/release.yml",
				WriteCapable:           true,
				DeployWrite:            true,
				ProductionWrite:        true,
				OwnerEvidenceState:     EvidenceStateVerified,
				ApprovalEvidenceState:  EvidenceStateVerified,
				ProofEvidenceState:     EvidenceStateUnknown,
				PolicyCoverageStatus:   PolicyCoverageStatusNone,
				ControlResolutionState: ControlResolutionStateNoVisibleControl,
				ControlPriority:        ControlPriorityControlFirst,
			}),
			requirementType: ClosureRequirementAttachPolicyReference,
			wantContains:    []string{"release workflow path"},
			wantExcludes:    []string{"dependency inventory signal"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := DecorateEvidenceContext([]ActionPath{tc.path}, nil)[0]
			requirement, ok := findClosureRequirement(path.ClosureRequirements, tc.requirementType)
			if !ok {
				t.Fatalf("expected requirement %s, got %+v", tc.requirementType, path.ClosureRequirements)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(requirement.Guidance, want) {
					t.Fatalf("expected guidance %q to contain %q, got %+v", requirement.Guidance, want, requirement)
				}
			}
			for _, unwanted := range tc.wantExcludes {
				if strings.Contains(requirement.Guidance, unwanted) {
					t.Fatalf("expected guidance %q to omit %q, got %+v", requirement.Guidance, unwanted, requirement)
				}
			}
		})
	}
}

func findClosureRequirement(items []ClosureRequirement, requirementType string) (ClosureRequirement, bool) {
	for _, item := range items {
		if strings.TrimSpace(item.RequirementType) == strings.TrimSpace(requirementType) {
			return item, true
		}
	}
	return ClosureRequirement{}, false
}

func axisScore(t *testing.T, completeness *EvidenceCompleteness, axis string) int {
	t.Helper()
	for _, item := range completeness.AxisScores {
		if item.Axis == axis {
			return item.Score
		}
	}
	t.Fatalf("missing axis %s in %+v", axis, completeness.AxisScores)
	return 0
}

var credentialProvenanceJIT = agginventory.CredentialProvenance{
	Type:           agginventory.CredentialProvenanceJIT,
	Scope:          agginventory.CredentialScopeWorkflow,
	Confidence:     "high",
	LikelyJIT:      true,
	RiskMultiplier: 1,
}

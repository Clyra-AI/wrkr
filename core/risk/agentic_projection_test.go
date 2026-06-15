package risk

import (
	"reflect"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestProjectActionPathDerivesWave1AutonomyAndControlProjection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		path      ActionPath
		wantTier  string
		wantReady string
		wantCtl   string
	}{
		{
			name: "safe metadata stays delegateable",
			path: ActionPath{
				PathID:          "apc-safe-metadata",
				Org:             "acme",
				Repo:            "acme/docs",
				ToolType:        "codex",
				Location:        "docs/usage.md",
				PathContext:     &agginventory.PathContext{Kind: agginventory.PathContextDocs, Confidence: "high"},
				ControlPriority: ControlPriorityInventoryHygiene,
				RiskTier:        RiskTierLow,
				ReviewBurden:    ReviewBurdenLow,
			},
			wantTier:  AutonomyTier0SafeMetadata,
			wantReady: DelegationReadinessSafeToDelegate,
			wantCtl:   RecommendedControlAllow,
		},
		{
			name: "app code path needs owner review",
			path: ActionPath{
				PathID:                "apc-app-code",
				Org:                   "acme",
				Repo:                  "acme/app",
				ToolType:              "codex",
				Location:              "cmd/app/main.go",
				WriteCapable:          true,
				PathContext:           &agginventory.PathContext{Kind: agginventory.PathContextRuntimeSource, Confidence: "high"},
				OwnerEvidenceState:    EvidenceStateUnknown,
				ApprovalEvidenceState: EvidenceStateVerified,
				ProofEvidenceState:    EvidenceStateVerified,
			},
			wantTier:  AutonomyTier2AppCodeOwnerReview,
			wantReady: DelegationReadinessReviewRequired,
			wantCtl:   RecommendedControlOwnerReview,
		},
		{
			name: "sensitive workflow missing proof requires proof",
			path: ActionPath{
				PathID:                "apc-sensitive-proof",
				Org:                   "acme",
				Repo:                  "acme/release",
				ToolType:              "compiled_action",
				Location:              ".github/workflows/release.yml",
				WriteCapable:          true,
				CredentialAccess:      true,
				PathContext:           &agginventory.PathContext{Kind: agginventory.PathContextDeployableSource, Confidence: "high"},
				OwnerEvidenceState:    EvidenceStateVerified,
				ApprovalEvidenceState: EvidenceStateVerified,
				ProofEvidenceState:    EvidenceStateUnknown,
				CredentialAuthority: &agginventory.CredentialAuthority{
					CredentialPresent:      true,
					CredentialUsableByPath: true,
					LikelyJIT:              true,
					AccessType:             agginventory.CredentialAccessTypeJIT,
				},
			},
			wantTier:  AutonomyTier3SensitiveCodeOrInfra,
			wantReady: DelegationReadinessProofRequired,
			wantCtl:   RecommendedControlProofRequired,
		},
		{
			name: "standing prod credential is blocked",
			path: ActionPath{
				PathID:                "apc-prod-standing",
				Org:                   "acme",
				Repo:                  "acme/payments",
				ToolType:              "ci_agent",
				Location:              ".github/workflows/deploy.yml",
				WriteCapable:          true,
				CredentialAccess:      true,
				DeployWrite:           true,
				ProductionWrite:       true,
				TargetClass:           TargetClassProductionImpacting,
				PathContext:           &agginventory.PathContext{Kind: agginventory.PathContextDeployableSource, Confidence: "high"},
				OwnerEvidenceState:    EvidenceStateVerified,
				ApprovalEvidenceState: EvidenceStateVerified,
				ProofEvidenceState:    EvidenceStateVerified,
				CredentialAuthority: &agginventory.CredentialAuthority{
					CredentialPresent:      true,
					CredentialUsableByPath: true,
					StandingAccess:         true,
					AccessType:             agginventory.CredentialAccessTypeStanding,
				},
			},
			wantTier:  AutonomyTier4ProdPrivilegedCustomerImpact,
			wantReady: DelegationReadinessBlocked,
			wantCtl:   RecommendedControlBlockStandingCredential,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := ProjectActionPath(tc.path)
			if got.AutonomyTier != tc.wantTier {
				t.Fatalf("unexpected autonomy tier: got %q want %q (%+v)", got.AutonomyTier, tc.wantTier, got)
			}
			if got.DelegationReadinessState != tc.wantReady {
				t.Fatalf("unexpected delegation readiness: got %q want %q (%+v)", got.DelegationReadinessState, tc.wantReady, got)
			}
			if got.RecommendedControl != tc.wantCtl {
				t.Fatalf("unexpected recommended control: got %q want %q (%+v)", got.RecommendedControl, tc.wantCtl, got)
			}
		})
	}
}

func TestProjectActionPathPromotesUnsafeLowRiskWorkflowClaims(t *testing.T) {
	t.Parallel()

	path := ProjectActionPath(ActionPath{
		PathID:       "apc-low-risk-sensitive",
		Org:          "acme",
		Repo:         "acme/platform",
		ToolType:     "ci_agent",
		Location:     ".github/workflows/release.yml",
		PathContext:  &agginventory.PathContext{Kind: agginventory.PathContextDeployableSource, Confidence: "high"},
		ControlState: ControlStateInventoryOnly,
		RiskTier:     RiskTierLow,
		ReviewBurden: ReviewBurdenLow,
	})

	if !containsString(path.RiskClassificationValidationReasons, "classification:low_risk_sensitive_path") {
		t.Fatalf("expected low-risk validation reason, got %+v", path.RiskClassificationValidationReasons)
	}
	if path.AutonomyTier != AutonomyTier3SensitiveCodeOrInfra {
		t.Fatalf("expected validation to promote tier, got %+v", path)
	}
	if path.DelegationReadinessState == DelegationReadinessSafeToDelegate {
		t.Fatalf("expected sensitive low-risk claim to stop being delegateable, got %+v", path)
	}
}

func TestProjectActionPathContradictoryEvidenceBlocksContract(t *testing.T) {
	t.Parallel()

	path := ProjectActionPath(ActionPath{
		PathID:                "apc-contradictory",
		Org:                   "acme",
		Repo:                  "acme/prod",
		ToolType:              "ci_agent",
		Location:              ".github/workflows/deploy.yml",
		WriteCapable:          true,
		CredentialAccess:      true,
		DeployWrite:           true,
		ApprovalEvidenceState: EvidenceStateContradictory,
		ProofEvidenceState:    EvidenceStateContradictory,
	})

	if path.DelegationReadinessState != DelegationReadinessBlockedByContradiction {
		t.Fatalf("expected contradiction to block the path, got %+v", path)
	}
	if path.RecommendedActionContract == nil {
		t.Fatal("expected recommended action contract")
	}
	if path.RecommendedActionContract.ContractReadinessState != ActionContractReadinessBlockedContradict {
		t.Fatalf("expected blocked contract readiness, got %+v", path.RecommendedActionContract)
	}
	if path.TodayPath == nil || path.RecommendedGovernedPath == nil {
		t.Fatalf("expected governed path views, got today=%+v recommended=%+v", path.TodayPath, path.RecommendedGovernedPath)
	}
}

func TestProjectActionPathContextOnlySurfaceNeedsCorrelationContract(t *testing.T) {
	t.Parallel()

	path := ProjectActionPath(ActionPath{
		PathID:                "apc-openapi-context",
		Org:                   "acme",
		Repo:                  "acme/payments",
		ToolType:              "openapi",
		Location:              "openapi/payments.yaml",
		WriteCapable:          true,
		ApprovalEvidenceState: EvidenceStateVerified,
		OwnerEvidenceState:    EvidenceStateVerified,
		ProofEvidenceState:    EvidenceStateVerified,
		MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{{
			Semantic:     agginventory.EndpointSemanticPayment,
			Confidence:   "high",
			Surface:      "openapi",
			Operation:    "POST /v1/payments",
			EvidenceRefs: []string{"POST /v1/payments"},
		}},
	})

	if path.ActionPathEligible {
		t.Fatalf("expected uncorrelated target surface to remain ineligible, got %+v", path)
	}
	if path.RecommendedActionContract == nil {
		t.Fatal("expected correlation guidance contract")
	}
	if path.RecommendedActionContract.ContractReadinessState != ActionContractReadinessNeedsCorrelation {
		t.Fatalf("expected needs_correlation contract readiness, got %+v", path.RecommendedActionContract)
	}
}

func TestSummarizeActionPathsCountsWave1Enums(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{
		{
			PathID:      "apc-docs",
			Org:         "acme",
			Repo:        "acme/docs",
			ToolType:    "codex",
			Location:    "docs/readme.md",
			PathContext: &agginventory.PathContext{Kind: agginventory.PathContextDocs, Confidence: "high"},
		},
		{
			PathID:                "apc-blocked",
			Org:                   "acme",
			Repo:                  "acme/payments",
			ToolType:              "ci_agent",
			Location:              ".github/workflows/deploy.yml",
			WriteCapable:          true,
			CredentialAccess:      true,
			ProductionWrite:       true,
			DeployWrite:           true,
			ApprovalEvidenceState: EvidenceStateVerified,
			ProofEvidenceState:    EvidenceStateVerified,
			CredentialAuthority: &agginventory.CredentialAuthority{
				CredentialPresent:      true,
				CredentialUsableByPath: true,
				StandingAccess:         true,
				AccessType:             agginventory.CredentialAccessTypeStanding,
			},
		},
	})

	summary := SummarizeActionPaths(paths, ActionPathSummaryOptions{})
	if summary.AutonomyTiers.Tier0SafeMetadata != 1 || summary.AutonomyTiers.Tier4ProdPrivilegedCustomerImpact != 1 {
		t.Fatalf("unexpected autonomy summary: %+v", summary.AutonomyTiers)
	}
	if summary.DelegationReadiness.SafeToDelegate != 1 || summary.DelegationReadiness.Blocked != 1 {
		t.Fatalf("unexpected readiness summary: %+v", summary.DelegationReadiness)
	}
	if summary.RecommendedControls.Allow != 1 || summary.RecommendedControls.BlockStandingCredential != 1 {
		t.Fatalf("unexpected control summary: %+v", summary.RecommendedControls)
	}
}

func TestProjectActionPathRemainsStableOnReprojection(t *testing.T) {
	t.Parallel()

	original := ActionPath{
		PathID:                "apc-stable-reprojection",
		Org:                   "acme",
		Repo:                  "acme/platform",
		ToolType:              "codex",
		Location:              "cmd/app/main.go",
		WriteCapable:          true,
		OwnerEvidenceState:    EvidenceStateVerified,
		ApprovalEvidenceState: EvidenceStateVerified,
		ProofEvidenceState:    EvidenceStateVerified,
		PathContext:           &agginventory.PathContext{Kind: agginventory.PathContextRuntimeSource, Confidence: "high"},
		ControlPriority:       ControlPriorityReviewQueue,
		RiskTier:              RiskTierLow,
		ReviewBurden:          ReviewBurdenLow,
	}

	first := ProjectActionPath(original)
	second := ProjectActionPath(first)

	if first.AutonomyTier != second.AutonomyTier {
		t.Fatalf("autonomy tier drifted on reprojection: first=%q second=%q", first.AutonomyTier, second.AutonomyTier)
	}
	if first.DelegationReadinessState != second.DelegationReadinessState {
		t.Fatalf("delegation readiness drifted on reprojection: first=%q second=%q", first.DelegationReadinessState, second.DelegationReadinessState)
	}
	if first.RecommendedControl != second.RecommendedControl {
		t.Fatalf("recommended control drifted on reprojection: first=%q second=%q", first.RecommendedControl, second.RecommendedControl)
	}
	if !reflect.DeepEqual(first.RiskClassificationValidationReasons, second.RiskClassificationValidationReasons) {
		t.Fatalf("validation reasons drifted on reprojection: first=%v second=%v", first.RiskClassificationValidationReasons, second.RiskClassificationValidationReasons)
	}
}

func TestValidActionContractReadinessStatePreservesDraftCompatibility(t *testing.T) {
	t.Parallel()

	if !ValidActionContractReadinessState(ActionContractReadinessDraft) {
		t.Fatalf("expected draft readiness state to remain schema-compatible")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

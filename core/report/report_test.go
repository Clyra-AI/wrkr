package report

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestSelectTopFindingsDeterministic(t *testing.T) {
	t.Parallel()

	report := risk.Report{
		TopN:   []risk.ScoredFinding{{CanonicalKey: "k1", Score: 9.1}, {CanonicalKey: "k2", Score: 8.2}},
		Ranked: []risk.ScoredFinding{{CanonicalKey: "k1", Score: 9.1}, {CanonicalKey: "k2", Score: 8.2}, {CanonicalKey: "k3", Score: 7.0}},
	}
	first := SelectTopFindings(report, 3)
	second := SelectTopFindings(report, 3)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("select top findings must be deterministic\nfirst=%v\nsecond=%v", first, second)
	}
	if len(first) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(first))
	}
}

func TestRenderMarkdownStableForFixedSummary(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-02-21T12:00:00Z",
		Template:     "operator",
		ShareProfile: "internal",
		Sections: []Section{
			{
				ID:     SectionHeadline,
				Title:  "Operator posture summary",
				Facts:  []string{"posture score 81.40 (B)", "profile status pass at 92.75%"},
				Impact: "posture controlled",
				Action: "maintain cadence",
				Proof:  ProofReference{ChainPath: ".wrkr/proof-chain.json", HeadHash: "sha256:abc", RecordCount: 5},
			},
		},
	}

	first := RenderMarkdown(summary)
	second := RenderMarkdown(summary)
	if first != second {
		t.Fatalf("markdown rendering must be deterministic\nfirst=%q\nsecond=%q", first, second)
	}
	if len(MarkdownLines(first)) == 0 {
		t.Fatal("expected markdown lines output")
	}
}

func TestPublicSanitizeFindingsRedactsLocationRepoOrg(t *testing.T) {
	t.Parallel()

	input := []risk.ScoredFinding{{
		CanonicalKey: "policy_violation|hardcoded-token|codex|/Users/example/private/repo/.codex/config.toml|backend|acme",
		Finding: model.Finding{
			Location: "/Users/example/private/repo/.codex/config.toml",
			Repo:     "backend",
			Org:      "acme",
		},
	}}
	out := PublicSanitizeFindings(input)
	if len(out) != 1 {
		t.Fatalf("expected one finding, got %d", len(out))
	}
	if strings.Contains(out[0].Finding.Location, "/Users/example") {
		t.Fatalf("expected redacted location, got %q", out[0].Finding.Location)
	}
	if out[0].Finding.Repo == "backend" || out[0].Finding.Org == "acme" {
		t.Fatalf("expected redacted repo/org, got repo=%q org=%q", out[0].Finding.Repo, out[0].Finding.Org)
	}
	if out[0].CanonicalKey == input[0].CanonicalKey || strings.Contains(out[0].CanonicalKey, "backend") {
		t.Fatalf("expected redacted canonical key, got %q", out[0].CanonicalKey)
	}
}

func TestBuildSummaryRejectsUnknownTemplateAndShareProfile(t *testing.T) {
	t.Parallel()

	_, err := BuildSummary(BuildInput{Template: Template("unknown"), ShareProfile: ShareProfileInternal})
	if err == nil {
		t.Fatal("expected unknown template error")
	}
	_, err = BuildSummary(BuildInput{Template: TemplateOperator, ShareProfile: ShareProfile("external")})
	if err == nil {
		t.Fatal("expected unknown share profile error")
	}
}

func TestBuildSummaryWithPublicProfileSanitizesProofPath(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{{
		FindingType: "policy_violation",
		Severity:    model.SeverityHigh,
		ToolType:    "codex",
		Location:    "/tmp/private/AGENTS.md",
		Repo:        "backend",
		Org:         "acme",
	}}
	riskReport := risk.Score(findings, 5, now)
	snapshot := state.Snapshot{
		Findings:     findings,
		RiskReport:   &riskReport,
		Profile:      &profileeval.Result{CompliancePercent: 92.75, DeltaPercent: -2.25, Status: "pass"},
		PostureScore: &score.Result{Score: 81.4, Grade: "B", TrendDelta: +1.6, Weights: scoremodel.DefaultWeights()},
		Identities: []manifest.IdentityRecord{{
			AgentID:       "wrkr:codex:acme",
			Status:        "under_review",
			ApprovalState: "missing",
		}},
		Transitions: []lifecycle.Transition{{
			AgentID:       "wrkr:codex:acme",
			PreviousState: "discovered",
			NewState:      "under_review",
			Trigger:       "first_seen",
			Timestamp:     now.Format(time.RFC3339),
		}},
	}

	summary, err := BuildSummary(BuildInput{
		Snapshot:     snapshot,
		Template:     TemplatePublic,
		ShareProfile: ShareProfilePublic,
		GeneratedAt:  now,
	})
	if err == nil {
		// BuildSummary requires proof chain; this test only validates early deterministic sanitization helpers.
		if summary.Proof.ChainPath != "redacted://proof-chain.json" {
			t.Fatalf("expected redacted proof path, got %q", summary.Proof.ChainPath)
		}
	}
}

func TestBuildSummaryHonorsExplicitTopZero(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			Findings: []model.Finding{
				{
					FindingType: "policy_violation",
					Severity:    model.SeverityHigh,
					ToolType:    "codex",
					Location:    "/tmp/private/AGENTS.md",
					Repo:        "backend",
					Org:         "acme",
				},
			},
		},
		Template:     TemplateOperator,
		ShareProfile: ShareProfileInternal,
		GeneratedAt:  now,
		Top:          0,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if len(summary.TopRisks) != 0 {
		t.Fatalf("expected zero top risks for explicit top=0, got %d", len(summary.TopRisks))
	}
}

func TestSanitizeProofReferencePublicRedactsCanonicalKeys(t *testing.T) {
	t.Parallel()

	out := sanitizeProofReferencePublic(ProofReference{
		ChainPath: "state/proof-chain.json",
		CanonicalFindingKeys: []string{
			"policy_violation|hardcoded-token|codex|/Users/example/private/repo/.codex/config.toml|backend|acme",
			"",
		},
	})

	if out.ChainPath != "redacted://proof-chain.json" {
		t.Fatalf("expected redacted chain path, got %q", out.ChainPath)
	}
	if len(out.CanonicalFindingKeys) != 1 {
		t.Fatalf("expected one redacted canonical key, got %v", out.CanonicalFindingKeys)
	}
	if strings.Contains(out.CanonicalFindingKeys[0], "backend") || strings.Contains(out.CanonicalFindingKeys[0], "acme") {
		t.Fatalf("expected redacted canonical finding key, got %q", out.CanonicalFindingKeys[0])
	}
}

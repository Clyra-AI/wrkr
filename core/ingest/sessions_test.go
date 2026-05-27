package ingest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestParseSessionBundleJSONAutodetectsProviders(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		payload  string
		provider string
	}{
		{
			name: "codex",
			payload: `{
  "session_id": "sess-1",
  "run_id": "run-1",
  "repo": "acme/payments",
  "workflow": ".github/workflows/release.yml",
  "prompt": "ship release candidate",
  "response": "release approved",
  "changed_files": [".github/workflows/release.yml"],
  "actions": ["deploy"],
  "completed_at": "2026-05-27T14:00:00Z"
}`,
			provider: SessionProviderCodex,
		},
		{
			name: "claude_code",
			payload: `{
  "provider": "claude-code",
  "conversation_id": "conv-7",
  "repo": "acme/payments",
  "workflow": ".github/workflows/release.yml",
  "transcript": "summarized transcript",
  "reviewers": ["security"],
  "completed_at": "2026-05-27T14:01:00Z"
}`,
			provider: SessionProviderClaudeCode,
		},
		{
			name: "cursor",
			payload: `{
  "conversation_id": "conv-9",
  "cursor_workspace": "payments",
  "repo": "acme/payments",
  "workflow": ".github/workflows/release.yml",
  "changed_files": ["cmd/release.go"],
  "completed_at": "2026-05-27T14:02:00Z"
}`,
			provider: SessionProviderCursor,
		},
		{
			name: "copilot",
			payload: `{
  "agent_session_id": "copilot-4",
  "repo": "acme/payments",
  "workflow": ".github/workflows/release.yml",
  "files_touched": ["README.md"],
  "completed_at": "2026-05-27T14:03:00Z"
}`,
			provider: SessionProviderCopilot,
		},
		{
			name: "gait",
			payload: `{
  "trace_id": "trace-11",
  "repo": "acme/payments",
  "workflow": ".github/workflows/release.yml",
  "policy_decisions": ["allow"],
  "completed_at": "2026-05-27T14:04:00Z"
}`,
			provider: SessionProviderGait,
		},
		{
			name: "unknown",
			payload: `{
  "repo": "acme/payments",
  "workflow": ".github/workflows/release.yml",
  "proof_refs": ["proof-1"],
  "completed_at": "2026-05-27T14:05:00Z"
}`,
			provider: SessionProviderUnknown,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bundle, err := ParseSessionBundleJSON([]byte(tc.payload))
			if err != nil {
				t.Fatalf("parse session artifact: %v", err)
			}
			if len(bundle.Sessions) != 1 {
				t.Fatalf("expected one session, got %d", len(bundle.Sessions))
			}
			if bundle.Sessions[0].Provider != tc.provider {
				t.Fatalf("expected provider %q, got %q", tc.provider, bundle.Sessions[0].Provider)
			}
			if bundle.Sessions[0].SessionID == "" {
				t.Fatalf("expected deterministic session id, got %+v", bundle.Sessions[0])
			}
			if tc.name == "codex" && bundle.Sessions[0].PromptRef == "" {
				t.Fatalf("expected prompt digest ref to be populated, got %+v", bundle.Sessions[0])
			}
		})
	}
}

func TestNormalizeSessionBundleRejectsUnsafePathAndSecretLikeValues(t *testing.T) {
	t.Parallel()

	_, err := NormalizeSessionBundle(SessionBundle{
		Sessions: []SessionRecord{{
			Provider:     SessionProviderCodex,
			Repo:         "acme/payments",
			Workflow:     ".github/workflows/release.yml",
			ChangedFiles: []string{"../secrets.txt"},
			CompletedAt:  "2026-05-27T14:00:00Z",
		}},
	})
	if err == nil {
		t.Fatal("expected unsafe path rejection")
	}

	_, err = ParseSessionBundleJSON([]byte(`{
  "provider": "codex",
  "repo": "acme/payments",
  "workflow": ".github/workflows/release.yml",
  "prompt": "ghp_secret_token",
  "completed_at": "2026-05-27T14:00:00Z"
}`))
	if err == nil {
		t.Fatal("expected secret-like prompt rejection")
	}
}

func TestProjectSessionsToRuntimeBundleAndEvidencePackets(t *testing.T) {
	t.Parallel()

	bundle, err := NormalizeSessionBundle(SessionBundle{
		GeneratedAt: "2026-05-27T14:00:00Z",
		Sessions: []SessionRecord{{
			Provider:        SessionProviderCodex,
			SessionID:       "sess-1",
			Repo:            "acme/payments",
			Workflow:        ".github/workflows/release.yml",
			PathID:          "apc-1",
			Actions:         []string{"deploy", "write"},
			ChangedFiles:    []string{"cmd/release.go"},
			Approvals:       []string{"security"},
			PolicyDecisions: []string{"allow"},
			ProofRefs:       []string{"proof-1"},
			CompletedAt:     "2026-05-27T14:00:00Z",
		}},
	})
	if err != nil {
		t.Fatalf("normalize sessions: %v", err)
	}

	runtimeBundle := ProjectSessionsToRuntimeBundle(bundle)
	if len(runtimeBundle.Records) < 3 {
		t.Fatalf("expected projected runtime evidence records, got %+v", runtimeBundle.Records)
	}
	packetBundle := ProjectSessionsToEvidencePacketBundle(bundle)
	if len(packetBundle.Packets) != 1 {
		t.Fatalf("expected one projected evidence packet, got %+v", packetBundle.Packets)
	}
	if packetBundle.Packets[0].MissingEvidenceState != "partial" {
		t.Fatalf("expected partial missing evidence state, got %+v", packetBundle.Packets[0])
	}
}

func TestCorrelateSessionsMatchesByReviewRefAndChangedFile(t *testing.T) {
	t.Parallel()

	summary := CorrelateSessions(state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:   "apc-release-1",
				AgentID:  "wrkr:codex-release:acme",
				Repo:     "acme/payments",
				Location: ".github/workflows/release.yml",
				IntroducedBy: &attribution.Result{
					Reference:   "pr/42",
					ChangedFile: "cmd/release.go",
				},
			}},
		},
	}, "runtime-sessions.json", SessionBundle{
		SchemaVersion: SessionSchemaVersion,
		GeneratedAt:   time.Date(2026, 5, 27, 14, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Sessions: []SessionRecord{{
			Provider:       SessionProviderCodex,
			SessionID:      "sess-1",
			Repo:           "acme/payments",
			Workflow:       ".github/workflows/release.yml",
			PullRequestRef: "pr/42",
			ChangedFiles:   []string{"cmd/release.go"},
			CompletedAt:    time.Date(2026, 5, 27, 14, 0, 0, 0, time.UTC).Format(time.RFC3339),
		}},
	})
	if summary.MatchedSessions != 1 || summary.UnmatchedSessions != 0 {
		t.Fatalf("expected matched session summary, got %+v", summary)
	}
	if len(summary.Correlations) != 1 || summary.Correlations[0].PathID != "apc-release-1" {
		t.Fatalf("expected correlation to path apc-release-1, got %+v", summary.Correlations)
	}
}

func TestValidateSessionJSONAcceptsNormalizedBundle(t *testing.T) {
	t.Parallel()

	payload, err := json.Marshal(SessionBundle{
		SchemaVersion: SessionSchemaVersion,
		GeneratedAt:   "2026-05-27T14:00:00Z",
		Sessions: []SessionRecord{{
			Provider:           SessionProviderCodex,
			SessionID:          "sess-1",
			Repo:               "acme/payments",
			Workflow:           ".github/workflows/release.yml",
			CompletedAt:        "2026-05-27T14:00:00Z",
			ChangedFiles:       []string{"cmd/release.go"},
			SourceArtifactRefs: []string{"codex-session.json"},
		}},
	})
	if err != nil {
		t.Fatalf("marshal runtime sessions: %v", err)
	}
	if err := ValidateSessionJSON(payload); err != nil {
		t.Fatalf("validate runtime sessions schema: %v", err)
	}
}

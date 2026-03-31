package model

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/manifest"
)

func TestIsIdentityBearingFinding(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   Finding
		want bool
	}{
		{
			name: "real tool config finding allowed",
			in: Finding{
				FindingType: "tool_config",
				ToolType:    "codex",
			},
			want: true,
		},
		{
			name: "source discovery excluded",
			in: Finding{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
			},
			want: false,
		},
		{
			name: "secret presence excluded",
			in: Finding{
				FindingType: "secret_presence",
				ToolType:    "secret",
			},
			want: false,
		},
		{
			name: "policy check excluded",
			in: Finding{
				FindingType: "policy_check",
				ToolType:    "policy",
			},
			want: false,
		},
		{
			name: "policy violation excluded",
			in: Finding{
				FindingType: "policy_violation",
				ToolType:    "policy",
			},
			want: false,
		},
		{
			name: "parse error excluded",
			in: Finding{
				FindingType: "parse_error",
				ToolType:    "yaml",
			},
			want: false,
		},
		{
			name: "skill metrics excluded",
			in: Finding{
				FindingType: "skill_metrics",
				ToolType:    "skill",
			},
			want: false,
		},
		{
			name: "project signal excluded",
			in: Finding{
				FindingType: "ai_project_signal",
				ToolType:    "dependency",
			},
			want: false,
		},
		{
			name: "prompt channel finding excluded",
			in: Finding{
				FindingType: "prompt_channel_override",
				ToolType:    "prompt_channel",
			},
			want: false,
		},
		{
			name: "extension finding with real tool type excluded by default",
			in: Finding{
				FindingType: "custom_extension_finding",
				ToolType:    "custom_detector",
				Detector:    "extension",
			},
			want: false,
		},
		{
			name: "extension finding with non-tool type excluded",
			in: Finding{
				FindingType: "custom_secret_presence",
				ToolType:    "secret",
				Detector:    "extension",
			},
			want: false,
		},
		{
			name: "missing tool type excluded",
			in: Finding{
				FindingType: "source_discovery",
			},
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsIdentityBearingFinding(tc.in); got != tc.want {
				t.Fatalf("unexpected classifier result: got=%v want=%v finding=%+v", got, tc.want, tc.in)
			}
		})
	}
}

func TestIsIdentityBearingFinding_UsesExplicitAllowlist(t *testing.T) {
	t.Parallel()

	for _, findingType := range []string{
		"ai_project_signal",
		"mcp_gateway_posture",
		"prompt_channel_override",
		"secret_presence",
		"skill_contribution",
		"skill_metrics",
		"source_discovery",
	} {
		findingType := findingType
		t.Run(findingType, func(t *testing.T) {
			t.Parallel()
			if IsIdentityBearingFinding(Finding{FindingType: findingType, ToolType: "skill"}) {
				t.Fatalf("expected %s to be non-identity-bearing", findingType)
			}
		})
	}
}

func TestIsInventoryBearingFinding_UsesExplicitAllowlist(t *testing.T) {
	t.Parallel()

	if !IsInventoryBearingFinding(Finding{FindingType: "tool_config", ToolType: "codex"}) {
		t.Fatal("expected canonical finding to be inventory-bearing")
	}
	if IsInventoryBearingFinding(Finding{FindingType: "skill_metrics", ToolType: "skill"}) {
		t.Fatal("expected skill_metrics to be excluded from inventory-bearing classification")
	}
	if IsInventoryBearingFinding(Finding{FindingType: "source_discovery", ToolType: "source_repo"}) {
		t.Fatal("expected source_discovery to be excluded from inventory-bearing classification")
	}
	if IsInventoryBearingFinding(Finding{FindingType: "secret_presence", ToolType: "secret"}) {
		t.Fatal("expected secret_presence to be excluded from inventory-bearing classification")
	}
	if IsInventoryBearingFinding(Finding{FindingType: "custom_extension_finding", ToolType: "custom_detector", Detector: "extension"}) {
		t.Fatal("expected extension finding with real tool type to stay off authoritative inventory surfaces by default")
	}
	if IsInventoryBearingFinding(Finding{FindingType: "custom_extension_finding", ToolType: "secret", Detector: "extension"}) {
		t.Fatal("expected extension finding with non-tool type to stay excluded from inventory-bearing classification")
	}
}

func TestIsLegacyArtifactIdentityCandidate_RejectsKnownNonToolArtifacts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		toolType string
		toolID   string
		agentID  string
		want     bool
	}{
		{
			name:     "rejects source repo record by tool type",
			toolType: "source_repo",
			toolID:   "source-repo-aaaaaaaaaa",
			want:     false,
		},
		{
			name:   "rejects secret record by tool id",
			toolID: "secret-bbbbbbbbbb",
			want:   false,
		},
		{
			name:    "rejects prompt channel record by agent id",
			agentID: "wrkr:prompt-channel-inst-cccccccccc:acme",
			want:    false,
		},
		{
			name:     "preserves real tool records",
			toolType: "codex",
			toolID:   "codex-dddddddddd",
			want:     true,
		},
		{
			name:   "preserves uncertain legacy record",
			toolID: "shared-instance",
			want:   true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsLegacyArtifactIdentityCandidate(tc.toolType, tc.toolID, tc.agentID); got != tc.want {
				t.Fatalf("unexpected legacy artifact classifier result: got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestFilterLegacyArtifactIdentityRecords_OmitsLegacyNonToolEntries(t *testing.T) {
	t.Parallel()

	records := []manifest.IdentityRecord{
		{AgentID: "wrkr:source-repo-aaaaaaaaaa:acme", ToolID: "source-repo-aaaaaaaaaa", ToolType: "source_repo"},
		{AgentID: "wrkr:codex-bbbbbbbbbb:acme", ToolID: "codex-bbbbbbbbbb", ToolType: "codex"},
		{AgentID: "wrkr:secret-cccccccccc:acme", ToolID: "secret-cccccccccc", ToolType: "secret"},
	}

	filtered := FilterLegacyArtifactIdentityRecords(records)
	if len(filtered) != 1 {
		t.Fatalf("expected only real-tool identities to remain, got %+v", filtered)
	}
	if filtered[0].ToolType != "codex" {
		t.Fatalf("expected codex identity to remain, got %+v", filtered[0])
	}
}

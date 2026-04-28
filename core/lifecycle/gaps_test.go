package lifecycle

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
)

func TestDetectGapsOwnerlessCredentialed(t *testing.T) {
	t.Parallel()

	gaps := DetectGaps(GapInput{
		Identities: []manifest.IdentityRecord{{
			AgentID:       "wrkr:codex-aaaa:acme",
			ToolID:        "codex-aaaa",
			ToolType:      "codex",
			Org:           "acme",
			Repo:          "acme/repo",
			Location:      "AGENTS.md",
			Status:        identity.StateUnderReview,
			ApprovalState: "missing",
			Present:       true,
		}},
		Inventory: &agginventory.Inventory{
			Tools: []agginventory.Tool{{
				AgentID:   "wrkr:codex-aaaa:acme",
				ToolID:    "codex-aaaa",
				ToolType:  "codex",
				Org:       "acme",
				DataClass: "secrets",
			}},
			AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
				AgentID:          "wrkr:codex-aaaa:acme",
				ToolID:           "codex-aaaa",
				ToolType:         "codex",
				CredentialAccess: true,
			}},
		},
	})
	if !containsLifecycleGap(gaps, GapOwnerlessExposure) {
		t.Fatalf("expected ownerless exposure gap, got %+v", gaps)
	}
	if !containsLifecycleGap(gaps, GapInactiveCredentialed) {
		t.Fatalf("expected inactive credentialed gap, got %+v", gaps)
	}
}

func containsLifecycleGap(gaps []Gap, reason string) bool {
	for _, gap := range gaps {
		if gap.ReasonCode == reason {
			return true
		}
	}
	return false
}

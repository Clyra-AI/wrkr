package controlbacklog

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestDeclaredControlledPathMovesToResolvedAppendix(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{
		ActionPaths: []risk.ActionPath{{
			PathID:               "apc-controlled",
			Org:                  "acme",
			Repo:                 "acme/release",
			ToolType:             "compiled_action",
			Location:             ".github/workflows/release.yml",
			WriteCapable:         true,
			ProductionWrite:      true,
			ApprovalGap:          true,
			ActionClasses:        []string{"deploy"},
			TargetClass:          risk.TargetClassProductionImpacting,
			ReviewLifecycleState: risk.ReviewLifecycleStateDeclaredControlled,
			ReviewSource:         "control-declaration",
		}},
	})

	if len(backlog.Items) != 1 {
		t.Fatalf("expected one backlog item, got %+v", backlog.Items)
	}
	item := backlog.Items[0]
	if item.Queue != QueueInventoryHygiene {
		t.Fatalf("expected declared controlled path to leave the unresolved queues, got %+v", item)
	}
	if item.FindingVisibility != FindingVisibilityAppendix {
		t.Fatalf("expected declared controlled path to remain visible in the appendix, got %+v", item)
	}
}

func TestFalsePositiveVisibleInAuditAppendix(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{
		ActionPaths: []risk.ActionPath{{
			PathID:               "apc-false-positive",
			Org:                  "acme",
			Repo:                 "acme/release",
			ToolType:             "compiled_action",
			Location:             ".github/workflows/release.yml",
			WriteCapable:         true,
			ApprovalGap:          true,
			ActionClasses:        []string{"deploy"},
			TargetClass:          risk.TargetClassProductionImpacting,
			ReviewLifecycleState: risk.ReviewLifecycleStateFalsePositive,
			ReviewRationale:      "Customer confirmed this workflow is detector noise.",
			ReviewOwner:          "platform-security",
		}},
	})

	if len(backlog.Items) != 1 {
		t.Fatalf("expected one backlog item, got %+v", backlog.Items)
	}
	item := backlog.Items[0]
	if item.FindingVisibility != FindingVisibilityAppendix {
		t.Fatalf("expected false-positive decision to stay in appendix visibility, got %+v", item)
	}
	if item.ReviewLifecycleState != risk.ReviewLifecycleStateFalsePositive {
		t.Fatalf("expected false-positive lifecycle state to remain auditable, got %+v", item)
	}
	if item.ReviewRationale == "" || item.ReviewOwner == "" {
		t.Fatalf("expected review audit context to remain visible, got %+v", item)
	}
}

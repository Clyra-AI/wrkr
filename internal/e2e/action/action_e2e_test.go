package action

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/action/changes"
)

func TestDocsOnlyPRE2EDoesNotTriggerComment(t *testing.T) {
	t.Parallel()

	docsOnly := []string{"README.md", "docs/usage.md"}
	if changes.HasRelevantChanges(docsOnly) {
		t.Fatal("expected docs-only PR to skip action comments")
	}
}

func TestAIConfigChangeE2ETriggersComment(t *testing.T) {
	t.Parallel()

	paths := []string{"README.md", ".codex/config.toml"}
	if !changes.HasRelevantChanges(paths) {
		t.Fatal("expected AI config path to trigger action comments")
	}
}

package changes

import "testing"

func TestHasRelevantChanges(t *testing.T) {
	t.Parallel()

	if HasRelevantChanges([]string{"README.md", "docs/guide.md"}) {
		t.Fatal("docs-only changes should not be relevant")
	}
	if !HasRelevantChanges([]string{"README.md", ".claude/settings.json"}) {
		t.Fatal("expected claude config change to be relevant")
	}
}

func TestRelevantPathsDeterministicSorted(t *testing.T) {
	t.Parallel()

	got := RelevantPaths([]string{".cursor/mcp.json", ".claude/settings.json", ".cursor/mcp.json"})
	if len(got) != 2 {
		t.Fatalf("expected deduped relevant paths, got %#v", got)
	}
	if got[0] != ".claude/settings.json" || got[1] != ".cursor/mcp.json" {
		t.Fatalf("unexpected ordering: %#v", got)
	}
}

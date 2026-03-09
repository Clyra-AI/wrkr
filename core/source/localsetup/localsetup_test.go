package localsetup

import "testing"

func TestAcquireReturnsLocalMachineManifest(t *testing.T) {
	t.Parallel()

	manifests, err := Acquire()
	if err != nil {
		t.Fatalf("acquire local setup: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}
	if manifests[0].Repo != RepoName {
		t.Fatalf("unexpected repo name: %q", manifests[0].Repo)
	}
	if manifests[0].Source != "local_machine" {
		t.Fatalf("unexpected source: %q", manifests[0].Source)
	}
	if manifests[0].Location == "" {
		t.Fatal("expected non-empty location")
	}
}

package detectors

import (
	"context"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

// RunFixture executes a detector registry on one fixture root deterministically.
func RunFixture(t *testing.T, fixtureRoot, org, repo string, detectorList ...detect.Detector) []model.Finding {
	t.Helper()

	registry := detect.NewRegistry()
	for _, detector := range detectorList {
		if err := registry.Register(detector); err != nil {
			t.Fatalf("register detector %s: %v", detector.ID(), err)
		}
	}

	findings, err := registry.Run(context.Background(), []detect.Scope{{Org: org, Repo: repo, Root: fixtureRoot}}, detect.Options{})
	if err != nil {
		t.Fatalf("run detector registry: %v", err)
	}
	return findings
}

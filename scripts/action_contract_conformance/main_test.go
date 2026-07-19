package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSpecAcceptsCanonicalNineScenarioContract(t *testing.T) {
	t.Parallel()
	specPath := filepath.Join("..", "..", "scenarios", "cross-product", "action-contract-interop", "inputs", "scenario-specs.json")
	spec, err := loadSpec(specPath)
	if err != nil {
		t.Fatalf("load canonical fixture spec: %v", err)
	}
	if spec.FixtureVersion != "1" || len(spec.Scenarios) != 9 || len(spec.ExternalConsumers) != 2 {
		t.Fatalf("unexpected canonical fixture spec: %+v", spec)
	}
}

func TestLoadSpecRejectsUnsafeScenarioAndConsumerDrift(t *testing.T) {
	t.Parallel()
	validPath := filepath.Join("..", "..", "scenarios", "cross-product", "action-contract-interop", "inputs", "scenario-specs.json")
	valid, err := loadSpec(validPath)
	if err != nil {
		t.Fatalf("load canonical fixture spec: %v", err)
	}

	tests := map[string]func(*fixtureSpec){
		"unsafe scenario id": func(spec *fixtureSpec) { spec.Scenarios[0].ScenarioID = "../escape" },
		"unknown mutation":   func(spec *fixtureSpec) { spec.Scenarios[0].Mutation = "invented" },
		"consumer drift":     func(spec *fixtureSpec) { delete(spec.ExternalConsumers, "gait") },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			spec := valid
			spec.Scenarios = append([]scenarioSpec(nil), valid.Scenarios...)
			spec.ExternalConsumers = make(map[string]consumerSpec, len(valid.ExternalConsumers))
			for key, value := range valid.ExternalConsumers {
				spec.ExternalConsumers[key] = value
			}
			mutate(&spec)
			payload, err := json.Marshal(spec)
			if err != nil {
				t.Fatalf("marshal invalid spec: %v", err)
			}
			path := filepath.Join(t.TempDir(), "spec.json")
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				t.Fatalf("write invalid spec: %v", err)
			}
			if _, err := loadSpec(path); err == nil {
				t.Fatal("invalid fixture spec must be rejected")
			}
		})
	}
}

func TestCleanManifestRootRejectsTraversalAndAbsolutePaths(t *testing.T) {
	t.Parallel()
	if got, err := cleanManifestRoot("scenarios/cross-product/action-contract-interop/expected"); err != nil || got == "" {
		t.Fatalf("accept canonical manifest root: got=%q err=%v", got, err)
	}
	for _, value := range []string{"../expected", "/tmp/expected", `scenarios\expected`, "scenarios/../expected"} {
		if _, err := cleanManifestRoot(value); err == nil {
			t.Fatalf("unsafe manifest root must fail: %q", value)
		}
	}
}

package executiontopology

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCanonicalizesAndResolvesTopology(t *testing.T) {
	path := filepath.Join(t.TempDir(), "topology.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nmappings:\n  - kind: jenkins_shared_library\n    alias: delivery-lib\n    source_repo: acme/pipeline-lib\n    source_path: vars/deploy.groovy\n    version: v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	topology, err := Load(path)
	if err != nil {
		t.Fatalf("load topology: %v", err)
	}
	if topology.Digest == "" {
		t.Fatal("expected canonical digest")
	}
	if mapping, ok := topology.Resolve("jenkins_shared_library", "delivery-lib"); !ok || mapping.SourceRepo != "acme/pipeline-lib" {
		t.Fatalf("resolve mapping: %+v %v", mapping, ok)
	}
}

func TestLoadCanonicalizesPortableSourcePaths(t *testing.T) {
	t.Parallel()

	load := func(sourcePath string) *Topology {
		t.Helper()
		path := filepath.Join(t.TempDir(), "topology.yaml")
		payload := "version: 1\nmappings:\n  - kind: workflow_alias\n    alias: release\n    source_repo: acme/shared\n    source_path: '" + sourcePath + "'\n"
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		topology, err := Load(path)
		if err != nil {
			t.Fatalf("load %q: %v", sourcePath, err)
		}
		return topology
	}

	windows := load(`workflows\release.yml`)
	portable := load("workflows/release.yml")
	if windows.Mappings[0].SourcePath != "workflows/release.yml" || windows.Digest != portable.Digest {
		t.Fatalf("portable path normalization diverged: windows=%+v portable=%+v", windows, portable)
	}
}

func TestLoadRejectsTraversalAndAliasCollisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "topology.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nmappings:\n  - kind: jenkins_shared_library\n    alias: lib\n    source_repo: acme/lib\n    source_path: ../../outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !IsUnsafePathError(err) {
		t.Fatal("expected traversal rejection")
	}
}

func TestLoadRejectsSymlinkAsUnsafe(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "topology.yaml")
	if err := os.WriteFile(target, []byte("version: 1\nmappings: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "topology-link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil || !IsUnsafePathError(err) {
		t.Fatalf("expected unsafe symlink rejection, got %v", err)
	}
}

func TestLoadRejectsIntermediateSymlinkAsUnsafe(t *testing.T) {
	root := t.TempDir()
	targetDir := filepath.Join(root, "target")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(targetDir, "topology.yaml")
	if err := os.WriteFile(target, []byte("version: 1\nmappings:\n- kind: workflow_alias\n  alias: release\n  source_repo: acme/lib\n  source_path: workflow.yml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "linked")
	if err := os.Symlink(targetDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(linkDir, "topology.yaml")); err == nil || !IsUnsafePathError(err) {
		t.Fatalf("expected unsafe intermediate symlink rejection, got %v", err)
	}
}

func TestLoadValidationFailures(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		unsafe  bool
	}{
		{name: "malformed", payload: "version: ["},
		{name: "trailing_document", payload: "version: 1\nmappings:\n- kind: workflow_alias\n  alias: release\n  source_repo: acme/lib\n  source_path: workflow.yml\n---\nversion: 1\nmappings:\n- kind: workflow_alias\n  alias: ignored\n  source_repo: acme/other\n  source_path: ignored.yml\n"},
		{name: "unknown_top_level", payload: "version: 1\nextra: true\nmappings:\n- kind: workflow_alias\n  alias: release\n  source_repo: acme/lib\n  source_path: workflow.yml\n"},
		{name: "unknown_mapping_field", payload: "version: 1\nmappings:\n- kind: workflow_alias\n  alias: release\n  source_repo: acme/lib\n  source_path: workflow.yml\n  extra: true\n"},
		{name: "version", payload: "version: 2\nmappings: []\n"},
		{name: "empty", payload: "version: 1\nmappings: []\n"},
		{name: "kind", payload: "version: 1\nmappings:\n- kind: unsupported\n  alias: lib\n  source_repo: acme/lib\n  source_path: vars/release.groovy\n"},
		{name: "required", payload: "version: 1\nmappings:\n- kind: workflow_alias\n  alias: ''\n  source_repo: acme/lib\n  source_path: workflow.yml\n"},
		{name: "absolute", payload: "version: 1\nmappings:\n- kind: workflow_alias\n  alias: release\n  source_repo: acme/lib\n  source_path: /tmp/workflow.yml\n", unsafe: true},
		{name: "windows_absolute", payload: "version: 1\nmappings:\n- kind: workflow_alias\n  alias: release\n  source_repo: acme/lib\n  source_path: 'C:\\tmp\\workflow.yml'\n", unsafe: true},
		{name: "windows_traversal", payload: "version: 1\nmappings:\n- kind: workflow_alias\n  alias: release\n  source_repo: acme/lib\n  source_path: '..\\outside.yml'\n", unsafe: true},
		{name: "duplicate", payload: "version: 1\nmappings:\n- kind: api_runtime\n  alias: API\n  source_repo: acme/api\n  source_path: spec.json\n- kind: api_runtime\n  alias: api\n  source_repo: acme/api2\n  source_path: spec.json\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "topology.yaml")
			if err := os.WriteFile(path, []byte(tc.payload), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected validation failure")
			}
			if tc.unsafe != IsUnsafePathError(err) {
				t.Fatalf("unsafe=%v err=%v", IsUnsafePathError(err), err)
			}
		})
	}
}

func TestLoadPathAndResolveBoundaries(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("expected required path error")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("expected missing file error")
	}
	directory := t.TempDir()
	if _, err := Load(directory); err == nil || !IsUnsafePathError(err) {
		t.Fatalf("expected unsafe directory error, got %v", err)
	}
	var topology *Topology
	if _, ok := topology.Resolve("workflow_alias", "release"); ok {
		t.Fatal("nil topology must not resolve")
	}
	loaded := &Topology{Mappings: []Mapping{{Kind: "workflow_alias", Alias: "Release", SourceRepo: "acme/lib"}}}
	if mapping, ok := loaded.Resolve(" workflow_alias ", " release "); !ok || mapping.SourceRepo != "acme/lib" {
		t.Fatalf("expected case-insensitive alias resolution, got %+v %v", mapping, ok)
	}
	if _, ok := loaded.Resolve("api_runtime", "release"); ok {
		t.Fatal("unexpected kind resolution")
	}
}

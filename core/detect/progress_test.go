package detect

import (
	"context"
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
)

type fakeProgressDetector struct {
	id   string
	err  error
	make func(Scope) []model.Finding
}

func (d fakeProgressDetector) ID() string {
	return d.id
}

func (d fakeProgressDetector) Detect(_ context.Context, scope Scope, _ Options) ([]model.Finding, error) {
	if d.err != nil {
		return nil, d.err
	}
	if d.make == nil {
		return nil, nil
	}
	return d.make(scope), nil
}

type recordingDetectorProgress struct {
	events []string
}

func (r *recordingDetectorProgress) DetectorStart(event DetectorProgressEvent) {
	r.events = append(r.events, "start:"+event.Scope.Org+"/"+event.Scope.Repo+":"+event.DetectorID)
}

func (r *recordingDetectorProgress) DetectorComplete(event DetectorProgressEvent) {
	r.events = append(r.events, "complete:"+event.Scope.Org+"/"+event.Scope.Repo+":"+event.DetectorID)
}

func (r *recordingDetectorProgress) DetectorError(event DetectorProgressEvent) {
	r.events = append(r.events, "error:"+event.Scope.Org+"/"+event.Scope.Repo+":"+event.DetectorID)
}

func TestDetectorRegistryEmitsProgressInStableOrder(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	for _, detector := range []Detector{
		fakeProgressDetector{id: "b"},
		fakeProgressDetector{id: "a"},
	} {
		if err := registry.Register(detector); err != nil {
			t.Fatalf("register detector: %v", err)
		}
	}

	rootA := t.TempDir()
	rootB := t.TempDir()
	reporter := &recordingDetectorProgress{}
	_, err := registry.Run(context.Background(), []Scope{
		{Org: "beta", Repo: "two", Root: rootB},
		{Org: "alpha", Repo: "one", Root: rootA},
	}, Options{Progress: reporter})
	if err != nil {
		t.Fatalf("run registry: %v", err)
	}

	want := []string{
		"start:alpha/one:a",
		"complete:alpha/one:a",
		"start:alpha/one:b",
		"complete:alpha/one:b",
		"start:beta/two:a",
		"complete:beta/two:a",
		"start:beta/two:b",
		"complete:beta/two:b",
	}
	if !reflect.DeepEqual(reporter.events, want) {
		t.Fatalf("unexpected detector progress order\nwant=%v\ngot=%v", want, reporter.events)
	}
}

func TestDetectorProgressDoesNotChangeFindings(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	if err := registry.Register(fakeProgressDetector{
		id: "codex",
		make: func(scope Scope) []model.Finding {
			return []model.Finding{{
				FindingType:     "tool_config",
				Severity:        model.SeverityLow,
				DiscoveryMethod: model.DiscoveryMethodStatic,
				ToolType:        "codex",
				Location:        ".codex/config.toml",
				Repo:            scope.Repo,
				Org:             scope.Org,
				Detector:        "codex",
			}}
		},
	}); err != nil {
		t.Fatalf("register detector: %v", err)
	}

	scopes := []Scope{{Org: "local", Repo: "alpha", Root: t.TempDir()}}
	withoutProgress, err := registry.Run(context.Background(), scopes, Options{})
	if err != nil {
		t.Fatalf("run without progress: %v", err)
	}
	withProgress, err := registry.Run(context.Background(), scopes, Options{Progress: &recordingDetectorProgress{}})
	if err != nil {
		t.Fatalf("run with progress: %v", err)
	}
	if !reflect.DeepEqual(withoutProgress, withProgress) {
		t.Fatalf("expected detector progress callbacks to preserve run results\nwithout=%+v\nwith=%+v", withoutProgress, withProgress)
	}
}

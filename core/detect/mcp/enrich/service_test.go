package enrich

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServiceLookupAggregatesProviders(t *testing.T) {
	t.Parallel()

	advisory := mockAdvisoryProvider{result: AdvisoryResult{Count: 2, Source: "advisory-source", Schema: "osv/v1", Fresh: true}}
	registry := mockRegistryProvider{result: RegistryResult{Status: "listed", Source: "registry-source", Schema: "registry/v1", Fresh: true}}
	service := Service{
		Advisories: advisory,
		Registry:   registry,
		Clock: func() time.Time {
			return time.Date(2026, 2, 23, 10, 0, 0, 0, time.UTC)
		},
	}
	result := service.Lookup(context.Background(), "@scope/server", "1.2.3")
	if result.AdvisoryCount != 2 {
		t.Fatalf("expected advisory count 2, got %d", result.AdvisoryCount)
	}
	if result.RegistryStatus != "listed" {
		t.Fatalf("expected registry status listed, got %s", result.RegistryStatus)
	}
	if result.AsOf != "2026-02-23T10:00:00Z" {
		t.Fatalf("unexpected as_of value %s", result.AsOf)
	}
	if !strings.Contains(result.Source, "advisory:advisory-source") || !strings.Contains(result.Source, "registry:registry-source") {
		t.Fatalf("unexpected source string %s", result.Source)
	}
	if result.Quality != QualityOK {
		t.Fatalf("expected quality=ok, got %s", result.Quality)
	}
	if result.AdvisorySchema != "osv/v1" || result.RegistrySchema != "registry/v1" {
		t.Fatalf("unexpected schema values advisory=%s registry=%s", result.AdvisorySchema, result.RegistrySchema)
	}
}

func TestOSVAdvisoryClientAndRegistryClient(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/advisory":
			payload := map[string]any{"vulns": []any{map[string]any{"id": "GHSA-1"}, map[string]any{"id": "GHSA-2"}}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(payload)
		case strings.HasPrefix(r.URL.Path, "/registry/v0/servers/"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	advisory := OSVAdvisoryClient{HTTPClient: server.Client(), Endpoint: server.URL + "/advisory"}
	advisoryResult, advisoryErr := advisory.Lookup(context.Background(), "@scope/server", "1.2.3")
	if advisoryErr != nil {
		t.Fatalf("advisory lookup failed: %v", advisoryErr)
	}
	if advisoryResult.Count != 2 {
		t.Fatalf("expected 2 advisories, got %d", advisoryResult.Count)
	}

	registry := MCPRegistryClient{HTTPClient: server.Client(), BaseURL: server.URL + "/registry"}
	registryResult, registryErr := registry.Lookup(context.Background(), "@scope/server")
	if registryErr != nil {
		t.Fatalf("registry lookup failed: %v", registryErr)
	}
	if registryResult.Status != "listed" {
		t.Fatalf("expected listed registry status, got %s", registryResult.Status)
	}
	if registryResult.Schema != legacyRegistrySchema {
		t.Fatalf("expected legacy registry schema for empty body, got %s", registryResult.Schema)
	}
	if registryResult.Fresh {
		t.Fatal("expected empty-body registry lookup to be stale")
	}
}

func TestServiceLookupQualityUnavailableWhenProvidersFail(t *testing.T) {
	t.Parallel()

	service := Service{
		Advisories: mockAdvisoryProvider{err: context.DeadlineExceeded},
		Registry:   mockRegistryProvider{err: context.DeadlineExceeded},
	}
	result := service.Lookup(context.Background(), "pkg", "1.0.0")
	if result.Quality != QualityUnavailable {
		t.Fatalf("expected quality unavailable, got %s", result.Quality)
	}
	if result.RegistryStatus != "unknown" || result.AdvisoryCount != 0 {
		t.Fatalf("expected fail-safe no enrich data, got advisory_count=%d registry_status=%s", result.AdvisoryCount, result.RegistryStatus)
	}
}

func TestServiceLookupQualityPartialOnSingleProviderFailure(t *testing.T) {
	t.Parallel()

	service := Service{
		Advisories: mockAdvisoryProvider{result: AdvisoryResult{Count: 1, Source: "advisory-source", Schema: "osv/v1", Fresh: true}},
		Registry:   mockRegistryProvider{err: context.DeadlineExceeded},
	}
	result := service.Lookup(context.Background(), "pkg", "1.0.0")
	if result.Quality != QualityPartial {
		t.Fatalf("expected quality partial, got %s", result.Quality)
	}
	if result.AdvisoryCount != 1 || result.RegistryStatus != "unknown" {
		t.Fatalf("unexpected enrich values advisory_count=%d registry_status=%s", result.AdvisoryCount, result.RegistryStatus)
	}
}

func TestServiceLookupQualityStaleForCompatibilityDecoder(t *testing.T) {
	t.Parallel()

	service := Service{
		Advisories: mockAdvisoryProvider{result: AdvisoryResult{Count: 1, Source: "advisory-source", Schema: "osv/v2_compat", Fresh: false}},
		Registry:   mockRegistryProvider{result: RegistryResult{Status: "listed", Source: "registry-source", Schema: "registry/v1", Fresh: true}},
	}
	result := service.Lookup(context.Background(), "pkg", "1.0.0")
	if result.Quality != QualityStale {
		t.Fatalf("expected quality stale, got %s", result.Quality)
	}
}

func TestOSVAdvisoryClientCompatibilityDecoderMarksStale(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []any{map[string]any{"id": "GHSA-compat"}}})
	}))
	defer server.Close()

	advisory := OSVAdvisoryClient{HTTPClient: server.Client(), Endpoint: server.URL}
	result, err := advisory.Lookup(context.Background(), "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("compat advisory lookup failed: %v", err)
	}
	if result.Count != 1 {
		t.Fatalf("expected count=1, got %d", result.Count)
	}
	if result.Schema != "osv/v2_compat" || result.Fresh {
		t.Fatalf("expected stale compat schema, got schema=%s fresh=%t", result.Schema, result.Fresh)
	}
}

func TestRegistryClientRejectsUnknownSchemaVersion(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/registry/v0/servers/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": "v9"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	registry := MCPRegistryClient{HTTPClient: server.Client(), BaseURL: server.URL + "/registry"}
	result, err := registry.Lookup(context.Background(), "pkg")
	if err == nil {
		t.Fatalf("expected registry schema error, got nil (result=%+v)", result)
	}
}

func TestRegistryClient404PlainTextStillReturnsUnlisted(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/registry/v0/servers/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	registry := MCPRegistryClient{HTTPClient: server.Client(), BaseURL: server.URL + "/registry"}
	result, err := registry.Lookup(context.Background(), "pkg")
	if err != nil {
		t.Fatalf("expected unlisted result, got err=%v", err)
	}
	if result.Status != "unlisted" {
		t.Fatalf("expected unlisted status, got %s", result.Status)
	}
	if result.Schema != legacyRegistrySchema {
		t.Fatalf("expected legacy schema fallback, got %s", result.Schema)
	}
}

type mockAdvisoryProvider struct {
	result AdvisoryResult
	err    error
}

func (m mockAdvisoryProvider) Lookup(_ context.Context, _ string, _ string) (AdvisoryResult, error) {
	return m.result, m.err
}

type mockRegistryProvider struct {
	result RegistryResult
	err    error
}

func (m mockRegistryProvider) Lookup(_ context.Context, _ string) (RegistryResult, error) {
	return m.result, m.err
}
